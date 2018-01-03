/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/bufferevent_ssl.h>
#include "log.h"
#include "redsocks.h"
#include "http-auth.h"

#if LIBEVENT_VERSION_NUMBER >= 0x02010100
#  ifndef EVENT__HAVE_OPENSSL
#  error The libevent2 you are compiling with does not have OpenSSL enabled!
#  endif
#else
#  ifndef _EVENT_HAVE_OPENSSL
#  error The libevent2 you are compiling with does not have OpenSSL enabled!
#  endif
#endif

typedef enum httpsc_state_t {
    httpc_new,
    httpc_request_sent,
    httpc_reply_came,
    httpc_headers_skipped,
    httpc_MAX,
} httpc_state;

typedef struct httpsc_client_t {
    SSL * ssl;
} httpsc_client;

typedef struct httpsc_instance_t {
    http_auth auth;
    SSL_CTX * ctx;
} httpsc_instance;

#define HTTP_HEAD_WM_HIGH 8192 // that should be enough for one HTTP line.


static void log_ssl_error(redsocks_client *client, struct bufferevent * buffev)
{
    unsigned long err;
    while ((err = (bufferevent_get_openssl_error(buffev)))) {
        const char *msg = (const char*)
            ERR_reason_error_string(err);
        const char *lib = (const char*)
            ERR_lib_error_string(err);
        const char *func = (const char*)
            ERR_func_error_string(err);
        redsocks_log_errno(client, LOG_DEBUG, "SSL Error: %s %s: %s", lib, func, msg);
    }
}

static void httpsc_client_init(redsocks_client *client)
{
    client->state = httpc_new;
}

static void httpsc_client_fini(redsocks_client *client)
{
    httpsc_client *sclient = (void*)(client + 1);
    struct bufferevent * underlying = NULL;

    if (client->relay) {
        underlying = bufferevent_get_underlying(client->relay);
        if (underlying) {
            bufferevent_free(client->relay);
            client->relay = underlying;
        }
    }
    if (sclient->ssl) {
        SSL_free(sclient->ssl);
        sclient->ssl = NULL;
    }
}

static int httpsc_instance_init(struct redsocks_instance_t *instance)
{
    httpsc_instance * httpsc = (httpsc_instance *)(instance + 1);
    SSL_CTX * ctx = NULL;
    
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
    {
        unsigned long err = ERR_get_error();
        log_error(LOG_ERR, "Failed to allocate SSL context. SSL Error: %s", ERR_lib_error_string(err));
        return -1;
    }
    httpsc->ctx = ctx;
    return 0;
}

static void httpsc_instance_fini(redsocks_instance *instance)
{
    httpsc_instance * httpsc = (httpsc_instance *)(instance + 1);

    free(httpsc->auth.last_auth_query);
    httpsc->auth.last_auth_query = NULL;
    if (httpsc->ctx) {
        SSL_CTX_free (httpsc->ctx);
        httpsc->ctx = NULL;
    }
}

extern struct evbuffer *httpc_mkconnect(redsocks_client *client);
extern void httpc_read_cb(struct bufferevent *buffev, void *_arg);

static void httpsc_event_cb(struct bufferevent *buffev, short what, void *_arg)
{
    redsocks_client *client = _arg;
    assert(buffev == client->relay || buffev == client->client);

    redsocks_touch_client(client);

    if (!(what & BEV_EVENT_ERROR))
        errno = red_socket_geterrno(buffev);
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    else if (!bufferevent_openssl_get_allow_dirty_shutdown(client->relay))
#else
    else
#endif
        log_ssl_error(client, client->relay);
    redsocks_log_errno(client, LOG_DEBUG, "%s, what: " event_fmt_str, 
                            buffev == client->client?"client":"relay",
                            event_fmt(what));

    if (what == (BEV_EVENT_READING|BEV_EVENT_EOF)) {
        redsocks_shutdown(client, buffev, SHUT_RD, 1);
        // Ensure the other party could send remaining data and SHUT_WR also
        if (buffev == client->client)
        {
            if (!(client->relay_evshut & EV_WRITE) && client->relay_connected)
                // when we got EOF from client, we need to shutdown relay's write
                process_shutdown_on_write_(client, client->client, client->relay); 
        }
        else
        {
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
            if (bufferevent_openssl_get_allow_dirty_shutdown(client->relay))
#endif
                log_ssl_error(client, client->relay);
            if (!(client->client_evshut & EV_WRITE))
                bufferevent_enable(client->client, EV_WRITE);
        }
    }
    else if (what == BEV_EVENT_CONNECTED) {
        // usually this event is not generated as 'connect' is used to
        // setup connection. For openssl socket, this event is generated.
        client->relay_connected = 1;
        /* We do not need to detect timeouts any more.
           The two peers will handle it. */
        bufferevent_set_timeouts(client->relay, NULL, NULL);
        redsocks_write_helper_ex(
                buffev, client,
                httpc_mkconnect, httpc_request_sent, 0, HTTP_HEAD_WM_HIGH
                );
    }
    else {
        redsocks_drop_client(client);
    }
}

static void httpsc_read_cb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;

    httpc_read_cb(buffev, _arg);

    if (client->state == httpc_headers_skipped) {
        bufferevent_data_cb read_cb, write_cb;

        replace_eventcb(client->client, httpsc_event_cb);
        struct evbuffer * input = bufferevent_get_input(client->client);
        if (evbuffer_get_length(input))
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
            bufferevent_trigger(client->relay, EV_WRITE, 0);
#else
            if (client->relay->writecb)
                client->relay->writecb(client->relay, client);
#endif
    }
}

static void httpsc_write_cb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    struct bufferevent * from = client->client;
    struct bufferevent * to = client->relay;

    process_shutdown_on_write_(client, from, to);
}

static int httpsc_connect_relay(redsocks_client *client)
{
    httpsc_client *sclient = (void*)(client + 1);
    httpsc_instance *httpsc = (httpsc_instance *)(client->instance + 1);
    char * interface = client->instance->config.interface;
    struct timeval tv = {client->instance->config.timeout, 0};

    if (!sclient->ssl)
        sclient->ssl = SSL_new(httpsc->ctx); 

    // Allowing binding relay socket to specified IP for outgoing connections
    client->relay = red_connect_relay_ssl(interface, &client->instance->config.relayaddr,
                                      sclient->ssl,
                                      httpsc_read_cb, 
                                      NULL,
                                      httpsc_event_cb, client, &tv);
    if (!client->relay) {
        redsocks_log_errno(client, LOG_ERR, "red_connect_relay_ssl");
        redsocks_drop_client(client);
        return -1;
    }

    return 0;
}

relay_subsys https_connect_subsys =
{
    .name                 = "https-connect",
    .payload_len          = sizeof(httpsc_client),
    .instance_payload_len = sizeof(httpsc_instance),
    .readcb               = httpsc_read_cb,
    .writecb              = httpsc_write_cb,
    .init                 = httpsc_client_init,
    .fini                 = httpsc_client_fini,
    .connect_relay        = httpsc_connect_relay,
    .instance_init        = httpsc_instance_init,
    .instance_fini        = httpsc_instance_fini,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
