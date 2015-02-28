/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2015 Zhuofei Wang <semigodking@gmail.com>
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"
#include "encrypt.h"

#define INITIAL_BUFFER_SIZE 8192

static const int ss_addrtype_ipv4 = 1;
static const int ss_addrtype_domain = 3;
static const int ss_addrtype_ipv6 = 4;

typedef enum ss_state_t {
    ss_new,
    ss_connected,
    ss_MAX,
} ss_state;

typedef struct ss_client_t {
    struct enc_ctx e_ctx;
    struct enc_ctx d_ctx;
} ss_client;

typedef struct ss_instance_t {
    int init;
    int method; 
    // Clients of each instance share a same buffer for encryption/decryption
    void * buff;
    size_t buff_size;
    enc_info info;
} ss_instance;

void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg);

int ss_is_valid_cred(const char *method, const char *password)
{
    if (!method || !password)
        return 0;
    if (strlen(method) > 255) {
        log_error(LOG_WARNING, "Shadowsocks encryption method can't be more than 255 chars.");
        return 0;
    }
    if (strlen(password) > 255) {
        log_error(LOG_WARNING, "Shadowsocks encryption password can't be more than 255 chars.");
        return 0;
    }
    return 1;
}

void ss_client_init(redsocks_client *client)
{
    ss_client *sclient = (void*)(client + 1);
    ss_instance * ss = (ss_instance *)(client->instance+1);

    client->state = ss_new;
    enc_ctx_init(&ss->info, &sclient->e_ctx, 1);
    enc_ctx_init(&ss->info, &sclient->d_ctx, 0);
}

void ss_client_fini(redsocks_client *client)
{
    ss_client *sclient = (void*)(client + 1);
    enc_ctx_free(&sclient->e_ctx);
    enc_ctx_free(&sclient->d_ctx);
}

static int get_shared_buffer(redsocks_client *client, size_t in_size, void **buff, size_t *buff_size)
{
    ss_instance * ss = (ss_instance *)(client->instance+1);
    void * tmp;

    size_t required = ss_calc_buffer_size(ss->method, in_size); 
    if (ss->buff_size < required)
    {
        tmp = realloc(buff, required);
        if (!tmp)
            return -1;
        ss->buff = tmp;
        ss->buff_size = required; 
    }
    *buff = ss->buff;
    *buff_size = ss->buff_size;
    return 0;
}

static void encrypt_mem(redsocks_client * client,
                      char * data, size_t len,
                      struct bufferevent * to)
{
    ss_client *sclient = (void*)(client + 1);
    size_t buff_len;
    char * buff;
    int rc;

    rc = get_shared_buffer(client, len, (void **)&buff, &buff_len);
    if (rc || !data || !len)
        return;
    rc = ss_encrypt(&sclient->e_ctx, data, len, buff, &buff_len); 
    if (rc)
    {
        bufferevent_write(to, buff, buff_len);
    }
}


static void encrypt_buffer(redsocks_client *client,
                           struct bufferevent * from,
                           struct bufferevent * to)
{
    // To reduce memory copy, just encrypt one block a time
    size_t input_size = evbuffer_get_contiguous_space(bufferevent_get_input(from));
    char * input;

    if (!input_size)
        return;

    input = (char *)evbuffer_pullup(bufferevent_get_input(from), input_size);    
    encrypt_mem(client, input, input_size, to); 
    evbuffer_drain(bufferevent_get_input(from), input_size);
}

static void decrypt_buffer(redsocks_client * client,
                           struct bufferevent * from,
                           struct bufferevent * to)
{
    ss_client *sclient = (void*)(client + 1);
    struct enc_ctx * ctx = &sclient->d_ctx; 
    // To reduce memory copy, just decrypt one block a time
    size_t input_size = evbuffer_get_contiguous_space(bufferevent_get_input(from));
    size_t buff_len;
    char * buff;
    char * input;
    int    rc;

    rc = get_shared_buffer(client, input_size, (void **)&buff, &buff_len);
    if (rc || !buff || !input_size)
        return;

    input = (char *)evbuffer_pullup(bufferevent_get_input(from), input_size);
    rc = ss_decrypt(ctx, input, input_size, buff, &buff_len); 
    if (rc)
    {
        bufferevent_write(to, buff, buff_len);
        evbuffer_drain(bufferevent_get_input(from), input_size);
    }
}


static void ss_client_writecb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    struct bufferevent * from = client->relay;
    struct bufferevent * to   = buffev;
    char from_eof = client->relay_evshut & EV_READ;
    size_t input_size = evbuffer_get_contiguous_space(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    assert(buffev == client->client);
    redsocks_touch_client(client);

    if (input_size == 0 && from_eof)
    {
        redsocks_shutdown(client, to, SHUT_WR);
        return;
    }

    if (client->state == ss_connected) 
    {
        /* encrypt and forward data received from client side */
        if (output_size < to->wm_write.high)
        {
            if (input_size)
                decrypt_buffer(client, from, to);
            if (bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }
    }
    else
    {
        redsocks_drop_client(client);
    }
}

static void ss_client_readcb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    struct bufferevent * from = buffev;
    struct bufferevent * to   = client->relay;
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    assert(buffev == client->client);
    redsocks_touch_client(client);

    if (client->state == ss_connected)
    {
        /* encrypt and forward data to the other side  */
        if (output_size < to->wm_write.high)
        {
            encrypt_buffer(client, from, to);
            if (bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }
        else
        {
            if (bufferevent_disable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
        }
    }
    else
    {
        redsocks_drop_client(client);
    }
}


static void ss_relay_writecb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    struct bufferevent * from = client->client;
    struct bufferevent * to   = buffev;
    char from_eof = client->client_evshut & EV_READ;
    size_t input_size = evbuffer_get_contiguous_space(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    assert(buffev == client->relay);
    redsocks_touch_client(client);

    if (input_size == 0 && from_eof)
    {
        redsocks_shutdown(client, to, SHUT_WR);
        return;
    }

    if (client->state == ss_connected) 
    {
        /* encrypt and forward data received from client side */
        if (output_size < to->wm_write.high)
        {
            if (input_size)
                encrypt_buffer(client, from, to);
            if (bufferevent_enable(from, EV_READ) == -1)
                    redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }
    }
    else
    {
        redsocks_drop_client(client);
    }
}

static void ss_relay_readcb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    struct bufferevent * from = buffev;
    struct bufferevent * to   = client->client;
    size_t input_size = evbuffer_get_contiguous_space(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    assert(buffev == client->relay);
    redsocks_touch_client(client);

    if (client->state == ss_connected)
    {
        /* decrypt and forward data to client side */
        if (output_size < to->wm_write.high)
        {
            if (input_size)
                decrypt_buffer(client, from, to);
            if (bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }
        else
        {
            if (bufferevent_disable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
        }
    }
    else
    {
        redsocks_drop_client(client);
    }
}

static void ss_relay_connected(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    char buff[512] ; 
    size_t len = 0;

    assert(buffev == client->relay);
    assert(client->state == ss_new);
    redsocks_touch_client(client);

    if (!red_is_socket_connected_ok(buffev)) {
        redsocks_log_error(client, LOG_DEBUG, "failed to connect to destination");
        redsocks_drop_client(client);
        return;
    }

    /* We do not need to detect timeouts any more.
    The two peers will handle it. */
    bufferevent_set_timeouts(client->relay, NULL, NULL);

    if (!redsocks_start_relay(client))
    {
        /* overwrite theread callback to my function */
        bufferevent_setcb(client->client, ss_client_readcb,
                                         ss_client_writecb,
                                         redsocks_event_error,
                                         client);
        bufferevent_setcb(client->relay, ss_relay_readcb,
                                         ss_relay_writecb,
                                         redsocks_event_error,
                                         client);
    }
    else
    {
        redsocks_log_error(client, LOG_DEBUG, "failed to start relay");
        redsocks_drop_client(client);
        return;
    }

    /* build and send header */
    // TODO: Better implementation and IPv6 Support
    buff[len] = ss_addrtype_ipv4;
    len += 1;
    memcpy(&buff[len], &client->destaddr.sin_addr, sizeof(client->destaddr.sin_addr));
    len += sizeof(client->destaddr.sin_addr);
    memcpy(&buff[len], &client->destaddr.sin_port, sizeof(client->destaddr.sin_port));
    len += sizeof(client->destaddr.sin_port);
    encrypt_mem(client, &buff[0], len, client->relay);

    client->state = ss_connected; 

    // Write any data received from client side to relay.
    if (evbuffer_get_length(bufferevent_get_input(client->client)))
        ss_relay_writecb(client->relay, client);
    return;

}


static void ss_connect_relay(redsocks_client *client)
{
    struct timeval tv;

    tv.tv_sec = client->instance->config.timeout;
    tv.tv_usec = 0;
    /* use default timeout if timeout is not configured */
    if (tv.tv_sec == 0)
        tv.tv_sec = DEFAULT_CONNECT_TIMEOUT; 
    
    client->relay = red_connect_relay2(&client->instance->config.relayaddr,
                    NULL, ss_relay_connected, redsocks_event_error, client, 
                    &tv);

    if (!client->relay) {
        redsocks_log_errno(client, LOG_ERR, "ss_connect_relay");
        redsocks_drop_client(client);
    }
}

static int ss_instance_init(struct redsocks_instance_t *instance)
{
    ss_instance * ss = (ss_instance *)(instance+1);
    const redsocks_config *config = &instance->config;

    int valid_cred =  ss_is_valid_cred(config->login, config->password);
    if (!valid_cred 
    || (ss->method = enc_init(&ss->info, config->password, config->login), ss->method == -1))
    {
        log_error(LOG_ERR, "Invalided encrytion method or password.");
        return -1;
    }
    else
    {
        log_error(LOG_INFO, "using encryption method: %s", config->login);
    }
    /* Setting up shared buffer */
    ss->buff = malloc(INITIAL_BUFFER_SIZE); 
    ss->buff_size = INITIAL_BUFFER_SIZE;
    if (!ss->buff)
        return -1;
    return 0;
}

static void ss_instance_fini(struct redsocks_instance_t *instance)
{
    ss_instance * ss = (ss_instance *)(instance + 1);
    if (ss->buff)
        free (ss->buff);
}

relay_subsys shadowsocks_subsys =
{
    .name                 = "shadowsocks",
    .payload_len          = sizeof(ss_client),
    .instance_payload_len = sizeof(ss_instance),
    .init                 = ss_client_init,
    .fini                 = ss_client_fini,
    .connect_relay        = ss_connect_relay,
    .instance_init        = ss_instance_init,
    .instance_fini        = ss_instance_fini,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
