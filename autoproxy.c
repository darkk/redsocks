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
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"
#include "parser.h"
#include "list.h"
#include "main.h"
#include "ipcache.h"

typedef enum autoproxy_state_t {
    /* Introduce subsystem */
    AUTOPROXY_NEW=10000,
    AUTOPROXY_CONNECTED,
    AUTOPROXY_CONFIRMED,
    AUTOPROXY_SHUTDOWN, // Not used
} autoproxy_state;

typedef struct autoproxy_client_t {
    autoproxy_state state;
    time_t time_connect_relay; // timestamp when start to connect relay
    size_t data_recv;
    size_t data_sent;
    struct event * recv_timer_event;
    int    quick_check; // flag indicating quick check initiated.
} autoproxy_client;


void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);
void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg);
static int auto_retry_or_drop(redsocks_client * client);
static void direct_relay_clientreadcb(struct bufferevent *from, void *_client);
static void auto_event_error(struct bufferevent *buffev, short what, void *_arg);

#define QUICK_CONNECT_TIMEOUT_SECONDS 3 
#define NO_CHECK_SECONDS 60 


typedef struct autoproxy_config_t {
    list_head  list; // Make it a list to support multiple configurations
    int    quick_connect_timeout;
    int    no_quick_check_seconds;
} autoproxy_config;

static autoproxy_config default_config = {
    .quick_connect_timeout = QUICK_CONNECT_TIMEOUT_SECONDS,
    .no_quick_check_seconds = NO_CHECK_SECONDS,
};

static list_head configs = LIST_HEAD_INIT(configs);

static parser_entry autoproxy_entries[] =
{
    { .key = "quick_connect_timeout",  .type = pt_uint16 },
    { .key = "no_quick_check_seconds",  .type = pt_uint16 },
    { }
};

static int autoproxy_onenter(parser_section *section)
{
    autoproxy_config * config = malloc(sizeof(*config));
    if (!config) {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    INIT_LIST_HEAD(&config->list);
    /* initialize with default config */
    memcpy(config, &default_config, sizeof(*config));

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "quick_connect_timeout") == 0) ? (void*)&config->quick_connect_timeout:
            (strcmp(entry->key, "no_quick_check_seconds") == 0) ? (void*)&config->no_quick_check_seconds:
            NULL;
    section->data = config; 
    return 0;
}

static int autoproxy_onexit(parser_section *section)
{
    /* FIXME: Rewrite in bullet-proof style. There are memory leaks if config
     *        file is not correct, so correct on-the-fly config reloading is
     *        currently impossible.
     */
    const char *err = NULL;
    autoproxy_config * config = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    /* Check and update values here */
    if (!config->quick_connect_timeout)
        err = "Timeout value for quick check can not be 0. Default: 3";

    if (err)
        parser_error(section->context, err);
    else
        // Add config to config list
        list_add(&config->list, &configs);

    return err ? -1 : 0;
}

static parser_section autoproxy_conf_section =
{
    .name    = "autoproxy",
    .entries = autoproxy_entries,
    .onenter = autoproxy_onenter,
    .onexit  = autoproxy_onexit
};

app_subsys autoproxy_app_subsys =
{
//    .init = autoproxy_init,
//    .fini = autoproxy_fini,
    .conf_section = &autoproxy_conf_section,
};


static autoproxy_config * get_config(redsocks_client * client)
{
    // TODO: By far, only the first configuration section takes effect.
    // We need to find a proper way to let user specify which config section
    // to associate with.
    autoproxy_config * config = NULL;
    if (!list_empty(&configs))
    {
        list_for_each_entry(config, &configs, list)
            break;
        return config;
    }
    else
    {
        return &default_config;
    }
}

#define get_autoproxy_client(client) (void*)(client + 1) + client->instance->relay_ss->payload_len;

static void auto_client_init(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);

    memset((void *) aclient, 0, sizeof(autoproxy_client));
    aclient->state = AUTOPROXY_NEW;
}

static void auto_client_fini(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);

    if (aclient->recv_timer_event)
    {
        event_del(aclient->recv_timer_event);
        event_free(aclient->recv_timer_event);
        aclient->recv_timer_event = NULL;
    }
}

static void on_connection_confirmed(redsocks_client *client)
{
    redsocks_log_error(client, LOG_DEBUG, "IP Confirmed"); 

    cache_del_addr(&client->destaddr);
}

static void on_connection_blocked(redsocks_client *client)
{
    redsocks_log_error(client, LOG_DEBUG, "IP Blocked"); 
}

static void auto_confirm_connection(redsocks_client * client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);

    assert(aclient->state == AUTOPROXY_CONNECTED);
    aclient->state = AUTOPROXY_CONFIRMED;
    if (aclient->data_sent)
    {
        evbuffer_drain(bufferevent_get_input(client->client), aclient->data_sent);
        aclient->data_sent = 0;
    }
    // Cancel timer and release event object for timer
    if (aclient->recv_timer_event)
    {
        event_del(aclient->recv_timer_event);
        event_free(aclient->recv_timer_event);
        aclient->recv_timer_event = NULL;
    }
    on_connection_confirmed(client);
}

static void auto_recv_timeout_cb(evutil_socket_t fd, short events, void * arg)
{
    redsocks_client *client = arg;
    autoproxy_client * aclient = get_autoproxy_client(client);

    redsocks_log_error(client, LOG_DEBUG, "RECV Timeout, state: %d, data_sent: %u", aclient->state, aclient->data_sent); 
    assert(events & EV_TIMEOUT);

    redsocks_touch_client(client);
    // Let's make connection confirmed
    if (aclient->state == AUTOPROXY_CONNECTED)
        auto_confirm_connection(client);
    else
        return;

    // No ERROR/EOF/data received before timeout, continue sending data
    if (!(client->relay_evshut & EV_WRITE))
    {
        if (bufferevent_write_buffer(client->relay, bufferevent_get_input(client->client)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (!(client->client_evshut & EV_READ) && bufferevent_enable(client->client, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
}


static void direct_relay_readcb_helper(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    if (evbuffer_get_length(bufferevent_get_output(to)) < to->wm_write.high)
    {
        if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (bufferevent_enable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
    else {
        if (bufferevent_disable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
    }
}

// Caller should continue writing if this function returns 0.
// Otherwise, stop writing.
static int handle_write_to_relay(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct bufferevent * from = client->client;
    struct bufferevent * to = client->relay;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    if (aclient->state == AUTOPROXY_CONNECTED )
    {
        redsocks_log_error(client, LOG_DEBUG, "sent: %u, recv: %u, in:%u, out:%u",
                                    aclient->data_sent,
                                    aclient->data_recv,
                                    input_size,
                                    output_size
                                    );
        /* Not send or receive data. */
        if (!aclient->data_sent && !aclient->data_recv)
        {
            /* Ensure we have data to send */
            if (input_size)
            {
                /* copy data from input to output of relay */
                aclient->data_sent = copy_evbuffer (to, from, 0);
                return 1;
            }
        }
        /* 
         * Relay reaceived data before writing to relay.
        */
        else if (!aclient->data_sent && aclient->data_recv)
        {
            // TODO: 
            // In case we receive data before sending any data,
            // should we confirm connection immediately or after
            // sending data?
            //aclient->data_sent = copy_evbuffer(to, from, 0);
            auto_confirm_connection(client);
             
        }
        /* aclient->state = AUTOPROXY_CONFIRMED; */
        /* We have writen data to relay, but got nothing until we are requested to 
        * write to it again.
        */
        else if (aclient->data_sent && !aclient->data_recv)
        {
            /* No response from relay and no CONNECTION RESET,
                Send more data.
            */
            /* Write more data util input buffer of relay is full */
            if (input_size - aclient->data_sent > 0) /* we have more data waiting to be sent  */
            {
                aclient->data_sent += copy_evbuffer(to, from, aclient->data_sent);
            }

            else if (output_size < aclient->data_sent /*  data is sent out, more or less */
                && input_size == aclient->data_sent /* all data in read buffer is sent */
                && !aclient->recv_timer_event /* timer is not activated yet */
                ) 
            {
                aclient->recv_timer_event = evtimer_new(bufferevent_get_base(to), auto_recv_timeout_cb, client);
                if (aclient->recv_timer_event)
                {
                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 600000;
                    if (-1 == evtimer_add(aclient->recv_timer_event, &tv))
                    {
                        redsocks_log_error(client, LOG_DEBUG, "Failed to add timer!");
                        // In case we failed to add timer, it is abnormal. 
                        // Let's confirm the connection directly so that normal service is not
                        // impacted.
                        auto_confirm_connection(client);
                        return 0;
                    }
                }
            }
            return 1;
        }
        /* We sent data to and got data from relay. */
        else if (aclient->data_sent && aclient->data_recv)
        {
            /* No CONNECTION RESET error occur after sending data, good. */
            auto_confirm_connection(client);
        }
    }
    return 0;
}

// Caller should continue writing if this function returns 0.
// Otherwise, stop writing.
static int handle_write_to_client(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct bufferevent * from = client->relay;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    if (aclient->state == AUTOPROXY_CONNECTED)
    {
        if (!aclient->data_recv)
        {
            aclient->data_recv = input_size;
            if (input_size)
                auto_confirm_connection(client);
        }
    }
    return 0;
}

static void direct_relay_clientreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    redsocks_log_error(client, LOG_DEBUG, "client in: %u", input_size); 
    redsocks_touch_client(client);
    if (handle_write_to_relay(client))
        return;
    direct_relay_readcb_helper(client, client->client, client->relay);
}


static void direct_relay_relayreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    redsocks_log_error(client, LOG_DEBUG, "relay in: %u", input_size); 
    redsocks_touch_client(client);
    if (handle_write_to_client(client))
        return;
    direct_relay_readcb_helper(client, client->relay, client->client);
}

static void direct_relay_clientwritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    struct bufferevent * from = client->relay;
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    redsocks_touch_client(client);
    if (process_shutdown_on_write_(client, from, to))
        return;
    if (handle_write_to_client(client))
        return;
    if (output_size < to->wm_write.high) 
    {
        if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (!(client->relay_evshut & EV_READ) && bufferevent_enable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
}

static int process_shutdown_on_write_2(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));
    unsigned short from_evshut = from == client->client ? client->client_evshut : client->relay_evshut;
    unsigned short to_evshut = to == client->client ? client->client_evshut : client->relay_evshut;

    redsocks_log_error(client, LOG_DEBUG, "WCB %s, fs: %u, ts: %u, fin: %u, fout: %u, tin: %u",
                                to == client->client?"client":"relay",
                                from_evshut,
                                to_evshut,
                                evbuffer_get_length(bufferevent_get_input(from)),
                                evbuffer_get_length(bufferevent_get_output(from)),
                                evbuffer_get_length(bufferevent_get_input(to)));

    if ((from_evshut & EV_READ) && !(to_evshut & EV_WRITE))
    {
        if (input_size == 0
            || (input_size == aclient->data_sent && aclient->state == AUTOPROXY_CONNECTED))
        {
            redsocks_shutdown(client, to, SHUT_WR);
            return 1;
        }
    }
    return 0;
}


static void direct_relay_relaywritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct bufferevent * from = client->client;
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    redsocks_touch_client(client);

    if (process_shutdown_on_write_2(client, from, to))
        return;
    if (handle_write_to_relay(client))
        return;
    if (aclient->state == AUTOPROXY_CONFIRMED)
    {
        if (output_size < to->wm_write.high) 
        {
            if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
            if (!(client->client_evshut & EV_READ) && bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }   
    }
}

static void auto_drop_relay(redsocks_client *client)
{
    int fd;
    if (client->relay)
    {
        redsocks_log_error(client, LOG_DEBUG, "dropping relay only ");
        fd = bufferevent_getfd(client->relay);
        bufferevent_free(client->relay);
        redsocks_close(fd);
        client->relay = NULL;
    }
    client->relay_connected = 0;
}

static int auto_retry(redsocks_client * client, int updcache)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    int rc;

    if (aclient->state == AUTOPROXY_CONNECTED)
        bufferevent_disable(client->client, EV_READ| EV_WRITE); 
    /* drop relay and update state, then retry with specified relay */
    if (updcache)
    {
        /* only add IP to cache when the IP is not in cache */
        if (cache_get_addr_time(&client->destaddr) == NULL)
        {
            cache_add_addr(&client->destaddr);
            redsocks_log_error(client, LOG_DEBUG, "ADD IP to cache: %s", 
                            inet_ntoa(client->destaddr.sin_addr));
        }
    }
    // Release timer
    if (aclient->recv_timer_event)
    {
        event_del(aclient->recv_timer_event);
        event_free(aclient->recv_timer_event);
        aclient->recv_timer_event = NULL;
    }

    auto_drop_relay(client);

    // restore callbacks for ordinary client.
    bufferevent_setcb(client->client, NULL, NULL, redsocks_event_error, client);
    // enable reading to handle EOF from client
    if (!(client->client_evshut & EV_READ))
        bufferevent_enable(client->client, EV_READ); 

    /* connect to relay */
    if (client->instance->relay_ss->connect_relay)
    {
        rc = client->instance->relay_ss->connect_relay(client);
        // In case the underline relay system does not connect relay,
        // it maybe is waiting for client read event.
        // Take 'http-relay' for example.
        if (!rc && !client->relay && evbuffer_get_length(bufferevent_get_input(client->client)))
#ifdef bufferevent_trigger_event
            bufferevent_trigger_event(client->client, EV_READ, 0);
#else
            client->client->readcb(client->client, client);
#endif
    }
    else
        rc = redsocks_connect_relay(client);
    return rc;
}

/* return 1 for drop, 0 for retry. */
static int auto_retry_or_drop(redsocks_client * client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    
    if (aclient->state == AUTOPROXY_NEW || aclient->state == AUTOPROXY_CONNECTED)
    {
        on_connection_blocked(client);  
        auto_retry(client, 0);
        return 0; 
    }
    /* drop */
    return 1;
}

static void auto_relay_connected(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    autoproxy_client * aclient = get_autoproxy_client(client);
    
    assert(buffev == client->relay);
        
    redsocks_touch_client(client);

    if (!red_is_socket_connected_ok(buffev)) {
        if (aclient->state == AUTOPROXY_NEW && !auto_retry_or_drop(client))
            return;
            
        redsocks_log_error(client, LOG_DEBUG, "failed to connect to destination");
        redsocks_drop_client(client);
        return;
    }

    /* update client state */   
    aclient->state = AUTOPROXY_CONNECTED;
    client->relay_connected = 1;

    /* We do not need to detect timeouts any more.
    The two peers will handle it. */
    bufferevent_set_timeouts(client->relay, NULL, NULL);

    if (!redsocks_start_relay(client))
    {
        /* overwrite theread callback to my function */
        bufferevent_setcb(client->client, direct_relay_clientreadcb,
                                         direct_relay_clientwritecb,
                                         auto_event_error,
                                         client);
        bufferevent_setcb(client->relay, direct_relay_relayreadcb,
                                         direct_relay_relaywritecb,
                                         auto_event_error,
                                         client);
    }
    else
    {
        redsocks_log_error(client, LOG_DEBUG, "failed to start relay");
        redsocks_drop_client(client);
        return;
    }
    // Write any data received from client side to relay.
    if (evbuffer_get_length(bufferevent_get_input(client->client)))
        direct_relay_relaywritecb(client->relay, client);
    return;
}

// Note: before relay is connected, READING EOF/ERROR reported from client
// is handled by redsocks default ERROR handler.
static void auto_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    redsocks_client *client = _arg;
    autoproxy_client * aclient = get_autoproxy_client(client);
    int saved_errno = errno;

    assert(buffev == client->relay || buffev == client->client);
    redsocks_touch_client(client);

    if (!(what & BEV_EVENT_ERROR))
        errno = red_socket_geterrno(buffev);
    redsocks_log_errno(client, LOG_DEBUG, "%s, errno(%d), State: %d, what: " event_fmt_str, 
                            buffev == client->client?"client":"relay",
                            errno, aclient->state, event_fmt(what));
    if (buffev == client->relay)
    {
/*
        if (what & BEV_EVENT_CONNECTED) 
        {
            auto_relay_connected(buffev, _arg);
            return;
        }
*/
        if ( aclient->state == AUTOPROXY_NEW 
        && what == (BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT))
        {
            // Update access time for IP fails again.
            if (aclient->quick_check)
                cache_touch_addr(&client->destaddr);

            on_connection_blocked(client);  
            /* In case timeout occurs while connecting relay, we try to connect
            to target via configured proxy. It is possible that the connection to
            target can be set up a bit longer than the timeout value we set. 
            However, it is still better to make connection via proxy. */
            auto_retry(client, 1);
            return;
        }

        if (aclient->state == AUTOPROXY_NEW  && saved_errno == ECONNRESET)
            if (!auto_retry_or_drop(client))
                return;

        if (aclient->state == AUTOPROXY_CONNECTED
                && what == (BEV_EVENT_READING|BEV_EVENT_ERROR) 
                /* No matter it is disconnected due to Connection Reset or any
                other reason, we still have a chance to forward connection via
                 proxy. I prefer retry only if we got connection reset.
                */
                && saved_errno == ECONNRESET)
        {
            if (!auto_retry_or_drop(client))
                return;
        }
    }   

    if (what == (BEV_EVENT_READING|BEV_EVENT_EOF))
    {
        // Timer cases:
        //  1. READ EOF from relay (normal case, need to releae timer)
        //  2. READ EOF from client (normal case, no need to release timer)
        //  3. READ ERROR from client (abnormal, not recoverable)
        //  4. READ ERROR from erlay (abnormal, not recoverable)
        if (aclient->recv_timer_event && buffev == client->relay)
            auto_confirm_connection(client);

        redsocks_shutdown(client, buffev, SHUT_RD);
        // Ensure the other party could send remaining data and SHUT_WR also
        if (buffev == client->client)
        {
            if (!(client->relay_evshut & EV_WRITE))
                bufferevent_enable(client->relay, EV_WRITE);
        }
        else
        {
            if (!(client->client_evshut & EV_WRITE))
                bufferevent_enable(client->client, EV_WRITE);
        }
    }
    else
    {
        redsocks_drop_client(client);
    }
}                                                                       


static int auto_connect_relay(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    autoproxy_config * config = NULL;
    struct timeval tv;
    tv.tv_sec = client->instance->config.timeout;
    tv.tv_usec = 0;
    time_t * acc_time = NULL;
    time_t now = redsocks_time(NULL);   

    /* use default timeout if timeout is not configured */
    if (tv.tv_sec == 0)
        tv.tv_sec = DEFAULT_CONNECT_TIMEOUT; 
    
    if (aclient->state == AUTOPROXY_NEW)
    {
        acc_time = cache_get_addr_time(&client->destaddr);
        if (acc_time)
        {
            redsocks_log_error(client, LOG_DEBUG, "Found dest IP in cache");
            config = get_config(client);
            // No quick check when the time passed since IP is added to cache is 
            // less than NO_CHECK_SECONDS. Just let it go via proxy.
            if (config->no_quick_check_seconds == 0
              || now - *acc_time < config->no_quick_check_seconds)
                return auto_retry(client, 0);
            /* update timeout value for quick detection.
             * Sometimes, good sites are added into cache due to occasionally
             * connection timeout. It is annoying. So, decision is made to
             * always try to connect to destination first when the destination
             * is found in cache. 
             * For most destinations, the connection could be set up correctly
             * in short time. And, for most blocked sites, we get connection
             * reset almost immediately when connection is set up or when HTTP
             * request is sent. 
             */
            tv.tv_sec = config->quick_connect_timeout;
            aclient->quick_check = 1;
        }
        /* connect to target directly without going through proxy */    
        client->relay = red_connect_relay2(&client->destaddr,
                        NULL, auto_relay_connected, auto_event_error, client, 
                        &tv);
    
        aclient->time_connect_relay = redsocks_time(NULL);
           
        if (!client->relay) {
            redsocks_log_errno(client, LOG_ERR, "auto_connect_relay");
            redsocks_drop_client(client);
            return -1;
        }
    }
    else
    {
        redsocks_log_errno(client, LOG_ERR, "invalid state: %d", aclient->state);
        redsocks_drop_client(client);
        return -1;
    }
    return 0;
}
                                                    

relay_subsys autoproxy_subsys =
{
    .name                 = "autoproxy",
    .payload_len          = sizeof(autoproxy_client),
    .instance_payload_len = 0,
    .readcb               = direct_relay_relayreadcb,
    .writecb              = direct_relay_relaywritecb,
    .init                 = auto_client_init,
    .fini                 = auto_client_fini,
    .connect_relay        = auto_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
