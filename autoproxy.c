/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2014 Zhuofei Wang <semigodking@gmail.com>
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
static void auto_connect_relay(redsocks_client *client);
static void direct_relay_clientreadcb(struct bufferevent *from, void *_client);
static void auto_event_error(struct bufferevent *buffev, short what, void *_arg);

#define CIRCUIT_RESET_SECONDS 1
#define DEFAULT_CONNECT_TIMEOUT_SECONDS 10 
#define QUICK_CONNECT_TIMEOUT_SECONDS 3 
#define NO_CHECK_SECONDS 60 
#define CACHE_ITEM_STALE_SECONDS 60*30
#define ADDR_CACHE_BLOCKS 256 
#define ADDR_CACHE_BLOCK_SIZE 16 
#define ADDR_PORT_CHECK 1
#define block_from_sockaddr_in(addr) (addr->sin_addr.s_addr & 0xFF) / (256/ADDR_CACHE_BLOCKS)
#define get_autoproxy_client(client) (void*)(client + 1) + client->instance->relay_ss->payload_len;

typedef struct cache_data_t {
    struct sockaddr_in addr;
    time_t access_time;
} cache_data;

static cache_data addr_cache[ADDR_CACHE_BLOCKS][ADDR_CACHE_BLOCK_SIZE];
static int addr_cache_counters[ADDR_CACHE_BLOCKS];
static int addr_cache_pointers[ADDR_CACHE_BLOCKS];
static int cache_init = 0;

static void init_addr_cache()
{           
    if (!cache_init)
    {
        memset((void *)addr_cache, 0, sizeof(addr_cache));
        memset((void *)addr_cache_counters, 0, sizeof(addr_cache_counters));
        memset((void *)addr_cache_pointers, 0, sizeof(addr_cache_pointers));
        cache_init = 1;
    }
}

static int is_addr_in_cache(const struct sockaddr_in * addr)
{
    /* get block index */
    int block = block_from_sockaddr_in(addr);
    int count = addr_cache_counters[block];
    int first = addr_cache_pointers[block];
    int i = 0;
    /* do reverse search for efficency */
    for ( i = count - 1; i >= 0; i -- )
    {
        if (0 == evutil_sockaddr_cmp((const struct sockaddr *)addr,
                 (const struct sockaddr *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr,
                 ADDR_PORT_CHECK))
            return 1;
    }       
    return 0;
}

static time_t * get_addr_time_in_cache(const struct sockaddr_in * addr)
{
    /* get block index */
    int block = block_from_sockaddr_in(addr);
    int count = addr_cache_counters[block];
    int first = addr_cache_pointers[block];
    int i = 0;
    /* do reverse search for efficency */
    for ( i = count - 1; i >= 0; i -- )
    {
        if (0 == evutil_sockaddr_cmp((const struct sockaddr *)addr,
                 (const struct sockaddr *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr,
                 ADDR_PORT_CHECK))
            return &addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].access_time;
    }       
    return NULL;
}

void set_addr_time_in_cache(const struct sockaddr_in * addr, time_t time)
{
    /* get block index */
    int block = block_from_sockaddr_in(addr);
    int count = addr_cache_counters[block];
    int first = addr_cache_pointers[block];
    int i = 0;
    /* do reverse search for efficency */
    for ( i = count - 1; i >= 0; i -- )
    {
        if (0 == evutil_sockaddr_cmp((const struct sockaddr *)addr,
                 (const struct sockaddr *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr,
                 ADDR_PORT_CHECK))
        {
             addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].access_time = time;
             return;
        }
    }       
}

static void add_addr_to_cache(const struct sockaddr_in * addr)
{
    int block = block_from_sockaddr_in(addr);
    int count = addr_cache_counters[block]; 
    /* use 'first' to index item in cache block when count is equal or greater than block size */
    int first = addr_cache_pointers[block]; 

    if (count < ADDR_CACHE_BLOCK_SIZE)
    {
        memcpy((void *)&addr_cache[block][count].addr, (void *) addr, sizeof(struct sockaddr_in));
        addr_cache[block][count].access_time = redsocks_time(NULL);
        addr_cache_counters[block]++;
    }
    else
    {
        memcpy((void *)&addr_cache[block][first].addr, (void *) addr, sizeof(struct sockaddr_in));
        addr_cache[block][first].access_time = redsocks_time(NULL);
        addr_cache_pointers[block]++;
        addr_cache_pointers[block]%=ADDR_CACHE_BLOCK_SIZE;
    }   
}

static void del_addr_from_cache(const struct sockaddr_in * addr)
{   /* get block index */
    int block = block_from_sockaddr_in(addr);
    int count = addr_cache_counters[block];
    int first = addr_cache_pointers[block];
    int i = 0;
    /* do reverse search for efficency */
    for ( i = count - 1; i >= 0; i -- )
    {
        if (0 == evutil_sockaddr_cmp((const struct sockaddr *)addr,
                 (const struct sockaddr *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr,
                 ADDR_PORT_CHECK))
            /* found. zero this item */
        {
            memset((void *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE], 0, sizeof(cache_data));
            break;
        }
    }
}

void auto_client_init(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);

    memset((void *) aclient, 0, sizeof(autoproxy_client));
    aclient->state = AUTOPROXY_NEW;
    init_addr_cache();
}

void auto_client_fini(redsocks_client *client)
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

    del_addr_from_cache(&client->destaddr);
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

    redsocks_log_error(client, LOG_DEBUG, "RECV Timeout, state: %d, data_sent: %d", aclient->state, aclient->data_sent); 

    assert(events & EV_TIMEOUT);
    // Let's make connection confirmed
    if (aclient->state == AUTOPROXY_CONNECTED)
        auto_confirm_connection(client);
    else
        return;

    // TODO: need or not?
    if (!(client->relay_evshut & EV_READ) && !(client->client_evshut & EV_WRITE)) 
    {
        if (bufferevent_write_buffer(client->client, bufferevent_get_input(client->relay)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (bufferevent_enable(client->client, EV_READ) == -1)
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


static void direct_relay_clientreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    autoproxy_client * aclient = get_autoproxy_client(client);
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    redsocks_log_error(client, LOG_DEBUG, "client readcb: client in: %d", input_size); 
    redsocks_touch_client(client);

    if (aclient->state == AUTOPROXY_CONNECTED)
    {
        if (aclient->data_sent && aclient->data_recv)
        {
            /* No CONNECTION RESET error occur after sending data, good. */
            auto_confirm_connection(client);
        }
    }
    direct_relay_readcb_helper(client, client->client, client->relay);
}


static void direct_relay_relayreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    autoproxy_client * aclient = get_autoproxy_client(client);
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));

    redsocks_touch_client(client);
    if (!aclient->data_recv)
    {
        aclient->data_recv = input_size;
        if (input_size && aclient->state == AUTOPROXY_CONNECTED)
        {
            auto_confirm_connection(client);
        }
    }
    direct_relay_readcb_helper(client, client->relay, client->client);
}

static void direct_relay_clientwritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct bufferevent * from = client->relay;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    redsocks_touch_client(client);

    if (input_size == 0 && (client->relay_evshut & EV_READ))
    {
        redsocks_shutdown(client, to, SHUT_WR);
        return;
    }
    if (aclient->state == AUTOPROXY_CONNECTED)
    {
        if (!aclient->data_recv)
        {
            aclient->data_recv = input_size;
            if (input_size)
                auto_confirm_connection(client);
        }
    }
    if (output_size < to->wm_write.high) 
    {
        if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (bufferevent_enable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
}

static void direct_relay_relaywritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct bufferevent * from = client->client;
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));
    size_t output_size = evbuffer_get_length(bufferevent_get_output(to));

    redsocks_touch_client(client);

    if (input_size == 0 && (client->client_evshut & EV_READ)) {
        redsocks_shutdown(client, to, SHUT_WR);
        return;
    }
    else if (aclient->state == AUTOPROXY_CONNECTED )
    {
        redsocks_log_error(client, LOG_DEBUG, "sent: %d, recv: %d, in:%d, out:%d",
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
                ) 
            {
                aclient->recv_timer_event = evtimer_new(bufferevent_get_base(to), auto_recv_timeout_cb , _client);
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
                    }
                }
            }
        }
        /* We sent data to and got data from relay. */
        else if (aclient->data_sent && aclient->data_recv)
        {
            /* No CONNECTION RESET error occur after sending data, good. */
            auto_confirm_connection(client);
        }
    }

    if (aclient->state == AUTOPROXY_CONFIRMED)
    {
        if (output_size < to->wm_write.high) 
        {
            if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
            if (bufferevent_enable(from, EV_READ) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        }   
    }
}

static void auto_drop_relay(redsocks_client *client)
{
    if (client->relay)
    {
        redsocks_log_error(client, LOG_DEBUG, "dropping relay only");

        redsocks_close(bufferevent_getfd(client->relay));
        bufferevent_free(client->relay);
        client->relay = NULL;
    }
}

static void auto_retry(redsocks_client * client, int updcache)
{
    autoproxy_client * aclient = get_autoproxy_client(client);

    if (aclient->state == AUTOPROXY_CONNECTED)
        bufferevent_disable(client->client, EV_READ| EV_WRITE); 
    /* drop relay and update state, then retry with specified relay */
    if (updcache)
    {
        /* only add IP to cache when the IP is not in cache */
        if (get_addr_time_in_cache(&client->destaddr) == NULL)
        {
            add_addr_to_cache(&client->destaddr);
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
    bufferevent_enable(client->client, EV_READ); 

    /* connect to relay */
    if (client->instance->relay_ss->connect_relay)
        client->instance->relay_ss->connect_relay(client);
    else
        redsocks_connect_relay(client);
}

/* return 1 for drop, 0 for retry. */
static int auto_retry_or_drop(redsocks_client * client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    time_t now = redsocks_time(NULL);
    
    if (aclient->state == AUTOPROXY_NEW)
    {
        if (now - aclient->time_connect_relay <= CIRCUIT_RESET_SECONDS) 
        {
            on_connection_blocked(client);  
            auto_retry(client, 0);
            return 0; 
        }
    }
    else if ( aclient->state == AUTOPROXY_CONNECTED)
    {
//      if (now - aclient->time_connect_relay <= CIRCUIT_RESET_SECONDS) 
        {
            on_connection_blocked(client);  
            auto_retry(client, 0);
            return 0; 
        }
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

static void auto_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    redsocks_client *client = _arg;
    autoproxy_client * aclient = get_autoproxy_client(client);
    int saved_errno = errno;
    assert(buffev == client->relay || buffev == client->client);
        
    redsocks_touch_client(client);
            
    redsocks_log_errno(client, LOG_DEBUG, "%s, errno(%d), State: %d, what: " event_fmt_str, 
                            buffev == client->client?"client":"relay",
                            saved_errno, aclient->state, event_fmt(what));
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
                set_addr_time_in_cache(&client->destaddr, redsocks_time(NULL)); 

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
                && saved_errno == ECONNRESET )
        {
            if (!auto_retry_or_drop(client))
                return;
        }
    }   

    if (what == (BEV_EVENT_READING|BEV_EVENT_EOF))
    {
        struct bufferevent *antiev;
        if (buffev == client->relay)
            antiev = client->client;
        else
            antiev = client->relay;

        // Release timer
        if (aclient->recv_timer_event)
        {
            event_del(aclient->recv_timer_event);
            event_free(aclient->recv_timer_event);
            aclient->recv_timer_event = NULL;
        }

        redsocks_shutdown(client, buffev, SHUT_RD);
        
        if (antiev != NULL && evbuffer_get_length(bufferevent_get_output(antiev)) == 0)
            redsocks_shutdown(client, antiev, SHUT_WR);
    }
    else
    {
        redsocks_drop_client(client);
    }
}                                                                       


static void auto_connect_relay(redsocks_client *client)
{
    autoproxy_client * aclient = get_autoproxy_client(client);
    struct timeval tv;
    tv.tv_sec = client->instance->config.timeout;
    tv.tv_usec = 0;
    time_t * acc_time = NULL;
    time_t now = redsocks_time(NULL);   

    /* use default timeout if timeout is not configured */
    if (tv.tv_sec == 0)
        tv.tv_sec = DEFAULT_CONNECT_TIMEOUT_SECONDS; 
    
    if (aclient->state == AUTOPROXY_NEW)
    {
        acc_time = get_addr_time_in_cache(&client->destaddr);
        if (acc_time)
        {
            redsocks_log_error(client, LOG_DEBUG, "Found dest IP in cache");
            // No quick check when the time passed since IP is added to cache is 
            // less than NO_CHECK_SECONDS. Just let it go via proxy.
            if (now - *acc_time < NO_CHECK_SECONDS)
            {
                auto_retry(client, 0);
                return;
            }

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
            tv.tv_sec = QUICK_CONNECT_TIMEOUT_SECONDS;
            aclient->quick_check = 1;
            if (now - *acc_time >= CACHE_ITEM_STALE_SECONDS )
            {
                /* stale this address in cache */
                del_addr_from_cache(&client->destaddr);
            }
        }
        /* connect to target directly without going through proxy */    
        client->relay = red_connect_relay2(&client->destaddr,
                        NULL, auto_relay_connected, auto_event_error, client, 
                        &tv);
    
        aclient->time_connect_relay = redsocks_time(NULL);
           
        if (!client->relay) {
            redsocks_log_errno(client, LOG_ERR, "auto_connect_relay");
            redsocks_drop_client(client);
        }
    }
    else
    {
        redsocks_log_errno(client, LOG_ERR, "invalid state: %d", aclient->state);
    }
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
