/* Copyright (C) 2013 Zhuofei Wang <semigodking@gmail.com>
 *
 *
 * redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2011 Leonid Evdokimov <leon@darkk.net.ru>
 *
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
} autoproxy_state;

typedef struct autoproxy_client_t {
	autoproxy_state state;
	time_t time_connect_relay; // timestamp when start to connect relay
	size_t data_recv;
	size_t data_sent;
} autoproxy_client;


void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);
static int auto_retry_or_drop(redsocks_client * client);
static void auto_connect_relay(redsocks_client *client);
static void direct_relay_clientreadcb(struct bufferevent *from, void *_client);

#define CIRCUIT_RESET_SECONDS 1
#define DEFAULT_CONNECT_TIMEOUT_SECONDS 10 
#define QUICK_CONNECT_TIMEOUT_SECONDS 2 
#define CACHE_ITEM_STALE_SECONDS 60*15
#define ADDR_CACHE_BLOCKS 128
#define ADDR_CACHE_BLOCK_SIZE 16 
#define block_from_sockaddr_in(addr) (addr->sin_addr.s_addr & 0xFF) / (256/ADDR_CACHE_BLOCKS)

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
		if (addr->sin_addr.s_addr == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_addr.s_addr
			 && addr->sin_family == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_family
           )
			return 1;
			
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
		if (addr->sin_addr.s_addr == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_addr.s_addr
			 && addr->sin_family == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_family
           )
			return &addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].access_time;
			
	return NULL;
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
{	/* get block index */
	int block = block_from_sockaddr_in(addr);
	int count = addr_cache_counters[block];
	int first = addr_cache_pointers[block];
	int i = 0;
	/* do reverse search for efficency */
	for ( i = count - 1; i >= 0; i -- )
		if (addr->sin_addr.s_addr == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_addr.s_addr
			 && addr->sin_family == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].addr.sin_family
           )
			/* found. zero this item */
		{
			memset((void *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE], 0, sizeof(cache_data));
			break;
		}
}



void auto_client_init(redsocks_client *client)
{
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;

	aclient->state = AUTOPROXY_NEW;
	aclient->data_recv = 0;
	aclient->data_sent = 0;
	init_addr_cache();
}

static void on_connection_confirmed(redsocks_client *client)
{
	redsocks_log_error(client, LOG_DEBUG, "IP Confirmed"); 
}

static void on_connection_blocked(redsocks_client *client)
{
	redsocks_log_error(client, LOG_DEBUG, "IP Blocked"); 
}

static void direct_relay_readcb_helper(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
	if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
		if (bufferevent_write_buffer(to, from->input) == -1)
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
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;

	redsocks_touch_client(client);

	if (aclient->state == AUTOPROXY_CONNECTED)
	{
		if (aclient->data_sent && aclient->data_recv)
		{
			/* No CONNECTION RESET error occur after sending data, good. */
			aclient->state = AUTOPROXY_CONFIRMED;
			on_connection_confirmed(client);
			if (evbuffer_get_length(from->input))
			{
				evbuffer_drain(from->input, aclient->data_sent);
				aclient->data_sent = 0;
			}
		}
	}
	direct_relay_readcb_helper(client, client->client, client->relay);
}


static void direct_relay_relayreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;

	redsocks_touch_client(client);
	if (!aclient->data_recv)
		aclient->data_recv = EVBUFFER_LENGTH(from->input);
	direct_relay_readcb_helper(client, client->relay, client->client);
}

static void direct_relay_clientwritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
	struct bufferevent * from = client->relay;

	redsocks_touch_client(client);

	if (EVBUFFER_LENGTH(from->input) == 0 && (client->relay_evshut & EV_READ)) {
		redsocks_shutdown(client, to, SHUT_WR);
		return;
	}
	if (aclient->state == AUTOPROXY_CONNECTED)
	{
		if (!aclient->data_recv)
			aclient->data_recv = EVBUFFER_LENGTH(from->input);
	}
	if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
		if (bufferevent_write_buffer(to, from->input) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
		if (bufferevent_enable(from, EV_READ) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
	}
}



static void direct_relay_relaywritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
	struct bufferevent * from = client->client;

	redsocks_touch_client(client);

	if (EVBUFFER_LENGTH(from->input) == 0 && (client->client_evshut & EV_READ)) {
		redsocks_shutdown(client, to, SHUT_WR);
		return;
	}
	else if (aclient->state == AUTOPROXY_CONNECTED )
	{
		/* Not send or receive data. */
		if (!aclient->data_sent && !aclient->data_recv)
		{
			/* Ensure we have data to send */
			if (EVBUFFER_LENGTH(from->input))
			{
				/* copy data from input to output of relay */
				aclient->data_sent = copy_evbuffer (to, from, 0);
				redsocks_log_error(client, LOG_DEBUG, "not sent, not  got %d", EVBUFFER_LENGTH(from->input));
			}
		}
		/* 
		 * Relay reaceived data before writing to relay.
		*/
		else if (!aclient->data_sent && aclient->data_recv)
		{
			redsocks_log_error(client, LOG_DEBUG, "not sent, got");
			aclient->data_sent = copy_evbuffer(to, from, 0);
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
			redsocks_log_error(client, LOG_DEBUG, "sent, not got in:%d out:%d high:%d sent:%d",
										 evbuffer_get_length(from->input),
										 evbuffer_get_length(to->output),
											to->wm_write.high, aclient->data_sent	);
			/* Write more data util input buffer is full */
			if (EVBUFFER_LENGTH(from->input)- aclient->data_sent > 0) /* we have more data waiting to be sent  */
			{
				aclient->data_sent += copy_evbuffer(to, from, aclient->data_sent);
			}
			else if (EVBUFFER_LENGTH(to->output) < aclient->data_sent /*  data is sent out, more or less */
				&& EVBUFFER_LENGTH(from->input) == from->wm_read.high /* do not confirm unless read buffer is full */
				&& EVBUFFER_LENGTH(from->input) == aclient->data_sent /* all data in read buffer is sent */
				) 
			{
				evbuffer_drain(from->input, aclient->data_sent);
				aclient->data_sent = 0;
				aclient->state = AUTOPROXY_CONFIRMED;
				on_connection_confirmed(client);
			}
		}
		/* We sent data to and got data from relay. */
		else if (aclient->data_sent && aclient->data_recv)
		{
			/* No CONNECTION RESET error occur after sending data, good. */
			aclient->state = AUTOPROXY_CONFIRMED;
			on_connection_confirmed(client);
			redsocks_log_error(client, LOG_DEBUG, "sent, got %d ", aclient->data_recv);
			if (evbuffer_get_length(from->input))
			{
				evbuffer_drain(from->input, aclient->data_sent);
				aclient->data_sent = 0;
			}
		}
	}

	if (aclient->state == AUTOPROXY_CONFIRMED)
	{
		if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
			if (bufferevent_write_buffer(to, from->input) == -1)
				redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
			if (bufferevent_enable(from, EV_READ) == -1)
				redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
		}	
	}
}

static void auto_drop_relay(redsocks_client *client)
{
	if (client->relay) {
		redsocks_log_error(client, LOG_DEBUG, "dropping relay only");

		redsocks_close(EVENT_FD(&client->relay->ev_write));
		bufferevent_free(client->relay);
		client->relay = NULL;
	}
}

static void auto_retry(redsocks_client * client, int updcache)
{
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;

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
	auto_drop_relay(client);

	// restore callbacks for ordinary client.
	bufferevent_setcb(client->client, NULL, NULL, client->client->errorcb, client);
	// enable reading to handle EOF from client
	bufferevent_enable(client->client, EV_READ); 
	/* connect to relay */
	if (client->instance->relay_ss->connect_relay)
		client->instance->relay_ss->connect_relay(client);
	else
		redsocks_connect_relay(client);
	// 
	if (EVBUFFER_LENGTH(client->client->input) && client->client->readcb)
		client->client->readcb(client->client, client);
}

/* return 1 for drop, 0 for retry. */
static int auto_retry_or_drop(redsocks_client * client)
{
	time_t now = redsocks_time(NULL);
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
	
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
//		if (now - aclient->time_connect_relay <= CIRCUIT_RESET_SECONDS) 
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
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
	
	assert(buffev == client->relay);
		
	redsocks_touch_client(client);
			
	if (!red_is_socket_connected_ok(buffev)) {
		if (aclient->state == AUTOPROXY_NEW && !auto_retry_or_drop(client))
			return;
			
		redsocks_log_error(client, LOG_DEBUG, "failed to connect to proxy");
		goto fail;
	}

    /* update client state */	
	aclient->state = AUTOPROXY_CONNECTED;

	/* We do not need to detect timeouts any more.
	The two peers will handle it. */
	bufferevent_set_timeouts(client->relay, NULL, NULL);

	if (!redsocks_start_relay(client))
	{
		/* overwrite theread callback to my function */
		client->client->readcb = direct_relay_clientreadcb;
		client->client->writecb = direct_relay_clientwritecb;
		client->relay->readcb  = direct_relay_relayreadcb;
		client->relay->writecb = direct_relay_relaywritecb;
	}
	else
	{
		redsocks_log_error(client, LOG_DEBUG, "failed to start relay");
		goto fail;
	}
	client->relay->writecb(buffev, _arg);
	return;
													
fail:
	redsocks_drop_client(client);
}
	
static void auto_event_error(struct bufferevent *buffev, short what, void *_arg)
{
	redsocks_client *client = _arg;
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
	int saved_errno = errno;
	assert(buffev == client->relay || buffev == client->client);
		
	redsocks_touch_client(client);
			
	redsocks_log_errno(client, LOG_DEBUG, "%s errno(%d), State: %d, what: " event_fmt_str, 
							buffev == client->client?"client":"relay",
							saved_errno, aclient->state, event_fmt(what));
	if (buffev == client->relay)
	{
		
		if ( aclient->state == AUTOPROXY_NEW 
		&& what == (EVBUFFER_WRITE|EVBUFFER_TIMEOUT))
		{
			on_connection_blocked(client);	
			/* In case timeout occurs while connecting relay, we try to connect
			to target via SOCKS5 proxy. It is possible that the connection to
			target can be set up a bit longer than the timeout value we set. 
			However, it is still better to make connection via proxy. */
			auto_retry(client, 1);
			return;
		}

		if (aclient->state == AUTOPROXY_NEW  && saved_errno == ECONNRESET)
			if (!auto_retry_or_drop(client))
				return;

		if (aclient->state == AUTOPROXY_CONNECTED && what == (EVBUFFER_READ|EVBUFFER_ERROR) 
				&& saved_errno == ECONNRESET )
		{
			if (!auto_retry_or_drop(client))
				return;
		}
	}	

	if (what == (EVBUFFER_READ|EVBUFFER_EOF)) {
		struct bufferevent *antiev;
		if (buffev == client->relay)
			antiev = client->client;
		else
			antiev = client->relay;
			
		redsocks_shutdown(client, buffev, SHUT_RD);
		
		if (antiev != NULL && EVBUFFER_LENGTH(antiev->output) == 0)
			redsocks_shutdown(client, antiev, SHUT_WR);
	}
	else {
		redsocks_drop_client(client);
	}
}																		


static void auto_connect_relay(redsocks_client *client)
{
	autoproxy_client * aclient = (void*)(client + 1) + client->instance->relay_ss->payload_len;
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
			if (now - *acc_time < CACHE_ITEM_STALE_SECONDS )
			{
				redsocks_log_error(client, LOG_DEBUG, "Found dest IP in cache");

				auto_retry(client, 0);
				return ;
			}
			else
			{
				/* stale this address in cache */
				del_addr_from_cache(&client->destaddr);
				/* update timeout value for quick detection */
				tv.tv_sec = QUICK_CONNECT_TIMEOUT_SECONDS;
			}
		}
		/* connect to target directly without going through proxy */	
		client->relay = red_connect_relay2(&client->destaddr,
						auto_relay_connected, auto_event_error, client, 
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
/*
	.readcb               = auto_read_cb,
	.writecb              = auto_write_cb,
*/
	.init                 = auto_client_init,
	.connect_relay        = auto_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
