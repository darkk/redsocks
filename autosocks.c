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
#include "socks5.h"

typedef enum socks5_state_t {
	socks5_new,
	socks5_method_sent,
	socks5_auth_sent,
	socks5_request_sent,
	socks5_skip_domain,
	socks5_skip_address,
	socks5_MAX,
    socks5_pre_detect=100, /* Introduce additional states to socks5 subsystem */
    socks5_direct,
} socks5_state;

typedef struct socks5_client_t {
	int do_password; // 1 - password authentication is possible
	int to_skip;     // valid while reading last reply (after main request)
	time_t time_connect_relay; // timestamp when start to connect relay
	int got_data;
} socks5_client;


int socks5_is_valid_cred(const char *login, const char *password);
void socks5_write_cb(struct bufferevent *buffev, void *_arg);
void socks5_read_cb(struct bufferevent *buffev, void *_arg);

void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);
static int auto_retry_or_drop(redsocks_client * client);
static void auto_connect_relay(redsocks_client *client);

#define CIRCUIT_RESET_SECONDS 1
#define CONNECT_TIMEOUT_SECONDS 13 
#define ADDR_CACHE_BLOCKS 64
#define ADDR_CACHE_BLOCK_SIZE 32 
#define block_from_sockaddr_in(addr) (addr->sin_addr.s_addr & 0xFF) / (256/ADDR_CACHE_BLOCKS)
static struct sockaddr_in addr_cache[ADDR_CACHE_BLOCKS][ADDR_CACHE_BLOCK_SIZE];
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
		/*
		if (0 == memcmp((void *)addr, (void *)&addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE], sizeof(struct sockaddr_in)))
*/
		if (addr->sin_addr.s_addr == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].sin_addr.s_addr
			 && addr->sin_family == addr_cache[block][(first+i)%ADDR_CACHE_BLOCK_SIZE].sin_family
           )
			return 1;
			
	return 0;
}

static void add_addr_to_cache(const struct sockaddr_in * addr)
{
	int block = block_from_sockaddr_in(addr);
	int count = addr_cache_counters[block];
	int first = addr_cache_pointers[block];

	if (count < ADDR_CACHE_BLOCK_SIZE)
	{
		memcpy((void *)&addr_cache[block][count], (void *) addr, sizeof(struct sockaddr_in));
		addr_cache_counters[block]++;
	}
	else
	{
		memcpy((void *)&addr_cache[block][first], (void *) addr, sizeof(struct sockaddr_in));
		addr_cache_pointers[block]++;
		addr_cache_pointers[block]%=ADDR_CACHE_BLOCK_SIZE;
	}	
}


void auto_socks5_client_init(redsocks_client *client)
{
	socks5_client * socks5= (void*)(client + 1);
	const redsocks_config *config = &client->instance->config;

	client->state = socks5_pre_detect;
	socks5->got_data = 0;
	socks5->do_password = socks5_is_valid_cred(config->login, config->password);
	init_addr_cache();
}

static void auto_relay_readcb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
	if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
		if (bufferevent_write_buffer(to, from->input) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
	}
	else {
		if (bufferevent_disable(from, EV_READ) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
	}
}

static void auto_relay_relayreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	socks5_client *socks5 = (void*)(client + 1);

	redsocks_touch_client(client);
	socks5->got_data = 1;
	auto_relay_readcb(client, client->relay, client->client);
}


static void auto_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	struct timeval tv;

	redsocks_touch_client(client);

	if (client->state == socks5_pre_detect) {
		client->state = socks5_direct;

		/* We do not need to detect timeouts any more.
		The two ppers will handle it. */

		if (!redsocks_start_relay(client))
		{
			/* overwrite theread callback to my function */
			client->relay->readcb = auto_relay_relayreadcb;
		}
	}

	else if (client->state == socks5_direct)
		redsocks_log_error(client, LOG_DEBUG, "Should not be here!");
	else
		socks5_write_cb(buffev, _arg);
}



static void auto_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	socks5_client *socks5 = (void*)(client + 1);

	redsocks_touch_client(client);

	if (client->state == socks5_pre_detect) {
		/* Should never be here */
/*
		client->state = socks5_direct;
		redsocks_start_relay(client);
*/
	}
	else if (client->state == socks5_direct) {
	/*	if (EVBUFFER_LENGTH(buffev->input) == 0 && client->relay_evshut & EV_READ) */
	}
	else {
		socks5_read_cb(buffev, _arg);
	}
}

static void auto_drop_relay(redsocks_client *client)
{
	redsocks_log_error(client, LOG_INFO, "dropping relay only");
	
	if (client->relay) {
		redsocks_close(EVENT_FD(&client->relay->ev_write));
		bufferevent_free(client->relay);
		client->relay = NULL;
	}
}

static void auto_retry(redsocks_client * client, int updcache)
{
	if (client->state == socks5_direct)
		bufferevent_disable(client->client, EV_READ| EV_WRITE); 
	/* drop relay and update state, then retry with socks5 relay */
	if (updcache)
	{
		add_addr_to_cache(&client->destaddr);
		redsocks_log_error(client, LOG_DEBUG, "ADD IP to cache: %x", client->destaddr.sin_addr.s_addr);
	}
	auto_drop_relay(client);
	client->state = socks5_new;
	auto_connect_relay(client); /* Retry SOCKS5 proxy relay */
}

/* return 1 for drop, 0 for retry. */
static int auto_retry_or_drop(redsocks_client * client)
{
	time_t now = redsocks_time(NULL);
	socks5_client *socks5 = (void*)(client + 1);
	
	if (client->state == socks5_pre_detect)
	{
		if (now - socks5->time_connect_relay <= CIRCUIT_RESET_SECONDS) 
		{
			auto_retry(client, 1);
			return 0; 
		}
	}
	if ( client->state == socks5_direct && socks5->got_data == 0)
	{
		if (now - socks5->time_connect_relay <= CIRCUIT_RESET_SECONDS) 
		{
			redsocks_log_error(client, LOG_DEBUG, "ADD IP to cache: %x", client->destaddr.sin_addr.s_addr);
			add_addr_to_cache(&client->destaddr);
		    /* Do not retry. The client may already sent data to relay,
			   and we have lost the data sent. 
			   Connection can not be retried.
			*/	
			return 1; 
		}
	}

	
	/* drop */
	return 1;
}

static void auto_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	
	assert(buffev == client->relay);
		
	redsocks_touch_client(client);
			
	if (!red_is_socket_connected_ok(buffev)) {
		if (client->state == socks5_pre_detect && !auto_retry_or_drop(client))
			return;
			
		redsocks_log_error(client, LOG_DEBUG, "failed to connect to proxy");
		goto fail;
	}
	
	client->relay->readcb = client->instance->relay_ss->readcb;
	client->relay->writecb = client->instance->relay_ss->writecb;
	client->relay->writecb(buffev, _arg);
	return;
													
fail:
	redsocks_drop_client(client);
}
	
static void auto_event_error(struct bufferevent *buffev, short what, void *_arg)
{
	redsocks_client *client = _arg;
	int saved_errno = errno;
	assert(buffev == client->relay || buffev == client->client);
		
	redsocks_touch_client(client);
			
	redsocks_log_errno(client, LOG_DEBUG, "Errno: %d, State: %d, what: %x", saved_errno, client->state, what);
	if (buffev == client->relay)
	{
		if ( client->state == socks5_pre_detect 
		&& what == (EVBUFFER_WRITE|EVBUFFER_TIMEOUT))
		{
			/* In case timeout occurs for connecting relay, we try to connect
			to target with SOCKS5 proxy. It is possible that the connection to
			target can be set up a bit longer than the timeout value we set. 
			However, it is still better to make connection via proxy. */
			auto_retry(client, 1);
			return;
		}

		if (client->state == socks5_pre_detect  && saved_errno == ECONNRESET)
			if (!auto_retry_or_drop(client))
				return;

		if (client->state == socks5_direct && what == (EVBUFFER_READ|EVBUFFER_ERROR) && saved_errno == ECONNRESET) 
		//&& saved_errno == ECONNRESET )
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
		
		/*
		myerrno = red_socket_geterrno(buffev);
		redsocks_log_errno(client, LOG_NOTICE, "%s error, code " event_fmt_str,
				buffev == client->relay ? "relay" : "client",
				event_fmt(what));
		*/
		redsocks_drop_client(client);
	}
}																		


static void auto_connect_relay(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	struct timeval tv;
	tv.tv_sec = CONNECT_TIMEOUT_SECONDS;
	tv.tv_usec = 0;
	
	if (client->state == socks5_pre_detect)
	{
		if (is_addr_in_cache(&client->destaddr))
		{
			client->state = socks5_new; /* Connect SOCKS5 */
			redsocks_log_error(client, LOG_DEBUG, "Found in cache");
		}
	}
	client->relay = red_connect_relay2( client->state == socks5_pre_detect
									 ? &client->destaddr : &client->instance->config.relayaddr,
					auto_relay_connected, auto_event_error, client, 
					client->state == socks5_pre_detect ? &tv: NULL);

	socks5->time_connect_relay = redsocks_time(NULL);
       
	if (!client->relay) {
		redsocks_log_errno(client, LOG_ERR, "auto_connect_relay");
		redsocks_drop_client(client);
	}
}




													

relay_subsys autosocks5_subsys =
{
	.name                 = "autosocks5",
	.payload_len          = sizeof(socks5_client),
	.instance_payload_len = 0,
	.readcb               = auto_read_cb,
	.writecb              = auto_write_cb,
	.init                 = auto_socks5_client_init,
	.connect_relay        = auto_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
