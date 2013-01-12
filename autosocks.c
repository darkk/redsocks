/* redsocks - transparent TCP-to-proxy redirector
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
#include <sys/socket.h>
#include <arpa/inet.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"
#include "socks5.h"

typedef enum socks5_state_t {
        socks5_pre_detect,
        socks5_direct,
	socks5_new,
	socks5_method_sent,
	socks5_auth_sent,
	socks5_request_sent,
	socks5_skip_domain,
	socks5_skip_address,
	socks5_MAX,
} socks5_state;

typedef struct socks5_client_t {
	int do_password; // 1 - password authentication is possible
	int to_skip;     // valid while reading last reply (after main request)
	time_t time_connect_relay; // timestamp when start to connect relay
} socks5_client;

static const char *socks5_strstatus[] = {
	"ok",
	"server failure",
	"connection not allowed by ruleset",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
};
static const size_t socks5_strstatus_len = SIZEOF_ARRAY(socks5_strstatus);

const char* socks5_status_to_str(int socks5_status);

int socks5_is_valid_cred(const char *login, const char *password);

static int auto_retry_or_drop(redsocks_client * client);

static void auto_connect_relay(redsocks_client *client);

#define ADDR_CACHE_SIZE 64 
static struct sockaddr_in addr_cache[ADDR_CACHE_SIZE];
static int addr_count = 0;
static int first_addr = 0;
static int cache_init = 0;

static void init_addr_cache()
{			
	if (!cache_init)
	{
		memset((void *)addr_cache, 0, sizeof(struct sockaddr_in)*ADDR_CACHE_SIZE);
		addr_count = 0;
		first_addr = 0;
		cache_init = 1;
	}
}

static int is_addr_in_cache(const struct sockaddr_in * addr)
{
	int i = 0;
	/* do reverse search for efficency */
	for ( i = addr_count - 1; i >= 0; i -- )
		if (0 == memcmp((void *)addr, (void *)&addr_cache[(first_addr+i)%ADDR_CACHE_SIZE], sizeof(struct sockaddr_in)))
			return 1;
			
	return 0;
}

static void add_addr_to_cache(const struct sockaddr_in * addr)
{
	if (addr_count < ADDR_CACHE_SIZE)
	{
		memcpy((void *)&addr_cache[addr_count], (void *) addr, sizeof(struct sockaddr_in));
		addr_count ++;
	}
	else
	{
		memcpy((void *)&addr_cache[first_addr], (void *) addr, sizeof(struct sockaddr_in));
		first_addr ++;
		first_addr %=  ADDR_CACHE_SIZE;
	}	
}


void auto_socks5_client_init(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	const redsocks_config *config = &client->instance->config;

	client->state = socks5_pre_detect;
	socks5->do_password = socks5_is_valid_cred(config->login, config->password);
	init_addr_cache();
}

static struct evbuffer *socks5_mkmethods(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	return socks5_mkmethods_plain(socks5->do_password);
}

struct evbuffer *socks5_mkmethods_plain(int do_password);

static struct evbuffer *socks5_mkpassword(redsocks_client *client)
{
	return socks5_mkpassword_plain(client->instance->config.login, client->instance->config.password);
}

struct evbuffer *socks5_mkpassword_plain(const char *login, const char *password);
struct evbuffer *socks5_mkcommand_plain(int socks5_cmd, const struct sockaddr_in *destaddr);

static struct evbuffer *socks5_mkconnect(redsocks_client *client)
{
	return socks5_mkcommand_plain(socks5_cmd_connect, &client->destaddr);
}

static void socks5_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	redsocks_touch_client(client);

	if (client->state == socks5_pre_detect) {
		client->state = socks5_direct;

/*
		if (EVBUFFER_LENGTH(buffev->input) == 0 && client->relay_evshut & EV_READ)
		{
			if 	(auto_retry_or_drop(client))
				redsocks_drop_client(client);
		}
		else
*/
			redsocks_start_relay(client);
/*
			if (bufferevent_enable(client->relay, EV_READ | EV_WRITE))
			redsocks_drop_client(client);
*/
	}
/*
	else if (client->state == socks5_direct)
			redsocks_start_relay(client);
*/
	else if (client->state == socks5_new) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkmethods, socks5_method_sent, sizeof(socks5_method_reply)
			);
	}
}

const char* socks5_is_known_auth_method(socks5_method_reply *reply, int do_password);


static void socks5_read_auth_methods(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_method_reply reply;
	const char *error = NULL;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_equal, sizeof(reply)) < 0)
		return;

	error = socks5_is_known_auth_method(&reply, socks5->do_password);
	if (error) {
		redsocks_log_error(client, LOG_NOTICE, "socks5_is_known_auth_method: %s", error);
		redsocks_drop_client(client);
	}
	else if (reply.method == socks5_auth_none) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkconnect, socks5_request_sent, sizeof(socks5_reply)
			);
	}
	else if (reply.method == socks5_auth_password) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkpassword, socks5_auth_sent, sizeof(socks5_auth_reply)
			);
	}
}

static void socks5_read_auth_reply(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_auth_reply reply;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_equal, sizeof(reply)) < 0)
		return;

	if (reply.ver != socks5_password_ver) {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected auth reply version...");
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_password_passed)
		redsocks_write_helper(
			buffev, client,
			socks5_mkconnect, socks5_request_sent, sizeof(socks5_reply)
			);
	else
		redsocks_drop_client(client);
}

static void socks5_read_reply(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_reply reply;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_greater_equal, sizeof(reply)) < 0)
		return;

	if (reply.ver != socks5_ver) {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected reply version...");
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_status_succeeded) {
		socks5_state nextstate;
		size_t len;

		if (reply.addrtype == socks5_addrtype_ipv4) {
			len = socks5->to_skip = sizeof(socks5_addr_ipv4);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_ipv6) {
			len = socks5->to_skip = sizeof(socks5_addr_ipv6);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_domain) {
			socks5_addr_domain domain;
			len = sizeof(domain.size);
			nextstate = socks5_skip_domain;
		}
		else {
			redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected address type...");
			redsocks_drop_client(client);
			return;
		}

		redsocks_write_helper(
			buffev, client,
			NULL, nextstate, len
			);
	}
	else {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server status: %s (%i)",
				/* 0 <= reply.status && */ reply.status < SIZEOF_ARRAY(socks5_strstatus)
				? socks5_strstatus[reply.status] : "?", reply.status);
		redsocks_drop_client(client);
	}
}

static void socks5_read_cb(struct bufferevent *buffev, void *_arg)
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
	else if (client->state == socks5_method_sent) {
		socks5_read_auth_methods(buffev, client, socks5);
	}
	else if (client->state == socks5_auth_sent) {
		socks5_read_auth_reply(buffev, client, socks5);
	}
	else if (client->state == socks5_request_sent) {
		socks5_read_reply(buffev, client, socks5);
	}
	else if (client->state == socks5_skip_domain) {
		socks5_addr_ipv4 ipv4; // all socks5_addr*.port are equal
		uint8_t size;
		if (redsocks_read_expected(client, buffev->input, &size, sizes_greater_equal, sizeof(size)) < 0)
			return;
		socks5->to_skip = size + sizeof(ipv4.port);
		redsocks_write_helper(
			buffev, client,
			NULL, socks5_skip_address, socks5->to_skip
			);
	}
	else if (client->state == socks5_skip_address) {
		uint8_t data[socks5->to_skip];
		if (redsocks_read_expected(client, buffev->input, data, sizes_greater_equal, socks5->to_skip) < 0)
			return;
		redsocks_start_relay(client);
	}
	else {
		redsocks_drop_client(client);
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

void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);


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
	assert(buffev == client->relay || buffev == client->client);
		
	redsocks_touch_client(client);
			
	redsocks_log_errno(client, LOG_DEBUG, "EOF %d", client->state);
	if (client->state == socks5_pre_detect || client->state == socks5_direct )
	{
		if (!auto_retry_or_drop(client))
			return;
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
		errno = redsocks_socket_geterrno(client, buffev);
		redsocks_log_errno(client, LOG_NOTICE, "%s error, code " event_fmt_str,
				buffev == client->relay ? "relay" : "client",
				event_fmt(what));
		*/
		redsocks_drop_client(client);
	}
}																		


/* return 1 for drop, 0 for retry. */
static int auto_retry_or_drop(redsocks_client * client)
{
	time_t now = redsocks_time(NULL);
	socks5_client *socks5 = (void*)(client + 1);
	
	if (client->state == socks5_pre_detect || client->state == socks5_direct)
	{
		if (now - socks5->time_connect_relay <= 3) 
		{
			if (client->state == socks5_direct)
				bufferevent_disable(client->client, EV_READ| EV_WRITE);
			/* drop relay and update state, then retry with socks5 relay */
			auto_drop_relay(client);
			client->state = socks5_new;
			add_addr_to_cache(&client->destaddr);
			auto_connect_relay(client); /* Retry SOCKS5 proxy relay */
			return 0; 
		}
	}
	/* drop */
	return 1;
}

static void auto_connect_relay(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	
	if (client->state == socks5_pre_detect)
	{
		if (is_addr_in_cache(&client->destaddr))
		{
			client->state = socks5_new; /* Connect SOCKS5 */
			redsocks_log_error(client, LOG_DEBUG, "Found in cache");
		}
	}
	client->relay = red_connect_relay( client->state == socks5_pre_detect
									 ? &client->destaddr : &client->instance->config.relayaddr,
				auto_relay_connected, auto_event_error, client);

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
	.readcb               = socks5_read_cb,
	.writecb              = socks5_write_cb,
	.init                 = auto_socks5_client_init,
	.connect_relay        = auto_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
