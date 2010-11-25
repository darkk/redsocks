/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2008 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "log.h"
#include "redsocks.h"

typedef enum socks4_state_t {
	socks4_new,
	socks4_request_sent,
	socks4_reply_came,
	socks4_MAX,
} socks4_state;

typedef struct socks4_req_t {
	uint8_t ver;
	uint8_t cmd;
	uint16_t port;
	uint32_t addr;
	char login[1]; // we need at least zero-byte
} PACKED socks4_req;

const int socks4_ver = 4;
const int socks4_cmd_connect = 1;
const int socks4_cmd_bind = 2;

typedef struct socks4_reply_t {
	uint8_t ver;
	uint8_t status;
	uint16_t port;
	uint32_t addr;
} PACKED socks4_reply;

const int socks4_status_ok = 90;
const int socks4_status_fail = 91;
const int socks4_status_no_ident = 92;
const int socks4_status_fake_ident = 93;


void socks4_client_init(redsocks_client *client)
{
	if (client->instance->config.password)
		redsocks_log_error(client, LOG_WARNING, "password is ignored for socks4 connections");

	client->state = socks4_new;
}


static void socks4_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	assert(client->state >= socks4_request_sent);

	redsocks_touch_client(client);

	if (client->state == socks4_request_sent) {
		socks4_reply reply;

		if (redsocks_read_expected(client, buffev->input, &reply, sizes_greater_equal, sizeof(reply)) < 0)
			return;

		client->state = socks4_reply_came;
		if (reply.ver != 0) {
			redsocks_log_error(client, LOG_NOTICE, "Socks4 server reported unexpected reply version...");
			redsocks_drop_client(client);
		}
		else if (reply.status == socks4_status_ok)
			redsocks_start_relay(client);
		else {
			redsocks_log_error(client, LOG_NOTICE, "Socks4 server status: %s (%i)",
				reply.status == socks4_status_fail ? "fail" :
				reply.status == socks4_status_no_ident ? "no ident" :
				reply.status == socks4_status_fake_ident ? "fake ident" : "?",
				reply.status);
			redsocks_drop_client(client);
		}
	}
}

static struct evbuffer *socks4_mkconnect(redsocks_client *client)
{
	const redsocks_config *config = &client->instance->config;
	const char *username = config->login ? config->login : "";
	int len = sizeof(socks4_req) + strlen(username);
	socks4_req *req = calloc(1, len);

	req->ver = socks4_ver;
	req->cmd = socks4_cmd_connect;
	req->port = client->destaddr.sin_port;
	req->addr = client->destaddr.sin_addr.s_addr;
	strcpy(req->login, username);

	struct evbuffer *ret = mkevbuffer(req, len);
	free(req);
	return ret;
}

static void socks4_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	redsocks_touch_client(client);

	if (client->state == socks4_new) {
		redsocks_write_helper(
			buffev, client,
			socks4_mkconnect, socks4_request_sent, sizeof(socks4_reply)
			);
	}
	else if (client->state >= socks4_request_sent) {
		bufferevent_disable(buffev, EV_WRITE);
	}
}


relay_subsys socks4_subsys =
{
	.name                 = "socks4",
	.payload_len          = 0,
	.instance_payload_len = 0,
	.readcb               = socks4_read_cb,
	.writecb              = socks4_write_cb,
	.init                 = socks4_client_init,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
