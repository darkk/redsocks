/** http-relay upstream module for redsocks
 * $Id$ 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "redsocks.h"

typedef enum httpr_state_t {
	httpr_new,
} httpr_state;

typedef struct httpr_client_t {
	struct evbuffer *buff;
	char *firstline;
	int need_host;
	int has_host;
} httpr_client;


static void httpr_client_init(redsocks_client *client)
{
	httpr_client *httpr = (void*)(client +1);

	if (client->instance->config.login)
		redsocks_log_error(client, "login is ignored for http-relay connections");
	
	if (client->instance->config.password)
		redsocks_log_error(client, "password is ignored for http-relay connections");
	
	client->state = httpr_new;
	memset(httpr, 0, sizeof(*httpr));
}

static void httpr_client_fini(redsocks_client *client)
{
	httpr_client *httpr = (void*)(client +1);

	if (httpr->buff) {
		evbuffer_free(httpr->buff);
		httpr->buff = 0;
	}
}

static void httpr_relay_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	httpr_client *httpr = (void*)(client +1);
	int len;

	assert(httpr->buff);

	len = bufferevent_write_buffer(client->relay, httpr->buff);
	// free is done either at _start_relay or at _drop_client

	if (len >= 0) {
		redsocks_start_relay(client);
	}
	else {
		redsocks_log_errno(client, "bufferevent_write_buffer");
		redsocks_drop_client(client);
	}
}

// drops client on failure
static int httpr_append_header(redsocks_client *client, char *line)
{
	httpr_client *httpr = (void*)(client +1);
	int error;

	error = evbuffer_add(httpr->buff, line, strlen(line));
	if (!error)
		evbuffer_add(httpr->buff, "\x0d\x0a", 2);
	if (error) {
		redsocks_log_errno(client, "evbuffer_add");
	}
	return error;
}

// This function is not reenterable
static char *fmt_http_host(struct sockaddr_in addr)
{
	static char host[] = "123.123.123.123:12345";
	if (ntohs(addr.sin_port) == 80)
		return inet_ntoa(addr.sin_addr);
	else {
		snprintf(host, sizeof(host), 
				"%s:%u",
				inet_ntoa(addr.sin_addr),
				ntohs(addr.sin_port)
				);
		return host;
	}
}

static int httpr_toss_http_firstline(redsocks_client *client)
{
	httpr_client *httpr = (void*)(client +1);
	char *uri = NULL;
	struct evbuffer *buff = NULL;
	char *host = fmt_http_host(client->destaddr);
	
	assert(httpr->firstline);
	
	uri = strchr(httpr->firstline, ' ');
	if (uri) 
		uri += 1; // one char further
	else {
		redsocks_log_error(client, "malformed request came");
		goto fail;
	}

	buff = evbuffer_new();
	if (!buff) {
		redsocks_log_error(client, "evbuffer_new");
		goto fail;
	}

	if (evbuffer_add(buff, httpr->firstline, uri - httpr->firstline) < 0)
		goto addition_fail;
	if (evbuffer_add(buff, "http://", 7) < 0)
		goto addition_fail;
	if (evbuffer_add(buff, host, strlen(host)) < 0)
		goto addition_fail;
	if (evbuffer_add(buff, uri, strlen(uri)) < 0)
		goto addition_fail;
	if (evbuffer_add(buff, "\x0d\x0a", 2) < 0)
		goto addition_fail;
	if (evbuffer_add_buffer(buff, httpr->buff) < 0)
		goto addition_fail;

	evbuffer_free(httpr->buff);
	httpr->buff = buff;
	return 0;
	
addition_fail:
	redsocks_log_error(client, "evbuffer_add");
fail:
	if (buff)
		evbuffer_free(buff);
	return -1;
}

static void httpr_client_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	httpr_client *httpr = (void*)(client +1);
	char *line = NULL;
	int connect_relay = 0;
	
	while ( (line = evbuffer_readline(buffev->input)) && !connect_relay) {
		int skip_line = 0;
		int do_drop = 0;

		if (strlen(line) > 0) {
			if (EVBUFFER_LENGTH(httpr->buff) == 0) { // FOO uri HTTP/3.14
				char *space = strchr(line, ' ');

				if (space)
					httpr->need_host = (space[1] == '/' || space[1] == '*');

				if (httpr->need_host) {
					httpr->firstline = line;
					line = 0;
				}
			}
			else if (strncasecmp(line, "Host", 4) == 0)
				httpr->has_host = 1;
			else if (strncasecmp(line, "Proxy-Connection", 16) == 0)
				skip_line = 1;
			else if (strncasecmp(line, "Connection", 10) == 0)
				skip_line = 1;
		}
		else { // last line of request
			if (httpr->firstline) {
				if (httpr_toss_http_firstline(client) < 0)
					do_drop = 1;
			}

			if (httpr->need_host && !httpr->has_host) {
				char host[32]; // "Host: 123.456.789.012:34567"
				strncpy(host, "Host: ", sizeof(host));
				strncat(host, fmt_http_host(client->destaddr), sizeof(host));
				if (httpr_append_header(client, host) < 0)
					do_drop = 1;
			}

			if (httpr_append_header(client, "Proxy-Connection: close") < 0)
				do_drop = 1;

			if (httpr_append_header(client, "Connection: close") < 0)
				do_drop = 1;

			connect_relay = 1;
		}

		if (line && !skip_line)
			if (httpr_append_header(client, line) < 0)
				do_drop = 1;
		
		free(line);

		if (do_drop) {
			redsocks_drop_client(client);
			return;
		}
	}
	
	if (connect_relay)
		redsocks_connect_relay(client);
}

static void httpr_connect_relay(redsocks_client *client)
{
	httpr_client *httpr = (void*)(client +1);
	int error;

	httpr->buff = evbuffer_new();
	if (!httpr->buff) {
		redsocks_log_errno(client, "evbuffer_new");
		redsocks_drop_client(client);
	}
	
	client->client->readcb = httpr_client_read_cb;
	error = bufferevent_enable(client->client, EV_READ);
	if (error) {
		redsocks_log_errno(client, "bufferevent_enable");
		redsocks_drop_client(client);
	}
}

relay_subsys http_relay_subsys = 
{
	.name          = "http-relay",
	.payload_len   = sizeof(httpr_client),
	.init          = httpr_client_init,
	.fini          = httpr_client_fini,
	.connect_relay = httpr_connect_relay,
	.writecb       = httpr_relay_write_cb,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
