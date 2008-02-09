/** http-connect upstream module for redsocks
 * $Id$ 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "redsocks.h"

typedef enum httpc_state_t {
	httpc_new,
	httpc_request_sent,
	httpc_reply_came,
	httpc_headers_skipped,
	httpc_MAX,
} httpc_state;


#define HTTP_HEAD_WM_HIGH 4096  // that should be enough for one HTTP line.



static void httpc_client_init(redsocks_client *client)
{
	if (client->instance->config.login)
		redsocks_log_error(client, LOG_WARNING, "login is ignored for http-connect connections");
	
	if (client->instance->config.password)
		redsocks_log_error(client, LOG_WARNING, "password is ignored for http-connect connections");
	
	client->state = httpc_new;
}


static void httpc_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	int dropped = 0;

	assert(client->state >= httpc_request_sent);

	if (client->state == httpc_request_sent) {
		size_t len = EVBUFFER_LENGTH(buffev->input);
		char *line = evbuffer_readline(buffev->input);
		if (line) {
			unsigned int code;
			if (sscanf(line, "HTTP/%*u.%*u %u", &code) == 1) { // 1 == one _assigned_ match
				if (200 <= code && code <= 299) {
					client->state = httpc_reply_came;
				}
				else {
					redsocks_log_error(client, LOG_NOTICE, "%s", line);
					redsocks_drop_client(client);
					dropped = 1;
				}
			}
			free(line);
		}
		else if (len >= HTTP_HEAD_WM_HIGH) {
			redsocks_drop_client(client);
			dropped = 1;
		}
	}

	if (dropped)
		return;
	
	while (client->state == httpc_reply_came) {
		char *line = evbuffer_readline(buffev->input);
		if (line) {
			if (strlen(line) == 0) {
				client->state = httpc_headers_skipped;
			}
			free(line);
		}
		else {
			break;
		}
	}

	if (client->state == httpc_headers_skipped) {
		redsocks_start_relay(client);
	}
}

static struct evbuffer *httpc_mkconnect(redsocks_client *client)
{
	struct evbuffer *buff = NULL, *retval = NULL;
	int len;

	buff = evbuffer_new();
	if (!buff) {
		redsocks_log_errno(client, LOG_ERR, "evbuffer_new");
		goto fail;
	}

	len = evbuffer_add_printf(buff, 
		"CONNECT %s:%u HTTP/1.0\r\n\r\n", 
		inet_ntoa(client->destaddr.sin_addr),
		ntohs(client->destaddr.sin_port)
	);
	if (len < 0) {
		redsocks_log_errno(client, LOG_ERR, "evbufer_add_printf");
		goto fail;
	}
	
	retval = buff;
	buff = NULL;

fail:
	if (buff)
		evbuffer_free(buff);
	return retval;
}


static void httpc_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	if (client->state == httpc_new) {
		redsocks_write_helper_ex(
			buffev, client,
			httpc_mkconnect, httpc_request_sent, 1, HTTP_HEAD_WM_HIGH
			);
	}
	else if (client->state >= httpc_request_sent) {
		bufferevent_disable(buffev, EV_WRITE);
	}
}


relay_subsys http_connect_subsys = 
{
	.name        = "http-connect",
	.payload_len = 0,
	.readcb      = httpc_read_cb,
	.writecb     = httpc_write_cb,
	.init        = httpc_client_init,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
