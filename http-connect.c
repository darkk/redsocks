/** http-connect upstream module for redsocks
 * $Id$ 
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "redsocks.h"

typedef enum http_state_t {
	http_new,
	http_request_sent,
	http_reply_came,
	http_headers_skipped,
	http_MAX,
} http_state;


#define HTTP_HEAD_WM_HIGH 4096  // that should be enough for one HTTP line.



void http_client_init(redsocks_client *client)
{
	if (client->instance->config.login)
		log_error("login is ignored for http-connect connections");
	
	if (client->instance->config.password)
		log_error("password is ignored for http-connect connections");
	
	client->state = http_new;
}


static void http_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	int dropped = 0;

	assert(client->state >= http_request_sent);

	if (client->state == http_request_sent) {
		size_t len = EVBUFFER_LENGTH(buffev->input);
		char *line = evbuffer_readline(buffev->input);
		if (line) {
			unsigned int code;
			if (sscanf(line, "HTTP/%*u.%*u %u", &code) == 1) { // 1 == one _assigned_ match
				if (200 <= code && code <= 299) {
					client->state = http_reply_came;
				}
				else {
					log_error(line);
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
	
	while (client->state == http_reply_came) {
		char *line = evbuffer_readline(buffev->input);
		if (line) {
			if (strlen(line) == 0) {
				client->state = http_headers_skipped;
			}
			free(line);
		}
		else {
			break;
		}
	}

	if (client->state == http_headers_skipped) {
		redsocks_start_relay(client);
	}
}

static struct evbuffer *http_mkconnect(redsocks_client *client)
{
	struct evbuffer *buff = NULL, *retval = NULL;
	int len;

	buff = evbuffer_new();
	if (!buff) {
		log_errno("evbuffer_new");
		goto fail;
	}

	len = evbuffer_add_printf(buff, 
		"CONNECT %s:%u HTTP/1.0\r\n\r\n", 
		inet_ntoa(client->destaddr.sin_addr),
		ntohs(client->destaddr.sin_port)
	);
	if (len < 0) {
		log_errno("evbufer_add_printf");
		goto fail;
	}
	
	retval = buff;
	buff = NULL;

fail:
	if (buff)
		evbuffer_free(buff);
	return retval;
}


static void http_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	if (client->state == http_new) {
		redsocks_write_helper_ex(
			buffev, client,
			http_mkconnect, http_request_sent, 1, HTTP_HEAD_WM_HIGH
			);
	}
	else if (client->state >= http_request_sent) {
		bufferevent_disable(buffev, EV_WRITE);
	}
}


relay_subsys http_connect_subsys = 
{
	.name        = "http-connect",
	.payload_len = 0,
	.readcb      = http_read_cb,
	.writecb     = http_write_cb,
	.init        = http_client_init,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
