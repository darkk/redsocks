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

/** http-connect upstream module for redsocks
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "redsocks.h"
#include "http-auth.h"

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
	client->state = httpc_new;
}

static void httpc_instance_fini(redsocks_instance *instance)
{
	http_auth *auth = (void*)(instance + 1);
	free(auth->last_auth_query);
	auth->last_auth_query = NULL;
}

static struct evbuffer *httpc_mkconnect(redsocks_client *client);

extern const char *auth_request_header;
extern const char *auth_response_header;

static char *get_auth_request_header(struct evbuffer *buf)
{
	char *line;
	for (;;) {
		line = evbuffer_readline(buf);
		if (line == NULL || *line == '\0' || strchr(line, ':') == NULL) {
			free(line);
			return NULL;
		}
		if (strncasecmp(line, auth_request_header, strlen(auth_request_header)) == 0)
			return line;
		free(line);
	}
}

static void httpc_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	int dropped = 0;

	assert(client->state >= httpc_request_sent);

	redsocks_touch_client(client);

	if (client->state == httpc_request_sent) {
		size_t len = EVBUFFER_LENGTH(buffev->input);
		char *line = evbuffer_readline(buffev->input);
		if (line) {
			unsigned int code;
			if (sscanf(line, "HTTP/%*u.%*u %u", &code) == 1) { // 1 == one _assigned_ match
				if (code == 407) { // auth failed
					http_auth *auth = (void*)(client->instance + 1);

					if (auth->last_auth_query != NULL && auth->last_auth_count == 1) {
						redsocks_log_error(client, LOG_NOTICE, "proxy auth failed");
						redsocks_drop_client(client);

						dropped = 1;
					} else if (client->instance->config.login == NULL || client->instance->config.password == NULL) {
						redsocks_log_error(client, LOG_NOTICE, "proxy auth required, but no login information provided");
						redsocks_drop_client(client);

						dropped = 1;
					} else {
						char *auth_request = get_auth_request_header(buffev->input);

						if (!auth_request) {
							redsocks_log_error(client, LOG_NOTICE, "403 found, but no proxy auth challenge");
							redsocks_drop_client(client);
							dropped = 1;
						} else {
							free(line);
							free(auth->last_auth_query);
							char *ptr = auth_request;

							ptr += strlen(auth_request_header);
							while (isspace(*ptr))
								ptr++;

							auth->last_auth_query = calloc(strlen(ptr) + 1, 1);
							strcpy(auth->last_auth_query, ptr);
							auth->last_auth_count = 0;

							free(auth_request);

							if (bufferevent_disable(client->relay, EV_WRITE)) {
								redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
								return;
							}

							/* close relay tunnel */
							close(EVENT_FD(&client->relay->ev_write));
							bufferevent_free(client->relay);

							/* set to initial state*/
							client->state = httpc_new;

							/* and reconnect */
							redsocks_connect_relay(client);
							return;
						}
					}
				} else if (200 <= code && code <= 299) {
					client->state = httpc_reply_came;
				} else {
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

	http_auth *auth = (void*)(client->instance + 1);
	++auth->last_auth_count;

	const char *auth_scheme = NULL;
	char *auth_string = NULL;

	if (auth->last_auth_query != NULL) {
		/* find previous auth challange */

		if (strncasecmp(auth->last_auth_query, "Basic", 5) == 0) {
			auth_string = basic_authentication_encode(client->instance->config.login, client->instance->config.password);
			auth_scheme = "Basic";
		} else if (strncasecmp(auth->last_auth_query, "Digest", 6) == 0) {
			/* calculate uri */
			char uri[128];
			snprintf(uri, 128, "%s:%u", inet_ntoa(client->destaddr.sin_addr), ntohs(client->destaddr.sin_port));

			/* prepare an random string for cnounce */
			char cnounce[17];
			for (int i = 0; i < 16; i += 4)
				sprintf(cnounce + i, "%02x", rand() & 65535);

			auth_string = digest_authentication_encode(auth->last_auth_query + 7, //line
					client->instance->config.login, client->instance->config.password, //user, pass
					"CONNECT", uri, auth->last_auth_count, cnounce); // method, path, nc, cnounce
			auth_scheme = "Digest";
		}
	}

	if (auth_string == NULL) {
		len = evbuffer_add_printf(buff,
			"CONNECT %s:%u HTTP/1.0\r\n\r\n",
			inet_ntoa(client->destaddr.sin_addr),
			ntohs(client->destaddr.sin_port)
		);
	} else {
		len = evbuffer_add_printf(buff,
			"CONNECT %s:%u HTTP/1.0\r\n%s %s %s\r\n\r\n",
			inet_ntoa(client->destaddr.sin_addr),
			ntohs(client->destaddr.sin_port),
			auth_response_header,
			auth_scheme,
			auth_string
		);
	}

	free(auth_string);

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

	redsocks_touch_client(client);

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
	.name                 = "http-connect",
	.payload_len          = 0,
	.instance_payload_len = sizeof(http_auth),
	.readcb               = httpc_read_cb,
	.writecb              = httpc_write_cb,
	.init                 = httpc_client_init,
	.instance_fini        = httpc_instance_fini,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
