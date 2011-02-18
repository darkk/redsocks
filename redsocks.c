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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <event.h>
#include "list.h"
#include "parser.h"
#include "log.h"
#include "main.h"
#include "base.h"
#include "redsocks.h"
#include "utils.h"


#define THE_ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING 42

#define REDSOCKS_RELAY_HALFBUFF  4096


static void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);


extern relay_subsys http_connect_subsys;
extern relay_subsys http_relay_subsys;
extern relay_subsys socks4_subsys;
extern relay_subsys socks5_subsys;
static relay_subsys *relay_subsystems[] =
{
	&http_connect_subsys,
	&http_relay_subsys,
	&socks4_subsys,
	&socks5_subsys,
};

static list_head instances = LIST_HEAD_INIT(instances);

static parser_entry redsocks_entries[] =
{
	{ .key = "local_ip",   .type = pt_in_addr },
	{ .key = "local_port", .type = pt_uint16 },
	{ .key = "ip",         .type = pt_in_addr },
	{ .key = "port",       .type = pt_uint16 },
	{ .key = "type",       .type = pt_pchar },
	{ .key = "login",      .type = pt_pchar },
	{ .key = "password",   .type = pt_pchar },
	{ }
};

static int redsocks_onenter(parser_section *section)
{
	// FIXME: find proper way to calulate instance_payload_len
	int instance_payload_len = 0;
	relay_subsys **ss;
	FOREACH(ss, relay_subsystems)
		if (instance_payload_len < (*ss)->instance_payload_len)
			instance_payload_len = (*ss)->instance_payload_len;

	redsocks_instance *instance = calloc(1, sizeof(*instance) + instance_payload_len);
	if (!instance) {
		parser_error(section->context, "Not enough memory");
		return -1;
	}

	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->clients);
	instance->config.bindaddr.sin_family = AF_INET;
	instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.relayaddr.sin_family = AF_INET;
	instance->config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr =
			(strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
			(strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
			(strcmp(entry->key, "ip") == 0)         ? (void*)&instance->config.relayaddr.sin_addr :
			(strcmp(entry->key, "port") == 0)       ? (void*)&instance->config.relayaddr.sin_port :
			(strcmp(entry->key, "type") == 0)       ? (void*)&instance->config.type :
			(strcmp(entry->key, "login") == 0)      ? (void*)&instance->config.login :
			(strcmp(entry->key, "password") == 0)   ? (void*)&instance->config.password :
			NULL;
	section->data = instance;
	return 0;
}

static int redsocks_onexit(parser_section *section)
{
	/* FIXME: Rewrite in bullet-proof style. There are memory leaks if config
	 *        file is not correct, so correct on-the-fly config reloading is
	 *        currently impossible.
	 */
	const char *err = NULL;
	redsocks_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);

	if (instance->config.type) {
		relay_subsys **ss;
		FOREACH(ss, relay_subsystems) {
			if (!strcmp((*ss)->name, instance->config.type)) {
				instance->relay_ss = *ss;
				list_add(&instance->list, &instances);
				break;
			}
		}
		if (!instance->relay_ss)
			err = "invalid `type` for redsocks";
	}
	else {
		err = "no `type` for redsocks";
	}

	if (err)
		parser_error(section->context, err);

	return err ? -1 : 0;
}

static parser_section redsocks_conf_section =
{
	.name    = "redsocks",
	.entries = redsocks_entries,
	.onenter = redsocks_onenter,
	.onexit  = redsocks_onexit
};

void redsocks_log_write_plain(
		const char *file, int line, const char *func, int do_errno,
		const struct sockaddr_in *clientaddr, const struct sockaddr_in *destaddr,
		int priority, const char *orig_fmt, ...
) {
	int saved_errno = errno;
	struct evbuffer *fmt = evbuffer_new();
	va_list ap;
	char clientaddr_str[INET6_ADDRSTRLEN], destaddr_str[INET6_ADDRSTRLEN];

	if (!fmt) {
		log_errno(LOG_ERR, "evbuffer_new()");
		// no return, as I have to call va_start/va_end
	}

	if (!inet_ntop(clientaddr->sin_family, &clientaddr->sin_addr, clientaddr_str, sizeof(clientaddr_str)))
		strncpy(clientaddr_str, "???", sizeof(clientaddr_str));
	if (!inet_ntop(destaddr->sin_family, &destaddr->sin_addr, destaddr_str, sizeof(destaddr_str)))
		strncpy(destaddr_str, "???", sizeof(destaddr_str));

	if (fmt) {
		evbuffer_add_printf(fmt, "[%s:%i->%s:%i]: %s",
				clientaddr_str, ntohs(clientaddr->sin_port),
				destaddr_str, ntohs(destaddr->sin_port),
				orig_fmt);
	}

	va_start(ap, orig_fmt);
	if (fmt) {
		errno = saved_errno;
		_log_vwrite(file, line, func, do_errno, priority, redsocks_evbuffer_pullup(fmt), ap);
		evbuffer_free(fmt);
	}
	va_end(ap);
}

void redsocks_touch_client(redsocks_client *client)
{
	redsocks_time(&client->last_event);
}


static void redsocks_relay_readcb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
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

static void redsocks_relay_writecb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
	assert(from == client->client || from == client->relay);
	char from_eof = (from == client->client ? client->client_evshut : client->relay_evshut) & EV_READ;

	if (EVBUFFER_LENGTH(from->input) == 0 && from_eof) {
		redsocks_shutdown(client, to, SHUT_WR);
	}
	else if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
		if (bufferevent_write_buffer(to, from->input) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
		if (bufferevent_enable(from, EV_READ) == -1)
			redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
	}
}


static void redsocks_relay_relayreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	redsocks_touch_client(client);
	redsocks_relay_readcb(client, client->relay, client->client);
}

static void redsocks_relay_relaywritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
	redsocks_touch_client(client);
	redsocks_relay_writecb(client, client->client, client->relay);
}

static void redsocks_relay_clientreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	redsocks_touch_client(client);
	redsocks_relay_readcb(client, client->client, client->relay);
}

static void redsocks_relay_clientwritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
	redsocks_touch_client(client);
	redsocks_relay_writecb(client, client->relay, client->client);
}

void redsocks_start_relay(redsocks_client *client)
{
	int error;

	if (client->instance->relay_ss->fini)
		client->instance->relay_ss->fini(client);

	client->relay->wm_read.low = 0;
	client->relay->wm_write.low = 0;
	client->client->wm_read.low = 0;
	client->client->wm_write.low = 0;
	client->relay->wm_read.high = REDSOCKS_RELAY_HALFBUFF;
	client->relay->wm_write.high = REDSOCKS_RELAY_HALFBUFF;
	client->client->wm_read.high = REDSOCKS_RELAY_HALFBUFF;
	client->client->wm_write.high = REDSOCKS_RELAY_HALFBUFF;

	client->client->readcb = redsocks_relay_clientreadcb;
	client->client->writecb = redsocks_relay_clientwritecb;
	client->relay->readcb = redsocks_relay_relayreadcb;
	client->relay->writecb = redsocks_relay_relaywritecb;

	error = bufferevent_enable(client->client, EV_READ | EV_WRITE);
	if (!error)
		error = bufferevent_enable(client->relay, EV_READ | EV_WRITE);

	if (!error) {
		redsocks_log_error(client, LOG_DEBUG, "data relaying started");
	}
	else {
		redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
		redsocks_drop_client(client);
	}
}

void redsocks_drop_client(redsocks_client *client)
{
	redsocks_log_error(client, LOG_INFO, "dropping client");

	if (client->instance->relay_ss->fini)
		client->instance->relay_ss->fini(client);

	if (client->client) {
		close(EVENT_FD(&client->client->ev_write));
		bufferevent_free(client->client);
	}

	if (client->relay) {
		close(EVENT_FD(&client->relay->ev_write));
		bufferevent_free(client->relay);
	}

	list_del(&client->list);
	free(client);
}

static void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how)
{
	short evhow = 0;
	char *strev, *strhow = NULL, *strevhow = NULL;
	unsigned short *pevshut;

	assert(how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR);
	assert(buffev == client->client || buffev == client->relay);
	assert(EVENT_FD(&buffev->ev_read) == EVENT_FD(&buffev->ev_write));

	if (how == SHUT_RD) {
		strhow = "SHUT_RD";
		evhow = EV_READ;
		strevhow = "EV_READ";
	}
	else if (how == SHUT_WR) {
		strhow = "SHUT_WR";
		evhow = EV_WRITE;
		strevhow = "EV_WRITE";
	}
	else if (how == SHUT_RDWR) {
		strhow = "SHUT_RDWR";
		evhow = EV_READ|EV_WRITE;
		strevhow = "EV_READ|EV_WRITE";
	}

	assert(strhow && strevhow);

	strev = buffev == client->client ? "client" : "relay";
	pevshut = buffev == client->client ? &client->client_evshut : &client->relay_evshut;

	// if EV_WRITE is already shut and we're going to shutdown read then
	// we're either going to abort data flow (bad behaviour) or confirm EOF
	// and in this case socket is already SHUT_RD'ed
	if ( !(how == SHUT_RD && (*pevshut & EV_WRITE)) )
		if (shutdown(EVENT_FD(&buffev->ev_read), how) != 0)
			redsocks_log_errno(client, LOG_ERR, "shutdown(%s, %s)", strev, strhow);

	if (bufferevent_disable(buffev, evhow) != 0)
		redsocks_log_errno(client, LOG_ERR, "bufferevent_disable(%s, %s)", strev, strevhow);

	*pevshut |= evhow;

	if (client->relay_evshut == (EV_READ|EV_WRITE) && client->client_evshut == (EV_READ|EV_WRITE)) {
		redsocks_log_error(client, LOG_DEBUG, "both client and server disconnected");
		redsocks_drop_client(client);
	}
}

// I assume that -1 is invalid errno value
static int redsocks_socket_geterrno(redsocks_client *client, struct bufferevent *buffev)
{
	int pseudo_errno = red_socket_geterrno(buffev);
	if (pseudo_errno == -1) {
		redsocks_log_errno(client, LOG_ERR, "red_socket_geterrno");
		return -1;
	}
	return pseudo_errno;
}

static void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg)
{
	redsocks_client *client = _arg;
	assert(buffev == client->relay || buffev == client->client);

	redsocks_touch_client(client);

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
		errno = redsocks_socket_geterrno(client, buffev);
		redsocks_log_errno(client, LOG_NOTICE, "%s error, code " event_fmt_str,
				buffev == client->relay ? "relay" : "client",
				event_fmt(what));
		redsocks_drop_client(client);
	}
}

int sizes_equal(size_t a, size_t b)
{
	return a == b;
}

int sizes_greater_equal(size_t a, size_t b)
{
	return a >= b;
}

int redsocks_read_expected(redsocks_client *client, struct evbuffer *input, void *data, size_comparator comparator, size_t expected)
{
	size_t len = EVBUFFER_LENGTH(input);
	if (comparator(len, expected)) {
		int read = evbuffer_remove(input, data, expected);
		UNUSED(read);
		assert(read == expected);
		return 0;
	}
	else {
		redsocks_log_error(client, LOG_NOTICE, "Can't get expected amount of data");
		redsocks_drop_client(client);
		return -1;
	}
}

struct evbuffer *mkevbuffer(void *data, size_t len)
{
	struct evbuffer *buff = NULL, *retval = NULL;

	buff = evbuffer_new();
	if (!buff) {
		log_errno(LOG_ERR, "evbuffer_new");
		goto fail;
	}

	if (evbuffer_add(buff, data, len) < 0) {
		log_errno(LOG_ERR, "evbuffer_add");
		goto fail;
	}

	retval = buff;
	buff = NULL;

fail:
	if (buff)
		evbuffer_free(buff);
	return retval;
}

int redsocks_write_helper_ex(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_low, size_t wm_high)
{
	assert(client);
	return redsocks_write_helper_ex_plain(buffev, client, (redsocks_message_maker_plain)mkmessage,
	                                      client, state, wm_low, wm_high);
}

int redsocks_write_helper_ex_plain(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker_plain mkmessage, void *p, int state, size_t wm_low, size_t wm_high)
{
	int len;
	struct evbuffer *buff = NULL;
	int drop = 1;

	if (mkmessage) {
		buff = mkmessage(p);
		if (!buff)
			goto fail;

		assert(!client || buffev == client->relay);
		len = bufferevent_write_buffer(buffev, buff);
		if (len < 0) {
			if (client)
				redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
			else
				log_errno(LOG_ERR, "bufferevent_write_buffer");
			goto fail;
		}
	}

	if (client)
		client->state = state;
	buffev->wm_read.low = wm_low;
	buffev->wm_read.high = wm_high;
	bufferevent_enable(buffev, EV_READ);
	drop = 0;

fail:
	if (buff)
		evbuffer_free(buff);
	if (drop && client)
		redsocks_drop_client(client);
	return drop ? -1 : 0;
}

int redsocks_write_helper(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_only)
{
	assert(client);
	return redsocks_write_helper_ex(buffev, client, mkmessage, state, wm_only, wm_only);
}

static void redsocks_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	assert(buffev == client->relay);

	redsocks_touch_client(client);

	if (!red_is_socket_connected_ok(buffev)) {
		redsocks_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
		goto fail;
	}

	client->relay->readcb = client->instance->relay_ss->readcb;
	client->relay->writecb = client->instance->relay_ss->writecb;
	client->relay->writecb(buffev, _arg);
	return;

fail:
	redsocks_drop_client(client);
}

void redsocks_connect_relay(redsocks_client *client)
{
	client->relay = red_connect_relay(&client->instance->config.relayaddr,
			                          redsocks_relay_connected, redsocks_event_error, client);
	if (!client->relay) {
		redsocks_log_errno(client, LOG_ERR, "red_connect_relay");
		redsocks_drop_client(client);
	}
}

static void redsocks_accept_client(int fd, short what, void *_arg)
{
	redsocks_instance *self = _arg;
	redsocks_client   *client = NULL;
	struct sockaddr_in clientaddr;
	struct sockaddr_in myaddr;
	struct sockaddr_in destaddr;
	socklen_t          addrlen = sizeof(clientaddr);
	int on = 1;
	int client_fd = -1;
	int error;

	// working with client_fd
	client_fd = accept(fd, (struct sockaddr*)&clientaddr, &addrlen);
	if (client_fd == -1) {
		log_errno(LOG_WARNING, "accept");
		goto fail;
	}

	// socket is really bound now (it could be bound to 0.0.0.0)
	addrlen = sizeof(myaddr);
	error = getsockname(client_fd, (struct sockaddr*)&myaddr, &addrlen);
	if (error) {
		log_errno(LOG_WARNING, "getsockname");
		goto fail;
	}

	error = getdestaddr(client_fd, &clientaddr, &myaddr, &destaddr);
	if (error) {
		goto fail;
	}

	error = setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	if (error) {
		log_errno(LOG_WARNING, "setsockopt");
		goto fail;
	}

	// everything seems to be ok, let's allocate some memory
	client = calloc(1, sizeof(redsocks_client) + self->relay_ss->payload_len);
	if (!client) {
		log_errno(LOG_ERR, "calloc");
		goto fail;
	}
	client->instance = self;
	memcpy(&client->clientaddr, &clientaddr, sizeof(clientaddr));
	memcpy(&client->destaddr, &destaddr, sizeof(destaddr));
	INIT_LIST_HEAD(&client->list);
	self->relay_ss->init(client);

	if (redsocks_time(&client->first_event) == ((time_t)-1))
		goto fail;

	redsocks_touch_client(client);

	client->client = bufferevent_new(client_fd, NULL, NULL, redsocks_event_error, client);
	if (!client->client) {
		log_errno(LOG_ERR, "bufferevent_new");
		goto fail;
	}
	client_fd = -1;

	list_add(&client->list, &self->clients);

	// enable reading to handle EOF from client
	if (bufferevent_enable(client->client, EV_READ) != 0) {
		redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
		goto fail;
	}

	redsocks_log_error(client, LOG_INFO, "accepted");

	if (self->relay_ss->connect_relay)
		self->relay_ss->connect_relay(client);
	else
		redsocks_connect_relay(client);

	return;

fail:
	if (client) {
		redsocks_drop_client(client);
	}
	if (client_fd != -1)
		close(client_fd);
}

static const char *redsocks_evshut_str(unsigned short evshut)
{
	return
		evshut == EV_READ ? "SHUT_RD" :
		evshut == EV_WRITE ? "SHUT_WR" :
		evshut == (EV_READ|EV_WRITE) ? "SHUT_RDWR" :
		evshut == 0 ? "" :
		"???";
}

static const char *redsocks_event_str(unsigned short what)
{
	return
		what == EV_READ ? "R/-" :
		what == EV_WRITE ? "-/W" :
		what == (EV_READ|EV_WRITE) ? "R/W" :
		what == 0 ? "-/-" :
		"???";
}

static void redsocks_debug_dump_instance(redsocks_instance *instance, time_t now)
{
	redsocks_client *client = NULL;

	log_error(LOG_DEBUG, "Dumping client list for instance %p:", instance);
	list_for_each_entry(client, &instance->clients, list) {
		const char *s_client_evshut = redsocks_evshut_str(client->client_evshut);
		const char *s_relay_evshut = redsocks_evshut_str(client->relay_evshut);

		redsocks_log_error(client, LOG_DEBUG, "client: %i (%s)%s%s, relay: %i (%s)%s%s, age: %li sec, idle: %li sec.",
			EVENT_FD(&client->client->ev_write),
				redsocks_event_str(client->client->enabled),
				s_client_evshut[0] ? " " : "", s_client_evshut,
			EVENT_FD(&client->relay->ev_write),
				redsocks_event_str(client->relay->enabled),
				s_relay_evshut[0] ? " " : "", s_relay_evshut,
			now - client->first_event,
			now - client->last_event);
	}
	log_error(LOG_DEBUG, "End of client list.");
}

static void redsocks_debug_dump(int sig, short what, void *_arg)
{
	redsocks_instance *instance = NULL;
	time_t now = redsocks_time(NULL);

	list_for_each_entry(instance, &instances, list)
		redsocks_debug_dump_instance(instance, now);
}

static void redsocks_fini_instance(redsocks_instance *instance);

static int redsocks_init_instance(redsocks_instance *instance)
{
	/* FIXME: redsocks_fini_instance is called in case of failure, this
	 *        function will remove instance from instances list - result
	 *        looks ugly.
	 */
	int error;
	int on = 1;
	int fd = -1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		log_errno(LOG_ERR, "socket");
		goto fail;
	}

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (error) {
		log_errno(LOG_ERR, "setsockopt");
		goto fail;
	}

	error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, sizeof(instance->config.bindaddr));
	if (error) {
		log_errno(LOG_ERR, "bind");
		goto fail;
	}

	error = fcntl_nonblock(fd);
	if (error) {
		log_errno(LOG_ERR, "fcntl");
		goto fail;
	}

	error = listen(fd, THE_ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING); // does anyone know better value?
	if (error) {
		log_errno(LOG_ERR, "listen");
		goto fail;
	}

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redsocks_accept_client, instance);
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}

	return 0;

fail:
	redsocks_fini_instance(instance);

	if (fd != -1) {
		if (close(fd) != 0)
			log_errno(LOG_WARNING, "close");
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void redsocks_fini_instance(redsocks_instance *instance) {
	if (!list_empty(&instance->clients)) {
		redsocks_client *tmp, *client = NULL;

		log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
		list_for_each_entry_safe(client, tmp, &instance->clients, list) {
			redsocks_drop_client(client);
		}
	}

	if (instance->relay_ss->instance_fini)
		instance->relay_ss->instance_fini(instance);

	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		if (close(EVENT_FD(&instance->listener)) != 0)
			log_errno(LOG_WARNING, "close");
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	free(instance->config.type);
	free(instance->config.login);
	free(instance->config.password);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int redsocks_fini();

static struct event debug_dumper;

static int redsocks_init() {
	struct sigaction sa = { }, sa_old = { };
	redsocks_instance *tmp, *instance = NULL;

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGPIPE, &sa, &sa_old) == -1) {
		log_errno(LOG_ERR, "sigaction");
		return -1;
	}

	signal_set(&debug_dumper, SIGUSR1, redsocks_debug_dump, NULL);
	if (signal_add(&debug_dumper, NULL) != 0) {
		log_errno(LOG_ERR, "signal_add");
		goto fail;
	}

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (redsocks_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	// that was the first resource allocation, it return's on failure, not goto-fail's
	sigaction(SIGPIPE, &sa_old, NULL);

	redsocks_fini();

	return -1;
}

static int redsocks_fini()
{
	redsocks_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		redsocks_fini_instance(instance);

	if (signal_initialized(&debug_dumper)) {
		if (signal_del(&debug_dumper) != 0)
			log_errno(LOG_WARNING, "signal_del");
		memset(&debug_dumper, 0, sizeof(debug_dumper));
	}

	return 0;
}

app_subsys redsocks_subsys =
{
	.init = redsocks_init,
	.fini = redsocks_fini,
	.conf_section = &redsocks_conf_section,
};



/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
