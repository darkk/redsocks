/* $Id$ */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <event.h>
#include "list.h"
#include "parser.h"
#include "log.h"
#include "main.h"
#include "base.h"
#include "redsocks.h"


#define THE_ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING 42

#define REDSOCKS_RELAY_HALFBUFF  4096


static void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how);


/** simple fcntl(2) wrapper, provides errno and all logging to caller
 * I have to use it in event-driven code because of accept(2) (see NOTES)
 * and connect(2) (see ERRORS about EINPROGRESS)
 */
static int fcntl_nonblock(int fd)
{
	int error;
	int flags;
   
	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	error = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (error)
		return -1;

	return 0;
}

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

static redsocks_instance instance = 
{ // almost NULL-initializer
	.clients = LIST_HEAD_INIT(instance.clients)
};

static parser_entry redsocks_entries[] = 
{
	{ .key = "local_ip",   .type = pt_uint16,  .addr = &instance.config.bindaddr.sin_addr },
	{ .key = "local_port", .type = pt_uint16,  .addr = &instance.config.bindaddr.sin_port },
	{ .key = "ip",         .type = pt_in_addr, .addr = &instance.config.relayaddr.sin_addr },
	{ .key = "port",       .type = pt_uint16,  .addr = &instance.config.relayaddr.sin_port },
	{ .key = "type",       .type = pt_pchar,   .addr = &instance.config.type },
	{ .key = "login",      .type = pt_pchar,   .addr = &instance.config.login },
	{ .key = "password",   .type = pt_pchar,   .addr = &instance.config.password },
	{ }
};

static int redsocks_onenter(parser_section *section)
{
	if (instance.config.type) {
		parser_error(section->context, "only one instance of redsocks is valid");
		return -1;
	}
	instance.config.bindaddr.sin_family = AF_INET;
	instance.config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance.config.relayaddr.sin_family = AF_INET;
	instance.config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return 0;
}

static int redsocks_onexit(parser_section *section)
{
	const char *err = NULL;
	instance.config.bindaddr.sin_port = htons(instance.config.bindaddr.sin_port);
	instance.config.relayaddr.sin_port = htons(instance.config.relayaddr.sin_port);
	
	if (instance.config.type) {
		relay_subsys **ss;
		FOREACH(ss, relay_subsystems) {
			if (!strcmp((*ss)->name, instance.config.type)) {
				instance.relay_ss = *ss;
				break;
			}
		}
		if (!instance.relay_ss)
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

void redsocks_log_write(
		const char *file, int line, const char *func, int do_errno, 
		redsocks_client *client, const char *orig_fmt, ...
) {
	int saved_errno = errno;
	struct evbuffer *fmt = evbuffer_new();
	va_list ap;
	char clientaddr_str[INET6_ADDRSTRLEN], destaddr_str[INET6_ADDRSTRLEN];

	if (!fmt) {
		log_errno("evbuffer_new()");
		// no return, as I have to call va_start/va_end
	}

	if (!inet_ntop(client->clientaddr.sin_family, &client->clientaddr.sin_addr, clientaddr_str, sizeof(clientaddr_str)))
		strncpy(clientaddr_str, "???", sizeof(clientaddr_str));
	if (!inet_ntop(client->destaddr.sin_family, &client->destaddr.sin_addr, destaddr_str, sizeof(destaddr_str)))
		strncpy(destaddr_str, "???", sizeof(destaddr_str));

	if (fmt) {
		evbuffer_add_printf(fmt, "[%s:%i->%s:%i]: %s", 
				clientaddr_str, ntohs(client->clientaddr.sin_port),
				destaddr_str, ntohs(client->destaddr.sin_port),
				orig_fmt);
	}

	va_start(ap, orig_fmt);
	if (fmt) {
		errno = saved_errno;
		_log_vwrite(file, line, func, do_errno, fmt->buffer, ap);
		evbuffer_free(fmt);
	}
	va_end(ap);
}

static void redsocks_relay_readcb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
	if (EVBUFFER_LENGTH(to->output) < to->wm_write.high) {
		if (bufferevent_write_buffer(to, from->input) == -1)
			redsocks_log_errno(client, "bufferevent_write_buffer");
	}
	else {
		if (bufferevent_disable(from, EV_READ) == -1)
			redsocks_log_errno(client, "bufferevent_disable");
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
			redsocks_log_errno(client, "bufferevent_write_buffer");
		if (bufferevent_enable(from, EV_READ) == -1)
			redsocks_log_errno(client, "bufferevent_enable");
	}
}


static void redsocks_relay_relayreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	redsocks_relay_readcb(client, client->relay, client->client);
}

static void redsocks_relay_relaywritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
	redsocks_relay_writecb(client, client->client, client->relay);
}

static void redsocks_relay_clientreadcb(struct bufferevent *from, void *_client)
{
	redsocks_client *client = _client;
	redsocks_relay_readcb(client, client->client, client->relay);
}

static void redsocks_relay_clientwritecb(struct bufferevent *to, void *_client)
{
	redsocks_client *client = _client;
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
		redsocks_log_error(client, "data relaying started");
	}
	else {
		redsocks_log_errno(client, "bufferevent_enable");
		redsocks_drop_client(client);
	}
}

void redsocks_drop_client(redsocks_client *client)
{
	redsocks_log_error(client, "dropping client");

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
	short evhow;
	char *strev, *strhow, *strevhow;
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

	strev = buffev == client->client ? "client" : "relay";
	pevshut = buffev == client->client ? &client->client_evshut : &client->relay_evshut;

	// if EV_WRITE is already shut and we're going to shutdown read then 
	// we're either going to abort data flow (bad behaviour) or confirm EOF
	// and in this case socket is already SHUT_RD'ed
	if ( !(how == SHUT_RD && (*pevshut & EV_WRITE)) )
		if (shutdown(EVENT_FD(&buffev->ev_read), how) != 0)
			redsocks_log_errno(client, "shutdown(%s, %s)", strev, strhow);

	if (bufferevent_disable(buffev, evhow) != 0)
		redsocks_log_errno(client, "bufferevent_disable(%s, %s)", strev, strevhow);

	*pevshut |= evhow;

	if (client->relay_evshut == (EV_READ|EV_WRITE) && client->client_evshut == (EV_READ|EV_WRITE)) {
		redsocks_log_error(client, "both client and server disconnected");
		redsocks_drop_client(client);
	}
}

static void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg)
{
	redsocks_client *client = _arg;
	assert(buffev == client->relay || buffev == client->client);

	if (what == (EVBUFFER_READ|EVBUFFER_EOF)) {
		struct bufferevent *antiev;
		if (buffev == client->relay)
			antiev = client->client;
		else
			antiev = client->relay;

		redsocks_shutdown(client, buffev, SHUT_RD);

		if (EVBUFFER_LENGTH(antiev->output) == 0)
			redsocks_shutdown(client, antiev, SHUT_WR);
	}
	else {
		redsocks_log_error(client, "%s error, code %s|%s|%s|%s|%s == %X",
				buffev == client->relay ? "relay" : "client",
				what & EVBUFFER_READ ? "EVBUFFER_READ" : "0",
				what & EVBUFFER_WRITE ? "EVBUFFER_WRITE" : "0",
				what & EVBUFFER_EOF ? "EVBUFFER_EOF" : "0",
				what & EVBUFFER_ERROR ? "EVBUFFER_ERROR" : "0",
				what & EVBUFFER_TIMEOUT ? "EVBUFFER_TIMEOUT" : "0",
				what);
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
		assert(read == expected);
		return 0;
	}
	else {
		redsocks_log_error(client, "Can't get expected amount of data");
		redsocks_drop_client(client);
		return -1;
	}
}

struct evbuffer *mkevbuffer(void *data, size_t len)
{
	struct evbuffer *buff = NULL, *retval = NULL;

	buff = evbuffer_new();
	if (!buff) {
		log_errno("evbuffer_new");
		goto fail;
	}

	if (evbuffer_add(buff, data, len) < 0) {
		log_errno("evbuffer_add");
		goto fail;
	}

	retval = buff;
	buff = NULL;

fail:
	if (buff)
		evbuffer_free(buff);
	return retval;
}

void redsocks_write_helper_ex(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_low, size_t wm_high)
{
	int len;
	struct evbuffer *buff = NULL;
	int drop = 1;
	
	if (mkmessage) {
		buff = mkmessage(client);
		if (!buff)
			goto fail;
		
		len = bufferevent_write_buffer(client->relay, buff);
		if (len < 0) {
			redsocks_log_errno(client, "bufferevent_write_buffer");
			goto fail;
		}
	}

	client->state = state;
	buffev->wm_read.low = wm_low;
	buffev->wm_read.high = wm_high;
	bufferevent_enable(buffev, EV_READ);
	drop = 0;
	
fail:
	if (buff)
		evbuffer_free(buff);
	if (drop)
		redsocks_drop_client(client);
}

void redsocks_write_helper(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_only)
{
	redsocks_write_helper_ex(buffev, client, mkmessage, state, wm_only, wm_only);
}

static void redsocks_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	int error;
	int pseudo_errno;
	socklen_t optlen = sizeof(pseudo_errno);

	assert(buffev == client->relay);

	error = getsockopt(EVENT_FD(&buffev->ev_write), SOL_SOCKET, SO_ERROR, &pseudo_errno, &optlen);
	if (error) {
		redsocks_log_errno(client, "getsockopt");
		goto fail;
	}

	if (pseudo_errno) {
		errno = pseudo_errno;
		redsocks_log_errno(client, "connect");
		goto fail;
	}

	client->relay->readcb = client->instance->relay_ss->readcb;
	client->relay->writecb = client->instance->relay_ss->writecb;
	client->relay->writecb(buffev, _arg);
	return;

fail:
	redsocks_event_error(buffev, EVBUFFER_WRITE | EVBUFFER_ERROR, _arg);
}

void redsocks_connect_relay(redsocks_client *client)
{
	int relay_fd = -1;
	int error;

	relay_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (relay_fd == -1) {
		redsocks_log_errno(client, "socket");
		goto fail;
	}

	error = fcntl_nonblock(relay_fd);
	if (error) {
		redsocks_log_errno(client, "fcntl");
		goto fail;
	}

	error = connect(relay_fd, (struct sockaddr*)&client->instance->config.relayaddr, sizeof(client->instance->config.relayaddr));
	if (error && errno != EINPROGRESS) {
		redsocks_log_errno(client, "connect");
		goto fail;
	}

	client->relay = bufferevent_new(relay_fd, NULL, redsocks_relay_connected, redsocks_event_error, client);
	if (!client->relay) {
		redsocks_log_errno(client, "bufferevent_new");
		goto fail;
	}
	relay_fd = -1;

	error = bufferevent_enable(client->relay, EV_WRITE); // we wait for connection...
	if (error) {
		redsocks_log_errno(client, "bufferevent_enable");
		goto fail;
	}

	return; // OK

fail:
	if (relay_fd != -1)
		close(relay_fd);
	redsocks_drop_client(client);
}

static void redsocks_accept_client(int fd, short what, void *_arg)
{
	redsocks_instance *self = _arg;
	redsocks_client   *client = NULL;
	struct sockaddr_in clientaddr;
	struct sockaddr_in destaddr;
	socklen_t          addrlen = sizeof(clientaddr);
	int client_fd = -1;
	int error;
	
	// working with client_fd
	client_fd = accept(fd, (struct sockaddr*)&clientaddr, &addrlen);
	if (client_fd == -1) {
		log_errno("accept");
		goto fail;
	}

	error = getdestaddr(client_fd, &clientaddr, &self->config.bindaddr, &destaddr);
	if (error) {
		goto fail;
	}

	// everything seems to be ok, let's allocate some memory
	client = calloc(1, sizeof(redsocks_client) + self->relay_ss->payload_len);
	if (!client) {
		log_errno("calloc");
		goto fail;
	}
	client->instance = self;
	memcpy(&client->clientaddr, &clientaddr, sizeof(clientaddr));
	memcpy(&client->destaddr, &destaddr, sizeof(destaddr));
	INIT_LIST_HEAD(&client->list);
	self->relay_ss->init(client);
	
	client->client = bufferevent_new(client_fd, NULL, NULL, redsocks_event_error, client);
	if (!client->client) {
		log_errno("bufferevent_new");
		goto fail;
	}
	client_fd = -1;

	list_add(&client->list, &self->clients);

	// enable reading to handle EOF from client
	if (bufferevent_enable(client->client, EV_READ) != 0) {
		redsocks_log_errno(client, "bufferevent_enable");
		goto fail;
	}
	
	redsocks_log_error(client, "accepted");
	
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

static int redsocks_init()
{
	int error;
	int on = 1;
	int fd = -1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		log_errno("socket");
		return -1;
	}

	error = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (error) {
		log_errno("setsockopt");
		goto fail;
	}

	error = bind(fd, (struct sockaddr*)&instance.config.bindaddr, sizeof(instance.config.bindaddr));
	if (error) {
		log_errno("bind");
		goto fail;
	}

	error = fcntl_nonblock(fd);
	if (error) {
		log_errno("fcntl");
		goto fail;
	}

	error = listen(fd, THE_ANSWER_TO_THE_ULTIMATE_QUESTION_OF_LIFE_THE_UNIVERSE_AND_EVERYTHING); // does anyone know better value?
	if (error) {
		log_errno("listen");
		goto fail;
	}

	event_set(&instance.listener, fd, EV_READ | EV_PERSIST, redsocks_accept_client, &instance);
	error = event_add(&instance.listener, NULL);
	if (error) {
		log_errno("event_add");
		goto fail;
	}
	
	return 0;
fail:
	if (event_initialized(&instance.listener)) {
		event_del(&instance.listener);
		memset(&instance.listener, 0, sizeof(instance.listener));
	}

	if (fd != -1) {
		close(fd);
	}
	return -1;
}

static int redsocks_fini()
{
	if (event_initialized(&instance.listener)) {
		event_del(&instance.listener);
		close(EVENT_FD(&instance.listener));
		memset(&instance.listener, 0, sizeof(instance.listener));
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
