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
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#include "list.h"
#include "log.h"
#include "socks5.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "redudp.h"

#define redudp_log_error(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &(client)->clientaddr, &(client)->instance->config.destaddr, prio, ## msg)
#define redudp_log_errno(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &(client)->clientaddr, &(client)->instance->config.destaddr, prio, ## msg)

static void redudp_pkt_from_socks(int fd, short what, void *_arg);
static void redudp_drop_client(redudp_client *client);
static void redudp_fini_instance(redudp_instance *instance);
static int redudp_fini();

typedef struct redudp_expected_assoc_reply_t {
	socks5_reply h;
	socks5_addr_ipv4 ip;
} PACKED redudp_expected_assoc_reply;

/***********************************************************************
 * Helpers
 */
static void redudp_fill_preamble(socks5_udp_preabmle *preamble, redudp_client *client)
{
	preamble->reserved = 0;
	preamble->frag_no = 0; /* fragmentation is not supported */
	preamble->addrtype = socks5_addrtype_ipv4;
	preamble->ip.addr = client->instance->config.destaddr.sin_addr.s_addr;
	preamble->ip.port = client->instance->config.destaddr.sin_port;
}

static struct evbuffer* socks5_mkmethods_plain_wrapper(void *p)
{
	int *do_password = p;
	return socks5_mkmethods_plain(*do_password);
}

static struct evbuffer* socks5_mkpassword_plain_wrapper(void *p)
{
	redudp_instance *self = p;
	return socks5_mkpassword_plain(self->config.login, self->config.password);
}

static struct evbuffer* socks5_mkassociate(void *p)
{
	struct sockaddr_in sa;
	p = p; /* Make compiler happy */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	return socks5_mkcommand_plain(socks5_cmd_udp_associate, &sa);
}

static int recv_udp_pkt(int fd, char *buf, size_t buflen, struct sockaddr_in *inaddr)
{
	socklen_t addrlen = sizeof(*inaddr);
	ssize_t pktlen;

	pktlen = recvfrom(fd, buf, buflen, 0, (struct sockaddr*)inaddr, &addrlen);
	if (pktlen == -1) {
		log_errno(LOG_WARNING, "recvfrom");
		return -1;
	}

	if (addrlen != sizeof(*inaddr)) {
		log_error(LOG_WARNING, "unexpected address length %u instead of %u", addrlen, sizeof(*inaddr));
		return -1;
	}

	if (pktlen >= buflen) {
		char buf[INET6_ADDRSTRLEN];
		const char *addr = inet_ntop(inaddr->sin_family, &inaddr->sin_addr, buf, sizeof(buf));
		log_error(LOG_WARNING, "wow! Truncated udp packet of size %u from %s:%u! impossible! dropping it...",
		          pktlen, addr ? addr : "?", ntohs(inaddr->sin_port));
		return -1;
	}

	return pktlen;
}

/***********************************************************************
 * Logic
 */
static void redudp_drop_client(redudp_client *client)
{
	int fd;
	redudp_log_error(client, LOG_INFO, "Dropping...");
	enqueued_packet *q, *tmp;
	if (event_initialized(&client->timeout)) {
		if (event_del(&client->timeout) == -1)
			redudp_log_errno(client, LOG_ERR, "event_del");
	}
	if (client->relay) {
		fd = EVENT_FD(&client->relay->ev_read);
		bufferevent_free(client->relay);
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
	if (event_initialized(&client->udprelay)) {
		fd = EVENT_FD(&client->udprelay);
		if (event_del(&client->udprelay) == -1)
			redudp_log_errno(client, LOG_ERR, "event_del");
		close(fd);
	}
	list_for_each_entry_safe(q, tmp, &client->queue, list) {
		list_del(&q->list);
		free(q);
	}
	list_del(&client->list);
	free(client);
}

static void redudp_bump_timeout(redudp_client *client)
{
	struct timeval tv;
	tv.tv_sec = client->instance->config.udp_timeout;
	tv.tv_usec = 0;
	// TODO: implement udp_timeout_stream
	if (event_add(&client->timeout, &tv) != 0) {
		redudp_log_error(client, LOG_WARNING, "event_add(&client->timeout, ...)");
		redudp_drop_client(client);
	}
}

static void redudp_forward_pkt(redudp_client *client, char *buf, size_t pktlen)
{
	socks5_udp_preabmle req;
	struct msghdr msg;
	struct iovec io[2];
	ssize_t outgoing, fwdlen = pktlen + sizeof(req);

	redudp_fill_preamble(&req, client);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &client->udprelayaddr;
	msg.msg_namelen = sizeof(client->udprelayaddr);
	msg.msg_iov = io;
	msg.msg_iovlen = SIZEOF_ARRAY(io);

	io[0].iov_base = &req;
	io[0].iov_len = sizeof(req);
	io[1].iov_base = buf;
	io[1].iov_len = pktlen;

	outgoing = sendmsg(EVENT_FD(&client->udprelay), &msg, 0);
	if (outgoing == -1) {
		redudp_log_errno(client, LOG_WARNING, "sendmsg: Can't forward packet, dropping it");
		return;
	}
	else if (outgoing != fwdlen) {
		redudp_log_error(client, LOG_WARNING, "sendmsg: I was sending %u bytes, but only %u were sent.", fwdlen, outgoing);
		return;
	}
}

static int redudp_enqeue_pkt(redudp_client *client, char *buf, size_t pktlen)
{
	enqueued_packet *q = NULL;

	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (client->queue_len >= client->instance->config.max_pktqueue) {
		redudp_log_error(client, LOG_WARNING, "There are already %u packets in queue. Dropping.",
		                 client->queue_len);
		return -1;
	}

	q = calloc(1, sizeof(enqueued_packet) + pktlen);
	if (!q) {
		redudp_log_errno(client, LOG_ERR, "Can't enqueue packet: calloc");
		return -1;
	}

	q->len = pktlen;
	memcpy(q->data, buf, pktlen);
	client->queue_len += 1;
	list_add_tail(&q->list, &client->queue);
	return 0;
}

static void redudp_flush_queue(redudp_client *client)
{
	enqueued_packet *q, *tmp;
	redudp_log_error(client, LOG_INFO, "Starting UDP relay");
	list_for_each_entry_safe(q, tmp, &client->queue, list) {
		redudp_forward_pkt(client, q->data, q->len);
		list_del(&q->list);
		free(q);
	}
	client->queue_len = 0;
	assert(list_empty(&client->queue));
}

static void redudp_read_assoc_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	redudp_expected_assoc_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int fd = -1;
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %u",
		                 read, sizeof(reply));
		goto fail;
	}

	if (reply.h.ver != socks5_ver) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected reply version: %u", reply.h.ver);
		goto fail;
	}

	if (reply.h.status != socks5_status_succeeded) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server status: \"%s\" (%i)",
				socks5_status_to_str(reply.h.status), reply.h.status);
		goto fail;
	}

	if (reply.h.addrtype != socks5_addrtype_ipv4) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected address type for UDP dgram destination: %u",
		                 reply.h.addrtype);
		goto fail;
	}

	client->udprelayaddr.sin_family = AF_INET;
	client->udprelayaddr.sin_port = reply.ip.port;
	client->udprelayaddr.sin_addr.s_addr = reply.ip.addr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		redudp_log_errno(client, LOG_ERR, "socket");
		goto fail;
	}

	error = connect(fd, (struct sockaddr*)&client->udprelayaddr, sizeof(client->udprelayaddr));
	if (error) {
		redudp_log_errno(client, LOG_NOTICE, "connect");
		goto fail;
	}

	event_set(&client->udprelay, fd, EV_READ | EV_PERSIST, redudp_pkt_from_socks, client);
	error = event_add(&client->udprelay, NULL);
	if (error) {
		redudp_log_errno(client, LOG_ERR, "event_add");
		goto fail;
	}

	redudp_flush_queue(client);
	// TODO: bufferevent_disable ?

	return;

fail:
	if (fd != -1)
		close(fd);
	redudp_drop_client(client);
}

static void redudp_read_auth_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_auth_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %u",
		                 read, sizeof(reply));
		goto fail;
	}

	if (reply.ver != socks5_password_ver || reply.status != socks5_password_passed) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 authentication error. Version: %u, error code: %u",
		                 reply.ver, reply.status);
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
			sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
	if (error)
		goto fail;

	client->relay->readcb = redudp_read_assoc_reply;

	return;

fail:
	redudp_drop_client(client);
}

static void redudp_read_auth_methods(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	socks5_method_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	const char *error = NULL;
	int ierror = 0;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %u",
		                 read, sizeof(reply));
		goto fail;
	}

	error = socks5_is_known_auth_method(&reply, do_password);
	if (error) {
		redudp_log_error(client, LOG_NOTICE, "socks5_is_known_auth_method: %s", error);
		goto fail;
	}
	else if (reply.method == socks5_auth_none) {
		ierror = redsocks_write_helper_ex_plain(
				client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
				sizeof(redudp_expected_assoc_reply), sizeof(redudp_expected_assoc_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_assoc_reply;
	}
	else if (reply.method == socks5_auth_password) {
		ierror = redsocks_write_helper_ex_plain(
				client->relay, NULL, socks5_mkpassword_plain_wrapper, client->instance, 0, /* last one is ignored */
				sizeof(socks5_auth_reply), sizeof(socks5_auth_reply));
		if (ierror)
			goto fail;

		client->relay->readcb = redudp_read_auth_reply;
	}

	return;

fail:
	redudp_drop_client(client);
}

static void redudp_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (!red_is_socket_connected_ok(buffev)) {
		redudp_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			client->relay, NULL, socks5_mkmethods_plain_wrapper, &do_password, 0 /* does not matter */,
			sizeof(socks5_method_reply), sizeof(socks5_method_reply));
	if (error)
		goto fail;

	client->relay->readcb = redudp_read_auth_methods;
	client->relay->writecb = 0;
	//bufferevent_disable(buffev, EV_WRITE); // I don't want to check for writeability.
	return;

fail:
	redudp_drop_client(client);
}

static void redudp_relay_error(struct bufferevent *buffev, short what, void *_arg)
{
	redudp_client *client = _arg;
	// TODO: FIXME: Implement me
	redudp_log_error(client, LOG_NOTICE, "redudp_relay_error");
	redudp_drop_client(client);
}

static void redudp_timeout(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	redudp_log_error(client, LOG_INFO, "Client timeout. First: %u, last_client: %u, last_relay: %u.",
	                 client->first_event, client->last_client_event, client->last_relay_event);
	redudp_drop_client(client);
}

static void redudp_first_pkt_from_client(redudp_instance *self, struct sockaddr_in *clientaddr, char *buf, size_t pktlen)
{
	redudp_client *client = calloc(1, sizeof(*client));

	if (!client) {
		log_errno(LOG_WARNING, "calloc");
		return;
	}

	INIT_LIST_HEAD(&client->list);
	INIT_LIST_HEAD(&client->queue);
	client->instance = self;
	memcpy(&client->clientaddr, clientaddr, sizeof(*clientaddr));
	timeout_set(&client->timeout, redudp_timeout, client);
	// XXX: self->relay_ss->init(client);

	client->relay = red_connect_relay(&client->instance->config.relayaddr,
	                                  redudp_relay_connected, redudp_relay_error, client);
	if (!client->relay)
		goto fail;

	if (redsocks_time(&client->first_event) == (time_t)-1)
		goto fail;
	client->last_client_event = client->first_event;
	redudp_bump_timeout(client);

	if (redudp_enqeue_pkt(client, buf, pktlen) == -1)
		goto fail;

	list_add(&client->list, &self->clients);
	redudp_log_error(client, LOG_INFO, "got 1st packet from client");
	return;

fail:
	redudp_drop_client(client);
}

static void redudp_pkt_from_socks(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	union {
		char buf[0xFFFF];
		socks5_udp_preabmle header;
	} pkt;
	ssize_t pktlen, fwdlen, outgoing;
	struct sockaddr_in udprelayaddr;

	assert(fd == EVENT_FD(&client->udprelay));

	pktlen = recv_udp_pkt(fd, pkt.buf, sizeof(pkt.buf), &udprelayaddr);
	if (pktlen == -1) {
		redudp_log_errno(client, LOG_WARNING, "recv_udp_pkt");
		return;
	}

	if (memcmp(&udprelayaddr, &client->udprelayaddr, sizeof(udprelayaddr)) != 0) {
		char buf[INET6_ADDRSTRLEN];
		const char *addr = inet_ntop(udprelayaddr.sin_family, &udprelayaddr.sin_addr, buf, sizeof(buf));
		redudp_log_error(client, LOG_NOTICE, "Got packet from unexpected address %s:%u.",
		                 addr ? addr : "?", ntohs(udprelayaddr.sin_port));
		return;
	}

	if (pkt.header.frag_no != 0) {
		// FIXME: does anybody need it?
		redudp_log_error(client, LOG_WARNING, "Got fragment #%u. Packet fragmentation is not supported!",
		                 pkt.header.frag_no);
		return;
	}

	if (pkt.header.addrtype != socks5_addrtype_ipv4) {
		redudp_log_error(client, LOG_NOTICE, "Got address type #%u instead of expected #%u (IPv4).",
		                 pkt.header.addrtype, socks5_addrtype_ipv4);
		return;
	}

	if (pkt.header.ip.port != client->instance->config.destaddr.sin_port ||
	    pkt.header.ip.addr != client->instance->config.destaddr.sin_addr.s_addr)
	{
		char buf[INET6_ADDRSTRLEN];
		const char *addr = inet_ntop(AF_INET, &pkt.header.ip.addr, buf, sizeof(buf));
		redudp_log_error(client, LOG_NOTICE, "Socks5 server relayed packet from unexpected address %s:%u.",
		                 addr ? addr : "?", ntohs(pkt.header.ip.port));
		return;
	}

	redsocks_time(&client->last_relay_event);
	redudp_bump_timeout(client);

	fwdlen = pktlen - sizeof(pkt.header);
	outgoing = sendto(EVENT_FD(&client->instance->listener),
	                  pkt.buf + sizeof(pkt.header), fwdlen, 0,
	                  (struct sockaddr*)&client->clientaddr, sizeof(client->clientaddr));
	if (outgoing != fwdlen) {
		redudp_log_error(client, LOG_WARNING, "sendto: I was sending %d bytes, but only %d were sent.",
		                 fwdlen, outgoing);
		return;
	}
}

static void redudp_pkt_from_client(int fd, short what, void *_arg)
{
	redudp_instance *self = _arg;
	struct sockaddr_in clientaddr;
	char buf[0xFFFF]; // UDP packet can't be larger then that
	ssize_t pktlen;
	redudp_client *tmp, *client = NULL;

	assert(fd == EVENT_FD(&self->listener));
	pktlen = recv_udp_pkt(fd, buf, sizeof(buf), &clientaddr);
	if (pktlen == -1) {
		return;
	}

	// TODO: this lookup may be SLOOOOOW.
	list_for_each_entry(tmp, &self->clients, list) {
		if (0 == memcmp(&clientaddr, &tmp->clientaddr, sizeof(clientaddr))) {
			client = tmp;
			break;
		}
	}

	if (client) {
		redsocks_time(&client->last_client_event);
		redudp_bump_timeout(client);
		if (event_initialized(&client->udprelay)) {
			redudp_forward_pkt(client, buf, pktlen);
		}
		else {
			redudp_enqeue_pkt(client, buf, pktlen);
		}
	}
	else {
		redudp_first_pkt_from_client(self, &clientaddr, buf, pktlen);
	}
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry redudp_entries[] =
{
	{ .key = "local_ip",   .type = pt_in_addr },
	{ .key = "local_port", .type = pt_uint16 },
	{ .key = "ip",         .type = pt_in_addr },
	{ .key = "port",       .type = pt_uint16 },
	{ .key = "login",      .type = pt_pchar },
	{ .key = "password",   .type = pt_pchar },
	{ .key = "dest_ip",    .type = pt_in_addr },
	{ .key = "dest_port",  .type = pt_uint16 },
	{ .key = "udp_timeout", .type = pt_uint16 },
	{ .key = "udp_timeout_stream", .type = pt_uint16 },
	{ }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int redudp_onenter(parser_section *section)
{
	redudp_instance *instance = calloc(1, sizeof(*instance));
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
	instance->config.destaddr.sin_family = AF_INET;
	instance->config.destaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.max_pktqueue = 5;
	instance->config.udp_timeout = 30;
	instance->config.udp_timeout_stream = 180;

	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr =
			(strcmp(entry->key, "local_ip") == 0)   ? &instance->config.bindaddr.sin_addr :
			(strcmp(entry->key, "local_port") == 0) ? &instance->config.bindaddr.sin_port :
			(strcmp(entry->key, "ip") == 0)         ? &instance->config.relayaddr.sin_addr :
			(strcmp(entry->key, "port") == 0)       ? &instance->config.relayaddr.sin_port :
			(strcmp(entry->key, "login") == 0)      ? &instance->config.login :
			(strcmp(entry->key, "password") == 0)   ? &instance->config.password :
			(strcmp(entry->key, "dest_ip") == 0)    ? &instance->config.destaddr.sin_addr :
			(strcmp(entry->key, "dest_port") == 0)  ? &instance->config.destaddr.sin_port :
			(strcmp(entry->key, "max_pktqueue") == 0) ? &instance->config.max_pktqueue :
			(strcmp(entry->key, "udp_timeout") == 0) ? &instance->config.udp_timeout:
			(strcmp(entry->key, "udp_timeout_stream") == 0) ? &instance->config.udp_timeout_stream :
			NULL;
	section->data = instance;
	return 0;
}

static int redudp_onexit(parser_section *section)
{
	redudp_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);
	instance->config.destaddr.sin_port = htons(instance->config.destaddr.sin_port);

	if (instance->config.udp_timeout_stream < instance->config.udp_timeout) {
		parser_error(section->context, "udp_timeout_stream should be not less then udp_timeout");
		return -1;
	}

	list_add(&instance->list, &instances);

	return 0;
}

static int redudp_init_instance(redudp_instance *instance)
{
	/* FIXME: redudp_fini_instance is called in case of failure, this
	 *        function will remove instance from instances list - result
	 *        looks ugly.
	 */
	int error;
	int fd = -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		log_errno(LOG_ERR, "socket");
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

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redudp_pkt_from_client, instance);
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}
	fd = -1;

	return 0;

fail:
	redudp_fini_instance(instance);

	if (fd != -1) {
		if (close(fd) != 0)
			log_errno(LOG_WARNING, "close");
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void redudp_fini_instance(redudp_instance *instance)
{
	if (!list_empty(&instance->clients)) {
		redudp_client *tmp, *client = NULL;

		log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
		list_for_each_entry_safe(client, tmp, &instance->clients, list) {
			redudp_drop_client(client);
		}
	}

	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		if (close(EVENT_FD(&instance->listener)) != 0)
			log_errno(LOG_WARNING, "close");
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	free(instance->config.login);
	free(instance->config.password);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int redudp_init()
{
	redudp_instance *tmp, *instance = NULL;

	// TODO: init debug_dumper

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (redudp_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	redudp_fini();
	return -1;
}

static int redudp_fini()
{
	redudp_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		redudp_fini_instance(instance);

	return 0;
}

static parser_section redudp_conf_section =
{
	.name    = "redudp",
	.entries = redudp_entries,
	.onenter = redudp_onenter,
	.onexit  = redudp_onexit
};

app_subsys redudp_subsys =
{
	.init = redudp_init,
	.fini = redudp_fini,
	.conf_section = &redudp_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
