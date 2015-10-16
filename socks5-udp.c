/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2015 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
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
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include "main.h"
#include "utils.h"
#include "log.h"
#include "redudp.h"
#include "redsocks.h"
#include "socks5.h"

typedef struct socks5_expected_assoc_reply_t {
	socks5_reply h;
	socks5_addr_ipv4 ip;
} PACKED socks5_expected_assoc_reply;

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
	//p = p; /* Make compiler happy */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	return socks5_mkcommand_plain(socks5_cmd_udp_associate, &sa);
}

static void socks5_fill_preamble(socks5_udp_preabmle *preamble, struct sockaddr_in * addr)
{
	preamble->reserved = 0;
	preamble->frag_no = 0; /* fragmentation is not supported */
	preamble->addrtype = socks5_addrtype_ipv4;
	preamble->ip.addr = addr->sin_addr.s_addr;
	preamble->ip.port = addr->sin_port;
}



/**************************************************************************
 * Logic
 * */

typedef struct socks5_client_t {
	struct event        udprelay;
	struct sockaddr_in  udprelayaddr;
	struct bufferevent *relay;
	int ready_fwd;
} socks5_client;

static void socks5_client_init(redudp_client *client)
{
	socks5_client *socks5client = (void*)(client + 1);
	memset(socks5client, 0, sizeof(socks5_client));
}

static void socks5_client_fini(redudp_client *client)
{
	socks5_client *socks5client = (void*)(client + 1);
	int fd;

	if (event_initialized(&socks5client->udprelay)) {
		fd = EVENT_FD(&socks5client->udprelay);
		if (event_del(&socks5client->udprelay) == -1)
			redudp_log_errno(client, LOG_ERR, "event_del");
		close(fd);
	}
    if (socks5client->relay) {
        fd = EVENT_FD(&socks5client->relay->ev_read);
        bufferevent_free(socks5client->relay);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

static int socks5_ready_to_fwd(struct redudp_client_t *client)
{
	socks5_client *socks5client = (void*)(client + 1);
	return socks5client->ready_fwd; 
}

static void socks5_forward_pkt(redudp_client *client, struct sockaddr *destaddr, void *buf, size_t pktlen)
{
	socks5_client *socks5client = (void*)(client + 1);
	socks5_udp_preabmle req;
	struct msghdr msg;
	struct iovec io[2];
	ssize_t outgoing, fwdlen = pktlen + sizeof(req);

	socks5_fill_preamble(&req, (struct sockaddr_in *)destaddr);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &socks5client->udprelayaddr;
	msg.msg_namelen = sizeof(socks5client->udprelayaddr);
	msg.msg_iov = io;
	msg.msg_iovlen = SIZEOF_ARRAY(io);

	io[0].iov_base = &req;
	io[0].iov_len = sizeof(req);
	io[1].iov_base = buf;
	io[1].iov_len = pktlen;

	outgoing = sendmsg(EVENT_FD(&socks5client->udprelay), &msg, 0);
	if (outgoing == -1) {
		redudp_log_errno(client, LOG_WARNING, "sendmsg: Can't forward packet, dropping it");
		return;
	}
	else if (outgoing != fwdlen) {
		redudp_log_error(client, LOG_WARNING, "sendmsg: I was sending %zd bytes, but only %zd were sent.", fwdlen, outgoing);
		return;
	}
}

static void socks5_pkt_from_socks(int fd, short what, void *_arg)
{
	redudp_client *client = _arg;
	socks5_client *socks5client = (void*)(client + 1);
	union {
		char buf[0xFFFF];
		socks5_udp_preabmle header;
	} pkt;
	ssize_t pktlen, fwdlen;
	struct sockaddr_in udprelayaddr;

	assert(fd == EVENT_FD(&socks5client->udprelay));

	pktlen = red_recv_udp_pkt(fd, pkt.buf, sizeof(pkt.buf), &udprelayaddr, NULL);
	if (pktlen == -1)
		return;

	if (memcmp(&udprelayaddr, &socks5client->udprelayaddr, sizeof(udprelayaddr)) != 0) {
		char buf[RED_INET_ADDRSTRLEN];
		redudp_log_error(client, LOG_NOTICE, "Got packet from unexpected address %s.",
		                 red_inet_ntop(&udprelayaddr, buf, sizeof(buf)));
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

	struct sockaddr_in pktaddr = {
		.sin_family = AF_INET,
		.sin_addr   = { pkt.header.ip.addr },
		.sin_port   = pkt.header.ip.port,
	};

	fwdlen = pktlen - sizeof(pkt.header);
    redudp_fwd_pkt_to_sender(client, pkt.buf + sizeof(pkt.header), fwdlen, &pktaddr);
}


static void socks5_read_assoc_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_client *socks5client = (void*)(client + 1);
	socks5_expected_assoc_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int fd = -1;
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
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

	socks5client->udprelayaddr.sin_family = AF_INET;
	socks5client->udprelayaddr.sin_port = reply.ip.port;
	socks5client->udprelayaddr.sin_addr.s_addr = reply.ip.addr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		redudp_log_errno(client, LOG_ERR, "socket");
		goto fail;
	}

	error = connect(fd, (struct sockaddr*)&socks5client->udprelayaddr, sizeof(socks5client->udprelayaddr));
	if (error) {
		redudp_log_errno(client, LOG_NOTICE, "connect");
		goto fail;
	}

	event_assign(&socks5client->udprelay, get_event_base(), fd, EV_READ | EV_PERSIST, socks5_pkt_from_socks, client);
	error = event_add(&socks5client->udprelay, NULL);
	if (error) {
		redudp_log_errno(client, LOG_ERR, "event_add");
		goto fail;
	}

	socks5client->ready_fwd = 1;
	redudp_flush_queue(client);
	// TODO: bufferevent_disable ?

	return;

fail:
	if (fd != -1)
		close(fd);
	redudp_drop_client(client);
}

static void socks5_read_auth_reply(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_client *socks5client = (void*)(client + 1);
	socks5_auth_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	int error;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
		                 read, sizeof(reply));
		goto fail;
	}

	if (reply.ver != socks5_password_ver || reply.status != socks5_password_passed) {
		redudp_log_error(client, LOG_NOTICE, "Socks5 authentication error. Version: %u, error code: %u",
		                 reply.ver, reply.status);
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			socks5client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
			sizeof(socks5_expected_assoc_reply), sizeof(socks5_expected_assoc_reply));
	if (error)
		goto fail;

	socks5client->relay->readcb = socks5_read_assoc_reply;

	return;

fail:
	redudp_drop_client(client);
}


static void socks5_read_auth_methods(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_client *socks5client = (void*)(client + 1);
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	socks5_method_reply reply;
	int read = evbuffer_remove(buffev->input, &reply, sizeof(reply));
	const char *error = NULL;
	int ierror = 0;
	redudp_log_error(client, LOG_DEBUG, "<trace>");

	if (read != sizeof(reply)) {
		redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
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
				socks5client->relay, NULL, socks5_mkassociate, NULL, 0, /* last two are ignored */
				sizeof(socks5_expected_assoc_reply), sizeof(socks5_expected_assoc_reply));
		if (ierror)
			goto fail;

		socks5client->relay->readcb = socks5_read_assoc_reply;
	}
	else if (reply.method == socks5_auth_password) {
		ierror = redsocks_write_helper_ex_plain(
				socks5client->relay, NULL, socks5_mkpassword_plain_wrapper, client->instance, 0, /* last one is ignored */
				sizeof(socks5_auth_reply), sizeof(socks5_auth_reply));
		if (ierror)
			goto fail;

		socks5client->relay->readcb = socks5_read_auth_reply;
	}

	return;

fail:
	redudp_drop_client(client);
}

static void socks5_relay_connected(struct bufferevent *buffev, void *_arg)
{
	redudp_client *client = _arg;
	socks5_client *socks5client = (void*)(client + 1);
	int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
	int error;
	char relayaddr_str[RED_INET_ADDRSTRLEN];
	redudp_log_error(client, LOG_DEBUG, "via %s", red_inet_ntop(&client->instance->config.relayaddr, relayaddr_str, sizeof(relayaddr_str)));

	if (!red_is_socket_connected_ok(buffev)) {
		redudp_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
		goto fail;
	}

	error = redsocks_write_helper_ex_plain(
			socks5client->relay, NULL, socks5_mkmethods_plain_wrapper, &do_password, 0 /* does not matter */,
			sizeof(socks5_method_reply), sizeof(socks5_method_reply));
	if (error)
		goto fail;

	socks5client->relay->readcb = socks5_read_auth_methods;
	socks5client->relay->writecb = 0;
	//bufferevent_disable(buffev, EV_WRITE); // I don't want to check for writeability.
	return;

fail:
	redudp_drop_client(client);
}

static void socks5_relay_error(struct bufferevent *buffev, short what, void *_arg)
{
	redudp_client *client = _arg;
	// TODO: FIXME: Implement me
	redudp_log_error(client, LOG_NOTICE, "socks5_relay_error");
	redudp_drop_client(client);
}


static void socks5_connect_relay(redudp_client *client)
{
	socks5_client *socks5client = (void*)(client + 1);
	socks5client->relay = red_connect_relay(&client->instance->config.relayaddr, NULL, 
	                                  socks5_relay_connected, socks5_relay_error, client);
	if (!socks5client->relay)
		redudp_drop_client(client);
}

static int socks5_instance_init(struct redudp_instance_t *instance)
{
    return 0;
}

static void socks5_instance_fini(struct redudp_instance_t *instance)
{
}

udprelay_subsys socks5_udp_subsys =
{
	.name                 = "socks5",
	.payload_len          = sizeof(socks5_client),
	.instance_payload_len = 0,
	.init                 = socks5_client_init,
	.fini                 = socks5_client_fini,
	.instance_init		  = socks5_instance_init,
	.instance_fini		  = socks5_instance_fini,
	.connect_relay		  = socks5_connect_relay,
	.forward_pkt		  = socks5_forward_pkt,
	.ready_to_fwd		  = socks5_ready_to_fwd,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
