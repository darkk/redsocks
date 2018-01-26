/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2018 Leonid Evdokimov <leon@darkk.net.ru>
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
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <search.h>
#include <errno.h>

#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "dnsu2t.h"
#include "utils.h"

#define dnsu2t_log_error(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &clientaddr, &self->config.bindaddr, prio, ## msg)
#define dnsu2t_log_errno(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &clientaddr, &self->config.bindaddr, prio, ## msg)

static void dnsu2t_fini_instance(dnsu2t_instance *instance);
static int dnsu2t_fini();
static void dnsu2t_pkt_from_client(int fd, short what, void *_arg);
static void dnsu2t_pkt_from_relay(int fd, short what, void *_arg);
static void dnsu2t_relay_writable(int fd, short what, void *_arg);
static void dnsu2t_close_relay(dnsu2t_instance *self);

// this DNS query (IN SOA for `.`) acts as in-band DNS ping
static const uint8_t dnsq_soa_root[] = {
	0x00, 0x00, 0x01, 0x20,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x06, 0x00, 0x01};

typedef struct inflight_req_t {
	uint16_t id; // in network byte order
	struct sockaddr_in clientaddr;

} inflight_req;

static int inflight_cmp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(uint16_t));
}

/***********************************************************************
 * Logic
 */
static void dnsu2t_pkt_from_client(int srvfd, short what, void *_arg)
{
	dnsu2t_instance *self = _arg;
	struct sockaddr_in clientaddr;
	ssize_t pktlen;
	dns_tcp_pkt in;

	assert(srvfd == event_get_fd(&self->listener));
	pktlen = red_recv_udp_pkt(srvfd, in.dns.raw, sizeof(in.dns.raw), &clientaddr, NULL);
	if (pktlen == -1)
		return;

	if (pktlen <= sizeof(dns_header)) {
		dnsu2t_log_error(LOG_NOTICE, "incomplete DNS request");
		return;
	}

	if (pktlen > 0xffff
		|| (in.dns.hdr.qr_opcode_aa_tc_rd & DNS_QR) != 0 /* not a query */
		|| in.dns.hdr.qdcount == 0 /* no questions */
		|| in.dns.hdr.ancount || in.dns.hdr.nscount /* some answers */
	) {
		dnsu2t_log_error(LOG_NOTICE, "malformed DNS request");
		return;
	}

	inflight_req **preq = tfind(&in.dns.hdr.id, &self->inflight_root, inflight_cmp);
	if (preq) {
		// Technically, it's possible to re-number request and maintain matching
		// for up to 65535 in-flight requests, but I'm a bit lazy for that.
		assert((*preq)->id == in.dns.hdr.id);
		if (memcmp(&(*preq)->clientaddr, &clientaddr, sizeof(clientaddr)) != 0) {
			// that's not just re-transmission
			char other_addr[RED_INET_ADDRSTRLEN];
			dnsu2t_log_error(LOG_WARNING, "DNS request #%04x already in-flight from %s, renumbering not implemented",
					ntohs(in.dns.hdr.id),
					red_inet_ntop(&(*preq)->clientaddr, other_addr, sizeof(other_addr)));
		}
		return;
	}

	in.sz = htons((uint16_t)pktlen);
	pktlen += sizeof(in.sz);

	int fd = -1;
	inflight_req *node = calloc(1, sizeof(inflight_req));
	node->id = in.dns.hdr.id;
	node->clientaddr = clientaddr;

	int sent;
	if (!event_initialized(&self->relay_rd)) {
		fd = red_socket_client(SOCK_STREAM);
		if (fd < 0)
			goto fail;

		event_set(&self->relay_rd, fd, EV_READ | EV_PERSIST, dnsu2t_pkt_from_relay, self);
		event_set(&self->relay_wr, fd, EV_WRITE, dnsu2t_relay_writable, self);
		fd = -1;

		// The timeout on a persistent event resets whenever the event's callback runs.
		const struct timeval relay_timeout = { .tv_sec = self->config.relay_timeout };
		if (event_add(&self->relay_rd, &relay_timeout) != 0) {
			dnsu2t_log_error(LOG_ERR, "event_add");
			goto fail;
		}
		if (event_add(&self->relay_wr, &relay_timeout) != 0) {
			dnsu2t_log_error(LOG_ERR, "event_add");
			goto fail;
		}

		// MSG_FASTOPEN is available since Linux 3.6 released on 30 Sep 2012
		sent = sendto(event_get_fd(&self->relay_rd), &in, pktlen, MSG_FASTOPEN,
			(struct sockaddr*)&self->config.relayaddr, sizeof(self->config.relayaddr));
		// Also, socket is not writable, right after MSG_FASTOPEN, so listener
		// should be temporary disabled.
		if (event_del(&self->listener))
			dnsu2t_log_error(LOG_ERR, "event_del");
	} else {
		sent = write(event_get_fd(&self->relay_rd), &in, pktlen);
	}

	if (sent == pktlen || (sent == -1 && errno == EINPROGRESS)) {
		self->request_count++;
		self->inflight_count++;
		if (self->inflight_count >= self->config.inflight_max) {
			if (event_del(&self->listener))
				dnsu2t_log_error(LOG_ERR, "event_del");
		}
		inflight_req **new = tsearch(node, &self->inflight_root, inflight_cmp);
		if (!new)
			abort(); // ultimate ENOMEM handler
		assert(*new == node); // WAT?
		node = NULL;
		dnsu2t_log_error(LOG_DEBUG, "DNS request #%04x", ntohs(in.dns.hdr.id));

	}
	else if (sent == -1) {
		dnsu2t_log_errno(LOG_DEBUG, "DNS request #%04x write()", ntohs(in.dns.hdr.id));
		goto fail;
	}
	else if (sent != pktlen) {
		dnsu2t_log_error(LOG_WARNING, "short write is not handled");
		if (shutdown(fd, SHUT_WR) != 0)
			dnsu2t_log_error(LOG_ERR, "shutdown");
		// no more writes to broken stream, but that's not fatal failure
		if (event_del(&self->listener))
			dnsu2t_log_error(LOG_ERR, "event_del");
		self->reqstream_broken = true;
	}

	return;

fail:
	if (fd != -1)
		redsocks_close(fd);
	if (node)
		free(node);
	dnsu2t_close_relay(self);
}

static void free_inflight_req(void *p)
{
	inflight_req *preq = p;
	free(preq);
}

static void dnsu2t_close_relay(dnsu2t_instance *self)
{
	if (event_initialized(&self->relay_rd)) {
		int fd = event_get_fd(&self->relay_rd);
		assert(fd == event_get_fd(&self->relay_wr));
		if (event_del(&self->relay_rd) == -1)
			log_error(LOG_ERR, "event_del");
		if (event_del(&self->relay_wr) == -1)
			log_error(LOG_ERR, "event_del");
		redsocks_close(fd);
		memset(&self->relay_rd, 0, sizeof(self->relay_rd));
		memset(&self->relay_wr, 0, sizeof(self->relay_wr));

		// possibly `listener` is temporary disabled and we're in connection
		// cleanup code path, so let's enable it back
		if (!event_pending(&self->listener, EV_READ, NULL)) {
			if (event_add(&self->listener, NULL) != 0) {
				log_error(LOG_ERR, "event_del");
			}
		}
	}
	if (self->inflight_count) {
		log_error(LOG_WARNING, "%d in-flight DNS request lost (%d served)", self->inflight_count, self->request_count - self->inflight_count);
	}
	tdestroy(self->inflight_root, free_inflight_req);
	self->inflight_root = NULL; // WTF?
	self->inflight_count = 0;
	self->request_count = 0;
	self->reqstream_broken = false;
	// assert(!!self->inflight_count == !!self->inflight_root);
}

void dnsu2t_relay_writable(int fd, short what, void *_arg)
{
	dnsu2t_instance *self = _arg;
	assert(event_get_fd(&self->relay_wr) == fd);
	if ((what & EV_WRITE) && self->inflight_count < self->config.inflight_max && !self->reqstream_broken) {
		if (event_add(&self->listener, NULL) != 0)
			log_errno(LOG_ERR, "event_add");
	}
}

void dnsu2t_pkt_from_relay(int fd, short what, void *_arg)
{
	dnsu2t_instance *self = _arg;
	assert(event_get_fd(&self->relay_rd) == fd);

	if (what & EV_READ) {
		char* dst = ((char*)&self->pkt) + self->pkt_size;
		if (self->pkt_size)
			log_error(LOG_DEBUG, "partial packet, off=%lu", self->pkt_size);
		const size_t bufsz = sizeof(self->pkt) - self->pkt_size;
		assert(bufsz > 0 && self->pkt_size >= 0);
		ssize_t rcvd = recv(fd, dst, bufsz, 0);
		if (rcvd > 0) {
			self->pkt_size += rcvd;
			while (self->pkt_size >= sizeof(self->pkt.sz)) {
				const ssize_t pktlen = ntohs(self->pkt.sz);
				const ssize_t tcplen = pktlen + sizeof(self->pkt.sz);
				if (pktlen <= sizeof(dns_header)) {
					log_error(LOG_NOTICE, "malformed DNS reply");
					dnsu2t_close_relay(self);
					break;
				}
				else if (self->pkt_size >= tcplen) {
					inflight_req **preq = tfind(&self->pkt.dns.hdr.id, &self->inflight_root, inflight_cmp);
					if (preq) {
						inflight_req *req = *preq;
						assert(self->pkt.dns.hdr.id == req->id);
						log_error(LOG_DEBUG, "DNS reply #%04x", ntohs(self->pkt.dns.hdr.id));
						int sent = sendto(event_get_fd(&self->listener),
							&self->pkt.dns, pktlen, 0,
							(struct sockaddr*)&req->clientaddr, sizeof(req->clientaddr));
						if (sent == -1) {
							log_errno(LOG_WARNING, "sendto");
						}
						else if (sent != pktlen) {
							log_errno(LOG_WARNING, "short sendto");
						}
						self->inflight_count--;
						if (self->inflight_count < self->config.inflight_max && !self->reqstream_broken) {
							if (event_add(&self->listener, NULL))
								log_error(LOG_ERR, "event_del");
						}
						inflight_req* parent = tdelete(req, &self->inflight_root, inflight_cmp);
						assert(parent);
						free(req);
					} else {
						log_error(LOG_NOTICE, "DNS reply #%04x unexpected",
								ntohs(self->pkt.dns.hdr.id));
					}
					if (self->pkt_size == tcplen) {
						self->pkt_size = 0;
					} else {
						char* src = ((char*)&self->pkt) + tcplen;
						self->pkt_size -= tcplen;
						memmove(&self->pkt, src, self->pkt_size);
					}
				} else {
					break; // nothing to consume so far
				}
			}
		}
		else if (rcvd == 0) {
			log_error(LOG_DEBUG, "EOF from DNS server");
			dnsu2t_close_relay(self);
		}
		else {
			log_errno(LOG_DEBUG, "recv");
			dnsu2t_close_relay(self);
		}
	}
	if (what & EV_TIMEOUT) {
		log_error(LOG_DEBUG, "TIMEOUT from DNS server");
		dnsu2t_close_relay(self);
	}
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry dnsu2t_entries[] =
{
	{ .key = "local_ip",        .type = pt_in_addr },
	{ .key = "local_port",      .type = pt_uint16 },
	{ .key = "remote_ip",       .type = pt_in_addr },
	{ .key = "remote_port",     .type = pt_uint16 },
	{ .key = "remote_timeout",  .type = pt_uint16 },
	{ .key = "inflight_max",    .type = pt_uint16 },
	{ }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int dnsu2t_onenter(parser_section *section)
{
	dnsu2t_instance *instance = calloc(1, sizeof(*instance));
	if (!instance) {
		parser_error(section->context, "Not enough memory");
		return -1;
	}

	INIT_LIST_HEAD(&instance->list);
	instance->config.bindaddr.sin_family = AF_INET;
	instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	instance->config.bindaddr.sin_port = htons(53);;
	instance->config.relayaddr.sin_family = AF_INET;
	instance->config.relayaddr.sin_port = htons(53);
	instance->config.relay_timeout = 30;
	instance->config.inflight_max = 16;

	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr =
			(strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
			(strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
			(strcmp(entry->key, "remote_ip") == 0)  ? (void*)&instance->config.relayaddr.sin_addr :
			(strcmp(entry->key, "remote_port") == 0)? (void*)&instance->config.relayaddr.sin_port :
			(strcmp(entry->key, "remote_timeout") == 0)? (void*)&instance->config.relay_timeout:
			(strcmp(entry->key, "inflight_max") == 0)? (void*)&instance->config.inflight_max :
			NULL;
	section->data = instance;
	return 0;
}

static int dnsu2t_onexit(parser_section *section)
{
	dnsu2t_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
	instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);

	list_add(&instance->list, &instances);

	return 0;
}

static int dnsu2t_init_instance(dnsu2t_instance *instance)
{
	int error;
	int fd = red_socket_server(SOCK_DGRAM, &instance->config.bindaddr);

	if (fd == -1) {
		goto fail;
	}

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, dnsu2t_pkt_from_client, instance);
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}

	return 0;

fail:
	dnsu2t_fini_instance(instance);

	if (fd != -1) {
		if (close(fd) != 0)
			log_errno(LOG_WARNING, "close");
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void dnsu2t_fini_instance(dnsu2t_instance *instance)
{
	dnsu2t_close_relay(instance);

	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		if (close(event_get_fd(&instance->listener)) != 0)
			log_errno(LOG_WARNING, "close");
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int dnsu2t_init()
{
	dnsu2t_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (dnsu2t_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	dnsu2t_fini();
	return -1;
}

static int dnsu2t_fini()
{
	dnsu2t_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		dnsu2t_fini_instance(instance);

	return 0;
}

static parser_section dnsu2t_conf_section =
{
	.name    = "dnsu2t",
	.entries = dnsu2t_entries,
	.onenter = dnsu2t_onenter,
	.onexit  = dnsu2t_onexit
};

app_subsys dnsu2t_subsys =
{
	.init = dnsu2t_init,
	.fini = dnsu2t_fini,
	.conf_section = &dnsu2t_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
