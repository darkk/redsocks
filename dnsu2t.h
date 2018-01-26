#ifndef DNSU2T_H
#define DNSU2T_H

#include "utils.h"

typedef struct dnsu2t_config_t {
	struct sockaddr_in bindaddr;
	struct sockaddr_in relayaddr;
	uint16_t           relay_timeout;
	uint16_t           inflight_max;
} dnsu2t_config;

typedef struct dns_header_t {
	uint16_t id;
	uint8_t qr_opcode_aa_tc_rd;
	uint8_t ra_z_rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount; // may be >0 for EDNS queries
} PACKED dns_header;

#define DNS_QR 0x80
#define DNS_TC 0x02
#define DNS_Z  0x70

typedef struct dns_tcp_pkt_t {
	uint16_t sz;
	union {
		dns_header hdr;
		char raw[0xffff];
	} dns;
} PACKED dns_tcp_pkt;

typedef struct dnsu2t_instance_t {
	list_head          list;
	dnsu2t_config      config;
	struct event       listener;

	struct event       relay_rd;
	struct event       relay_wr;

	bool               reqstream_broken;
	int                request_count;
	int                inflight_count;
	void*              inflight_root;

	ssize_t            pkt_size;
	dns_tcp_pkt        pkt;
} dnsu2t_instance;

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* DNSU2T_H */
