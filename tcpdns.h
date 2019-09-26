#ifndef TCPDNS_H
#define TCPDNS_H

typedef struct tcpdns_config_t {
	struct sockaddr_storage bindaddr;
	struct sockaddr_storage tcpdns1_addr;
	struct sockaddr_storage tcpdns2_addr;
	char *bind;
	char *tcpdns1;
	char *tcpdns2;
	uint16_t timeout; /* timeout value for DNS response*/
} tcpdns_config;

typedef struct tcpdns_instance_t {
	list_head       list;
	tcpdns_config   config;
	struct event *  listener;
	list_head       requests;
    // Data for DNS resolver status tracking/checking
    int             udp1_delay_ms;
    int             udp2_delay_ms;
    int             tcp1_delay_ms;
    int             tcp2_delay_ms;
} tcpdns_instance;


typedef struct dns_header_t {
	uint16_t id;
	uint8_t qr_opcode_aa_tc_rd;
	uint8_t ra_z_rcode;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} PACKED dns_header;


typedef struct dns_request_t {
    list_head           list;
    tcpdns_instance *   instance;
    short               state;
    int                 flags;
    struct bufferevent* resolver;
    struct sockaddr_storage  client_addr;
    struct timeval      req_time; 
    int *               delay;
    size_t              data_len;
    union {
        char            raw[513]; // DNS request longer than 512 should go over TCP.
        dns_header header;
    } data;
} dns_request;

#endif /* TCPDNS_H */
