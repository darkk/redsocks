#ifndef REDUDP_H
#define REDUDP_H

#include <event.h>
#include "list.h"

struct redudp_client_t;
struct redudp_instance_t;

typedef struct udprelay_subsys_t {
	char   *name;
	size_t  payload_len; // size of relay-specific data in client section
	size_t  instance_payload_len; // size of relay-specify data in instance section
	void       (*init)(struct redudp_client_t *client);
	void       (*fini)(struct redudp_client_t *client);
	int        (*instance_init)(struct redudp_instance_t *instance);
	void       (*instance_fini)(struct redudp_instance_t *instance);
	// connect_relay (if any) is called instead of redudp_connect_relay after client connection acceptance
	void       (*connect_relay)(struct redudp_client_t *client);
	//void       (*relay_connected)(struct redudp_client_t *client);
	void       (*forward_pkt)(struct redudp_client_t *client, struct sockaddr * destaddr, void * data, size_t len);
	int	       (*ready_to_fwd)(struct redudp_client_t *client);
} udprelay_subsys;


typedef struct redudp_config_t {
	struct sockaddr_in bindaddr;
	struct sockaddr_in relayaddr;
	// TODO:           outgoingaddr;
	struct sockaddr_in destaddr;
	char *type;
	char *login;
	char *password;
	uint16_t max_pktqueue;
	uint16_t udp_timeout;
	uint16_t udp_timeout_stream;
} redudp_config;

typedef struct redudp_instance_t {
	list_head       list;
	redudp_config   config;
	struct event    listener;
	list_head       clients;
	udprelay_subsys   *relay_ss;
} redudp_instance;

typedef struct redudp_client_t {
	list_head           list;
	redudp_instance    *instance;
	struct sockaddr_in  clientaddr;
	struct sockaddr_in  destaddr;
	struct event        timeout;
	int                 state;         // it's used by bottom layer
	time_t              first_event;
	time_t              last_client_event;
	time_t              last_relay_event;
	unsigned int        queue_len;
	list_head           queue;
} redudp_client;

typedef struct enqueued_packet_t {
	list_head  list;
	struct sockaddr_in destaddr;
	size_t     len;
	char       data[1];
} enqueued_packet;

struct sockaddr_in* get_destaddr(redudp_client *client);
void redudp_drop_client(redudp_client *client);
void redudp_flush_queue(redudp_client *client);
void redudp_fwd_pkt_to_sender(redudp_client *client, void *buf, size_t len, struct sockaddr_in * srcaddr);
void redudp_bump_timeout(redudp_client *client);

#define redudp_log_error(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &(client)->clientaddr, get_destaddr(client), prio, ## msg)
#define redudp_log_errno(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &(client)->clientaddr, get_destaddr(client), prio, ## msg)

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* REDUDP_H */
