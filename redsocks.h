#ifndef REDSOCKS_H_WED_JAN_24_22_17_11_2007
#define REDSOCKS_H_WED_JAN_24_22_17_11_2007
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <event2/event.h>
#include "list.h"


#define DEFAULT_CONNECT_TIMEOUT 10 

struct redsocks_client_t;
struct redsocks_instance_t;

typedef struct relay_subsys_t {
	char   *name;
	size_t  payload_len; // size of relay-specific data in client section
	size_t  instance_payload_len; // size of relay-specify data in instance section
	bufferevent_data_cb readcb;
	bufferevent_data_cb writecb;
	void       (*init)(struct redsocks_client_t *client);
	void       (*fini)(struct redsocks_client_t *client);
	int        (*instance_init)(struct redsocks_instance_t *instance);
	void       (*instance_fini)(struct redsocks_instance_t *instance);
	// connect_relay (if any) is called instead of redsocks_connect_relay after client connection acceptance
	// It must returns 0 on success, returns -1 or error code on failures.
	int        (*connect_relay)(struct redsocks_client_t *client);
	//void       (*relay_connected)(struct redsocks_client_t *client);
} relay_subsys;

typedef struct redsocks_config_t {
	struct sockaddr_storage bindaddr;
	struct sockaddr_storage relayaddr;
	char *bind;
	char *relay;
	char *type;
	char *login;
	char *password;
	uint16_t min_backoff_ms;
	uint16_t max_backoff_ms; // backoff capped by 65 seconds is enough :)
	uint16_t listenq;
	uint16_t autoproxy;
	uint16_t timeout;
	char *interface;// interface of relay
} redsocks_config;

struct tracked_event {
	struct event * ev;
	struct timeval inserted;
};

typedef struct redsocks_instance_t {
	list_head       list;
	redsocks_config config;
	struct tracked_event listener;
	struct tracked_event accept_backoff;
	uint16_t        accept_backoff_ms;
	list_head       clients;
	relay_subsys   *relay_ss;
} redsocks_instance;

typedef struct redsocks_client_t {
	list_head           list;
	redsocks_instance  *instance;
	struct bufferevent *client;
	struct bufferevent *relay;
	struct sockaddr_storage  clientaddr;
	struct sockaddr_storage  destaddr;
	int                 state;         // it's used by bottom layer
	short               relay_connected;
	unsigned short      client_evshut;
	unsigned short      relay_evshut;
	time_t              first_event;
	time_t              last_event;
} redsocks_client;


void redsocks_drop_client(redsocks_client *client);
void redsocks_touch_client(redsocks_client *client);
int  redsocks_connect_relay(redsocks_client *client);
int redsocks_start_relay(redsocks_client *client);
void redsocks_dump_client(redsocks_client * client, int loglevel);
void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how, int pseudo);

typedef int (*size_comparator)(size_t a, size_t b);
int sizes_equal(size_t a, size_t b);
int sizes_greater_equal(size_t a, size_t b);
/** helper for functions when we expect ONLY reply of some size and anything else is error
 */
int redsocks_read_expected(redsocks_client *client, struct evbuffer *input, void *data, size_comparator comparator, size_t expected);

typedef struct evbuffer* (*redsocks_message_maker)(redsocks_client *client);
typedef struct evbuffer* (*redsocks_message_maker_plain)(void *p);
struct evbuffer *mkevbuffer(void *data, size_t len);
/* Yahoo! This code is ex-plain! :-D */
int redsocks_write_helper_ex_plain(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker_plain mkmessage, void *p, int state, size_t wm_low, size_t wm_high);
int redsocks_write_helper_ex(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_low, size_t wm_high);
int redsocks_write_helper(
	struct bufferevent *buffev, redsocks_client *client,
	redsocks_message_maker mkmessage, int state, size_t wm_only);


#define redsocks_close(fd) redsocks_close_internal((fd), __FILE__, __LINE__, __func__)
void redsocks_close_internal(int fd, const char* file, int line, const char *func);

#define redsocks_log_error(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, (struct sockaddr_storage *)&(client)->clientaddr, (struct sockaddr_storage *)&(client)->destaddr, prio, ## msg)
#define redsocks_log_errno(client, prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, (struct sockaddr_storage *)&(client)->clientaddr, (struct sockaddr_storage *)&(client)->destaddr, prio, ## msg)
void redsocks_log_write_plain(
		const char *file, int line, const char *func, int do_errno,
		const struct sockaddr_storage *clientaddr, const struct sockaddr_storage *destaddr,
		int priority, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__ (( format (printf, 8, 9) ))
#endif
;
/* unsafe internal functions. Only use them when you know exactly what
you are doing with */
int process_shutdown_on_write_(redsocks_client *client, struct bufferevent *from, struct bufferevent *to);

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* REDSOCKS_H_WED_JAN_24_22_17_11_2007 */

