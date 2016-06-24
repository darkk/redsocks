#ifndef UTILS_H_SAT_FEB__2_02_24_05_2008
#define UTILS_H_SAT_FEB__2_02_24_05_2008

#include <stddef.h>
#include <time.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

struct sockaddr_in;

#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)
#define FOREACH_REV(ptr, array)  for (ptr = array + SIZEOF_ARRAY(array) - 1; ptr >= array; ptr--)

#define UNUSED(x)                ((void)(x))

#if defined __GNUC__
#define PACKED __attribute__((packed))
#else
#error Unknown compiler, modify utils.h for it
#endif


#ifdef __GNUC__
#define member_type(type, member) __typeof(((type *)0)->member)
#else
#define member_type(type, member) const void
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) \
	((type *)( \
		(char *)(member_type(type, member) *){ ptr } - offsetof(type, member) \
	))


#define clamp_value(value, min_val, max_val) do { \
       if (value < min_val) \
               value = min_val; \
       if (value > max_val) \
               value = max_val; \
} while (0)


uint32_t red_randui32();
time_t redsocks_time(time_t *t);
char *redsocks_evbuffer_readline(struct evbuffer *buf);
struct bufferevent* red_prepare_relay(const char *ifname,
                                bufferevent_data_cb readcb,
                                bufferevent_data_cb writecb,
                                bufferevent_event_cb errorcb,
                                void *cbarg);
struct bufferevent* red_connect_relay(const char *ifname,
                                struct sockaddr_in *addr,
                                bufferevent_data_cb readcb,
                                bufferevent_data_cb writecb,
                                bufferevent_event_cb errorcb,
                                void *cbarg,
                                const struct timeval *timeout_write);
int red_socket_geterrno(struct bufferevent *buffev);
int red_is_socket_connected_ok(struct bufferevent *buffev);
int red_recv_udp_pkt(int fd, char *buf, size_t buflen, struct sockaddr_in *fromaddr, struct sockaddr_in *toaddr);

size_t copy_evbuffer(struct bufferevent * dst, struct bufferevent * src, size_t skip);
size_t get_write_hwm(struct bufferevent *bufev);
int make_socket_transparent(int fd);
int apply_tcp_fastopen(int fd);

#define event_fmt_str "%s|%s|%s|%s|%s|%s|0x%x"
#define event_fmt(what) \
				(what) & BEV_EVENT_READING ? "READING" : "0", \
				(what) & BEV_EVENT_WRITING ? "WRITING" : "0", \
				(what) & BEV_EVENT_EOF ? "EOF" : "0", \
				(what) & BEV_EVENT_ERROR ? "ERROR" : "0", \
				(what) & BEV_EVENT_TIMEOUT ? "TIMEOUT" : "0", \
				(what) & BEV_EVENT_CONNECTED ? "CONNECTED" : "0", \
				(what) & ~(BEV_EVENT_READING|BEV_EVENT_WRITING|BEV_EVENT_EOF|BEV_EVENT_ERROR|BEV_EVENT_TIMEOUT|BEV_EVENT_CONNECTED)

#if INET6_ADDRSTRLEN < INET_ADDRSTRLEN
#	error Impossible happens: INET6_ADDRSTRLEN < INET_ADDRSTRLEN
#else
#	define RED_INET_ADDRSTRLEN (1 + INET6_ADDRSTRLEN + 1 + 1 + 5 + 1) // [ + addr + ] + : + port + \0
#endif
char *red_inet_ntop(const struct sockaddr_in* sa, char* buffer, size_t buffer_size);

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* UTILS_H_SAT_FEB__2_02_24_05_2008 */
