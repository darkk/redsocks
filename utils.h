#ifndef UTILS_H_SAT_FEB__2_02_24_05_2008
#define UTILS_H_SAT_FEB__2_02_24_05_2008

#include <stddef.h>
#include <time.h>
#include <netinet/in.h>
#include <event.h>


#define SIZEOF_ARRAY(arr)        (sizeof(arr) / sizeof(arr[0]))
#define FOREACH(ptr, array)      for (ptr = array; ptr < array + SIZEOF_ARRAY(array); ptr++)
#define FOREACH_REV(ptr, array)  for (ptr = array + SIZEOF_ARRAY(array) - 1; ptr >= array; ptr--)

#define UNUSED(x)                ((void)(x))

#if defined __GNUC__
#define PACKED __attribute__((packed))
#else
#error Unknown compiler, modify utils.h for it
#endif


/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

time_t redsocks_time(time_t *t);
struct bufferevent* red_connect_relay(struct sockaddr_in *addr, evbuffercb writecb, everrorcb errorcb, void *cbarg);
int red_socket_geterrno(struct bufferevent *buffev);
int red_is_socket_connected_ok(struct bufferevent *buffev);

int fcntl_nonblock(int fd);

#define event_fmt_str "%s|%s|%s|%s|%s|0x%x"
#define event_fmt(what) \
				(what) & EVBUFFER_READ ? "EVBUFFER_READ" : "0", \
				(what) & EVBUFFER_WRITE ? "EVBUFFER_WRITE" : "0", \
				(what) & EVBUFFER_EOF ? "EVBUFFER_EOF" : "0", \
				(what) & EVBUFFER_ERROR ? "EVBUFFER_ERROR" : "0", \
				(what) & EVBUFFER_TIMEOUT ? "EVBUFFER_TIMEOUT" : "0", \
				(what) & ~(EVBUFFER_READ|EVBUFFER_WRITE|EVBUFFER_EOF|EVBUFFER_ERROR|EVBUFFER_TIMEOUT)

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* UTILS_H_SAT_FEB__2_02_24_05_2008 */
