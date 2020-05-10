/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2011 Leonid Evdokimov <leon@darkk.net.ru>
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
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include "config.h"
#include "main.h"
#include "log.h"
#include "base.h"
#include "utils.h"
#include "redsocks.h" // for redsocks_close
#include "libc-compat.h"


#define addr_size(addr) (((struct sockaddr *)addr)->sa_family == AF_INET ? sizeof(struct sockaddr_in): \
                         ((struct sockaddr *)addr)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6): sizeof(struct sockaddr_storage))

int red_recv_udp_pkt(
    int fd,
    char *buf,
    size_t buflen,
    struct sockaddr_storage *inaddr,
    struct sockaddr_storage *toaddr)
{
    ssize_t pktlen;
    struct msghdr msg;
    struct iovec io;
    char control[1024];

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = inaddr;
    msg.msg_namelen = sizeof(*inaddr);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    io.iov_base = buf;
    io.iov_len = buflen;

    pktlen = recvmsg(fd, &msg, 0);
    if (pktlen == -1) {
        log_errno(LOG_WARNING, "recvfrom");
        return -1;
    }

    if (pktlen >= buflen) {
        char buf[RED_INET_ADDRSTRLEN];
        log_error(LOG_WARNING, "wow! Truncated udp packet of size %zd from %s! impossible! dropping it...",
                  pktlen, red_inet_ntop(inaddr, buf, sizeof(buf)));
        return -1;
    }

    if (toaddr) {
        memset(toaddr, 0, sizeof(*toaddr));
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (
                ((cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_ORIGDSTADDR)
#ifdef SOL_IPV6
                 || (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_ORIGDSTADDR)
#endif
                 ) &&
                (cmsg->cmsg_len == CMSG_LEN(sizeof(struct sockaddr_in))
                 || cmsg->cmsg_len == CMSG_LEN(sizeof(struct sockaddr_in6))) &&
                cmsg->cmsg_len <= CMSG_LEN(sizeof(*toaddr))
            ) {
                struct sockaddr* cmsgaddr = (struct sockaddr*)CMSG_DATA(cmsg);
                if (cmsgaddr->sa_family == AF_INET) {
                    memcpy(toaddr, cmsgaddr, sizeof(struct sockaddr_in));
                }
                else if (cmsgaddr->sa_family == AF_INET6) {
                    memcpy(toaddr, cmsgaddr, sizeof(struct sockaddr_in6));
                }
                else {
                    log_error(LOG_WARNING,
                              "unexepcted socket address type: %d",
                              cmsgaddr->sa_family);
                }
                break;
            }
            else {
                log_error(LOG_WARNING, "unexepcted cmsg (level,type) = (%d,%d)",
                    cmsg->cmsg_level, cmsg->cmsg_type);
            }
        }
        if (toaddr->ss_family == 0) {
            log_error(LOG_WARNING, "(SOL_IP, IP_ORIGDSTADDR) not found");
            return -1;
        }
    }

    return pktlen;
}

uint32_t red_randui32()
{
    uint32_t ret;
    evutil_secure_rng_get_bytes(&ret, sizeof(ret));
    return ret;
}

time_t redsocks_time(time_t *t)
{
    time_t retval;
    retval = time(t);
    if (retval == ((time_t) -1))
        log_errno(LOG_WARNING, "time");
    return retval;
}

struct bufferevent* red_prepare_relay(const char *ifname,
                                int sa_family,
                                bufferevent_data_cb readcb,
                                bufferevent_data_cb writecb,
                                bufferevent_event_cb errorcb,
                                void *cbarg)
{
    struct bufferevent *retval = NULL;
    int relay_fd = -1;
    int error;

    relay_fd = socket(sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (relay_fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }
    if (ifname && strlen(ifname)) {
#ifdef USE_PF // BSD
        error = setsockopt(relay_fd, SOL_SOCKET, IP_RECVIF, ifname, strlen(ifname));
#else // Linux
        error = setsockopt(relay_fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));
#endif
        if (error) {
            log_errno(LOG_ERR, "setsockopt");
            goto fail;
        }
    }
    error = evutil_make_socket_nonblocking(relay_fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    retval = bufferevent_socket_new(get_event_base(), relay_fd, 0);
    if (!retval) {
        log_errno(LOG_ERR, "bufferevent_socket_new");
        goto fail;
    }

    bufferevent_setcb(retval, readcb, writecb, errorcb, cbarg);
    if (writecb) {
        error = bufferevent_enable(retval, EV_WRITE); // we wait for connection...
        if (error) {
            log_errno(LOG_ERR, "bufferevent_enable");
            goto fail;
        }
    }

    if (apply_tcp_keepalive(relay_fd))
        goto fail;

    return retval;

fail:
    if (retval){
        bufferevent_disable(retval, EV_READ|EV_WRITE);
        bufferevent_free(retval);
    }
    if (relay_fd != -1)
        redsocks_close(relay_fd);
    return NULL;
}

struct bufferevent* red_connect_relay(const char *ifname,
                                    struct sockaddr_storage *addr,
                                    bufferevent_data_cb readcb,
                                    bufferevent_data_cb writecb,
                                    bufferevent_event_cb errorcb,
                                    void *cbarg,
                                    const struct timeval *timeout_write)
{
    struct bufferevent *retval = NULL;
    int relay_fd = -1;
    int error;

    retval = red_prepare_relay(ifname, addr->ss_family, readcb, writecb, errorcb, cbarg);
    if (retval) {
        relay_fd = bufferevent_getfd(retval);
        if (timeout_write)
            bufferevent_set_timeouts(retval, NULL, timeout_write);

        //  error = bufferevent_socket_connect(retval, addr, sizeof(*addr));
        //  if (error) {
        error = connect(relay_fd, (struct sockaddr *)addr, addr_size(addr));
        if (error && errno != EINPROGRESS) {
            log_errno(LOG_NOTICE, "connect");
            goto fail;
        }
    }
    return retval;

fail:
    if (retval) {
        bufferevent_disable(retval, EV_READ|EV_WRITE);
        bufferevent_free(retval);
    }
    if (relay_fd != -1)
        redsocks_close(relay_fd);
    return NULL;
}

#if defined(ENABLE_HTTPS_PROXY)
struct bufferevent* red_connect_relay_ssl(const char *ifname,
                                    struct sockaddr_storage *addr,
                                    SSL * ssl,
                                    bufferevent_data_cb readcb,
                                    bufferevent_data_cb writecb,
                                    bufferevent_event_cb errorcb,
                                    void *cbarg,
                                    const struct timeval *timeout_write)
{
    struct bufferevent *retval = NULL;
    struct bufferevent *underlying = NULL;
    int relay_fd = -1;
    int error;

    underlying = red_prepare_relay(ifname, addr->ss_family, NULL, NULL, NULL, NULL);
    if (!underlying)
        goto fail;
    relay_fd = bufferevent_getfd(underlying);
    if (timeout_write)
        bufferevent_set_timeouts(underlying, NULL, timeout_write);

    error = connect(relay_fd, addr, addr_size(addr));
    if (error && errno != EINPROGRESS) {
        log_errno(LOG_NOTICE, "connect");
        goto fail;
    }
    retval = bufferevent_openssl_filter_new(bufferevent_get_base(underlying),
                                            underlying,
                                            ssl,
                                            BUFFEREVENT_SSL_CONNECTING,
                                            BEV_OPT_DEFER_CALLBACKS);
    if (!retval) {
        log_errno(LOG_NOTICE, "bufferevent_openssl_filter_new");
        goto fail;
    }
    if (timeout_write)
        bufferevent_set_timeouts(retval, NULL, timeout_write);

    bufferevent_setcb(retval, readcb, writecb, errorcb, cbarg);
    if (writecb) {
        error = bufferevent_enable(retval, EV_WRITE); // we wait for connection...
        if (error) {
            log_errno(LOG_ERR, "bufferevent_enable");
            goto fail;
        }
    }
    return retval;

fail:
    if (retval) {
        bufferevent_disable(retval, EV_READ|EV_WRITE);
        bufferevent_free(retval);
    }
    if (underlying) {
        bufferevent_disable(underlying, EV_READ|EV_WRITE);
        bufferevent_free(underlying);
    }
    if (relay_fd != -1)
        redsocks_close(relay_fd);
    return NULL;
}
#endif

struct bufferevent* red_connect_relay_tfo(const char *ifname,
                                    struct sockaddr_storage *addr,
                                    bufferevent_data_cb readcb,
                                    bufferevent_data_cb writecb,
                                    bufferevent_event_cb errorcb,
                                    void *cbarg,
                                    const struct timeval *timeout_write,
                                    void *data,
                                    size_t *len)
{
    struct bufferevent *retval = NULL;
    int relay_fd = -1;
    int error;

    retval = red_prepare_relay(ifname, addr->ss_family, readcb, writecb, errorcb, cbarg);
    if (retval) {
        relay_fd = bufferevent_getfd(retval);
        if (timeout_write)
            bufferevent_set_timeouts(retval, NULL, timeout_write);

#ifdef MSG_FASTOPEN
        size_t s = sendto(relay_fd, data, * len, MSG_FASTOPEN,
                (struct sockaddr *)addr, addr_size(addr)
                );
        if (s == -1) {
            if (errno == EINPROGRESS || errno == EAGAIN
                    || errno == EWOULDBLOCK) {
                // Remote server doesn't support tfo or it's the first connection to the server.
                // Connection will automatically fall back to conventional TCP.
                log_error(LOG_DEBUG, "TFO: no cookie");
                // write data to evbuffer so that data can be sent when connection is set up
                if (bufferevent_write(retval, data, *len) != 0) {
                    log_errno(LOG_NOTICE, "bufferevent_write");
                    goto fail;
                }
                return retval;
            } else if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT ||
                    errno == ENOPROTOOPT) {
                // Disable fast open as it's not supported
                log_error(LOG_DEBUG, "TFO: not support");
                goto fallback;
            } else {
                log_errno(LOG_NOTICE, "sendto");
                goto fail;
            }
        }
        else {
            log_error(LOG_DEBUG, "TFO: cookie found");
            *len = s; // data is put into socket buffer
            return retval;
        }
fallback:
#endif

        error = connect(relay_fd, (struct sockaddr *)addr, addr_size(addr));
        if (error && errno != EINPROGRESS) {
            log_errno(LOG_NOTICE, "connect");
            goto fail;
        }
        // write data to evbuffer so that data can be sent when connection is set up
        if (bufferevent_write(retval, data, *len) != 0) {
            log_errno(LOG_NOTICE, "bufferevent_write");
            goto fail;
        }
    }
    return retval;

fail:
    if (retval) {
        bufferevent_disable(retval, EV_READ|EV_WRITE);
        bufferevent_free(retval);
    }
    if (relay_fd != -1)
        redsocks_close(relay_fd);
    return NULL;
}


int red_socket_geterrno(struct bufferevent *buffev)
{
    int error;
    int pseudo_errno;
    socklen_t optlen = sizeof(pseudo_errno);
    int fd = bufferevent_getfd(buffev);

    error = getsockopt(fd, SOL_SOCKET, SO_ERROR, &pseudo_errno, &optlen);
    if (error) {
        log_errno(LOG_ERR, "getsockopt(fd=%d)", fd);
        return -1;
    }
    return pseudo_errno;
}

int red_is_socket_connected_ok(struct bufferevent *buffev)
{
    int pseudo_errno = red_socket_geterrno(buffev);

    if (pseudo_errno == -1) {
        return 0;
    }
    else if (pseudo_errno) {
        errno = pseudo_errno;
        log_errno(LOG_NOTICE, "connect");
        return 0;
    }
    else {
        return 1;
    }
}

char *red_inet_ntop(const struct sockaddr_storage* sa, char* buffer, size_t buffer_size)
{
    const char *retval = 0;
    size_t len = 0;
    uint16_t port;
    const char placeholder[] = "???:???";

    assert(buffer_size >= RED_INET_ADDRSTRLEN);

    memset(buffer, 0, buffer_size);
    if (sa->ss_family == AF_INET) {
        retval = inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buffer, buffer_size);
        port = ((struct sockaddr_in*)sa)->sin_port;
    }
    else if (sa->ss_family == AF_INET6) {
        buffer[0] = '[';
        retval = inet_ntop(AF_INET6, &((const struct sockaddr_in6*)sa)->sin6_addr, buffer+1, buffer_size-1);
        port = ((struct sockaddr_in6*)sa)->sin6_port;
        if (retval)
            retval = buffer;
    }
    if (retval) {
        assert(retval == buffer);
        len = strlen(retval);
        if (sa->ss_family == AF_INET6)
            snprintf(buffer + len, buffer_size - len, "]:%d", ntohs(port));
        else
            snprintf(buffer + len, buffer_size - len, ":%d", ntohs(port));
    }
    else {
        strcpy(buffer, placeholder);
    }
    return buffer;
}

/* copy event buffer from source to destination as much as possible. 
 * If parameter skip is not zero, copy will start from the number of skip bytes.
 */
size_t copy_evbuffer(struct bufferevent * dst, struct bufferevent * src, size_t skip)
{
    int n, i;
    size_t written = 0;
    struct evbuffer_iovec *v;
    struct evbuffer_iovec quick_v[5];/* a vector with 5 elements is usually enough */
    struct evbuffer * evbinput = bufferevent_get_input(src);
    size_t maxlen = get_write_hwm(dst) - evbuffer_get_length(bufferevent_get_output(dst));
    maxlen = evbuffer_get_length(evbinput) - skip > maxlen ? maxlen: evbuffer_get_length(evbinput)-skip;

    n = evbuffer_peek(evbinput, maxlen+skip, NULL, NULL, 0);
    if (n > sizeof(quick_v)/sizeof(struct evbuffer_iovec))
        v = malloc(sizeof(struct evbuffer_iovec)*n);
    else
        v = &quick_v[0];
    n = evbuffer_peek(evbinput, maxlen+skip, NULL, v, n);
    for (i=0; i<n; ++i) {
        size_t len = v[i].iov_len;
        if (skip >= len)
        {
            skip -= len;
            continue;
        }
        else 
        {
            len -= skip;
        }
        if (written + len > maxlen)
            len = maxlen - written;
        if (bufferevent_write(dst, v[i].iov_base+skip, len))
            break;
        skip = 0;
        /* We keep track of the bytes written separately; if we don't,
        *  we may write more than we need if the last chunk puts    
        * us over the limit. */
        written += len;
    }
    if (v != &quick_v[0])
        free(v);
    return written;
}

size_t get_write_hwm(struct bufferevent *bufev)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    size_t high;
    bufferevent_getwatermark(bufev, EV_WRITE, NULL, &high);
    return high;
#else
    return bufev->wm_write.high;
#endif
}

int make_socket_transparent(int fd)
{
    int on = 1;
    int error = 0;
#ifdef SOL_IPV6
    int error_6 = 0;
#endif

    error = setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
    if (error)
        log_errno(LOG_DEBUG, "setsockopt(fd, SOL_IP, IP_TRANSPARENT)");

#ifdef SOL_IPV6
    error_6 = setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &on, sizeof(on));
    if (error_6)
        log_errno(LOG_DEBUG, "setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT)");

    if (error && error_6)
        log_error(LOG_ERR, "Can not make socket transparent. See debug log for details.");
#endif
    return error;
}

int apply_tcp_fastopen(int fd)
{
#ifdef TCP_FASTOPEN
#ifdef __APPLE__
    int opt = 1;
#else
    int opt = 5;
#endif
    int rc = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));
    if (rc == -1)
        log_errno(LOG_ERR, "setsockopt");
    return rc;
#else
    return -1;
#endif
}


void replace_readcb(struct bufferevent * buffev, bufferevent_data_cb readcb)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_event_cb eventcb;
    bufferevent_data_cb  writecb;
    void * arg;
    bufferevent_getcb(buffev, NULL, &writecb, &eventcb, &arg);
    bufferevent_setcb(buffev, readcb, writecb, eventcb, arg);
#else
    buffev->readcb = readcb;
#endif
}

void replace_writecb(struct bufferevent * buffev, bufferevent_data_cb writecb)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_event_cb eventcb;
    bufferevent_data_cb  readcb;
    void * arg;
    bufferevent_getcb(buffev, &readcb, NULL, &eventcb, &arg);
    bufferevent_setcb(buffev, readcb, writecb, eventcb, arg);
#else
    buffev->writecb = writecb;
#endif
}

void replace_eventcb(struct bufferevent * buffev, bufferevent_event_cb eventcb)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_data_cb  readcb, writecb;
    void * arg;
    bufferevent_getcb(buffev, &readcb, &writecb, NULL, &arg);
    bufferevent_setcb(buffev, readcb, writecb, eventcb, arg);
#else
    buffev->errorcb = eventcb;
#endif
}


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
