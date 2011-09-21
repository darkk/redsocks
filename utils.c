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

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "utils.h"

int red_recv_udp_pkt(int fd, char *buf, size_t buflen, struct sockaddr_in *inaddr)
{
	socklen_t addrlen = sizeof(*inaddr);
	ssize_t pktlen;

	pktlen = recvfrom(fd, buf, buflen, 0, (struct sockaddr*)inaddr, &addrlen);
	if (pktlen == -1) {
		log_errno(LOG_WARNING, "recvfrom");
		return -1;
	}

	if (addrlen != sizeof(*inaddr)) {
		log_error(LOG_WARNING, "unexpected address length %u instead of %zu", addrlen, sizeof(*inaddr));
		return -1;
	}

	if (pktlen >= buflen) {
		char buf[INET6_ADDRSTRLEN];
		const char *addr = inet_ntop(inaddr->sin_family, &inaddr->sin_addr, buf, sizeof(buf));
		log_error(LOG_WARNING, "wow! Truncated udp packet of size %zd from %s:%u! impossible! dropping it...",
		          pktlen, addr ? addr : "?", ntohs(inaddr->sin_port));
		return -1;
	}

	return pktlen;
}

time_t redsocks_time(time_t *t)
{
	time_t retval;
	retval = time(t);
	if (retval == ((time_t) -1))
		log_errno(LOG_WARNING, "time");
	return retval;
}

struct bufferevent* red_connect_relay(struct sockaddr_in *addr, evbuffercb writecb, everrorcb errorcb, void *cbarg)
{
	struct bufferevent *retval = NULL;
	int on = 1;
	int relay_fd = -1;
	int error;

	relay_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (relay_fd == -1) {
		log_errno(LOG_ERR, "socket");
		goto fail;
	}

	error = fcntl_nonblock(relay_fd);
	if (error) {
		log_errno(LOG_ERR, "fcntl");
		goto fail;
	}

	error = setsockopt(relay_fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	if (error) {
		log_errno(LOG_WARNING, "setsockopt");
		goto fail;
	}

	error = connect(relay_fd, (struct sockaddr*)addr, sizeof(*addr));
	if (error && errno != EINPROGRESS) {
		log_errno(LOG_NOTICE, "connect");
		goto fail;
	}

	retval = bufferevent_new(relay_fd, NULL, writecb, errorcb, cbarg);
	if (!retval) {
		log_errno(LOG_ERR, "bufferevent_new");
		goto fail;
	}

	error = bufferevent_enable(retval, EV_WRITE); // we wait for connection...
	if (error) {
		log_errno(LOG_ERR, "bufferevent_enable");
		goto fail;
	}

	return retval;

fail:
	if (relay_fd != -1)
		close(relay_fd);
	if (retval)
		bufferevent_free(retval);
	return NULL;
}

int red_socket_geterrno(struct bufferevent *buffev)
{
	int error;
	int pseudo_errno;
	socklen_t optlen = sizeof(pseudo_errno);

	assert(EVENT_FD(&buffev->ev_read) == EVENT_FD(&buffev->ev_write));

	error = getsockopt(EVENT_FD(&buffev->ev_read), SOL_SOCKET, SO_ERROR, &pseudo_errno, &optlen);
	if (error) {
		log_errno(LOG_ERR, "getsockopt");
		return -1;
	}
	return pseudo_errno;
}

/** simple fcntl(2) wrapper, provides errno and all logging to caller
 * I have to use it in event-driven code because of accept(2) (see NOTES)
 * and connect(2) (see ERRORS about EINPROGRESS)
 */
int fcntl_nonblock(int fd)
{
	int error;
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	error = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (error)
		return -1;

	return 0;
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

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
