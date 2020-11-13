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

#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include "config.h"
#if defined USE_IPTABLES
# include <limits.h>
# include <linux/netfilter_ipv4.h>
#endif

#if defined USE_PF
# include <net/if.h>
#if defined _APPLE_
#define PRIVATE
#endif
# include <net/pfvar.h>
#if defined _APPLE_
#define sport sxport.port
#define dport dxport.port
#define rdport rdxport.port
#undef PRIVATE
#endif
# include <sys/ioctl.h>
#endif
#ifdef __FreeBSD__
# include <netinet/ip_fil.h>
# include <netinet/ip_nat.h>
#endif

#include <errno.h>
#include "log.h"
#include "main.h"
#include "parser.h"
#include "redsocks.h"
#include "utils.h"

typedef struct redirector_subsys_t {
	int (*init)();
	void (*fini)();
	int (*getdestaddr)(int fd, const struct sockaddr_storage *client, const struct sockaddr_storage *bindaddr, struct sockaddr_storage *destaddr);
	const char *name;
	// some subsystems may store data here:
	int private;
} redirector_subsys;

typedef struct base_instance_t {
	int configured;
	char *chroot;
	char *user;
	char *group;
	char *redirector_name;
	redirector_subsys *redirector;
	char *log_name;
	bool log_debug;
	bool log_info;
	bool daemon;
#ifdef SO_REUSEPORT
	bool reuseport;
#endif
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	uint16_t tcp_keepalive_time;
	uint16_t tcp_keepalive_probes;
	uint16_t tcp_keepalive_intvl;
#endif
} base_instance;

static base_instance instance = {
	.configured = 0,
	.log_debug = false,
	.log_info = false,
};

#if defined __FreeBSD__ || defined USE_PF
static int redir_open_private(const char *fname, int flags)
{
	int fd = open(fname, flags);
	if (fd < 0) {
		log_errno(LOG_ERR, "open(%s)", fname);
		return -1;
	}
	instance.redirector->private = fd;
	return 0;
}

static void redir_close_private()
{
	close(instance.redirector->private);
	instance.redirector->private = -1;
}
#endif

#ifdef __FreeBSD__
static int redir_init_ipf()
{
#ifdef IPNAT_NAME
	const char *fname = IPNAT_NAME;
#else
	const char *fname = IPL_NAME;
#endif
	return redir_open_private(fname, O_RDONLY);
}

static int getdestaddr_ipf(int fd,
	const struct sockaddr_storage *client,
	const struct sockaddr_storage *bindaddr,
	struct sockaddr_storage *destaddr)
{
	int natfd = instance.redirector->private;
	struct natlookup nl;
	int x;
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	struct ipfobj obj;
#else
	static int siocgnatl_cmd = SIOCGNATL & 0xff;
#endif

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(nl);
	obj.ipfo_ptr = &nl;
	obj.ipfo_type = IPFOBJ_NATLOOKUP;
	obj.ipfo_offset = 0;
#endif

	nl.nl_inport = ((struct sockaddr_in *)bindaddr)->sin_port;
	nl.nl_outport = ((struct sockaddr_in *)client)->sin_port;
	nl.nl_inip = ((struct sockaddr_in *)bindaddr)->sin_addr;
	nl.nl_outip = ((struct sockaddr_in *)client)->sin_addr;
	nl.nl_flags = IPN_TCP;
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	x = ioctl(natfd, SIOCGNATL, &obj);
#else
	/*
	 * IP-Filter changed the type for SIOCGNATL between
	 * 3.3 and 3.4.  It also changed the cmd value for
	 * SIOCGNATL, so at least we can detect it.  We could
	 * put something in configure and use ifdefs here, but
	 * this seems simpler.
	 */
	if (63 == siocgnatl_cmd) {
		struct natlookup *nlp = &nl;
		x = ioctl(natfd, SIOCGNATL, &nlp);
	} else {
		x = ioctl(natfd, SIOCGNATL, &nl);
	}
#endif
	if (x < 0) {
		if (errno != ESRCH)
			log_errno(LOG_WARNING, "ioctl(SIOCGNATL)\n");
		return -1;
	} else {
		destaddr->ss_family = AF_INET;
		((struct sockaddr_in *)destaddr)->sin_port = nl.nl_realport;
		((struct sockaddr_in *)destaddr)->sin_addr = nl.nl_realip;
		return 0;
	}
}
#endif

#ifdef USE_PF
static int redir_init_pf()
{
	return redir_open_private("/dev/pf", O_RDWR);
}

// FIXME: Support IPv6
static int getdestaddr_pf(
		int fd,
		const struct sockaddr_storage *client,
		const struct sockaddr_storage *bindaddr,
		struct sockaddr_storage *destaddr)
{
	int pffd = instance.redirector->private;
	struct pfioc_natlook nl;
	int saved_errno;
    char clientaddr_str[RED_INET_ADDRSTRLEN], bindaddr_str[RED_INET_ADDRSTRLEN];

	memset(&nl, 0, sizeof(struct pfioc_natlook));
	if (client->ss_family == AF_INET) {
		nl.saddr.v4 = ((const struct sockaddr_in *)client)->sin_addr;
		nl.sport = ((struct sockaddr_in *)client)->sin_port;
	}
	else if (client->ss_family == AF_INET6) {
		memcpy(&nl.saddr.v6, &((const struct sockaddr_in6 *)client)->sin6_addr, sizeof(struct in6_addr));
		nl.sport = ((struct sockaddr_in6 *)client)->sin6_port;
	}
	else {
		goto fail;
	}
	if (bindaddr->ss_family == AF_INET) {
		nl.daddr.v4 = ((const struct sockaddr_in *)bindaddr)->sin_addr;
		nl.dport = ((struct sockaddr_in *)bindaddr)->sin_port;
	}
	else if (bindaddr->ss_family == AF_INET6) {
		memcpy(&nl.daddr.v6, &((const struct sockaddr_in6 *)bindaddr)->sin6_addr, sizeof(struct in6_addr));
		nl.dport = ((struct sockaddr_in6 *)bindaddr)->sin6_port;
	}
	else {
		goto fail;
	}
	nl.af = client->ss_family;  // Use same address family ass client
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;

	if (ioctl(pffd, DIOCNATLOOK, &nl) != 0) {
		if (errno == ENOENT) {
			nl.direction = PF_IN; // required to redirect local packets
			if (ioctl(pffd, DIOCNATLOOK, &nl) != 0) {
				goto fail;
			}
		}
		else {
			goto fail;
		}
	}
	destaddr->ss_family = nl.af;
	if (nl.af == AF_INET) {
		((struct sockaddr_in *)destaddr)->sin_port = nl.rdport;
		((struct sockaddr_in *)destaddr)->sin_addr = nl.rdaddr.v4;
	}
	else {
		((struct sockaddr_in6 *)destaddr)->sin6_port = nl.rdport;
		memcpy(&(((struct sockaddr_in6 *)destaddr)->sin6_addr), &nl.rdaddr.v6, sizeof(struct in6_addr));
	}
	return 0;

fail:
	saved_errno = errno;
	red_inet_ntop(client, clientaddr_str, sizeof(clientaddr_str));
	red_inet_ntop(bindaddr, bindaddr_str, sizeof(bindaddr_str));
	errno = saved_errno;
	log_errno(LOG_WARNING, "ioctl(DIOCNATLOOK {src=%s, dst=%s})",
			  clientaddr_str, bindaddr_str);
	return -1;
}
#endif

#ifdef USE_IPTABLES
static int getdestaddr_iptables(
	int fd,
	const struct sockaddr_storage *client,
	const struct sockaddr_storage *bindaddr,
	struct sockaddr_storage *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

#ifdef SOL_IPV6
	int sol = (client->ss_family == AF_INET6) ? SOL_IPV6 : SOL_IP;
#else
	int sol = SOL_IP;
#endif
	error = getsockopt(fd, sol, SO_ORIGINAL_DST, destaddr, &socklen);
#ifdef SOL_IPV6
	if (error && sol == SOL_IPV6) {
		sol = SOL_IP;
		error = getsockopt(fd, sol, SO_ORIGINAL_DST, destaddr, &socklen);
	}
#endif
	if (error) {
		log_errno(LOG_WARNING, "getsockopt");
		return -1;
	}
	return 0;
}
#endif

static int getdestaddr_generic(
	int fd,
	const struct sockaddr_storage *client,
	const struct sockaddr_storage *bindaddr,
	struct sockaddr_storage *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

	error = getsockname(fd, (struct sockaddr*)destaddr, &socklen);
	if (error) {
		log_errno(LOG_WARNING, "getsockopt");
		return -1;
	}
	return 0;
}

int getdestaddr(
	int fd,
	const struct sockaddr_storage *client,
	const struct sockaddr_storage *bindaddr,
	struct sockaddr_storage *destaddr)
{
	return instance.redirector->getdestaddr(fd, client, bindaddr, destaddr);
}

int apply_tcp_keepalive(int fd)
{
	struct { int level, option, value; } opt[] = {
		{ SOL_SOCKET, SO_KEEPALIVE, 1 },
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
		{ IPPROTO_TCP, TCP_KEEPIDLE, instance.tcp_keepalive_time },
		{ IPPROTO_TCP, TCP_KEEPCNT, instance.tcp_keepalive_probes },
		{ IPPROTO_TCP, TCP_KEEPINTVL, instance.tcp_keepalive_intvl },
#endif
	};
	for (int i = 0; i < SIZEOF_ARRAY(opt); ++i) {
		if (opt[i].value) {
			int error = setsockopt(fd, opt[i].level, opt[i].option, &opt[i].value, sizeof(opt[i].value));
			if (error) {
				log_errno(LOG_WARNING, "setsockopt(%d, %d, %d, &%d, %zu)", fd, opt[i].level, opt[i].option, opt[i].value, sizeof(opt[i].value));
				return -1;
			}
		}
	}
	return 0;
}

int apply_reuseport(int fd)
{
#ifdef SO_REUSEPORT
    if (!instance.reuseport)
        return 0;

    int opt = 1;
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    if (rc == -1)
        log_errno(LOG_ERR, "setsockopt");
    return rc;
#else
    return -1;
#endif
}

static redirector_subsys redirector_subsystems[] =
{
#ifdef __FreeBSD__
	{ .name = "ipf", .init = redir_init_ipf, .fini = redir_close_private, .getdestaddr = getdestaddr_ipf },
#endif
#ifdef USE_PF
	{ .name = "pf",  .init = redir_init_pf,  .fini = redir_close_private, .getdestaddr = getdestaddr_pf },
#endif
#ifdef USE_IPTABLES
	{ .name = "iptables", .getdestaddr = getdestaddr_iptables },
#endif
	{ .name = "generic",  .getdestaddr = getdestaddr_generic  },
};

/***********************************************************************
 * `base` config parsing
 */
static parser_entry base_entries[] =
{
	{ .key = "chroot",     .type = pt_pchar,   .addr = &instance.chroot },
	{ .key = "user",       .type = pt_pchar,   .addr = &instance.user },
	{ .key = "group",      .type = pt_pchar,   .addr = &instance.group },
	{ .key = "redirector", .type = pt_pchar,   .addr = &instance.redirector_name },
	{ .key = "log",        .type = pt_pchar,   .addr = &instance.log_name },
	{ .key = "log_debug",  .type = pt_bool,    .addr = &instance.log_debug },
	{ .key = "log_info",   .type = pt_bool,    .addr = &instance.log_info },
	{ .key = "daemon",     .type = pt_bool,    .addr = &instance.daemon },
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPCNT) && defined(TCP_KEEPINTVL)
	{ .key = "tcp_keepalive_time",   .type = pt_uint16, .addr = &instance.tcp_keepalive_time },
	{ .key = "tcp_keepalive_probes", .type = pt_uint16, .addr = &instance.tcp_keepalive_probes },
	{ .key = "tcp_keepalive_intvl",  .type = pt_uint16, .addr = &instance.tcp_keepalive_intvl },
#endif
#ifdef SO_REUSEPORT
	{ .key = "reuseport",  .type = pt_bool,    .addr = &instance.reuseport},
#endif
	{ }
};

static int base_onenter(parser_section *section)
{
	if (instance.configured) {
		parser_error(section->context, "only one instance of base is valid");
		return -1;
	}
	memset(&instance, 0, sizeof(instance));
	return 0;
}

static int base_onexit(parser_section *section)
{
	const char *err = NULL;

	if (instance.redirector_name) {
		redirector_subsys *ss;
		FOREACH(ss, redirector_subsystems) {
			if (!strcmp(ss->name, instance.redirector_name)) {
				instance.redirector = ss;
				instance.redirector->private = -1;
				break;
			}
		}
		if (!instance.redirector)
			err = "invalid `redirector` set";
	}
	else {
		err = "no `redirector` set";
	}

	if (err)
		parser_error(section->context, "%s", err);

	if (!err)
		instance.configured = 1;

	return err ? -1 : 0;
}

static parser_section base_conf_section =
{
	.name    = "base",
	.entries = base_entries,
	.onenter = base_onenter,
	.onexit  = base_onexit
};

/***********************************************************************
 * `base` initialization
 */
static int base_fini();

static int base_init()
{
	uid_t uid = -1;
	gid_t gid = -1;
	int devnull = -1;

	if (!instance.configured) {
		log_error(LOG_ERR, "there is no configured instance of `base`, check config file");
		return -1;
	}

	if (instance.redirector->init && instance.redirector->init() < 0)
		return -1;

	if (instance.user) {
		struct passwd *pw = getpwnam(instance.user);
		if (pw == NULL) {
			log_errno(LOG_ERR, "getpwnam(%s)", instance.user);
			goto fail;
		}
		uid = pw->pw_uid;
	}

	if (instance.group) {
		struct group *gr = getgrnam(instance.group);
		if (gr == NULL) {
			log_errno(LOG_ERR, "getgrnam(%s)", instance.group);
			goto fail;
		}
		gid = gr->gr_gid;
	}

	if (log_preopen(
			instance.log_name ? instance.log_name : instance.daemon ? "syslog:daemon" : "stderr",
			instance.log_debug,
			instance.log_info
	) < 0 ) {
		goto fail;
	}

	if (instance.daemon) {
		devnull = open("/dev/null", O_RDWR);
		if (devnull == -1) {
			log_errno(LOG_ERR, "open(\"/dev/null\", O_RDWR");
			goto fail;
		}
	}

	if (instance.chroot) {
		if (chroot(instance.chroot) < 0) {
			log_errno(LOG_ERR, "chroot(%s)", instance.chroot);
			goto fail;
		}
	}

	if (instance.daemon || instance.chroot) {
		if (chdir("/") < 0) {
			log_errno(LOG_ERR, "chdir(\"/\")");
			goto fail;
		}
	}

	if (instance.group) {
		if (setgid(gid) < 0) {
			log_errno(LOG_ERR, "setgid(%i)", gid);
			goto fail;
		}
	}

	if (instance.user) {
		if (setuid(uid) < 0) {
			log_errno(LOG_ERR, "setuid(%i)", uid);
			goto fail;
		}
	}

	if (instance.daemon) {
		switch (fork()) {
		case -1: // error
			log_errno(LOG_ERR, "fork()");
			goto fail;
		case 0:  // child
			break;
		default: // parent, pid is returned
			exit(EXIT_SUCCESS);
		}
	}

	log_open(); // child has nothing to do with TTY

	if (instance.daemon) {
		if (setsid() < 0) {
			log_errno(LOG_ERR, "setsid()");
			goto fail;
		}

		int fds[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };
		int *pfd;
		FOREACH(pfd, fds)
			if (dup2(devnull, *pfd) < 0) {
				log_errno(LOG_ERR, "dup2(devnull, %i)", *pfd);
				goto fail;
			}

		close(devnull);
	}
	return 0;
fail:
	if (devnull != -1)
		close(devnull);

	base_fini();

	return -1;
}

static int base_fini()
{
	if (instance.redirector->fini)
		instance.redirector->fini();

	free(instance.chroot);
	free(instance.user);
	free(instance.group);
	free(instance.redirector_name);
	free(instance.log_name);

	memset(&instance, 0, sizeof(instance));

	return 0;
}

app_subsys base_subsys =
{
	.init = base_init,
	.fini = base_fini,
	.conf_section = &base_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
