/* $Id$ */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include "config.h"
#if defined USE_IPTABLES
# include <limits.h>
# include <linux/netfilter_ipv4.h>
#endif
#include "log.h"
#include "main.h"
#include "parser.h"
#include "redsocks.h"

typedef struct redirector_subsys_t {
	int (*init)();
	void (*fini)();
	int (*getdestaddr)(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr);
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
} base_instance;

static base_instance instance = {
	.configured = 0,
};

#if defined __FreeBSD__ || defined __OpenBSD__
static int redir_open_private(const char *fname, int flags)
{
	int fd = open(fname, flags);
	if (fd < 0) {
		log_errno("open(%s)", fname);
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
	return redir_init_open_fname(fname, O_RDONLY);
}

static int getdestaddr_ipf(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	int natfd = instance.redirector->private;
	struct natlookup natLookup;
	int x;
#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	struct ipfobj obj;
#else
	static int siocgnatl_cmd = SIOCGNATL & 0xff;
#endif

#if defined(IPFILTER_VERSION) && (IPFILTER_VERSION >= 4000027)
	obj.ipfo_rev = IPFILTER_VERSION;
	obj.ipfo_size = sizeof(natLookup);
	obj.ipfo_ptr = &natLookup;
	obj.ipfo_type = IPFOBJ_NATLOOKUP;
	obj.ipfo_offset = 0;
#endif

	natLookup.nl_inport = bindaddr->sin_port;
	natLookup.nl_outport = client->sin_port;
	natLookup.nl_inip = bindaddr->sin_addr;
	natLookup.nl_outip = client->sin_addr;
	natLookup.nl_flags = IPN_TCP;
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
		struct natlookup *nlp = &natLookup;
		x = ioctl(natfd, SIOCGNATL, &nlp);
	} else {
		x = ioctl(natfd, SIOCGNATL, &natLookup);
	}
#endif
	if (x < 0) {
		if (errno != ESRCH) 
			log_errno("ioctl(SIOCGNATL)\n");
		return -1;
	} else {
		destaddr->sin_family = AF_INET;
		destaddr->sin_port = natLookup.nl_realport;
		destaddr->sin_addr = natLookup.nl_realip;
		return 0;
	}
}
#endif

#ifdef __OpenBSD__
static int redir_init_pf()
{
	return redir_init_open_fname("/dev/pf", O_RDWR);
}

static int getdestaddr_pf(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	int pffd = instance.redirector->private;
    struct pfioc_natlook nl;

	memset(&nl, 0, sizeof(struct pfioc_natlook));
	nl.saddr.v4.s_addr = client->sin_addr.s_addr;
	nl.sport = client->sin_port;
	nl.daddr.v4.s_addr = bindaddr->sin_addr.s_addr;
	nl.dport = bindaddr->sin_port;
	nl.af = AF_INET;
	nl.proto = IPPROTO_TCP;
	nl.direction = PF_OUT;

	if (ioctl(pffd, DIOCNATLOOK, &nl) == 0) {
		destaddr->sin_family = AF_INET;
		destaddr->sin_port = nl.rdport;
		destaddr->sin_addr = nl.rdaddr.v4;
		return 0;
	} else {
		if (errno != ENOENT)
			log_errno("ioctl(DIOCNATLOOK)");
		return -1;
	}
}
#endif

#ifdef USE_IPTABLES
static int getdestaddr_iptables(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

	error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
	if (error) {
		log_errno("getsockopt");
		return -1;
	}
	return 0;
}
#endif

static int getdestaddr_generic(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	socklen_t socklen = sizeof(*destaddr);
	int error;

	error = getsockname(fd, (struct sockaddr*)destaddr, &socklen);
	if (error) {
		log_errno("getsockopt");
		return -1;
	}
	return 0;
}

int getdestaddr(int fd, const struct sockaddr_in *client, const struct sockaddr_in *bindaddr, struct sockaddr_in *destaddr)
{
	return instance.redirector->getdestaddr(fd, client, bindaddr, destaddr);
}

static redirector_subsys redirector_subsystems[] = 
{
#ifdef __FreeBSD__
	{ .name = "ipf", .init = redir_init_ipf, .fini = redir_close_private, .getdestaddr = getdestaddr_ipf },
#endif
#ifdef __OpenBSD__
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
		parser_error(section->context, err);

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
static int base_init()
{
	uid_t uid;
	gid_t gid;

	if (!instance.configured) {
		log_error("there is no configured instance of `base`, check config file");
		return -1;
	}
	
	if (instance.redirector->init && instance.redirector->init() < 0)
		return -1;

	if (instance.user) {
		struct passwd *pw = getpwnam(instance.user);
		if (pw == NULL) {
			log_errno("getpwnam(%s)", instance.user);
			goto fail;
		}
		uid = pw->pw_uid;
	}

	if (instance.group) {
		struct group *gr = getgrnam(instance.group);
		if (gr == NULL) {
			log_errno("getgrnam(%s)", instance.group);
			goto fail;
		}
		gid = gr->gr_gid;
	}

	if (instance.chroot) {
		if (chroot(instance.chroot) < 0) {
			log_errno("chroot(%s)", instance.chroot);
			goto fail;
		}
	}

	if (instance.group) {
		if (setgid(gid) < 0) {
			log_errno("setgid(%i)", gid);
			goto fail;
		}
	}

	if (instance.user) {
		if (setuid(uid) < 0) {
			log_errno("setuid(%i)", uid);
			goto fail;
		}
	}

	if (daemon(0, 0) < 0) {
		log_errno("daemon()");
		goto fail;
	}
	return 0;
fail:
	if (instance.redirector->fini)
		instance.redirector->fini();
	return -1;
}

app_subsys base_subsys = 
{
	.init = base_init,
	.conf_section = &base_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
