#ifndef UUID_67C91670_FCCB_4855_BDF7_609F1EECB8B4
#define UUID_67C91670_FCCB_4855_BDF7_609F1EECB8B4

/* all these definitions, are included into bits/in.h from libc6-dev 2.15-0ubuntu10
 * from Ubuntu 12.04 and is not included into libc6-dev 2.11.1-0ubuntu7.10 from
 * Ubuntu 10.04.
 * linux/in.h is not included directly because of lots of redefinitions,
 * extracting single value from linux/in.h is not done because it looks like
 * autotools reinvention */
#ifndef IP_ORIGDSTADDR
#   warning Using hardcoded value for IP_ORIGDSTADDR as libc headers do not define it.
#   define IP_ORIGDSTADDR 20
#endif

#ifndef IP_RECVORIGDSTADDR
#   warning Using hardcoded value for IP_RECVORIGDSTADDR as libc headers do not define it.
#   define IP_RECVORIGDSTADDR IP_ORIGDSTADDR
#endif

#ifndef IPV6_ORIGDSTADDR
#   warning Using hardcoded value for IPV6_ORIGDSTADDR as libc headers do not define it.
#   define IPV6_ORIGDSTADDR 74
#endif

#ifndef IPV6_RECVORIGDSTADDR
#   warning Using hardcoded value for IPV6_RECVORIGDSTADDR as libc headers do not define it.
#   define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#endif

#ifndef IP_TRANSPARENT
#   warning Using hardcoded value for IP_TRANSPARENT as libc headers do not define it.
#   define IP_TRANSPARENT 19
#endif

#ifndef IPV6_TRANSPARENT
#   warning Using hardcoded value for IPV6_TRANSPARENT as libc headers do not define it.
#   define IPV6_TRANSPARENT 75
#endif

#ifndef SOL_IP
#   warning Using hardcoded value for SOL_IP as libc headers do not define it.
#   define SOL_IP IPPROTO_IP
#endif

#ifdef __FreeBSD__
#ifndef INADDR_LOOPBACK
#   warning Using hardcoded value for INADDR_LOOPBACK for FreeBSD.
#   define INADDR_LOOPBACK		0x7F000001
#endif
#endif
#endif // 67C91670_FCCB_4855_BDF7_609F1EECB8B4
