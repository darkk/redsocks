#ifndef SHADOWSOCKS_H
#define SHADOWSOCKS_H

enum {
    ss_addrtype_ipv4 = 1,
    ss_addrtype_domain = 3,
    ss_addrtype_ipv6 = 4,
};

typedef struct ss_header_ipv4_t {
    unsigned char addr_type;
    uint32_t addr;
    uint16_t port;
} PACKED ss_header_ipv4;

typedef struct ss_header_ipv6_t {
    unsigned char addr_type;
    struct in6_addr addr;
    uint16_t port;
} PACKED ss_header_ipv6;

typedef union {
    unsigned char addr_type;
    ss_header_ipv4 v4;
    ss_header_ipv6 v6;
} ss_header;

#endif
