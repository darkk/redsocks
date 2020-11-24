/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
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
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#include "base.h"
#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "tcpdns.h"
#include "utils.h"

#define tcpdns_log_error(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &req->client_addr, &req->instance->config.bindaddr, prio, ## msg)
#define tcpdns_log_errno(prio, msg...) \
    redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &req->client_addr, &req->instance->config.bindaddr, prio, ## msg)

static void tcpdns_fini_instance(tcpdns_instance *instance);
static int tcpdns_fini();

#define DNS_QR 0x80
#define DNS_TC 0x02
#define DNS_Z  0x40
#define DNS_RC_MASK      0x0F

#define DNS_RC_NOERROR   0
#define DNS_RC_FORMERR   1
#define DNS_RC_SERVFAIL  2
#define DNS_RC_NXDOMAIN  3
#define DNS_RC_NOTIMP    4
#define DNS_RC_REFUSED   5
#define DNS_RC_YXDOMAIN  6
#define DNS_RC_XRRSET    7
#define DNS_RC_NOTAUTH   8
#define DNS_RC_NOTZONE   9

#define DEFAULT_TIMEOUT_SECONDS 4

#define FLAG_TCP_TEST 0x01
#define FLAG_UDP_TEST 0x02

typedef enum tcpdns_state_t {
    STATE_NEW,
    STATE_REQUEST_SENT,
    STATE_RESPONSE_SENT,
} tcpdns_state;


/***********************************************************************
 * Logic
 */
static void tcpdns_drop_request(dns_request * req)
{
    int fd;
    tcpdns_log_error(LOG_DEBUG, "dropping request @ state: %d", req->state);
    if (req->resolver)
    {
        fd = bufferevent_getfd(req->resolver);
        bufferevent_free(req->resolver);
        close(fd);
    }

    list_del(&req->list);
    free(req);
}

static inline void tcpdns_update_delay(dns_request * req, int delay)
{
    if (req->delay)
        * req->delay = delay;
}

static void tcpdns_readcb(struct bufferevent *from, void *_arg)
{
    dns_request * req = _arg;
    union {
        short len;
        char  raw[4096];
    } buff;
    struct timeval tv;
    assert(from == req->resolver);
    size_t input_size = evbuffer_get_length(bufferevent_get_input(from));
    size_t read_size;

    tcpdns_log_error(LOG_DEBUG, "response size: %zu", input_size);

    if (input_size == 0 || input_size > sizeof(buff))
        // EOF or response is too large. Drop it.
        goto finish;

    if (req->state == STATE_REQUEST_SENT 
        && input_size > 2 // At least length indicator is received
        )
    {
        // FIXME:
        // suppose we got all data in one read 
        read_size = bufferevent_read(from, &buff, sizeof(buff));
        if (read_size > (2 + sizeof(dns_header)))
        {
            dns_header * dh = (dns_header *)&buff.raw[2]; 
            switch (dh->ra_z_rcode & DNS_RC_MASK) {
                case DNS_RC_NOERROR:
                case DNS_RC_FORMERR:
                case DNS_RC_NXDOMAIN:
                    {
                        int fd = event_get_fd(req->instance->listener);
                        if (sendto(fd, &buff.raw[2], read_size - 2, 0,
                                (struct sockaddr*)&req->client_addr,
                                sizeof(req->client_addr)) != read_size - 2) {
                            tcpdns_log_errno(LOG_ERR, "sendto");
                        }
                        req->state = STATE_RESPONSE_SENT;
                        // calculate and update DNS resolver's delay
                        gettimeofday(&tv, 0);
                        timersub(&tv, &req->req_time, &tv);
                        tcpdns_update_delay(req, tv.tv_sec*1000+tv.tv_usec/1000);
                    }
                    break;
                default:
                    // panalize server
                    tcpdns_update_delay(req, (req->instance->config.timeout + 1) * 1000);
            }
        }
    }
finish:
    tcpdns_drop_request(req);
}


static void tcpdns_connected(struct bufferevent *buffev, void *_arg)
{
    dns_request * req = _arg;
    assert(buffev == req->resolver);
    struct timeval tv, tv2;

    if (!red_is_socket_connected_ok(buffev)) 
    {
        tcpdns_log_error(LOG_DEBUG, "failed to connect to destination");
        tcpdns_drop_request(req);
        return;
    }

    if (req->state != STATE_NEW)
        // Nothing to write
        return;

    // Write dns request to DNS resolver and shutdown connection
    uint16_t len = htons((uint16_t)req->data_len);
    if (bufferevent_write(buffev, &len, sizeof(uint16_t)) == -1
        || bufferevent_write(buffev, &req->data.raw, req->data_len) == -1)
    {
        tcpdns_log_errno(LOG_ERR, "bufferevent_write");
        tcpdns_drop_request(req);
        return;
    }
    
    // Set timeout for read with time left since connection setup.
    gettimeofday(&tv, 0);
    timersub(&tv, &req->req_time, &tv);
    tv2.tv_sec = req->instance->config.timeout;
    tv2.tv_usec = 0;
    timersub(&tv2, &tv, &tv);
    if (tv.tv_sec > 0 || tv.tv_usec > 0) {
        bufferevent_set_timeouts(buffev, &tv, NULL);
        // Allow reading response
        bufferevent_enable(buffev, EV_READ);
        req->state = STATE_REQUEST_SENT;
    }
    else {
        tcpdns_update_delay(req, tv2.tv_sec * 1000);
        tcpdns_drop_request(req);
    }
}


static void tcpdns_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    dns_request * req = _arg;
    int saved_errno = errno;
    assert(buffev == req->resolver);

    tcpdns_log_errno(LOG_DEBUG, "errno(%d), what: " event_fmt_str, 
                            saved_errno, event_fmt(what));

    if (req->state == STATE_NEW 
        && what == (BEV_EVENT_WRITING | BEV_EVENT_TIMEOUT))
    {
        tcpdns_update_delay(req, -1);
    }
    else if (saved_errno == ECONNRESET) {
        // If connect is reset, try to not use this DNS server next time.
        tcpdns_update_delay(req, (req->instance->config.timeout + 1) * 1000);
    }
    tcpdns_drop_request(req);
}

static struct sockaddr_storage * choose_tcpdns(tcpdns_instance * instance, int **delay)
{
    static int n = 0;
    log_error(LOG_DEBUG, "Dealy of TCP DNS resolvers: %d, %d", instance->tcp1_delay_ms, instance->tcp2_delay_ms);
    if (instance->config.tcpdns1 && instance->config.tcpdns2)
    {
        if (instance->tcp1_delay_ms <= 0 
           && instance->tcp2_delay_ms <= 0)
        {
            // choose one
            n += 1;
            if (n%2)
                goto return_tcp1;
            else
                goto return_tcp2;
        }
        if (instance->tcp1_delay_ms > instance->tcp2_delay_ms)
        {
            if (instance->tcp2_delay_ms < 0)
                goto return_tcp1;
            else
                goto return_tcp2;
        }
        else
        {
            if (instance->tcp1_delay_ms < 0)
                goto return_tcp2;
            else
                goto return_tcp1;
        }
    }
    if (instance->config.tcpdns1)
        goto return_tcp1;
    if (instance->config.tcpdns2)
        goto return_tcp2;

    * delay = NULL;
    return NULL;

return_tcp1:
    * delay = &instance->tcp1_delay_ms;
    return &instance->config.tcpdns1_addr;

return_tcp2:
    * delay = &instance->tcp2_delay_ms;
    return &instance->config.tcpdns2_addr;

}

static void tcpdns_pkt_from_client(int fd, short what, void *_arg)
{
    tcpdns_instance *self = _arg;
    dns_request * req = NULL;
    struct timeval tv;
    struct sockaddr_storage * destaddr;
    ssize_t pktlen;

    assert(fd == event_get_fd(self->listener));
    /* allocate and initialize request structure */
    req = (dns_request *)calloc(sizeof(dns_request), 1);
    if (!req)
    {
        log_error(LOG_ERR, "Out of memeory.");
        return;
    }
    req->instance = self;
    req->state = STATE_NEW;
    gettimeofday(&req->req_time, 0);
    pktlen = red_recv_udp_pkt(fd, req->data.raw, sizeof(req->data.raw), &req->client_addr, NULL);
    if (pktlen == -1)
    {
        free(req);
        return;
    }
    if (pktlen <= sizeof(dns_header)) 
    {
        tcpdns_log_error(LOG_INFO, "incomplete DNS request");
        free(req);
        return;
    }
    req->data_len = pktlen;

    if ( (req->data.header.qr_opcode_aa_tc_rd & DNS_QR) == 0 /* query */
        && (req->data.header.ra_z_rcode & DNS_Z) == 0 /* Z is Zero */
        && req->data.header.qdcount /* some questions */
        && !req->data.header.ancount && !req->data.header.nscount
    ) 
    {
        tv.tv_sec = self->config.timeout;
        tv.tv_usec = 0;

        destaddr = choose_tcpdns(self, &req->delay);
        if (!destaddr)
        {
            tcpdns_log_error(LOG_WARNING, "No valid DNS resolver configured");
            free(req);
            return;
        }
        /* connect to target directly without going through proxy */
        req->resolver = red_connect_relay(NULL, destaddr,
                        tcpdns_readcb, tcpdns_connected, tcpdns_event_error, req, 
                        &tv);
        if (req->resolver) 
            list_add(&req->list, &self->requests);
        else
        {
            tcpdns_log_error(LOG_INFO, "Failed to setup connection to DNS resolver");
            free(req);
        }
    }
    else
    {
        tcpdns_log_error(LOG_INFO, "malformed DNS request");
        free(req);
    }
}

/***********************************************************************
 * DNS Resolver Delay Checking
 */
static void check_udpdns_delay()
{
}

static void check_tcpdns_delay()
{
}

static void check_dns_delay()
{
    check_udpdns_delay();
    check_tcpdns_delay();
}


/***********************************************************************
 * Init / shutdown
 */
static parser_entry tcpdns_entries[] =
{
    { .key = "bind",       .type = pt_pchar },
    { .key = "tcpdns1",    .type = pt_pchar },
    { .key = "tcpdns2",    .type = pt_pchar },
    { .key = "timeout",    .type = pt_uint16 },
    { }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int tcpdns_onenter(parser_section *section)
{
    tcpdns_instance *instance = calloc(1, sizeof(*instance));
    if (!instance) {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    INIT_LIST_HEAD(&instance->list);
    INIT_LIST_HEAD(&instance->requests);
    struct sockaddr_in * addr = (struct sockaddr_in *)&instance->config.bindaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr->sin_port = htons(53);

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "bind") == 0)   ? (void*)&instance->config.bind:
            (strcmp(entry->key, "tcpdns1") == 0)   ? (void*)&instance->config.tcpdns1 :
            (strcmp(entry->key, "tcpdns2") == 0)   ? (void*)&instance->config.tcpdns2 :
            (strcmp(entry->key, "timeout") == 0) ? (void*)&instance->config.timeout :
            NULL;
    section->data = instance;
    return 0;
}

static int tcpdns_onexit(parser_section *section)
{
    const char *err = NULL;
    tcpdns_instance *instance = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    // Parse and update bind address and relay address
    if (instance->config.bind) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.bindaddr;
        int addr_size = sizeof(instance->config.bindaddr);
        if (evutil_parse_sockaddr_port(instance->config.bind, addr, &addr_size))
            err = "invalid bind address";
    }
    if (!err && instance->config.tcpdns1) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.tcpdns1_addr;
        int addr_size = sizeof(instance->config.tcpdns1_addr);
        if (evutil_parse_sockaddr_port(instance->config.tcpdns1, addr, &addr_size))
            err = "invalid tcpdns1 address";
        else if (addr->sa_family == AF_INET && ((struct sockaddr_in *)addr)->sin_port == 0)
            ((struct sockaddr_in *)addr)->sin_port = htons(53);
        else if (addr->sa_family == AF_INET6 && ((struct sockaddr_in6 *)addr)->sin6_port == 0)
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(53);
    }
    if (!err && instance->config.tcpdns2) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.tcpdns2_addr;
        int addr_size = sizeof(instance->config.tcpdns2_addr);
        if (evutil_parse_sockaddr_port(instance->config.tcpdns2, addr, &addr_size))
            err = "invalid tcpdns2 address";
        else if (addr->sa_family == AF_INET && ((struct sockaddr_in *)addr)->sin_port == 0)
            ((struct sockaddr_in *)addr)->sin_port = htons(53);
        else if (addr->sa_family == AF_INET6 && ((struct sockaddr_in6 *)addr)->sin6_port == 0)
            ((struct sockaddr_in6 *)addr)->sin6_port = htons(53);
    }


    if (instance->config.tcpdns1 == NULL && instance->config.tcpdns2 == NULL)
        err = "At least one TCP DNS resolver must be configured.";

    if (err)
        parser_error(section->context, "%s", err);
    else
        list_add(&instance->list, &instances);
    // If timeout is not configured or is configured as zero, use default timeout.
    if (instance->config.timeout == 0)
        instance->config.timeout = DEFAULT_TIMEOUT_SECONDS;
    return err ? -1 : 0;
}

static int tcpdns_init_instance(tcpdns_instance *instance)
{
    /* FIXME: tcpdns_fini_instance is called in case of failure, this
     *        function will remove instance from instances list - result
     *        looks ugly.
     */
    int error;
    int fd = -1;
    int bindaddr_len = 0;
    char buf1[RED_INET_ADDRSTRLEN];

    fd = socket(instance->config.bindaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }
    if (apply_reuseport(fd))
        log_error(LOG_WARNING, "Continue without SO_REUSEPORT enabled");

#if defined(__APPLE__) || defined(__FreeBSD__)
    bindaddr_len = instance->config.bindaddr.ss_len > 0 ? instance->config.bindaddr.ss_len : sizeof(instance->config.bindaddr);
#else
    bindaddr_len = sizeof(instance->config.bindaddr);
#endif
    error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, bindaddr_len);
    if (error) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    instance->listener = event_new(get_event_base(), fd, EV_READ | EV_PERSIST, tcpdns_pkt_from_client, instance);
    if (!instance->listener) {
        log_errno(LOG_ERR, "event_new");
        goto fail;
    }
    error = event_add(instance->listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    log_error(LOG_INFO, "tcpdns @ %s",
        red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)));
    return 0;

fail:
    tcpdns_fini_instance(instance);

    if (fd != -1 && close(fd) != 0)
        log_errno(LOG_WARNING, "close");

    return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void tcpdns_fini_instance(tcpdns_instance *instance)
{
    if (instance->listener) {
        if (event_del(instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        if (close(event_get_fd(instance->listener)) != 0)
            log_errno(LOG_WARNING, "close");
        event_free(instance->listener);
    }

    list_del(&instance->list);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

static int tcpdns_init()
{
    tcpdns_instance *tmp, *instance = NULL;

    list_for_each_entry_safe(instance, tmp, &instances, list) {
        if (tcpdns_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    tcpdns_fini();
    return -1;
}

static int tcpdns_fini()
{
    tcpdns_instance *tmp, *instance = NULL;

    list_for_each_entry_safe(instance, tmp, &instances, list)
        tcpdns_fini_instance(instance);

    return 0;
}

static void tcpdns_dump_instance(tcpdns_instance *instance)
{
    char buf1[RED_INET_ADDRSTRLEN];

    log_error(LOG_INFO, "Dumping data for instance (tcpdns @ %s):",
                        red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)));
    log_error(LOG_INFO, "Delay of TCP DNS [%s]: %dms",
                        red_inet_ntop(&instance->config.tcpdns1_addr, buf1, sizeof(buf1)),
                        instance->tcp1_delay_ms);
    log_error(LOG_INFO, "Delay of TCP DNS [%s]: %dms",
                        red_inet_ntop(&instance->config.tcpdns2_addr, buf1, sizeof(buf1)),
                        instance->tcp2_delay_ms);
    log_error(LOG_INFO, "End of data dumping.");
}


static void tcpdns_debug_dump()
{
    tcpdns_instance *instance = NULL;

    list_for_each_entry(instance, &instances, list)
        tcpdns_dump_instance(instance);
}

static parser_section tcpdns_conf_section =
{
    .name    = "tcpdns",
    .entries = tcpdns_entries,
    .onenter = tcpdns_onenter,
    .onexit  = tcpdns_onexit
};

app_subsys tcpdns_subsys =
{
    .init = tcpdns_init,
    .fini = tcpdns_fini,
    .dump = tcpdns_debug_dump,
    .conf_section = &tcpdns_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
