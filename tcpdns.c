/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2014 Zhuofei Wang <semigodking@gmail.com>
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
#define DNS_Z  0x70
#define DEFAULT_TIMEOUT_SECONDS 4

#define FLAG_TCP_TEST 0x01
#define FLAG_UDP_TEST 0x02

typedef enum tcpdns_state_t {
    STATE_NEW,
    STATE_REQUEST_SENT,
    STATE_RECV_RESPONSE,
    STATE_RESPONSE_SENT,
    STATE_CONNECTION_TIMEOUT,
} tcpdns_state;


/***********************************************************************
 * Logic
 */
static void tcpdns_drop_request(dns_request * req)
{
    int fd;
    tcpdns_log_error(LOG_DEBUG, "dropping request");
    if (req->resolver)
    {
        fd = bufferevent_getfd(req->resolver);
        bufferevent_free(req->resolver);
        close(fd);
    }

    if (req->delay && req->state != STATE_RESPONSE_SENT)
    {
        * req->delay = req->state == STATE_CONNECTION_TIMEOUT ? -1 : 0; 
    }

    list_del(&req->list);
    free(req);
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

    tcpdns_log_error(LOG_DEBUG, "response size: %d", input_size);

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
        if (read_size > 2)
        {
            int fd = EVENT_FD(&req->instance->listener);
            sendto(fd, &buff.raw[2], ntohs(buff.len), 0,
                  (struct sockaddr*)&req->client_addr, sizeof(req->client_addr));
            req->state = STATE_RESPONSE_SENT;
            // calculate and update DNS resolver's delay
            if (req->delay)
            {
                gettimeofday(&tv, 0);
                timersub(&tv, &req->req_time, &tv);
                * req->delay = tv.tv_sec*1000+tv.tv_usec/1000;
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
        tcpdns_log_errno(LOG_ERR, "bufferevent_write_buffer");
        tcpdns_drop_request(req);
        return;
    }
    
    // Set timeout for read with time left since connection setup.
    gettimeofday(&tv, 0);
    timersub(&tv, &req->req_time, &tv);
    tv2.tv_sec = DEFAULT_TIMEOUT_SECONDS;
    tv2.tv_usec = 0;
    if (req->instance->config.timeout > 0)
        tv2.tv_sec = req->instance->config.timeout;
    timersub(&tv2, &tv, &tv);
    if (tv.tv_sec >=0) {
        bufferevent_set_timeouts(buffev, &tv, NULL);
        bufferevent_enable(buffev, EV_READ);
        req->state = STATE_REQUEST_SENT;
    }
    else {
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
        req->state = STATE_CONNECTION_TIMEOUT;
    }
    tcpdns_drop_request(req);
}

static struct sockaddr_in * choose_tcpdns(tcpdns_instance * instance, int **delay)
{
    static int n = 0;
    log_error(LOG_DEBUG, "Dealy of TCP DNS resolvers: %d, %d", instance->tcp1_delay_ms, instance->tcp2_delay_ms);
    if (instance->config.tcpdns1_addr.sin_addr.s_addr != htonl(INADDR_ANY)
    && (instance->config.tcpdns2_addr.sin_addr.s_addr != htonl(INADDR_ANY))
    )
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
    if (instance->config.tcpdns1_addr.sin_addr.s_addr != htonl(INADDR_ANY))
        goto return_tcp1;
    if (instance->config.tcpdns2_addr.sin_addr.s_addr != htonl(INADDR_ANY))
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
    struct sockaddr_in * destaddr;
    ssize_t pktlen;

    assert(fd == EVENT_FD(&self->listener));
    /* allocate and initialize request structure */
    req = (dns_request *)calloc(sizeof(dns_request), 1);
    if (!req)
    {
        log_error(LOG_INFO, "Out of memeory.");
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
        && !req->data.header.ancount && !req->data.header.nscount && !req->data.header.arcount /* no answers */
    ) 
    {
        tv.tv_sec = DEFAULT_TIMEOUT_SECONDS;
        tv.tv_usec = 0;
        if (self->config.timeout>0)
            tv.tv_sec = self->config.timeout;

        destaddr = choose_tcpdns(self, &req->delay);
        if (!destaddr)
        {
            tcpdns_log_error(LOG_WARNING, "No valid DNS resolver configured");
            free(req);
            return;
        }
        /* connect to target directly without going through proxy */
        req->resolver = red_connect_relay2(destaddr,
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
    { .key = "local_ip",   .type = pt_in_addr },
    { .key = "local_port", .type = pt_uint16 },
    { .key = "tcpdns1",    .type = pt_in_addr },
    { .key = "tcpdns2",    .type = pt_in_addr },
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
    instance->config.bindaddr.sin_family = AF_INET;
    instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.udpdns1_addr.sin_family = AF_INET;
    instance->config.udpdns1_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    instance->config.udpdns1_addr.sin_port = htons(53);
    instance->config.udpdns2_addr.sin_family = AF_INET;
    instance->config.udpdns2_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    instance->config.udpdns2_addr.sin_port = htons(53);
    instance->config.tcpdns1_addr.sin_family = AF_INET;
    instance->config.tcpdns1_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    instance->config.tcpdns1_addr.sin_port = htons(53);
    instance->config.tcpdns2_addr.sin_family = AF_INET;
    instance->config.tcpdns2_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    instance->config.tcpdns2_addr.sin_port = htons(53);

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
            (strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
            (strcmp(entry->key, "udpdns1") == 0)   ? (void*)&instance->config.udpdns1_addr.sin_addr :
            (strcmp(entry->key, "udpdns2") == 0)   ? (void*)&instance->config.udpdns2_addr.sin_addr :
            (strcmp(entry->key, "tcpdns1") == 0)   ? (void*)&instance->config.tcpdns1_addr.sin_addr :
            (strcmp(entry->key, "tcpdns2") == 0)   ? (void*)&instance->config.tcpdns2_addr.sin_addr :
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

    if (instance->config.bindaddr.sin_port == 0)
        err = "Local port must be configured";
    else
        instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);

    if (instance->config.tcpdns1_addr.sin_addr.s_addr == htonl(INADDR_ANY)
        && instance->config.tcpdns2_addr.sin_addr.s_addr == htonl(INADDR_ANY))
        err = "At least one TCP DNS resolver must be configured.";

    if (err)
        parser_error(section->context, "%s", err);
    else
        list_add(&instance->list, &instances);

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

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, sizeof(instance->config.bindaddr));
    if (error) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    event_assign(&instance->listener, get_event_base(), fd, EV_READ | EV_PERSIST, tcpdns_pkt_from_client, instance);
    error = event_add(&instance->listener, NULL);
    if (error)
    {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    return 0;

fail:
    tcpdns_fini_instance(instance);

    if (fd != -1) {
        if (close(fd) != 0)
            log_errno(LOG_WARNING, "close");
    }

    return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void tcpdns_fini_instance(tcpdns_instance *instance)
{
    if (event_initialized(&instance->listener)) {
        if (event_del(&instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        if (close(EVENT_FD(&instance->listener)) != 0)
            log_errno(LOG_WARNING, "close");
        memset(&instance->listener, 0, sizeof(instance->listener));
    }

    list_del(&instance->list);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

static int tcpdns_init()
{
    tcpdns_instance *tmp, *instance = NULL;

    // TODO: init debug_dumper

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
    .conf_section = &tcpdns_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
