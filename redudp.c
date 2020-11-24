/* redsocks2 - transparent TCP/UDP-to-proxy redirector
 * Copyright (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
 * Licensed under the Apache License, Version 2.0 (the "License").
 *
 *
 * redsocks - transparent TCP-to-proxy redirector
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
#include <search.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "base.h"
#include "list.h"
#include "log.h"
#include "socks5.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "redudp.h"
#include "libc-compat.h"

#define DEFAULT_MAX_PKTQUEUE  5
#define DEFAULT_UDP_TIMEOUT   30
#define REDUDP_AUDIT_INTERVAL 10

// Multiple instances share the same buffer for message receiving
static char shared_buff[MAX_UDP_PACKET_SIZE];// max size of UDP packet is less than 64K

static void redudp_fini_instance(redudp_instance *instance);
static int redudp_fini();

struct bound_udp4_key {
    struct in_addr sin_addr;
    uint16_t       sin_port;
};

struct bound_udp4 {
    struct bound_udp4_key key;
    int ref;
    int fd;
    time_t t_last_rx;
};

extern udprelay_subsys socks5_udp_subsys;
#if !defined(DISABLE_SHADOWSOCKS)
extern udprelay_subsys shadowsocks_udp_subsys;
#endif
static udprelay_subsys *relay_subsystems[] =
{
    &socks5_udp_subsys,
    #if !defined(DISABLE_SHADOWSOCKS)
    &shadowsocks_udp_subsys,
    #endif
};
/***********************************************************************
 * Helpers
 */
// TODO: separate binding to privileged process (this operation requires uid-0)
static void* root_bound_udp4 = NULL; // to avoid two binds to same IP:port

static int bound_udp4_cmp(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(struct bound_udp4_key));
}

static void bound_udp4_mkkey(struct bound_udp4_key *key, const struct sockaddr_in *addr)
{
    memset(key, 0, sizeof(*key));
    key->sin_addr = addr->sin_addr;
    key->sin_port = addr->sin_port;
}

static int bound_udp4_get(const struct sockaddr_in *addr)
{
    struct bound_udp4_key key;
    struct bound_udp4 *node, **pnode;

    bound_udp4_mkkey(&key, addr);
    // I assume, that memory allocation for lookup is awful, so I use
    // tfind/tsearch pair instead of tsearch/check-result.
    pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
    if (pnode) {
        assert((*pnode)->ref > 0);
        (*pnode)->ref++;
        (*pnode)->t_last_rx = redsocks_time(NULL);
        return (*pnode)->fd;
    }

    node = calloc(1, sizeof(*node));
    if (!node) {
        log_errno(LOG_ERR, "calloc");
        goto fail;
    }

    node->key = key;
    node->ref = 1;
    node->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    node->t_last_rx = redsocks_time(NULL);
    if (node->fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    if (0 != make_socket_transparent(node->fd))
        goto fail;

    if (evutil_make_listen_socket_reuseable(node->fd)) {
        log_errno(LOG_ERR, "evutil_make_listen_socket_reuseable");
        goto fail;
    }

    if (0 != bind(node->fd, (struct sockaddr*)addr, sizeof(*addr))) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    if (0 != evutil_make_socket_nonblocking(node->fd)) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    pnode = tsearch(node, &root_bound_udp4, bound_udp4_cmp);
    if (!pnode) {
        log_errno(LOG_ERR, "tsearch(%p) == %p", node, pnode);
        goto fail;
    }
    assert(node == *pnode);

    return node->fd;

fail:
    if (node) {
        if (node->fd != -1)
            close(node->fd);
        free(node);
    }
    return -1;
}

static void bound_udp4_put(const struct sockaddr_in *addr)
{
    struct bound_udp4_key key;
    struct bound_udp4 **pnode, *node;
    void *parent;

    bound_udp4_mkkey(&key, addr);
    pnode = tfind(&key, &root_bound_udp4, bound_udp4_cmp);
    assert(pnode && (*pnode)->ref > 0);

    node = *pnode;

    node->ref--;
    if (node->ref)
        return;

    parent = tdelete(node, &root_bound_udp4, bound_udp4_cmp);
    assert(parent);

    close(node->fd); // expanding `pnode` to avoid use after free
    free(node);
}

/*
 * This procedure is ued to audit tree items for destination addresses.
 * For each destination address, if no packet received from it for a certain period,
 * it is removed and the corresponding FD is closed.
 */
static void bound_udp4_action(const void *nodep, const VISIT which, const int depth)
{
    time_t now;
    struct bound_udp4 *datap;
    void *parent;
    char buf[RED_INET_ADDRSTRLEN];

    switch (which) {
        case preorder:
        case postorder:
            break;
        case endorder:
        case leaf:
            now = redsocks_time(NULL);
            datap = *(struct bound_udp4 **) nodep;
            // TODO: find a proper way to make timeout configurable for each instance.
            if (datap->t_last_rx + 20 < now) {
                parent = tdelete(datap, &root_bound_udp4, bound_udp4_cmp);
                assert(parent);

                inet_ntop(AF_INET, &datap->key.sin_addr, &buf[0], sizeof(buf));
                log_error(LOG_DEBUG, "Close UDP socket %d to %s:%u", datap->fd,
                                     &buf[0], datap->key.sin_port);
                close(datap->fd);
                free(datap);
            }
            break;
    }
}

static int do_tproxy(redudp_instance* instance)
{
    return instance->config.dest == NULL;
}

struct sockaddr_storage* get_destaddr(redudp_client *client)
{
    if (do_tproxy(client->instance))
        return &client->destaddr;
    else
        return &client->instance->config.destaddr;
}

/***********************************************************************
 * Logic
 */
void redudp_drop_client(redudp_client *client)
{
    redudp_log_error(client, LOG_DEBUG, "Dropping client @ state: %d", client->state);
    enqueued_packet *q, *tmp;

    if (client->instance->relay_ss->fini)
        client->instance->relay_ss->fini(client);

    if (client->timeoutev) {
        if (evtimer_del(client->timeoutev) == -1)
            redudp_log_errno(client, LOG_ERR, "event_del");
        event_free(client->timeoutev);
    }
    list_for_each_entry_safe(q, tmp, &client->queue, list) {
        list_del(&q->list);
        free(q);
    }
    list_del(&client->list);
    free(client);
}

void redudp_bump_timeout(redudp_client *client)
{
    struct timeval tv;
    tv.tv_sec = client->instance->config.udp_timeout;
    tv.tv_usec = 0;
    // TODO: implement udp_timeout_stream
    if (event_add(client->timeoutev, &tv) != 0) {
        redudp_log_error(client, LOG_WARNING, "event_add(&client->timeoutev, ...)");
        redudp_drop_client(client);
    }
}

void redudp_fwd_pkt_to_sender(redudp_client *client, void *buf, size_t len,
                              struct sockaddr_storage * srcaddr)
{
    size_t sent;
    int fd;
    redsocks_time(&client->last_relay_event);
    redudp_bump_timeout(client);

    // When working with TPROXY, we have to get sender FD from tree on
    // receipt of each packet from relay.
    // FIXME: Support IPv6
    fd = (do_tproxy(client->instance) && srcaddr->ss_family == AF_INET)
        ? bound_udp4_get((struct sockaddr_in*)srcaddr) : event_get_fd(client->instance->listener);
    if (fd == -1) {
        redudp_log_error(client, LOG_WARNING, "bound_udp4_get failure");
        return;
    }
    // TODO: record remote address in client

    sent = sendto(fd, buf, len, 0,
                  (struct sockaddr*)&client->clientaddr, sizeof(client->clientaddr));
    if (sent != len) {
        redudp_log_error(
            client,
            LOG_WARNING,
            "sendto: I was sending %zd bytes, but only %zd were sent.",
            len,
            sent);
        return;
    }
}

static int redudp_enqeue_pkt(
    redudp_client *client,
    struct sockaddr_storage * destaddr,
    char *buf,
    size_t pktlen)
{
    enqueued_packet *q = NULL;

    if (client->queue_len >= client->instance->config.max_pktqueue) {
        redudp_log_error(client, LOG_WARNING, "There are already %u packets in queue. Dropping.",
                         client->queue_len);
        return -1;
    }

    q = malloc(sizeof(enqueued_packet) + pktlen);
    if (!q) {
        redudp_log_errno(client, LOG_ERR, "Can't enqueue packet: malloc");
        return -1;
    }

    INIT_LIST_HEAD(&q->list);
    memcpy(&q->destaddr, destaddr, sizeof(*destaddr));
    q->len = pktlen;
    memcpy(q->data, buf, pktlen);
    client->queue_len += 1;
    list_add_tail(&q->list, &client->queue);
    return 0;
}

void redudp_flush_queue(redudp_client *client)
{
    enqueued_packet *q, *tmp;
    assert(client->instance->relay_ss->ready_to_fwd(client));

    redudp_log_error(client, LOG_DEBUG, "Starting UDP relay");
    list_for_each_entry_safe(q, tmp, &client->queue, list) {
        client->instance->relay_ss->forward_pkt(client, (struct sockaddr *)&q->destaddr, q->data, q->len);
        list_del(&q->list);
        free(q);
    }
    client->queue_len = 0;
    assert(list_empty(&client->queue));
}

static void redudp_timeout(int fd, short what, void *_arg)
{
    redudp_client *client = _arg;
    redudp_log_error(client, LOG_DEBUG, "Client timeout. First: %li, last_client: %li, last_relay: %li.",
                     client->first_event, client->last_client_event, client->last_relay_event);
    redudp_drop_client(client);
}

static void redudp_first_pkt_from_client(
    redudp_instance *self,
    struct sockaddr_storage *clientaddr,
    struct sockaddr_storage *destaddr,
    char *buf,
    size_t pktlen)
{
    redudp_client *client = calloc(1, sizeof(*client)+self->relay_ss->payload_len);
    if (!client) {
        log_errno(LOG_WARNING, "calloc");
        return;
    }

    INIT_LIST_HEAD(&client->list);
    INIT_LIST_HEAD(&client->queue);
    client->instance = self;
    memcpy(&client->clientaddr, clientaddr, sizeof(*clientaddr));
    // TODO: remove client->destaddr
    if (destaddr)
        memcpy(&client->destaddr, destaddr, sizeof(client->destaddr));
    client->timeoutev = evtimer_new(get_event_base(), redudp_timeout, client);
    self->relay_ss->init(client);

    redsocks_time(&client->first_event);
    client->last_client_event = client->first_event;
    redudp_bump_timeout(client);

    list_add(&client->list, &self->clients);

    redudp_log_error(client, LOG_DEBUG, "got 1st packet from client");

    if (redudp_enqeue_pkt(client, destaddr, buf, pktlen) == -1)
        goto fail;

    if (self->relay_ss->connect_relay)
        self->relay_ss->connect_relay(client);
    return;

fail:
    redudp_drop_client(client);
}

static void redudp_pkt_from_client(int fd, short what, void *_arg)
{
    redudp_instance *self = _arg;
    struct sockaddr_storage clientaddr, destaddr, *pdestaddr;
    ssize_t pktlen;
    redudp_client *tmp, *client = NULL;

    pdestaddr = do_tproxy(self) ? &destaddr : NULL;

    assert(fd == event_get_fd(self->listener));
    // destaddr will be filled with true destination if it is available
    pktlen = red_recv_udp_pkt(fd, self->shared_buff, MAX_UDP_PACKET_SIZE, &clientaddr, pdestaddr);
    if (pktlen == -1)
        return;
    if (!pdestaddr)
        // In case tproxy is not used, use configured destination address instead.
        pdestaddr = &self->config.destaddr;

    // TODO: this lookup may be SLOOOOOW.
    list_for_each_entry(tmp, &self->clients, list) {
        if (0 == memcmp(&clientaddr, &tmp->clientaddr, sizeof(clientaddr))) {
            client = tmp;
            break;
        }
    }

    if (client) {
        redsocks_time(&client->last_client_event);
        redudp_bump_timeout(client);

        if (self->relay_ss->ready_to_fwd(client)) {
            self->relay_ss->forward_pkt(client, (struct sockaddr *)pdestaddr, self->shared_buff, pktlen);
        }
        else {
            redudp_enqeue_pkt(client, pdestaddr, self->shared_buff, pktlen);
        }
    }
    else {
        redudp_first_pkt_from_client(self, &clientaddr, pdestaddr, self->shared_buff, pktlen);
    }
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry redudp_entries[] =
{
    { .key = "bind",       .type = pt_pchar },
    { .key = "relay",      .type = pt_pchar },
    { .key = "dest",       .type = pt_pchar },
    { .key = "type",       .type = pt_pchar },
    { .key = "login",      .type = pt_pchar },
    { .key = "password",   .type = pt_pchar },
    { .key = "udp_timeout", .type = pt_uint16 },
    { .key = "udp_timeout_stream", .type = pt_uint16 },
    { .key = "max_pktqueue", .type = pt_uint16 },
    { }
};

static list_head instances = LIST_HEAD_INIT(instances);

static int redudp_onenter(parser_section *section)
{
    // FIXME: find proper way to calulate instance_payload_len
    int instance_payload_len = 0;
    udprelay_subsys **ss;
    FOREACH(ss, relay_subsystems)
        if (instance_payload_len < (*ss)->instance_payload_len)
            instance_payload_len = (*ss)->instance_payload_len;

    redudp_instance *instance = calloc(1, sizeof(*instance) + instance_payload_len);
    if (!instance) {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    INIT_LIST_HEAD(&instance->list);
    INIT_LIST_HEAD(&instance->clients);
    struct sockaddr_in * addr = (struct sockaddr_in *)&instance->config.bindaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.max_pktqueue = DEFAULT_MAX_PKTQUEUE;
    instance->config.udp_timeout = DEFAULT_UDP_TIMEOUT;
    instance->config.udp_timeout_stream = 180;

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "bind") == 0)       ? (void*)&instance->config.bind :
            (strcmp(entry->key, "relay") == 0)      ? (void*)&instance->config.relay :
            (strcmp(entry->key, "dest") == 0)       ? (void*)&instance->config.dest :
            (strcmp(entry->key, "type") == 0)       ? (void*)&instance->config.type :
            (strcmp(entry->key, "login") == 0)      ? (void*)&instance->config.login :
            (strcmp(entry->key, "password") == 0)   ? (void*)&instance->config.password :
            (strcmp(entry->key, "max_pktqueue") == 0) ? (void*)&instance->config.max_pktqueue :
            (strcmp(entry->key, "udp_timeout") == 0) ? (void*)&instance->config.udp_timeout:
            (strcmp(entry->key, "udp_timeout_stream") == 0) ? (void*)&instance->config.udp_timeout_stream :
            NULL;
    section->data = instance;
    return 0;
}

static int redudp_onexit(parser_section *section)
{
    redudp_instance *instance = section->data;
    char * err = NULL;

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
    if (!err && instance->config.relay) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.relayaddr;
        int addr_size = sizeof(instance->config.relayaddr);
        if (evutil_parse_sockaddr_port(instance->config.relay, addr, &addr_size))
            err = "invalid relay address";
    }
    else if (!instance->config.relay)
        err = "missing relay address";
    if (!err && instance->config.dest) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.destaddr;
        int addr_size = sizeof(instance->config.destaddr);
        if (evutil_parse_sockaddr_port(instance->config.dest, addr, &addr_size))
            err = "invalid dest address";
    }

    if (instance->config.type) {
        udprelay_subsys **ss;
        FOREACH(ss, relay_subsystems) {
            if (!strcmp((*ss)->name, instance->config.type)) {
                instance->relay_ss = *ss;
                list_add(&instance->list, &instances);
                break;
            }
        }
        if (!instance->relay_ss)
            err = "invalid `type` for redudp";
    }
    else {
        err = "no `type` for redudp";
    }


    if (instance->config.max_pktqueue == 0) {
        parser_error(section->context, "max_pktqueue must be greater than 0.");
        return -1;
    }
    if (instance->config.udp_timeout == 0) {
        parser_error(section->context, "udp_timeout must be greater than 0.");
        return -1;
    }
    if (instance->config.udp_timeout_stream < instance->config.udp_timeout) {
        parser_error(section->context, "udp_timeout_stream should be not less than udp_timeout");
        return -1;
    }

    return err?-1:0;
}

static int redudp_init_instance(redudp_instance *instance)
{
    /* FIXME: redudp_fini_instance is called in case of failure, this
     *        function will remove instance from instances list - result
     *        looks ugly.
     */
    int error;
    int fd = -1;
    int bindaddr_len = 0;
    char buf1[RED_INET_ADDRSTRLEN], buf2[RED_INET_ADDRSTRLEN];

    instance->shared_buff = &shared_buff[0];
    if (instance->relay_ss->instance_init
        && instance->relay_ss->instance_init(instance)) {
        log_errno(LOG_ERR, "Failed to init UDP relay subsystem.");
        goto fail;
    }

    fd = socket(instance->config.bindaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    if (do_tproxy(instance)) {
        int on = 1;
        // iptables TPROXY target does not send packets to non-transparent sockets
        if (0 != make_socket_transparent(fd))
            goto fail;
 
#ifdef SOL_IPV6
        if (instance->config.bindaddr.ss_family == AF_INET) {
#endif
            error = setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
            if (error) {
                log_errno(LOG_ERR, "setsockopt(listener, SOL_IP, IP_RECVORIGDSTADDR)");
                goto fail;
            }
#ifdef SOL_IPV6
        }
        else {
            error = setsockopt(fd, SOL_IPV6, IPV6_RECVORIGDSTADDR, &on, sizeof(on));
            if (error) {
                log_errno(LOG_ERR, "setsockopt(listener, SOL_IPV6, IPV6_RECVORIGDSTADDR)");
                goto fail;
            }
        }
#endif
        log_error(LOG_INFO, "redudp @ %s: TPROXY", red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)));
    }
    else {
        log_error(LOG_INFO, "redudp @ %s: destaddr=%s",
            red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)),
            red_inet_ntop(&instance->config.destaddr, buf2, sizeof(buf2)));
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
        log_errno(LOG_ERR, "set nonblocking");
        goto fail;
    }

    instance->listener = event_new(get_event_base(), fd, EV_READ | EV_PERSIST, redudp_pkt_from_client, instance);
    if (!instance->listener) {
        log_errno(LOG_ERR, "event_new");
        goto fail;
    }
    error = event_add(instance->listener, NULL);
    if (error) {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    return 0;

fail:
    redudp_fini_instance(instance);

    if (fd != -1) {
        close(fd);
    }

    return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void redudp_fini_instance(redudp_instance *instance)
{
    if (!list_empty(&instance->clients)) {
        redudp_client *tmp, *client = NULL;

        log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
        list_for_each_entry_safe(client, tmp, &instance->clients, list) {
            redudp_drop_client(client);
        }
    }

    if (instance->listener) {
        if (event_del(instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        close(event_get_fd(instance->listener));
        memset(&instance->listener, 0, sizeof(instance->listener));
    }

    if (instance->relay_ss->instance_fini)
        instance->relay_ss->instance_fini(instance);

    list_del(&instance->list);
    free(instance->config.type);
    free(instance->config.login);
    free(instance->config.password);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

static struct event * audit_event = NULL;

static void redudp_audit(int sig, short what, void *_arg)
{
    twalk(root_bound_udp4, bound_udp4_action);
}

static int redudp_init()
{
    redudp_instance *tmp, *instance = NULL;
    struct timeval audit_time;
    struct event_base * base = get_event_base();

    list_for_each_entry_safe(instance, tmp, &instances, list) {
        if (redudp_init_instance(instance) != 0)
            goto fail;
    }

    /* Start audit */
    audit_time.tv_sec = REDUDP_AUDIT_INTERVAL;
    audit_time.tv_usec = 0;
    audit_event = event_new(base, -1, EV_TIMEOUT|EV_PERSIST, redudp_audit, NULL);
    evtimer_add(audit_event, &audit_time);

    return 0;

fail:
    redudp_fini();
    return -1;
}

static int redudp_fini()
{
    redudp_instance *tmp, *instance = NULL;

    /* stop audit */
    if (audit_event) {
        evtimer_del(audit_event);
        event_free(audit_event);
        audit_event = NULL;
    }
    list_for_each_entry_safe(instance, tmp, &instances, list)
        redudp_fini_instance(instance);

    return 0;
}

static parser_section redudp_conf_section =
{
    .name    = "redudp",
    .entries = redudp_entries,
    .onenter = redudp_onenter,
    .onexit  = redudp_onexit
};

app_subsys redudp_subsys =
{
    .init = redudp_init,
    .fini = redudp_fini,
    .conf_section = &redudp_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
