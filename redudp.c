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
#include <search.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "list.h"
#include "log.h"
#include "socks5.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "redudp.h"

/* Just in case the IP_TRANSPARENT define isn't included somehow */
#if !defined(IP_TRANSPARENT)
#define IP_TRANSPARENT 19
#define IP_ORIGDSTADDR       20
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR
#endif

// Multiple instances share the same buffer for message receiving
static char recv_buff[64*1024];// max size of UDP packet is less than 64K

static void redudp_fini_instance(redudp_instance *instance);
static int redudp_fini();
static int redudp_transparent(int fd);

struct bound_udp4_key {
    struct in_addr sin_addr;
    uint16_t       sin_port;
};

struct bound_udp4 {
    struct bound_udp4_key key;
    int ref;
    int fd;
};

extern udprelay_subsys socks5_udp_subsys;
extern udprelay_subsys shadowsocks_udp_subsys;
static udprelay_subsys *relay_subsystems[] =
{
    &socks5_udp_subsys,
    &shadowsocks_udp_subsys,
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
        return (*pnode)->fd;
    }

    node = calloc(1, sizeof(*node));
    if (!node) {
        log_errno(LOG_ERR, "calloc");
        goto fail;
    }

    node->key = key;
    node->ref = 1;
    node->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (node->fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    if (0 != redudp_transparent(node->fd))
        goto fail;

    if (0 != bind(node->fd, (struct sockaddr*)addr, sizeof(*addr))) {
        log_errno(LOG_ERR, "bind");
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

static int redudp_transparent(int fd)
{
    int on = 1;
    int error = setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on));
    if (error)
        log_errno(LOG_ERR, "setsockopt(..., SOL_IP, IP_TRANSPARENT)");
    return error;
}

static int do_tproxy(redudp_instance* instance)
{
    return instance->config.destaddr.sin_addr.s_addr == 0;
}

struct sockaddr_in* get_destaddr(redudp_client *client)
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
    redudp_log_error(client, LOG_DEBUG, "Dropping...");
    enqueued_packet *q, *tmp;

    if (client->instance->relay_ss->fini)
        client->instance->relay_ss->fini(client);

    if (event_initialized(&client->timeout)) {
        if (event_del(&client->timeout) == -1)
            redudp_log_errno(client, LOG_ERR, "event_del");
    }
    redudp_log_error(client, LOG_DEBUG, "Dropping...2");
    if (client->sender_fd != -1)
        bound_udp4_put(&client->destaddr);
    list_for_each_entry_safe(q, tmp, &client->queue, list) {
        list_del(&q->list);
        free(q);
    }
    redudp_log_error(client, LOG_DEBUG, "Dropping...3");
    list_del(&client->list);
    free(client);
    redudp_log_error(client, LOG_DEBUG, "Dropping...4");
}

void redudp_bump_timeout(redudp_client *client)
{
    struct timeval tv;
    tv.tv_sec = client->instance->config.udp_timeout;
    tv.tv_usec = 0;
    // TODO: implement udp_timeout_stream
    if (event_add(&client->timeout, &tv) != 0) {
        redudp_log_error(client, LOG_WARNING, "event_add(&client->timeout, ...)");
        redudp_drop_client(client);
    }
}

void redudp_fwd_pkt_to_sender(redudp_client *client, void *buf, size_t len)
{
    size_t sent;
    redsocks_time(&client->last_relay_event);
    redudp_bump_timeout(client);

    if (do_tproxy(client->instance) && client->sender_fd == -1) {
        client->sender_fd = bound_udp4_get(&client->destaddr);
        if (client->sender_fd == -1) {
            redudp_log_error(client, LOG_WARNING, "bound_udp4_get failure");
            return;
        }
    }

    sent = sendto(do_tproxy(client->instance)
                          ? client->sender_fd
                          : EVENT_FD(&client->instance->listener),
                       buf, len, 0,
                      (struct sockaddr*)&client->clientaddr, sizeof(client->clientaddr));
    if (sent != len) {
        redudp_log_error(client, LOG_WARNING, "sendto: I was sending %zd bytes, but only %zd were sent.",
                         len, sent);
        return;
    }

}

static int redudp_enqeue_pkt(redudp_client *client, char *buf, size_t pktlen)
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
        client->instance->relay_ss->forward_pkt(client, q->data, q->len);
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

static void redudp_first_pkt_from_client(redudp_instance *self, struct sockaddr_in *clientaddr, struct sockaddr_in *destaddr, char *buf, size_t pktlen)
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
    if (destaddr)
        memcpy(&client->destaddr, destaddr, sizeof(client->destaddr));
    evtimer_assign(&client->timeout, get_event_base(), redudp_timeout, client);
    self->relay_ss->init(client);

    client->sender_fd = -1; // it's postponed until proxy replies to avoid trivial DoS

    redsocks_time(&client->first_event);
    client->last_client_event = client->first_event;
    redudp_bump_timeout(client);

    list_add(&client->list, &self->clients);

    if (redudp_enqeue_pkt(client, buf, pktlen) == -1)
        goto fail;

    if (self->relay_ss->connect_relay)
        self->relay_ss->connect_relay(client);

    redudp_log_error(client, LOG_DEBUG, "got 1st packet from client");
    return;

fail:
    redudp_drop_client(client);
}

static void redudp_pkt_from_client(int fd, short what, void *_arg)
{
    redudp_instance *self = _arg;
    struct sockaddr_in clientaddr, destaddr, *pdestaddr;
    ssize_t pktlen;
    redudp_client *tmp, *client = NULL;

    pdestaddr = do_tproxy(self) ? &destaddr : NULL;

    assert(fd == EVENT_FD(&self->listener));
    pktlen = red_recv_udp_pkt(fd, recv_buff, sizeof(recv_buff), &clientaddr, pdestaddr);
    if (pktlen == -1)
        return;

    // TODO: this lookup may be SLOOOOOW.
    list_for_each_entry(tmp, &self->clients, list) {
        // TODO: check destaddr
        if (0 == memcmp(&clientaddr, &tmp->clientaddr, sizeof(clientaddr))) {
            client = tmp;
            break;
        }
    }

    if (client) {
        redsocks_time(&client->last_client_event);
        redudp_bump_timeout(client);
        if (self->relay_ss->ready_to_fwd(client)) {
            self->relay_ss->forward_pkt(client, recv_buff, pktlen);
        }
        else {
            redudp_enqeue_pkt(client, recv_buff, pktlen);
        }
    }
    else {
        redudp_first_pkt_from_client(self, &clientaddr, pdestaddr, recv_buff, pktlen);
    }
}

/***********************************************************************
 * Init / shutdown
 */
static parser_entry redudp_entries[] =
{
    { .key = "local_ip",   .type = pt_in_addr },
    { .key = "local_port", .type = pt_uint16 },
    { .key = "ip",         .type = pt_in_addr },
    { .key = "port",       .type = pt_uint16 },
    { .key = "type",       .type = pt_pchar },
    { .key = "login",      .type = pt_pchar },
    { .key = "password",   .type = pt_pchar },
    { .key = "dest_ip",    .type = pt_in_addr },
    { .key = "dest_port",  .type = pt_uint16 },
    { .key = "udp_timeout", .type = pt_uint16 },
    { .key = "udp_timeout_stream", .type = pt_uint16 },
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
    instance->config.bindaddr.sin_family = AF_INET;
    instance->config.bindaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.relayaddr.sin_family = AF_INET;
    instance->config.relayaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    instance->config.destaddr.sin_family = AF_INET;
    instance->config.max_pktqueue = 5;
    instance->config.udp_timeout = 30;
    instance->config.udp_timeout_stream = 180;

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "local_ip") == 0)   ? (void*)&instance->config.bindaddr.sin_addr :
            (strcmp(entry->key, "local_port") == 0) ? (void*)&instance->config.bindaddr.sin_port :
            (strcmp(entry->key, "ip") == 0)         ? (void*)&instance->config.relayaddr.sin_addr :
            (strcmp(entry->key, "port") == 0)       ? (void*)&instance->config.relayaddr.sin_port :
            (strcmp(entry->key, "type") == 0)       ? (void*)&instance->config.type :
            (strcmp(entry->key, "login") == 0)      ? (void*)&instance->config.login :
            (strcmp(entry->key, "password") == 0)   ? (void*)&instance->config.password :
            (strcmp(entry->key, "dest_ip") == 0)    ? (void*)&instance->config.destaddr.sin_addr :
            (strcmp(entry->key, "dest_port") == 0)  ? (void*)&instance->config.destaddr.sin_port :
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

    instance->config.bindaddr.sin_port = htons(instance->config.bindaddr.sin_port);
    instance->config.relayaddr.sin_port = htons(instance->config.relayaddr.sin_port);
    instance->config.destaddr.sin_port = htons(instance->config.destaddr.sin_port);

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

    if (instance->config.udp_timeout_stream < instance->config.udp_timeout) {
        parser_error(section->context, "udp_timeout_stream should be not less then udp_timeout");
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

    if (instance->relay_ss->instance_init 
        && instance->relay_ss->instance_init(instance)) {
        log_errno(LOG_ERR, "Failed to init UDP relay subsystem.");
        goto fail;
    } 

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    if (do_tproxy(instance)) {
        int on = 1;
        char buf[RED_INET_ADDRSTRLEN];
        // iptables TPROXY target does not send packets to non-transparent sockets
        if (0 != redudp_transparent(fd))
            goto fail;

        error = setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &on, sizeof(on));
        if (error) {
            log_errno(LOG_ERR, "setsockopt(listener, SOL_IP, IP_RECVORIGDSTADDR)");
            goto fail;
        }

        log_error(LOG_DEBUG, "redudp @ %s: TPROXY", red_inet_ntop(&instance->config.bindaddr, buf, sizeof(buf)));
    }
    else {
        char buf1[RED_INET_ADDRSTRLEN], buf2[RED_INET_ADDRSTRLEN];
        log_error(LOG_DEBUG, "redudp @ %s: destaddr=%s",
            red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)),
            red_inet_ntop(&instance->config.destaddr, buf2, sizeof(buf2)));
    }

    error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, sizeof(instance->config.bindaddr));
    if (error) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        log_errno(LOG_ERR, "set nonblocking");
        goto fail;
    }

    event_assign(&instance->listener, get_event_base(), fd, EV_READ | EV_PERSIST, redudp_pkt_from_client, instance);
    error = event_add(&instance->listener, NULL);
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

    if (event_initialized(&instance->listener)) {
        if (event_del(&instance->listener) != 0)
            log_errno(LOG_WARNING, "event_del");
        close(EVENT_FD(&instance->listener));
        memset(&instance->listener, 0, sizeof(instance->listener));
    }

    if (instance->relay_ss->instance_fini)
        instance->relay_ss->instance_fini(instance);

    list_del(&instance->list);

    free(instance->config.login);
    free(instance->config.password);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

static int redudp_init()
{
    redudp_instance *tmp, *instance = NULL;

    // TODO: init debug_dumper

    list_for_each_entry_safe(instance, tmp, &instances, list) {
        if (redudp_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    redudp_fini();
    return -1;
}

static int redudp_fini()
{
    redudp_instance *tmp, *instance = NULL;

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
