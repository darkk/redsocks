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
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"
#include "main.h"
#include "redudp.h"
#include "encrypt.h"
#include "shadowsocks.h"

typedef struct ss_client_t {
    struct event * udprelay;
} ss_client;

typedef struct ss_instance_t {
    int method; 
    enc_info info;
    struct enc_ctx e_ctx;
    struct enc_ctx d_ctx;
    void * buff;
} ss_instance;


static int ss_is_valid_cred(const char *method, const char *password)
{
    if (!method || !password)
        return 0;
    if (strlen(method) > 255) {
        log_error(LOG_WARNING, "Shadowsocks encryption method can't be more than 255 chars.");
        return 0;
    }
    if (strlen(password) > 255) {
        log_error(LOG_WARNING, "Shadowsocks encryption password can't be more than 255 chars.");
        return 0;
    }
    return 1;
}

static void ss_client_init(redudp_client *client)
{
}

static void ss_client_fini(redudp_client *client)
{
    ss_client *ssclient = (void*)(client + 1);
    if (ssclient->udprelay) {
        int fd = event_get_fd(ssclient->udprelay);
        if (event_del(ssclient->udprelay) == -1)
            redudp_log_errno(client, LOG_ERR, "event_del");
        event_free(ssclient->udprelay);
        close(fd);
    }
}

static void ss_forward_pkt(redudp_client *client, struct sockaddr* destaddr, void *data, size_t pktlen)
{
    ss_client *ssclient = (void*)(client + 1);
    ss_instance * ss = (ss_instance *)(client->instance+1);
    struct sockaddr_storage * relayaddr = &client->instance->config.relayaddr;
    struct msghdr msg;
    struct iovec io[1];
    ssize_t outgoing;
    int rc;
    ss_header header;
    size_t len = 0;
    size_t header_len = 0;
    size_t fwdlen = 0;
    void * buff = client->instance->shared_buff;

    /* build and send header */
    if (client->destaddr.ss_family == AF_INET) {
        struct sockaddr_in * addr = (struct sockaddr_in *)&client->destaddr;
        header.v4.addr_type = ss_addrtype_ipv4;
        header.v4.addr = addr->sin_addr.s_addr;
        header.v4.port = addr->sin_port;
        header_len = sizeof(ss_header_ipv4);
    }
    else if (client->destaddr.ss_family == AF_INET6) {
        struct sockaddr_in6 * addr = (struct sockaddr_in6 *)&client->destaddr;
        header.v6.addr_type = ss_addrtype_ipv6;
        header.v6.addr = addr->sin6_addr;
        header.v6.port = addr->sin6_port;
        header_len = sizeof(ss_header_ipv6);
    }
    else {
        redudp_log_error(client, LOG_ERR, "Unsupported address family: %d", client->destaddr.ss_family);
        return ;
    }

    if (enc_ctx_init(&ss->info, &ss->e_ctx, 1)) {
        redudp_log_error(client, LOG_ERR, "Shadowsocks UDP failed to initialize encryption context.");
        return;
    }
    rc = ss_encrypt(&ss->e_ctx, (char *)&header, header_len, buff, &len);
    if (rc)
    {
        if (len + pktlen < MAX_UDP_PACKET_SIZE)
            rc = ss_encrypt(&ss->e_ctx, (char *)data, pktlen, buff+len, &fwdlen);
        else
            rc = 0;
    }
    enc_ctx_free(&ss->e_ctx);
    if (!rc)
    {
        redudp_log_error(client, LOG_DEBUG, "Can't encrypt packet, dropping it");
        return;
    }
    fwdlen += len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = relayaddr;
    msg.msg_namelen = sizeof(*relayaddr);
    msg.msg_iov = io;
    msg.msg_iovlen = SIZEOF_ARRAY(io);

    io[0].iov_base = buff;
    io[0].iov_len = fwdlen;

    outgoing = sendmsg(event_get_fd(ssclient->udprelay), &msg, 0);
    if (outgoing == -1) {
        redudp_log_errno(client, LOG_DEBUG, "sendmsg: Can't forward packet, dropping it");
        return;
    }
    else if (outgoing != fwdlen) {
        redudp_log_error(client, LOG_DEBUG, "sendmsg: I was sending %zd bytes, but only %zd were sent.", fwdlen, outgoing);
        return;
    }
}

static void ss_pkt_from_server(int fd, short what, void *_arg)
{
    redudp_client *client = _arg;
    ss_client *ssclient = (void*)(client + 1);
    ss_instance * ss = (ss_instance *)(client->instance+1);
    ss_header  * header;
    ssize_t pktlen;
    size_t  fwdlen;
    struct sockaddr_storage udprelayaddr;
    int rc;
    void * buff = client->instance->shared_buff;
    void * buff2 = ss->buff;

    assert(fd == event_get_fd(ssclient->udprelay));

    pktlen = red_recv_udp_pkt(fd, buff, MAX_UDP_PACKET_SIZE, &udprelayaddr, NULL);
    if (pktlen == -1)
        return;

    if (enc_ctx_init(&ss->info, &ss->d_ctx, 0)) {
        redudp_log_error(client, LOG_ERR, "Shadowsocks UDP failed to initialize decryption context.");
        return;
    }
    rc = ss_decrypt(&ss->d_ctx, buff, pktlen, buff2, &fwdlen);
    enc_ctx_free(&ss->d_ctx);
    if (!rc) {
        redudp_log_error(client, LOG_DEBUG, "Can't decrypt packet, dropping it");
        return;
    }
    header = (ss_header*)buff2;
    // We do not verify src address, but at least, we need to ensure address type is correct.
    if (header->addr_type == ss_addrtype_ipv4) {
        struct sockaddr_in pktaddr = {
            .sin_family = AF_INET,
            .sin_addr   = { header->v4.addr },
            .sin_port   = header->v4.port,
        };

        if (fwdlen < sizeof(header->v4)) {
            redudp_log_error(client, LOG_DEBUG, "Packet too short.");
            return;
        }
        fwdlen -= sizeof(header->v4);
        redudp_fwd_pkt_to_sender(
                client,
                buff2 + sizeof(header->v4),
                fwdlen,
                (struct sockaddr_storage*)&pktaddr);
    }
    else if (header->addr_type == ss_addrtype_ipv6) {
        struct sockaddr_in6 pktaddr = {
            .sin6_family = AF_INET6,
            .sin6_port   = header->v6.port,
        };
        memcpy(&pktaddr.sin6_addr, &header->v6.addr, sizeof(header->v6.addr));

        if (fwdlen < sizeof(header->v6)) {
            redudp_log_error(client, LOG_DEBUG, "Packet too short.");
            return;
        }
        fwdlen -= sizeof(header->v6);
        redudp_fwd_pkt_to_sender(
                client,
                buff2 + sizeof(header->v6),
                fwdlen,
                (struct sockaddr_storage*)&pktaddr);
    }
    else {
        redudp_log_error(client, LOG_DEBUG, "Got address type #%u instead of expected #%u (IPv4/IPv6).",
                header->addr_type, ss_addrtype_ipv4);
        return;
    }
}

static int ss_ready_to_fwd(struct redudp_client_t *client)
{
    return 1; 
}

static void ss_connect_relay(redudp_client *client)
{
    ss_client *ssclient = (void*)(client + 1);
    struct sockaddr_storage * addr = &client->instance->config.relayaddr;
    int fd = -1;
    int error;

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        redudp_log_errno(client, LOG_ERR, "socket");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        redudp_log_errno(client, LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    error = connect(fd, (struct sockaddr*)addr, sizeof(*addr));
    if (error) {
        redudp_log_errno(client, LOG_NOTICE, "connect");
        goto fail;
    }

    ssclient->udprelay = event_new(get_event_base(), fd, EV_READ | EV_PERSIST, ss_pkt_from_server, client);
    if (!ssclient->udprelay) {
        redudp_log_errno(client, LOG_ERR, "event_new");
        goto fail;
    }
    error = event_add(ssclient->udprelay, NULL);
    if (error) {
        redudp_log_errno(client, LOG_ERR, "event_add");
        goto fail;
    }

    redudp_flush_queue(client);
    return;

fail:
    if (fd != -1)
        close(fd);
    redudp_drop_client(client);
}

static int ss_instance_init(struct redudp_instance_t *instance)
{
    ss_instance * ss = (ss_instance *)(instance+1);
    const redudp_config *config = &instance->config;
    char buf1[RED_INET_ADDRSTRLEN];

    int valid_cred =  ss_is_valid_cred(config->login, config->password);
    if (!valid_cred 
    || (ss->method = enc_init(&ss->info, config->password, config->login), ss->method == -1))
    {
        log_error(LOG_ERR, "Invalided encrytion method or password.");
        return -1;
    }
    else
    {
        log_error(LOG_INFO, "%s @ %s: encryption method: %s",
            instance->relay_ss->name,
            red_inet_ntop(&instance->config.bindaddr, buf1, sizeof(buf1)),
            config->login);
    }
    // An additional buffer is allocated for each instance for encryption/decrption.
    ss->buff = malloc(MAX_UDP_PACKET_SIZE);
    if (!ss->buff) {
        log_error(LOG_ERR, "Out of memory.");
        return -1;
    }
    return 0;
}

static void ss_instance_fini(struct redudp_instance_t *instance)
{
    ss_instance * ss = (ss_instance *)(instance+1);
    if (ss->buff) {
        free(ss->buff);
        ss->buff = NULL;
    }
}

udprelay_subsys shadowsocks_udp_subsys =
{
    .name                 = "shadowsocks",
    .payload_len          = sizeof(ss_client),
    .instance_payload_len = sizeof(ss_instance),
    .init                 = ss_client_init,
    .fini                 = ss_client_fini,
    .instance_init        = ss_instance_init,
    .instance_fini        = ss_instance_fini,
    .connect_relay        = ss_connect_relay,
    .forward_pkt          = ss_forward_pkt,
    .ready_to_fwd         = ss_ready_to_fwd,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
