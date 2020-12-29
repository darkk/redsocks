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


#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "parser.h"
#include "log.h"
#include "main.h"
#include "redsocks.h"
#include "utils.h"


int redsocks_start_relay(redsocks_client *client);
void redsocks_touch_client(redsocks_client *client);
void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg);
void redsocks_relay_connected(struct bufferevent *buffev, void *_arg);

static void direct_relay_init(redsocks_client *client)
{
    client->state = 0;
}

static void direct_relay_fini(redsocks_client *client)
{
}

static void direct_write_cb(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    redsocks_touch_client(client);
    if (client->state == 0)
    {
        client->state = 1;
        if (redsocks_start_relay(client))
            // Failed to start relay. Connection is dropped.
            return;
        // Write any data received from client to relay
        struct evbuffer * input = bufferevent_get_input(client->client);
        if (evbuffer_get_length(input))
            if (bufferevent_write_buffer(client->relay, input) == -1)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
    }
}

static int direct_connect_relay(redsocks_client *client)
{
    redsocks_instance * instance = client->instance;
    char * interface = instance->config.interface;
    struct timeval tv = {instance->config.timeout, 0};
    struct sockaddr_storage * destaddr = &client->destaddr;

    if (instance->config.relay) {
	destaddr = &instance->config.relayaddr;
    }
    // Allowing binding relay socket to specified IP for outgoing connections
    client->relay = red_connect_relay(
            interface,
            destaddr,
            NULL,
            redsocks_relay_connected,
            redsocks_event_error,
            client,
            &tv);
    if (!client->relay)
    {
        redsocks_log_errno(client, LOG_ERR, "red_connect_relay");
        redsocks_drop_client(client);
        return -1;
    }
    return 0;
}

relay_subsys direct_connect_subsys =
{
    .name                 = "direct",
    .payload_len          = 0,
    .instance_payload_len = 0,
    .writecb = direct_write_cb,
    .init                 = direct_relay_init,
    .fini                 = direct_relay_fini,
    .connect_relay = direct_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
