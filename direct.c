/*  
 * Copyright (C) 2013 Zhuofei Wang <semigodking@gmail.com>
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include "parser.h"
#include "log.h"
#include "main.h"
#include "base.h"
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

static void direct_instance_fini(redsocks_instance *instance)
{
}

static void direct_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
    redsocks_touch_client(client);
    if (client->state == 0)
    {
        client->state = 1;
        redsocks_start_relay(client);
    }
}

static void direct_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
    redsocks_touch_client(client);
    if (client->state == 0)
    {
        client->state = 1;
        redsocks_start_relay(client);
    }
}

void redsocks_direct_connect_relay(redsocks_client *client)
{
	client->relay = red_connect_relay(&client->destaddr,
			                          redsocks_relay_connected, redsocks_event_error, client);
	if (!client->relay) {
		redsocks_log_errno(client, LOG_ERR, "red_connect_relay");
		redsocks_drop_client(client);
	}
}

relay_subsys direct_connect_subsys =
{
    .name                 = "direct",
    .payload_len          = 0,
    .instance_payload_len = 0,
	.readcb = direct_read_cb,
	.writecb = direct_write_cb,
	.init                 = direct_relay_init,
	.instance_fini        = direct_instance_fini,
    .connect_relay = redsocks_direct_connect_relay,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
