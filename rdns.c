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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "list.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "redsocks.h"
#include "rdns.h"
#include "utils.h"
#include "hashtable.h"

#define rdns_log_error(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 0, &clientaddr, &self->config.host_fifo, prio, ## msg)
#define rdns_log_errno(prio, msg...) \
	redsocks_log_write_plain(__FILE__, __LINE__, __func__, 1, &clientaddr, &self->config.host_fifo, prio, ## msg)

static void rdns_fini_instance(rdns_instance *instance);
static int rdns_fini();

/***********************************************************************
 * Init / shutdown
 */
static parser_entry rdns_entries[] =
{
	{ .key = "fifo", .type = pt_pchar },
	{ }
};

static DEFINE_HASHTABLE(hostnames, 8);

static list_head instances = LIST_HEAD_INIT(instances);

static int rdns_onenter(parser_section *section)
{
	rdns_instance *instance = calloc(1, sizeof(*instance));
	if (!instance) {
		parser_error(section->context, "Not enough memory");
		return -1;
	}

	INIT_LIST_HEAD(&instance->list);

        for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
                entry->addr =
                        (strcmp(entry->key, "fifo") == 0) ? (void*)&instance->config.host_fifo_name :
                        NULL;

	section->data = instance;
	return 0;
}

static int rdns_onexit(parser_section *section)
{
	rdns_instance *instance = section->data;

	section->data = NULL;
	for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
		entry->addr = NULL;

	list_add(&instance->list, &instances);

	return 0;
}

static void rdns_host_entries_added(int fd, short what, void *_arg)
{
	char buf[255];
	int len;
        rdns_instance *self = _arg;

	fprintf(stderr, "fifo_read called with fd: %d, event: %d, arg: %p\n",
	    (int)fd, what, _arg);
	len = read(fd, buf, sizeof(buf) - 1);

	if (len <= 0) {
		if (len == 0)
			return;
		perror("read");
		fprintf(stderr, "Connection closed\n");
/*		event_del(_arg);
		event_base_loopbreak(event_get_base(_arg));
*/
		return;
	}

	buf[len] = '\0';
	fprintf(stdout, "Read: %s\n", buf);
}

static int rdns_init_instance(rdns_instance *instance)
{
	/* FIXME: rdns_fini_instance is called in case of failure, this
	 *        function will remove instance from instances list - result
	 *        looks ugly.
	 */
	int error;
	int fd = -1;

	struct stat st;
	if (lstat(instance->config.host_fifo_name, &st) == 0) {
		if ((st.st_mode & S_IFMT) == S_IFREG) {
			errno = EEXIST;
			perror("lstat");
			goto fail;
		}
	}
	unlink(instance->config.host_fifo_name);
	if (mkfifo(instance->config.host_fifo_name, 0600) == -1) {
		perror("mkfifo");
		goto fail;
	}

	fd = open(instance->config.host_fifo_name, O_RDONLY | O_NONBLOCK, 0);

	if (fd == -1) {
		perror("open");
		goto fail;
	}

	instance->host_fifo = fd;

	event_set(&instance->listener, fd, EV_READ | EV_PERSIST, rdns_host_entries_added, instance);
	error = event_add(&instance->listener, NULL);
	if (error) {
		log_errno(LOG_ERR, "event_add");
		goto fail;
	}

	return 0;

fail:
	rdns_fini_instance(instance);

	if (fd != -1) {
		if (close(fd) != 0)
			log_errno(LOG_WARNING, "close");
	}

	return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void rdns_fini_instance(rdns_instance *instance)
{
	if (event_initialized(&instance->listener)) {
		if (event_del(&instance->listener) != 0)
			log_errno(LOG_WARNING, "event_del");
		if (close(event_get_fd(&instance->listener)) != 0)
			log_errno(LOG_WARNING, "close");
		memset(&instance->listener, 0, sizeof(instance->listener));
	}

	list_del(&instance->list);

	memset(instance, 0, sizeof(*instance));
	free(instance);
}

static int rdns_init()
{
	rdns_instance *tmp, *instance = NULL;

	// TODO: init debug_dumper

	list_for_each_entry_safe(instance, tmp, &instances, list) {
		if (rdns_init_instance(instance) != 0)
			goto fail;
	}

	return 0;

fail:
	rdns_fini();
	return -1;
}

static int rdns_fini()
{
	rdns_instance *tmp, *instance = NULL;

	list_for_each_entry_safe(instance, tmp, &instances, list)
		rdns_fini_instance(instance);

	return 0;
}

static parser_section rdns_conf_section =
{
	.name    = "rdns",
	.entries = rdns_entries,
	.onenter = rdns_onenter,
	.onexit  = rdns_onexit
};

app_subsys rdns_subsys =
{
	.init = rdns_init,
	.fini = rdns_fini,
	.conf_section = &rdns_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
