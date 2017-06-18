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

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <event.h>
#include "log.h"
#include "main.h"
#include "utils.h"
#include "version.h"
#include "config.h"
#include "base.h"

extern app_subsys redsocks_subsys;
extern app_subsys debug_subsys;
extern app_subsys base_subsys;
#ifndef __ANDROID__
extern app_subsys redudp_subsys;
extern app_subsys dnstc_subsys;
#endif

app_subsys *subsystems[] = {
	&redsocks_subsys,
#ifdef DBG_BUILD
	&debug_subsys,
#endif
	&base_subsys,
#ifndef __ANDROID__
	&redudp_subsys,
	&dnstc_subsys,
#endif
};

static const char *confname = "redsocks.conf";
static const char *pidfile = NULL;

static void terminate(int sig, short what, void *_arg)
{
	if (event_loopbreak() != 0)
		log_error(LOG_WARNING, "event_loopbreak");
}

int main(int argc, char **argv)
{
	int error;
	app_subsys **ss;
	int exit_signals[2] = {SIGTERM, SIGINT};
	struct event terminators[2];
	bool conftest = false;
	int opt;
	int i;

	evutil_secure_rng_init();
	while ((opt = getopt(argc, argv, "h?vtc:p:")) != -1) {
		switch (opt) {
		case 't':
			conftest = true;
			break;
		case 'c':
			confname = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 'v':
			puts(redsocks_version);
			printf("Built with libevent-%s\n", LIBEVENT_VERSION);
			printf("Runs  with libevent-%s\n", event_get_version());
			if (LIBEVENT_VERSION_NUMBER != event_get_version_number()) {
				printf("Warning: libevent version number mismatch.\n"
				       "  Headers: %8x\n"
				       "  Runtime: %8x\n", LIBEVENT_VERSION_NUMBER, event_get_version_number());
			}
			return EXIT_SUCCESS;
		default:
			printf(
				"Usage: %s [-?hvt] [-c config] [-p pidfile]\n"
				"  -h, -?       this message\n"
				"  -v           print version\n"
				"  -t           test config syntax\n"
				"  -p           write pid to pidfile\n",
				argv[0]);
			return (opt == '?' || opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}

	if (event_get_struct_event_size() != sizeof(struct event)) {
		puts("libevent event_get_struct_event_size() != sizeof(struct event)! Check `redsocks -v` and recompile redsocks");
		return EXIT_FAILURE;
	}

	FILE *f = fopen(confname, "r");
	if (!f) {
		perror("Unable to open config file");
		return EXIT_FAILURE;
	}

	parser_context* parser = parser_start(f);
	if (!parser) {
		perror("Not enough memory for parser");
		return EXIT_FAILURE;
	}

	FOREACH(ss, subsystems)
		if ((*ss)->conf_section)
			parser_add_section(parser, (*ss)->conf_section);
	error = parser_run(parser);
	parser_stop(parser);
	fclose(f);

	if (error)
		return EXIT_FAILURE;

	if (conftest)
		return EXIT_SUCCESS;

	struct event_base* evbase = event_init();
	memset(terminators, 0, sizeof(terminators));

	FOREACH(ss, subsystems) {
		if ((*ss)->init) {
			error = (*ss)->init(evbase);
			if (error)
				goto shutdown;
		}
	}

	if (pidfile) {
		f = fopen(pidfile, "w");
		if (!f) {
			perror("Unable to open pidfile for write");
			return EXIT_FAILURE;
		}
		fprintf(f, "%d\n", getpid());
		fclose(f);
	}

	assert(SIZEOF_ARRAY(exit_signals) == SIZEOF_ARRAY(terminators));
	for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
		signal_set(&terminators[i], exit_signals[i], terminate, NULL);
		if (signal_add(&terminators[i], NULL) != 0) {
			log_errno(LOG_ERR, "signal_add");
			goto shutdown;
		}
	}

	if (LIBEVENT_VERSION_NUMBER != event_get_version_number()) {
		log_error(LOG_WARNING, "libevent version mismatch! headers %8x, runtime %8x\n", LIBEVENT_VERSION_NUMBER, event_get_version_number());
	}

	log_error(LOG_NOTICE, "redsocks started, conn_max=%u", redsocks_conn_max());

	event_dispatch();

	log_error(LOG_NOTICE, "redsocks goes down");

shutdown:
	for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
		if (signal_initialized(&terminators[i])) {
			if (signal_del(&terminators[i]) != 0)
				log_errno(LOG_WARNING, "signal_del");
			memset(&terminators[i], 0, sizeof(terminators[i]));
		}
	}

	for (--ss; ss >= subsystems; ss--)
		if ((*ss)->fini)
			(*ss)->fini();

	event_base_free(evbase);

	return !error ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
