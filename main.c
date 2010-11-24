/* redsocks - transparent TCP-to-proxy redirector
 * Copyright (C) 2007-2008 Leonid Evdokimov <leon@darkk.net.ru>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

extern app_subsys redsocks_subsys;
extern app_subsys base_subsys;
// extern app_subsys reddns_subsys;

app_subsys *subsystems[] = {
	&redsocks_subsys,
	&base_subsys,
//	&reddns_subsys,
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

	while ((opt = getopt(argc, argv, "tc:p:")) != -1) {
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
		default:
			printf(
				"Usage: %s [-t] [-c config] [-p pidfile]\n"
				"  -t           test config syntax\n"
				"  -p           write pid to pidfile\n",
				argv[0]);
			return EXIT_FAILURE;
		}
	}


	FILE *f = fopen(confname, "r");
	if (!f) {
		perror("Unable to open config file");
		return EXIT_FAILURE;
	}

	parser_context* parser = parser_start(f, NULL);
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

	event_init();

	FOREACH(ss, subsystems) {
		if ((*ss)->init) {
			error = (*ss)->init();
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
	memset(terminators, 0, sizeof(terminators));
	for (i = 0; i < SIZEOF_ARRAY(exit_signals); i++) {
		signal_set(&terminators[i], exit_signals[i], terminate, NULL);
		if (signal_add(&terminators[i], NULL) != 0) {
			log_errno(LOG_ERR, "signal_add");
			goto shutdown;
		}
	}

	log_error(LOG_NOTICE, "redsocks started");

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

	event_base_free(NULL);

	return !error ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
