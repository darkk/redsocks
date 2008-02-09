/* $Id$ */

#include <sys/time.h>
#include <sys/types.h>
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

int main(int argc, char **argv)
{
	int error;
	app_subsys **ss;
	FILE *f = fopen("redsocks.conf", "r");
	if (!f) {
		perror("Unable to open config file");
		return 1;
	}
	
	parser_context* parser = parser_start(f, NULL);
	if (!parser) {
		perror("Not enough memory for parser");
		return 1;
	}

	FOREACH(ss, subsystems)
		if ((*ss)->conf_section)
			parser_add_section(parser, (*ss)->conf_section);
	error = parser_run(parser);
	parser_stop(parser);
	fclose(f);
	if (error)
		return 1;

	event_init();

	FOREACH(ss, subsystems) {
		if ((*ss)->init) {
			error = (*ss)->init();
			if (!error)
				continue; // goto next subsystem
			for (--ss; ss >= subsystems; ss--)
				if ((*ss)->fini)
					(*ss)->fini();
			return 1;
		}
	}
		
	log_error(LOG_NOTICE, "redsocks started");

	event_dispatch();

	FOREACH_REV(ss, subsystems)
		if ((*ss)->fini)
			(*ss)->fini();
	return 0;
}

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
