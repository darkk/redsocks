/* $Id$ */

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "main.h"

typedef struct reddns_config_t reddns_config;
struct reddns_config_t {
	struct sockaddr_in bindaddr;
	struct sockaddr_in relayaddr;
	struct in_addr     fakenet;
	struct in_addr     fakenetmask;
};

int reddns_onenter(parser_section *section)
{
	reddns_config *conf = calloc(1, sizeof(reddns_config));
	section->data = conf;
	section->entries[0].addr = &conf->bindaddr.sin_port;
	section->entries[1].addr = &conf->fakenet;
	section->entries[2].addr = &conf->fakenetmask;
	section->entries[3].addr = &conf->relayaddr.sin_addr;
	section->entries[4].addr = &conf->relayaddr.sin_port;
	fprintf(stderr, "%s\n", __FUNCTION__);
	return 0;
}

int reddns_onexit(parser_section *section)
{
	reddns_config *conf = section->data;
	fprintf(stderr, 
			"%s {\n"
			"local_port = %u;\n"
			"fakeip_net = %s/%s;\n"
			"ip = %s;\n"
			"port = %u;\n"
			"}\n", 
			__FUNCTION__,
			conf->bindaddr.sin_port,
			strdup(inet_ntoa(conf->fakenet)),
			strdup(inet_ntoa(conf->fakenetmask)),
			strdup(inet_ntoa(conf->relayaddr.sin_addr)),
			conf->relayaddr.sin_port
			);
	return 0;
}

parser_entry reddns_entries[] = {
	{ .key = "local_port",     .type = pt_uint16 },
	{ .key = "fakeip_net",     .type = pt_in_addr2 },
	{ .key = "fakeip_netmask", .type = pt_in_addr },
	{ .key = "ip",             .type = pt_in_addr },
	{ .key = "port",           .type = pt_uint16 },
	{ }
};

parser_section reddns_conf_section = {
	.name    = "reddns",
	.entries = reddns_entries,
	.onenter = reddns_onenter,
	.onexit  = reddns_onexit
};

int reddns_init() {
	return 0;	
}

int reddns_fini() {
	return 0;
}

app_subsys reddns_subsys = {
	.init = reddns_init,
	.fini = reddns_fini,
	.conf_section = &reddns_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
