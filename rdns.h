#ifndef RDNS_H
#define RDNS_H

#include "list.h"
#include "hashtable.h"

typedef struct rdns_config_t {
	char *host_fifo_name;
} rdns_config;

typedef struct rdns_instance_t {
	list_head       list;
	rdns_config     config;
	struct event    listener;
	int				host_fifo;
} rdns_instance;

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* RDNS_H */
