/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2015 Zhuofei Wang <semigodking@gmail.com>
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
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "redsocks.h"
#include "log.h"
#include "parser.h"
#include "main.h"
#include "ipcache.h"

#define ADDR_CACHE_BLOCKS 256 
#define ADDR_CACHE_BLOCK_SIZE 16 
#define ADDR_PORT_CHECK 1
#define CACHE_ITEM_STALE_SECONDS 60*30
#define MAX_BLOCK_SIZE 32
#define CACHE_FILE_UPDATE_INTERVAL 3600 * 2


//----------------------------------------------------------------------------------------
typedef struct cache_config_t {
    // Values to be read from config file
    uint16_t    cache_size;
    uint16_t    port_check;
    uint16_t    stale_time;
    char *          cache_file;
    uint16_t    autosave_interval;
    // Dynamically calculated values.
    unsigned int    block_size;
    unsigned int    block_count;
} cache_config;

static cache_config default_config = {
    .cache_size = ADDR_CACHE_BLOCKS * ADDR_CACHE_BLOCK_SIZE / 1024,
    .port_check = ADDR_PORT_CHECK, 
    .stale_time = CACHE_ITEM_STALE_SECONDS, 
    .autosave_interval = CACHE_FILE_UPDATE_INTERVAL,
    .block_size = ADDR_CACHE_BLOCK_SIZE,
    .block_count = ADDR_CACHE_BLOCKS,
};

static parser_entry cache_entries[] =
{
    { .key = "cache_size",  .type = pt_uint16 },
    { .key = "port_check",  .type = pt_uint16 },
    { .key = "stale_time",  .type = pt_uint16 },
    { .key = "cache_file",  .type = pt_pchar },
    { .key = "autosave_interval",  .type = pt_uint16 },
    { }
};

static int cache_onenter(parser_section *section)
{
    cache_config * config = &default_config; 

    config->cache_size = 0;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "cache_size") == 0) ? (void*)&config->cache_size:
            (strcmp(entry->key, "port_check") == 0) ? (void*)&config->port_check:
            (strcmp(entry->key, "stale_time") == 0) ? (void*)&config->stale_time:
            (strcmp(entry->key, "cache_file") == 0) ? (void*)&config->cache_file:
            (strcmp(entry->key, "autosave_interval") == 0) ? (void*)&config->autosave_interval:
            NULL;
    section->data = config; 
    return 0;
}

static int cache_onexit(parser_section *section)
{
    const char *err = NULL;
    cache_config * config = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    /* Check and update values here */
    /* 
    Let uer specify cache size by number of 1K items. 
    Make it easier for user to config cache size.
    */
    if (config->cache_size > MAX_BLOCK_SIZE)
        err = "Cache size must be in range [0-32]. 0 means default. Default: 4";
    else if (config->cache_size)
    {
        config->block_count = ADDR_CACHE_BLOCKS;
        config->block_size = config->cache_size * 1024 / config->block_count;
        while(config->block_size > MAX_BLOCK_SIZE)
        {
            config->block_count <<= 1;   
            config->block_size = config->cache_size * 1024 / config->block_count;
        }
    }

    if (!err && config->stale_time < 5)
        err = "Time to stale cache item must be equal or greater than 5 seconds.";

    if (err)
        parser_error(section->context, err);

    return err ? -1 : 0;
}

static parser_section cache_conf_section =
{
    .name    = "ipcache",
    .entries = cache_entries,
    .onenter = cache_onenter,
    .onexit  = cache_onexit
};

#define block_from_sockaddr_in(addr) (addr->sin_addr.s_addr & (config->block_count -1)) 
#define set_cache_changed(changed) (cache_changed = changed)
#define is_cache_changed(changed) (cache_changed != 0)

typedef struct cache_data_t {
    char   present;
    struct sockaddr_in addr;
    time_t access_time;
} cache_data;

static int * addr_cache_counters = NULL;
static int * addr_cache_pointers = NULL;
static cache_data * addr_cache = NULL;
static char  cache_changed = 0;
static struct event timer_event;

static inline cache_data * get_cache_data(unsigned int block, unsigned int index);

static inline cache_config * get_config()
{
    return &default_config;
}

static int load_cache(const char * path)
{
    FILE * f;
    char line[256];
    char * pline = 0;
    // TODO: IPv6 Support
    struct sockaddr_in addr;
    int addr_size;

    if (!path)
        return -1;

    f = fopen(path, "r");
    if (!f)
        return -1;
    while(1)
    {
        pline = fgets(line, sizeof(line), f);
        if (!pline)
            break;
        addr_size = sizeof(addr);
        if (evutil_parse_sockaddr_port(pline, (struct sockaddr *)&addr, &addr_size))
            log_error(LOG_INFO, "Invalid IP address: %s", line);
        else
            cache_add_addr(&addr);
    }
    fclose(f);
    return 0;
}

static int save_cache(const char * path)
{
    FILE * f;
    unsigned int blk = 0;
    unsigned int idx = 0;
    char addr_str[RED_INET_ADDRSTRLEN];
    cache_data * item;
    cache_config * config = get_config();


    if (!path)
        return -1;

    f = fopen(path, "w");
    if (!f)
        return -1;

    for (; blk < config->block_count; blk++)
    {
        for (idx=0; idx < config->block_size; idx++)
        {
            item = get_cache_data(blk, idx);
            if (item && item->present)
            {
                red_inet_ntop(&item->addr, addr_str, sizeof(addr_str));
                fprintf(f, "%s\n", addr_str);
            }
        }
    }
    fclose(f);
    return 0;
}

static void cache_auto_saver(int sig, short what, void *_arg)
{
    cache_config * config = get_config();
    if (is_cache_changed() && config->cache_file)
    {
        save_cache(config->cache_file);
        set_cache_changed(0);
    }
}

static int cache_init()
{
    cache_config * config = get_config();
    size_t size;
    struct timeval tv;

    size = sizeof(cache_data) * config->block_size * config->block_count;
    if (!addr_cache)
    {
       addr_cache = malloc(size);
    }
    memset((void *)addr_cache, 0, size);

    size = sizeof(* addr_cache_counters) * config->block_count; 
    if (!addr_cache_counters)
    {
       addr_cache_counters = malloc(size);
    }
    memset((void *)addr_cache_counters, 0, size);

    size = sizeof(* addr_cache_pointers) * config->block_count;
    if (!addr_cache_pointers)
    {
       addr_cache_pointers = malloc(size);
    }
    memset((void *)addr_cache_pointers, 0, size);

    memset(&timer_event, 0, sizeof(timer_event));
    if (config->cache_file)
    {
        if (load_cache(config->cache_file))
            log_error(LOG_INFO, "Failed to load IP addresses from cache file: %s", config->cache_file);

        // start timer to save cache into file periodically.
        if (config->autosave_interval)
        {
            tv.tv_sec = config->autosave_interval;
            tv.tv_usec = 0;
            event_assign(&timer_event, get_event_base(), 0, EV_TIMEOUT|EV_PERSIST, cache_auto_saver, NULL);
            evtimer_add(&timer_event, &tv);
        }
    }
    set_cache_changed(0);

    return 0;
}

static int cache_fini()
{
    cache_config * config = get_config();
    // Update cache file before exit 
    if (config->autosave_interval && is_cache_changed() && config->cache_file)
    {
        save_cache(config->cache_file);
        set_cache_changed(0);
    }
    if (event_initialized(&timer_event))
    {
        evtimer_del(&timer_event);
    }
    // Free buffers allocated for cache
    if (addr_cache)
    {
        free(addr_cache);
        addr_cache = NULL;
    }
    if (addr_cache_counters)
    {
        free(addr_cache_counters);
        addr_cache_counters = NULL;
    }
    if (addr_cache_pointers)
    {
        free(addr_cache_pointers);
        addr_cache_pointers = NULL;
    }
    return 0;
}

static inline cache_data * get_cache_data(unsigned int block, unsigned int index)
{
    cache_config * config = get_config();

    unsigned int i =  block * config->block_size + index % config->block_size;
    return &addr_cache[i];
}

static cache_data * get_cache_item(const struct sockaddr_in * addr)
{
    cache_config * config = get_config();
    time_t now = redsocks_time(NULL);
    cache_data * item;
    /* get block index */
    unsigned int block = block_from_sockaddr_in(addr);
    unsigned int count = addr_cache_counters[block];
    unsigned int first = addr_cache_pointers[block];
    unsigned int i = 0;
    /* do reverse search for efficency */
    for (i = count; i > 0; i--)
    {
        item = get_cache_data(block, first+i-1);
        if (item
            && item->present
            && 0 == evutil_sockaddr_cmp((const struct sockaddr *)addr,
                 (const struct sockaddr *)&item->addr,
                 config->port_check))
        {
            // Remove stale item
            if (config->stale_time > 0   
               && item->access_time + config->stale_time < now)
            {
               item->present = 0;
               set_cache_changed(1);
               return NULL;
            }
            return item;
        }
    }       
    return NULL;
}

time_t * cache_get_addr_time(const struct sockaddr_in * addr)
{
    cache_data * item = get_cache_item(addr);
    if (item)
        return &item->access_time;
    return NULL;
}

void cache_touch_addr(const struct sockaddr_in * addr)
{
    cache_data * item = get_cache_item(addr);
    if (item)
        item->access_time = redsocks_time(NULL);
}

void cache_add_addr(const struct sockaddr_in * addr)
{
    cache_config * config = get_config();
    cache_data * item;
    unsigned int block = block_from_sockaddr_in(addr);
    unsigned int count = addr_cache_counters[block]; 
    /* use 'first' to index item in cache block when count is equal or greater than block size */
    unsigned int first = addr_cache_pointers[block]; 

    if (count < config->block_size)
        item = get_cache_data(block, count);
    else
        item = get_cache_data(block, first);

    memcpy((void *)&item->addr, (void *)addr, sizeof(struct sockaddr_in));
    item->present = 1;
    item->access_time = redsocks_time(NULL);
    addr_cache_pointers[block]++;
    addr_cache_pointers[block] %= config->block_size;

    set_cache_changed(1);
}

void cache_del_addr(const struct sockaddr_in * addr)
{
    cache_data * item = get_cache_item(addr);
    if (item)
    {
        item->present = 0; 
        set_cache_changed(1);
    }
}

#define ADDR_COUNT_PER_LINE 4
static void cache_dumper()
{
    unsigned int count = 0;
    unsigned int blk = 0;
    unsigned int idx = 0;
    unsigned int p = 0, j;
    char addr_str[ADDR_COUNT_PER_LINE][RED_INET_ADDRSTRLEN];
    cache_data * item;
    cache_config * config = get_config();

    log_error(LOG_INFO, "Start dumping IP cache:");
    for (; blk < config->block_count; blk++)
    {
        for (idx=0; idx < config->block_size; idx++)
        {
            item = get_cache_data(blk, idx);
            if (item && item->present)
            {
                count++;  
                red_inet_ntop(&item->addr, addr_str[p], sizeof(addr_str[0]));
                p++;
                if (p == ADDR_COUNT_PER_LINE)
                {
                    p = 0;
                    // TODO: Replace this implementation with better one
                    log_error(LOG_INFO, "%s %s %s %s", addr_str[0], 
                                        addr_str[1], addr_str[2], addr_str[3]);
                }
            }
        }
    }
    if (p)
    {
        // TODO: Replace this implementation with better one
        for (j = p; j < ADDR_COUNT_PER_LINE; j++)
            addr_str[j][0] = 0;
        log_error(LOG_INFO, "%s %s %s %s", addr_str[0], 
                            addr_str[1], addr_str[2], addr_str[3]);
    }

    log_error(LOG_INFO, "End of dumping IP cache. Totally %u entries.", count);
}

app_subsys cache_app_subsys =
{
    .init = cache_init,
    .fini = cache_fini,
    .dump = cache_dumper,
    .conf_section = &cache_conf_section,
};

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
