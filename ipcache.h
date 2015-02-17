#ifndef REDSOCKS_CACHE_H
#define  REDSOCKS_CACHE_H

void cache_add_addr(const struct sockaddr_in * addr);
void cache_del_addr(const struct sockaddr_in * addr);
void cache_touch_addr(const struct sockaddr_in * addr);
time_t * cache_get_addr_time(const struct sockaddr_in * addr);

#endif

