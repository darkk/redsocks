#ifndef BASE_H_SUN_JUN__3_20_15_57_2007
#define BASE_H_SUN_JUN__3_20_15_57_2007

int getdestaddr(int fd, const struct sockaddr_storage *client, const struct sockaddr_storage *bindaddr, struct sockaddr_storage *destaddr);
int apply_tcp_keepalive(int fd);
int apply_reuseport(int fd);

/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* BASE_H_SUN_JUN__3_20_15_57_2007 */
