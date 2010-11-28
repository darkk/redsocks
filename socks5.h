#ifndef SOCKS5_H
#define SOCKS5_H

struct evbuffer *socks5_mkmethods_plain(int do_password);
struct evbuffer *socks5_mkpassword_plain(const char *login, const char *password);


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
#endif /* SOCKS5_H */
