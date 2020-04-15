# redsocks – transparent TCP-to-proxy redirector

This tool allows you to redirect any TCP connection to SOCKS or HTTPS
proxy using your firewall, so redirection may be system-wide or network-wide.

When is redsocks useful?

* you want to route part of TCP traffic via OpenSSH `DynamicForward` Socks5
  port using firewall policies. That was original redsocks development goal;
* you use DVB ISP and this ISP provides internet connectivity with some
  special daemon that may be also called "Internet accelerator" and the
  accelerator acts as a proxy and has no "transparent proxy" feature and you
  need it. [Globax](http://www.globax.biz) was an example of alike accelerator,
  but Globax 5 has transparent proxy feature. That was the second redsocks`
  development goal;
* you have to pass traffic through proxy due to corporate network limitation.
  That was never a goal for redsocks, but users have reported success with
  some proxy configurations.

When is redsocks probably a wrong tool?

* redirecting traffic to [tor](https://www.torproject.org). First, you **have**
  to [use tor-aware software for anonymity](https://www.torproject.org/download/download.html.en#warning).
  Second, [use `TransPort`](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy)
  if you don't actually need anonymity. Third, question everything :-)
* trying to redirect traffic of significant number of connections over single
  SSH connection. That's not exactly [TCP over TCP](http://sites.inka.de/bigred/devel/tcp-tcp.html),
  but [head-of-line blocking](https://en.wikipedia.org/wiki/Head-of-line_blocking)
  will still happen and performance of real-time applications (IM, interactive
  Web applications) may be degraded during bulk transfers;
* trying to make non-transparent HTTP-proxy (not HTTPS-proxy) transparent using
  `http-relay` module. First, it will likely be broken as the code is hack.
  Second, the code is vulnerable to `CVE-2009-0801` and will unlikely be ever fixed;
* making "really" transparent proxy, redsocks acts at TCP level, so three-way
  handshake is completed and redsocks accepts connection before connection
  through proxy (and _to_ proxy) is established;
* trying to redirect traffic of significant number of connections in
  resource-constrained environment like SOHO Linux router. Throughput of single
  connection may be good enough like 40 Mbit/s
  on [TP-Link TD-W8980](https://wiki.openwrt.org/toh/tp-link/td-w8980),
  but amount of concurrent connections may be limiting factor as TCP buffers
  are still consumed;
* redirecting traffic to proxy on mobile device running Android or iOS as it'll require
  [rooting](https://en.wikipedia.org/wiki/Rooting_(Android)) to update firewall
  rules. Probably, the better way is to use on-device VPN daemon to intercept
  traffic via [`VpnService` API for Android](https://developer.android.com/reference/android/net/VpnService.html)
  and [`NETunnelProvider` family of APIs for iOS](https://developer.apple.com/documentation/networkextension).
  That may require some code doing [TCP Reassembly](https://wiki.wireshark.org/TCP_Reassembly)
  like [`tun2socks`](https://github.com/ambrop72/badvpn/wiki/Tun2socks).

Linux/iptables is supported.  OpenBSD/pf and FreeBSD/ipfw may work with some
hacks. The author has no permanent root access to machines running OpenBSD,
FreeBSD and MacOSX to test and develop for these platforms.

[Transocks](http://transocks.sourceforge.net/) is alike project but it has
noticeable performance penality.

[Transsocks_ev](http://oss.tiggerswelt.net/transocks_ev/)
is alike project too, but it has no HTTPS-proxy support
and does not support authentication.

Several Android apps also use redsocks under-the-hood:
[ProxyDroid](https://github.com/madeye/proxydroid)
[<i class="fa fa-play"></i>](https://market.android.com/details?id=org.proxydroid) and
[sshtunnel](https://code.google.com/archive/p/sshtunnel/)
[<i class="fa fa-play"></i>](https://market.android.com/details?id=org.sshtunnel).
And that's over 1'500'000 downloads! Wow!

## Features

Redirect any TCP connection to Socks4, Socks5 or HTTPS (HTTP/CONNECT)
proxy server.

Login/password authentication is supported for Socks5/HTTPS connections.
Socks4 supports only username, password is ignored. for HTTPS, currently
only Basic and Digest scheme is supported.

Redirect UDP packets via Socks5 proxy server. NB: UDP still goes via UDP, so
you can't relay UDP via OpenSSH.

Handle DNS/UDP queries sending "truncated reply" as an answer or making them
DNS/TCP queries to some recursive resolver.

Redirect any HTTP connection to proxy that does not support transparent
proxying (e.g. old SQUID had broken `acl myport' for such connections).

### Enforcing DNS over TCP using `dnstc`

DNS is running over UDP and it may be an issue in some environments as proxy
servers usually don't handle UDP as a first-class citizen.  Redsocks includes
`dnstc` that is fake and really dumb DNS server that returns "truncated answer"
to every query via UDP. RFC-compliant resolver should repeat same query via TCP
in this case - so the request can be redirected using usual redsocks facilities.

Known compliant resolvers are:

* bind9 (server);
* dig, nslookup (tools based on bind9 code).

Known non-compliant resolvers are:

* eglibc resolver fails without any attempt to send request via TCP;
* powerdns-recursor can't properly startup without UDP connectivity as it
  can't load root hints.

On the other hand, DNS via TCP using bind9 may be painfully slow.
If your bind9 setup is really slow, you may want to try
[pdnsd](http://www.phys.uu.nl/~rombouts/pdnsd.html) caching server
that can run in TCP-only mode.

### Relaying DNS/UDP to DNS/TCP via `dnsu2t`

The code acts as DNS server that multiplexes several UDP queries into single
stream of TCP queries over keep-alive connection to upstream DNS server that
should be recursive resolver. TCP connection may be handled by `redsocks`
itself if firewall is configured with corresponding rules.

Different resolvers have different timeouts and allow different count of
in-flight connections, so you have to tune options yourself for optimal
performance (with some black magic, as script testing for optimal DNS/TCP
connection parameters is not written yet).

There are other programs doing alike job (with, probably, different bugs)

* [ttdnsd](http://www.mulliner.org/collin/ttdnsd.php)
* [dns2socks](https://github.com/qiuzi/dns2socks) for Windows
* [tcpdnsproxy](https://github.com/jtripper/dns-tcp-socks-proxy)

## Source

Source is available at [<i class="fa fa-github"></i> GitHub](https://github.com/darkk/redsocks).

Issue tracker is also at GitHub, but keep in mind that the project is not
actively maintained, so feature requests will unlikely be implemented within
reasonable timeframe.  Reproducable bugs having clean desciption will likely be
fixed. Destiny of hard-to-reproduce bugs is hard to predict.

New network protocols will unlikely be implemented within this source tree, but
if you're seeking for censorship circumvention protocols, you may want to take
a look at [redsocks2](https://github.com/semigodking/redsocks) by Zhuofei Wang
AKA @semigodking who is actively maintaining the fork with GFW in mind.

## License

All source code is licensed under Apache 2.0 license.
You can get a copy at http://www.apache.org/licenses/LICENSE-2.0.html

## Packages

* Archlinux: https://aur.archlinux.org/packages/redsocks-git
* Debian: http://packages.debian.org/search?searchon=names&keywords=redsocks
* Gentoo (zugaina overlay): http://gpo.zugaina.org/net-proxy/redsocks
* Gentoo: https://packages.gentoo.org/packages/net-proxy/redsocks
* Ubuntu: http://packages.ubuntu.com/search?searchon=names&keywords=redsocks

## Compilation

[libevent-2.0.x](http://libevent.org/) is required.

gcc and clang are supported right now, other compilers can be used
but may require some code changes.

Compilation is as easy as running `make`, there is no `./configure` magic.

GNU Make works, other implementations of make were not tested.

## Running

Program has following command-line options:

* `-c` sets proper path to config file ("./redsocks.conf" is default one)
* `-t` tests config file syntax
* `-p` set a file to write the getpid() into

Following signals are understood:
SIGUSR1 dumps list of connected clients to log,
SIGTERM and SIGINT terminates daemon, all active connections are closed.

You can see configuration file example in [redsocks.conf.example](https://github.com/darkk/redsocks/blob/master/redsocks.conf.example).

### iptables example

You have to build iptables with connection tracking and REDIRECT target.

```
# Create new chain
root# iptables -t nat -N REDSOCKS

# Ignore LANs and some other reserved addresses.
# See http://en.wikipedia.org/wiki/Reserved_IP_addresses#Reserved_IPv4_addresses
# and http://tools.ietf.org/html/rfc5735 for full list of reserved networks.
root# iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
root# iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
root# iptables -t nat -A REDSOCKS -d 100.64.0.0/10 -j RETURN
root# iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
root# iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
root# iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
root# iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
root# iptables -t nat -A REDSOCKS -d 198.18.0.0/15 -j RETURN
root# iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
root# iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN

# Anything else should be redirected to port 12345
root# iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 12345

# Any tcp connection made by `luser' should be redirected.
root# iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner luser -j REDSOCKS

# You can also control that in more precise way using `gid-owner` from
# iptables.
root# groupadd socksified
root# usermod --append --groups socksified luser
root# iptables -t nat -A OUTPUT -p tcp -m owner --gid-owner socksified -j REDSOCKS

# Now you can launch your specific application with GID `socksified` and it
# will be... socksified. See following commands (numbers may vary).
# Note: you may have to relogin to apply `usermod` changes.
luser$ id
uid=1000(luser) gid=1000(luser) groups=1000(luser),1001(socksified)
luser$ sg socksified -c id
uid=1000(luser) gid=1001(socksified) groups=1000(luser),1001(socksified)
luser$ sg socksified -c "firefox"

# If you want to configure socksifying router, you should look at
# doc/iptables-packet-flow.png, doc/iptables-packet-flow-ng.png and
# https://en.wikipedia.org/wiki/File:Netfilter-packet-flow.svg
# Note, you should have proper `local_ip' value to get external packets with
# redsocks, default 127.0.0.1 will not go. See iptables(8) manpage regarding
# REDIRECT target for details.
# Depending on your network configuration iptables conf. may be as easy as:
root# iptables -t nat -A PREROUTING --in-interface eth_int -p tcp -j REDSOCKS
```

### Note about GID-based redirection

Keep in mind, that changed GID affects filesystem permissions, so if your
application creates some files, the files will be created with luser:socksified
owner/group. So, if you're not the only user in the group `socksified` and your
umask allows to create group-readable files and your directory permissions, and
so on, blah-blah, etc. THEN you may expose your files to another user.
Ok, you have been warned.

## Homepage

http://darkk.net.ru/redsocks/

Mailing list: [redsocks@librelist.com](mailto:redsocks@librelist.com).

Mailing list also has [archives](http://librelist.com/browser/redsocks/).

## Author

This program was written by Leonid Evdokimov <leon@darkk.net.ru>
