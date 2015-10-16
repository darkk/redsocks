REDSOCKS2
=========
This is a modified version of original redsocks.
The name is changed to REDSOCKS2 to distinguish with original redsocks.
REDSOCKS2 contains several new features besides many bug fixes to original
redsocks.

1. Redirect TCP connections which are blocked via proxy automatically without
need of blacklist.
2. Redirect UDP based DNS requests via TCP connection.
3. Integrated [shadowsocks](http://shadowsocks.org/) proxy support(IPv4 Only).
4. Redirect TCP connections without proxy.
5. Redirect TCP connections via specified network interface.
6. UDP transparent proxy via shadowsocks proxy.
7. Support Ful-cone NAT Traversal when working with shadowsocks proxy.

[Chinese Reference](https://github.com/semigodking/redsocks/wiki)

HOW TO BUILD
------------
###Prerequisites
The following libraries are required.

* libevent2
* OpenSSL or PolarSSL

###Steps
On general linux, simply run command below to build with OpenSSL.

	make

To compile with PolarSSL

	make USE_CRYPTO_POLARSSL=true

Since this variant of redsocks is customized for running with Openwrt, please
read documents here (http://wiki.openwrt.org/doc/devel/crosscompile) for how
to cross compile.

Configurations
--------------
Please see 'redsocks.conf.example' for whole picture of configuration file.
Below are additional sample configuration sections for different usage.
Operations required to iptables are not listed here.

###Redirect Blocked Traffic via Proxy Automatically
To use the autoproxy feature, please change the redsocks section in
configuration file like this:

	redsocks {
	 local_ip = 192.168.1.1;
	 local_port = 1081;
	 ip = 192.168.1.1;
	 port = 9050;
	 type = socks5; // I use socks5 proxy for GFW'ed IP
	 autoproxy = 1; // I want autoproxy feature enabled on this section.
	 // timeout is meaningful when 'autoproxy' is non-zero.
	 // It specified timeout value when trying to connect to destination
	 // directly. Default is 10 seconds. When it is set to 0, default
	 // timeout value will be used.
	 // NOTE: decreasing the timeout value may lead increase of chance for
	 // normal IP to be misjudged.
	 timeout = 13;
	 //type = http-connect;
	 //login = username;
	 //password = passwd;
	}

###Redirect Blocked Traffic via VPN Automatically
Suppose you have VPN connection setup with interface tun0. You want all 
all blocked traffic pass through via VPN connection while normal traffic
pass through via default internet connection.

	redsocks {
		local_ip = 192.168.1.1;
		local_port = 1080;
		interface = tun0; // Outgoing interface for blocked traffic
		type = direct;
		timeout = 13;
		autoproxy = 1;
	}

###Redirect Blocked Traffic via shadowsocks proxy
Similar like other redsocks section. The encryption method is specified
by field 'login'.

	redsocks {
		local_ip = 192.168.1.1;
		local_port = 1080;
		type = shadowsocks;
	 	ip = 192.168.1.1;
		port = 8388;
		timeout = 13;
		autoproxy = 1;
		login = "aes-128-cfb"; // field 'login' is reused as encryption
							   // method of shadowsocks
		password = "your password"; // Your shadowsocks password
	}
	
	redudp {
		local_ip = 127.0.0.1;
		local_port = 1053;
		ip = your.ss-server.com;
		port = 443;
		type = shadowsocks;
		login = rc4-md5;
		password = "ss server password";
		dest_ip = 8.8.8.8;
		dest_port = 53;
		udp_timeout = 3;
	}


List of supported encryption methods(Compiled with OpenSSL):

	table
	rc4
	rc4-md5
	aes-128-cfb
	aes-192-cfb
	aes-256-cfb
	bf-cfb
	camellia-128-cfb
	camellia-192-cfb
	camellia-256-cfb
	cast5-cfb
	des-cfb
	idea-cfb
	rc2-cfb
	seed-cfb

List of supported encryption methods(Compiled with PolarSSL):

	table
	ARC4-128
	AES-128-CFB128
	AES-192-CFB128
	AES-256-CFB128
	BLOWFISH-CFB64
	CAMELLIA-128-CFB128
	CAMELLIA-192-CFB128
	CAMELLIA-256-CFB128

###Work with GoAgent
To make redsocks2 works with GoAgent proxy, you need to set proxy type as
'http-relay' for HTTP protocol and 'http-connect' for HTTPS protocol  
respectively.
Suppose your goagent local proxy is running at the same server as redsocks2,
The configuration for forwarding connections to GoAgent is like below:

	redsocks {
	 local_ip = 192.168.1.1;
	 local_port = 1081; //HTTP should be redirect to this port.
	 ip = 192.168.1.1;
	 port = 8080;
	 type = http-relay; // Must be 'htt-relay' for HTTP traffic. 
	 autoproxy = 1; // I want autoproxy feature enabled on this section.
	 // timeout is meaningful when 'autoproxy' is non-zero.
	 // It specified timeout value when trying to connect to destination
	 // directly. Default is 10 seconds. When it is set to 0, default
	 // timeout value will be used.
	 timeout = 13;
	}
	redsocks {
	 local_ip = 192.168.1.1;
	 local_port = 1082; // HTTPS should be redirect to this port.
	 ip = 192.168.1.1;
	 port = 8080;
	 type = http-connect; // Must be 'htt-connect' for HTTPS traffic. 
	 autoproxy = 1; // I want autoproxy feature enabled on this section.
	 // timeout is meaningful when 'autoproxy' is non-zero.
	 // It specified timeout value when trying to connect to destination
	 // directly. Default is 10 seconds. When it is set to 0, default
	 // timeout value will be used.
	 timeout = 13;
	}

###Redirect UDP based DNS Request via TCP connection
Sending DNS request via TCP connection is one way to prevent from DNS
poisoning. You can redirect all UDP based DNS requests via TCP connection
with the following config section.

    tcpdns {
    	// Transform UDP DNS requests into TCP DNS requests.
    	// You can also redirect connections to external TCP DNS server to
    	// REDSOCKS transparent proxy via iptables.
    	local_ip = 192.168.1.1; // Local server to act as DNS server
    	local_port = 1053;      // UDP port to receive UDP DNS requests
    	tcpdns1 = 8.8.4.4;      // DNS server that supports TCP DNS requests
    	tcpdns2 = 8.8.8.8;      // DNS server that supports TCP DNS requests
    	timeout = 4;            // Timeout value for TCP DNS requests
    }

Then, you can either redirect all your DNS requests to the local IP:port
configured above by iptables, or just change your system default DNS upstream
server as the local IP:port configured above.

AUTHOR
------
[Zhuofei Wang](mailto:semigodking.com) semigodking@gmail.com

