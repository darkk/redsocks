REDSOCKS2
=========
This is a modified version of original redsocks.
The name is changed to REDSOCKS2 to distinguish with original redsocks.
This variant is useful for anti-GFW (Great Fire Wall).

HOW it works
------------
Anyone can help me to complete this part? -_-

HOW TO BUILD
------------
On general linux, simply run command below to build.

	make

Since this variant of redsocks is customized for running with Openwrt, please
read documents here (http://wiki.openwrt.org/doc/devel/crosscompile) for how
to cross compile.

Configurations
--------------
Please see 'redsocks.conf.example' for whole picture of configuration file.
Below are additional sample configuration sections for different usage.

##Redirect Blocked Traffic via Proxy Automatically
To use the autoproxy feature, please change the redsocks section in
configuration file like this:

	redsocks {
	 local_ip = 192.168.1.1;
	 local_port = 1081;
	 ip = 192.168.1.1;
	 port = 9050;
	 type = socks5; // I use socks5 proxy for GFW'ed IP
	 autoproxy = 1; // I want autoproxy feature enabled on this section.
	                // The two lines above have same effect as
	                //    type = autosocks5;
	                // in previous release.
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


##Redirect Blocked Traffic via VPN Automatically
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


##Work with GoAgent
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

##Redirect UPD based DNS Request via TCP connection
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
Zhuofei Wang <semigodking@gmail.com> **Accept donations by AliPay with this email**
