REDSOCKS2
=========
This is a modified version of original redsocks.
The name is changed to be REDSOCKS2 since this release to distinguish
with original redsocks.
This variant is useful for anti-GFW (Great Fire Wall).

##Note:
Method 'autosocks5' and 'autohttp-connect' are removed.
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
	 //type = http-connect;
	 //login = username;
	 //password = passwd;
	}

