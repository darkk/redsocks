#
# spec file for package 
#
# Copyright (c) 2020 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

%if 0%{!?_fillupdir:1}
# < SLES15 (para SLE15>=, /usr/share/fillup-templates)
%define _fillupdir	%{_var}/adm/fillup-templates
%endif

Name:		redsocks
Version:	0.5.1
Release:	0
License:	Apache-2.0
Summary:	Redirect any TCP connection to a SOCKS or HTTPS proxy server
Url:		http://darkk.net.ru/redsocks/
Group:		Productivity/Networking/Other
Source:		%{name}-%{version}.tar.gz
BuildRequires:	libevent-devel
PreReq:		%fillup_prereq
PreReq:		/usr/bin/getent
%if 0%{?suse_version} >= 1210
BuildRequires: systemd
%endif
%{?systemd_requires}

%description
Redsocks is a daemon running on the local system, that will transparently
tunnel any TCP connection via a remote SOCKS4, SOCKS5 or HTTP proxy server. It
uses the system firewall's redirection facility to intercept TCP connections,
thus the redirection is system-wide, with fine-grained control, and does 
not depend on LD_PRELOAD libraries.

Redsocks supports tunneling TCP connections and UDP packets. It has
authentication support for both, SOCKS and HTTP proxies.

Also included is a small DNS server returning answers with the "truncated" flag
set for any UDP query, forcing the resolver to use TCP.

%prep
%setup 

%build
CFLAGS="$RPM_OPT_FLAGS" make %{?_smp_mflags}

%install
%{__install} -v -D -m 755 %{name} %buildroot/%_prefix/bin/%{name}
%{__install} -D %{name}.service %buildroot/%_unitdir/%{name}.service
sed -i -e 's#EnvironmentFile=.*#EnvironmentFile=%{_sysconfdir}/sysconfig/%{name}#' %buildroot/%_unitdir/%{name}.service
mkdir -p %{buildroot}%{_sbindir}
ln -s -f %{_sbindir}/service %{buildroot}%{_sbindir}/rc%{name}
%{__install} -D debian/%{name}.conf %buildroot/%_sysconfdir/%{name}/%{name}.conf
%{__install} -D debian/%{name}.8 %buildroot/%_mandir/man8/%{name}.8
gzip %buildroot/%_mandir/man8/%{name}.8
%{__install} -D -m644 SuSE/%{name}.sysconfig %{buildroot}%{_fillupdir}/sysconfig.%{name}
%{__install} -d -m 0755 %{buildroot}%{_tmpfilesdir}
echo "d /var/run/%name  755 %name %name" >%{buildroot}%{_tmpfilesdir}/%{name}.conf

%pre
%service_add_pre %{name}.service
if ! /usr/bin/getent passwd %name &>/dev/null; then
  echo "Creating %name user"
  /usr/sbin/useradd -c "RedSocks user" -s /sbin/nologin -r -d /var/run/%name -U %name 2> /dev/null || :
fi

%post
%fillup_only
%service_add_post %{name}.service
systemd-tmpfiles --create %{_tmpfilesdir}/%{name}.conf

%preun
%service_del_preun %{name}.service

%postun
%service_del_postun %{name}.service

%files
%defattr(-,root,root)
%doc README.md redsocks.conf.example
%doc %attr(644,root,root) %_mandir/*/*
%dir %_sysconfdir/%{name}
%config(noreplace) %attr(644,root,root) %_sysconfdir/%{name}/%{name}.conf
%attr(755,root,root) %{_prefix}/bin/%{name}
%attr(755,root,root) %{_sbindir}/rc%{name}
%attr(644,root,root) %_unitdir/%{name}.service
%{_fillupdir}/sysconfig.%{name}
%{_tmpfilesdir}/%{name}.conf

%changelog

