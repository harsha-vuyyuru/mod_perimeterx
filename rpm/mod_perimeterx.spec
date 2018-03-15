%{!?_httpd_apxs:       %{expand: %%global _httpd_apxs       %%{_sbindir}/apxs}}
%{!?_httpd_confdir:    %{expand: %%global _httpd_confdir    %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:     %{expand: %%global _httpd_moddir     %%{_libdir}/httpd/modules}}

Summary:	Apache 2 PerimeterX module
Name:		mod_perimeterx
Version:	2.10.0
Release:	1%{?dist}
Group:		System Environment/Daemons
License:	MIT
URL:		http://www.perimeterx.com/
Source0:	https://github.com/PerimeterX/mod_perimeterx
BuildRequires:	httpd-devel jansson-devel libcurl-devel
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id} -u -n)

%description
This is a PerimeterX module for the Apache 2.x web server.  PerimeterX is bot
detection platform for web applications, for more information please visit
http://www.perimeterx.com/

%prep
%setup -q

%build
%configure
%{__make} %{?_smp_mflags}

%install
rm -rf \$RPM_BUILD_ROOT
install -m0755 src/.libs/mod_perimeterx.so %{buildroot}%{_httpd_moddir}/mod_perimeterx.so

%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
# 2.4
install -Dp -m 0644 debian/perimeterx.load $RPM_BUILD_ROOT%{_httpd_modconfdir}/10-perimeterx.conf
%endif

%files
%defattr (-,root,root)
%{_httpd_moddir}/mod_perimeterx.so
%if "%{_httpd_modconfdir}" != "%{_httpd_confdir}"
%config(noreplace) %{_httpd_modconfdir}/*.conf
%endif

