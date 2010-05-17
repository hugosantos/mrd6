Summary: Multicast Routing Daemon for IPv6
Name: mrd6
Version: 0.9.5
Release: 1
URL: http://fivebits.net/mrd6/
License: GPL
Source0: http://fivebits.net/mrd6/download/mrd6-0.9.5.tar.gz
Group: Networking
Packager: Hugo Santos <hsantos@av.it.pt>
BuildRoot: %{_builddir}/%{name}-%{version}-root

%description
  MRD6 is a modular IPv6 Multicast Routing Daemon which implements:
    * MLDv1 and MLDv2 with forwarding capabilities
      - MLD proxying
    * PIM-SM (ASM and SSM)
      - Bootstrap (BSR) Mechanism support
      - Static RP configuration
      - Embedded-RP support
    * partial MBGP support
      - Uses IPv6 Multicast SAFI prefixes announced by
        peers to update local MRIB
      - Is able to announce local prefixes
      - Filter support
    * Native and virtual (tunnel) interfaces support
    * CLI support (remote configuration and management) via
      telnet or local access

%prep
%setup -q -n mrd6-0.9.5

%build
make

%install
[ %{buildroot} != "/" ] && rm -rf %{buildroot}
PREFIX=%{_prefix} DESTDIR=%{buildroot} make install

%clean
[ %{buildroot} != "/" ] && rm -rf %{buildroot}

%files
%defattr(-, root, root)
%doc README README.translator MRD6shQuickRef.txt src/confs/mrd.conf
%{_prefix}/sbin/mrd6
%{_prefix}/lib/mrd6/*
%{_prefix}/bin/mrd6sh

%changelog
* Sun Jan  8 2006 Hugo Santos <hsantos@av.it.pt> 0.9.5
- 0.9.5
