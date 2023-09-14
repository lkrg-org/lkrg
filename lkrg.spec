%define kmod_headers_version	%(rpm -qa kernel-devel | sed 's/^kernel-devel-//' | sort -r | head -1)
%define module_dir		/lib/modules/%kmod_headers_version
%global debug_package		%nil

Summary: Linux Kernel Runtime Guard (LKRG)
Name: lkrg
Version: 0.9.6
Release: 1%{?dist}
License: GPLv2
URL: https://lkrg.org
Source: https://lkrg.org/download/%name-%version.tar.gz
ExclusiveArch: %ix86 x86_64 %arm32 %arm64
BuildRequires: make, gcc, kernel-devel
BuildRoot: /override/%name-%version

%description
LKRG performs runtime integrity checking of the Linux kernel and detection of
security vulnerability exploits against the kernel.

As controversial as this concept is, LKRG attempts to post-detect and
hopefully promptly respond to unauthorized modifications to the running Linux
kernel (integrity checking) or to credentials such as user IDs of the running
processes (exploit detection).  For process credentials, LKRG attempts to
detect the exploit and take action before the kernel would grant access (such
as open a file) based on the unauthorized credentials.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf %buildroot
install -D -p -m 644 lkrg.ko %buildroot%module_dir/lkrg.ko
install -D -p -m 644 scripts/bootup/systemd/lkrg.service %buildroot%_unitdir/lkrg.service
install -D -p -m 644 scripts/bootup/lkrg.conf %buildroot%_sysconfdir/sysctl.d/01-lkrg.conf

%post
%sbindir/depmod -a
echo 'To start LKRG please use: systemctl start lkrg'
echo 'To enable LKRG on bootup please use: systemctl enable lkrg'

%preun
%systemd_preun lkrg.service

%postun
%systemd_postun_with_restart lkrg.service

%files
%defattr(-,root,root)
%doc CHANGES CONCEPTS LICENSE PATREONS PERFORMANCE README
%module_dir/*
%_unitdir/*
%_sysconfdir/sysctl.d/*

%changelog
* Wed Sep 13 2023 Solar Designer <solar@openwall.com> 0.9.6-1
- Wrote this rough RPM spec file for Red Hat'ish distros, seems to work fine on
RHEL 7, 8, 9 rebuilds, but is only reliable when there's exactly one
kernel-devel package installed at build time and it exactly matches the target
kernel version.
