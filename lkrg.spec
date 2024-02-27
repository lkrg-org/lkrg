%define kmod_headers_version	%(rpm -qa kernel-devel | sed 's/^kernel-devel-//' | sort -rV | head -1)
%define module_dir		/lib/modules/%kmod_headers_version/extra
%global debug_package		%nil

Summary: Linux Kernel Runtime Guard (LKRG)
Name: lkrg
Version: 0.9.8
Release: 1%{?dist}
License: GPLv2
URL: https://lkrg.org
Source: https://lkrg.org/download/%name-%version.tar.gz
ExclusiveArch: x86_64 %arm32 %arm64
BuildRequires: make, gcc, elfutils-libelf-devel, kernel, kernel-devel
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

%package logger
Summary: Linux Kernel Runtime Guard (LKRG) remote logging tools
Requires(pre): /usr/sbin/useradd

%description logger
Userspace tools to support Linux Kernel Runtime Guard (LKRG) remote logging.

%prep
%setup -q

%build
make %{?_smp_mflags} KERNELRELEASE=%kmod_headers_version
make -C logger %{?_smp_mflags} CFLAGS='%optflags'

%install
rm -rf %buildroot
install -D -p -m 644 lkrg.ko %buildroot%module_dir/lkrg.ko
install -D -p -m 644 scripts/bootup/systemd/lkrg.service %buildroot%_unitdir/lkrg.service
install -D -p -m 644 scripts/bootup/lkrg.conf %buildroot%_sysconfdir/sysctl.d/01-lkrg.conf
make -C logger install DESTDIR=%buildroot PREFIX=/usr UNITDIR=%_unitdir
mkdir -p %buildroot/var/log/lkrg-logger

%posttrans
if [ -e %_sbindir/weak-modules ]; then
	echo %module_dir/lkrg.ko | %_sbindir/weak-modules --verbose --add-modules --no-initramfs
else
	%sbindir/depmod -a
fi
echo 'To start LKRG please use: systemctl start lkrg'
echo 'To enable LKRG on bootup please use: systemctl enable lkrg'

%preun
%systemd_preun lkrg.service

%postun
if [ -e %_sbindir/weak-modules ]; then
	echo %module_dir/lkrg.ko | %_sbindir/weak-modules --verbose --remove-modules --no-initramfs
fi
%systemd_postun_with_restart lkrg.service

%pre logger
# Ignore errors so that we don't fail if the user already exists
/usr/sbin/useradd -r lkrg-logger -d / -s /sbin/nologin || :
# Don't remove this user on package uninstall because the user may still own
# files under /var/log/lkrg-logger, which won't be removed if non-empty

%files
%defattr(-,root,root)
%doc CHANGES CONCEPTS LICENSE PATREONS PERFORMANCE README
%module_dir/*
%_unitdir/lkrg.service
%config(noreplace) %_sysconfdir/sysctl.d/*

%files logger
%defattr(-,root,root)
%doc LOGGING
/usr/sbin/*
%_unitdir/lkrg-logger.service
%dir %attr(0750,lkrg-logger,lkrg-logger) /var/log/lkrg-logger

%changelog
* Tue Feb 27 2024 Solar Designer <solar@openwall.com> 0.9.8-1
- Update to 0.9.8
- Add logger sub-package
- Mark the sysctl configuration file config(noreplace)
- Use "sort -V" to build against the latest installed version of kernel-devel

* Wed Nov  8 2023 Solar Designer <solar@openwall.com> 0.9.7-4
- Add a couple of upstream patches, most notably to fix kINT false positives on
EL 8.8.

* Tue Oct 24 2023 Solar Designer <solar@openwall.com> 0.9.7-3
- Use weak-modules if available so that on RHEL and its rebuilds the same LKRG
  package build works across different kABI-compatible kernel revisions/builds
- Drop 32-bit x86 from ExclusiveArch since recent RHEL lacks such kernel-devel

* Thu Sep 14 2023 Solar Designer <solar@openwall.com> 0.9.7-2
- Use kernel build directory corresponding to the kernel-devel package, not to
the currently running kernel
- "BuildRequires: kernel" for the /lib/modules/* directory
- "BuildRequires: elfutils-libelf-devel" to support CONFIG_UNWINDER_ORC=y

* Thu Sep 14 2023 Solar Designer <solar@openwall.com> 0.9.7-1
- Wrote this rough RPM spec file for Red Hat'ish distros, seems to work fine on
RHEL 7, 8, 9 rebuilds, but is only reliable when there's exactly one
kernel-devel package installed at build time and it exactly matches the target
kernel version.
