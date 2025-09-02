%define kmod_headers_version	%(rpm -qa kernel-devel | sed 's/^kernel-devel-//' | sort -rV | head -1)
%define module_dir		/lib/modules/%kmod_headers_version/extra
%global debug_package		%nil

Summary: Linux Kernel Runtime Guard (LKRG)
Name: lkrg
Version: 1.0.0
Release: 1%{?dist}
License: GPLv2
URL: https://lkrg.org
Source: https://lkrg.org/download/%name-%version.tar.gz
ExclusiveArch: x86_64 %arm32 %arm64
BuildRequires: make, gcc, elfutils-libelf-devel, kernel-devel, systemd
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
make %{?_smp_mflags} KERNEL=/usr/src/kernels/%kmod_headers_version
make -C logger %{?_smp_mflags} CFLAGS='-fPIE %optflags' LDFLAGS='-s -fPIE -pie -Wl,-z,defs -Wl,-z,relro -Wl,-z,now %optflags'

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
* Tue Sep  2 2025 Solar Designer <solar@openwall.com> 1.0.0-1
- Update to 1.0.0

* Thu May 15 2025 Solar Designer <solar@openwall.com> 0.9.9-8
- Update to latest git as of today (aa6f685005bb27eccb060ed552877ba5677012d4)

* Fri May  2 2025 Solar Designer <solar@openwall.com> 0.9.9-7
- Update to latest git as of today (1bde9e5489268d877c07fd7a5fd91085e69a4fb5)

* Mon Feb  3 2025 Solar Designer <solar@openwall.com> 0.9.9-5
- Add -fPIE to logger CFLAGS for consistency with -pie in LDFLAGS
  (but no issues were seen on Rocky Linux 8 and 9 even without this change)

* Fri Jan 31 2025 Solar Designer <solar@openwall.com> 0.9.9-4
- Pass -s -pie -Wl,-z,defs -Wl,-z,relro -Wl,-z,now and optflags into LDFLAGS
  when building the logger userspace binaries

* Wed Oct 23 2024 Solar Designer <solar@openwall.com> 0.9.9-1
- Update to 0.9.9

* Wed May 22 2024 Solar Designer <solar@openwall.com> 0.9.8-2
- Pass direct kernel-devel's build path into make
- Drop "BuildRequires: kernel" as we no longer need /lib/modules/*/build
- Add "BuildRequires: systemd" for the _unitdir RPM macro (apparently this was
  previously an indirect dependency via the kernel package)

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
