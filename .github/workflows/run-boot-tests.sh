#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run some tests
#
# Copyright (c) 2022 Vitaly Chikunov <vt@altlinux.org>.
#

set -eux -o pipefail

if [ ! -d /sys/module/lkrg ]; then
	modprobe lkrg
fi

# Trigger loading vhost_vsock module (using UMH call to modprobe).
# Device numbers are from /lib/modules/*/modules.devname
mknod /dev/test c 10 241
true < /dev/test
dmesg -T | grep 'Registered.*protocol family' | grep -w -e 'PF_VSOCK' -e '40'

# Sleep (watchdog_thresh*2+1) seconds to let hard and soft lockup detectors to work.
sleep 21

# Failed tests will not output this line.
echo "$0 - SUCCESS"

# If there is no systemd shutdown manually.
if [ ! -d /run/systemd/system ]; then
	poweroff -f || echo o > /proc/sysrq-trigger
	sleep 11
fi
