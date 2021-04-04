#!/bin/bash -eux
# Non-default mkosi.prepare script (--prepare-script=) to install
# mainline kernel debs.
# (It does have network and can run additional installs if needed.)

banner "dpkg -i" >&2
cd /root/src
ls -l linux-*.deb
dpkg -i linux-*.deb
