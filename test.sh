#!/bin/sh -eux
# This script is used by out-of-tree (a tool to assist kernel module testing),
# https://github.com/jollheef/out-of-tree
dmesg | grep 'LKRG initialized successfully!'
