#!/bin/bash
set -e
KDIR="${KDIR:="/usr/src/linux"}"
cd "$KDIR"
# Add critical exports to prevent them from being optimized-out
echo "EXPORT_SYMBOL(change_page_attr_set_clr);" >> arch/x86/mm/pat/set_memory.c
echo "EXPORT_SYMBOL(lookup_fast);" >> fs/namei.c
echo "EXPORT_SYMBOL(do_seccomp);" >> kernel/seccomp.c
