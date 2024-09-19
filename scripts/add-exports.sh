#!/bin/bash
set -e
KDIR="${KDIR:="/usr/src/linux"}"
cd "$KDIR"
# Add critical exports to prevent them from being optimized-out
echo "EXPORT_SYMBOL(change_page_attr_set_clr);" >> arch/x86/mm/pat/set_memory.c
echo "EXPORT_SYMBOL(lookup_fast);" >> fs/namei.c
echo "EXPORT_SYMBOL(do_seccomp);" >> kernel/seccomp.c
# Fix modpost errors
sed -i 's/static int change_page_attr_set_clr/int change_page_attr_set_clr/' arch/x86/mm/pat/set_memory.c
sed -i 's/static struct dentry \*lookup_fast/struct dentry \*lookup_fast/' fs/namei.c
sed -i 's/static long do_seccomp/long do_seccomp/' kernel/seccomp.c
