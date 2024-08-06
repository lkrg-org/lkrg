#!/bin/bash
set -e
KDIR="${KDIR:="/usr/src/linux"}"
cd "$KDIR"
# Add critical exports to prevent them from being optimized-out
echo "EXPORT_SYMBOL(change_page_attr_set_clr);" >> arch/x86/mm/pat/set_memory.c
echo "EXPORT_SYMBOL(lookup_fast);" >> fs/namei.c
# keep symbol export inside the ifdef block defining the symbol
sed -i '/static void __seccomp_filter_release.*/iEXPORT_SYMBOL(__put_seccomp_filter);\n' kernel/seccomp.c
echo "EXPORT_SYMBOL(do_seccomp);" >> kernel/seccomp.c
# fixes modpost errors
sed -i 's/static int change_page_attr_set_clr/int change_page_attr_set_clr/g'  arch/x86/mm/pat/set_memory.c
sed -i 's/static struct dentry \*lookup_fast/struct dentry \*lookup_fast/g' fs/namei.c
sed -i 's/static long do_seccomp/long do_seccomp/g' kernel/seccomp.c
sed -i 's/static void __seccomp_filter_release(/void __seccomp_filter_release(/g' kernel/seccomp.c
sed -i 's/static void __put_seccomp_filter/void __put_seccomp_filter/g' kernel/seccomp.c