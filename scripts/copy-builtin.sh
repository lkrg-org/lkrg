#!/bin/sh

set -e
# Build simple variables
KDIR="${KDIR:="/usr/src/linux"}"
LDIR="$KDIR/security/lkrg"
BASEDIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SDIR="$BASEDIR/../src"
COMMIT="LKRG in-tree @ $(git log|head -1|cut -d' ' -f2|cut -c 1-24)"
# Build heredoc variables
KCONFIG=$( cat <<EOC
# SPDX-License-Identifier: GPL-2.0-only
config SECURITY_LKRG
	tristate "LKRG support"
	depends on SECURITY
	default m
	help
	  This selects LKRG - Linux Kernel Runtime Guard, which provides
          integrity validation and anti-exploitation functions.

	  If you are unsure how to answer this question, answer M.
EOC
)

MAKEFILE=$(cat <<EOC
# SPDX-License-Identifier: GPL-2.0-only

obj-\$(CONFIG_SECURITY_LKRG) := p_lkrg.o
$(awk '/^p_lkrg-objs/,/^$/' "$BASEDIR/../Makefile"|sed -e 's|src/||')
 
EOC
)

MAKEADD=$(cat <<EOC

# LKRG file list
subdir-\$(CONFIG_SECURITY_LKRG)         += lkrg
obj-\$(CONFIG_SECURITY_LKRG)            += lkrg/
EOC
)
# Tell user what we're about to do
echo "Copying $SDIR/* to $LDIR along with Kconfig:"
echo "$KCONFIG"
echo
echo "and Makefile"
echo "$MAKEFILE"
echo "Commit msg: $COMMIT"
echo "Ctrl+c to quit, any other key to continue"
read CANCEL
# Execute copy
mkdir -p "$LDIR"
echo "$KCONFIG" > "$LDIR/Kconfig"
echo "$MAKEFILE" > "$LDIR/Makefile"
pushd .
cd "$SDIR"
cp -a . "$LDIR/"
cd "$KDIR"
# Update sources for built-in usage
sed -i '/source "security\/integrity\/Kconfig"/asource "security/lkrg/Kconfig"' security/Kconfig
echo "$MAKEADD" >> security/Makefile
# Commit the changes
git add "security/lkrg"
git commit -am "$COMMIT"
popd
