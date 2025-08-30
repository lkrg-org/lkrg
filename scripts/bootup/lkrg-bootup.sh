#!/bin/bash
#
# Bootup installation script for LKRG (main branch)
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

set -eu

P_SCRIPT_DIR="$(dirname "$0")"
P_LKRG_SYSTEMD="${P_SCRIPT_DIR}/systemd/lkrg-systemd.sh"
P_LKRG_OPENRC="${P_SCRIPT_DIR}/openrc/lkrg-openrc.sh"

P_RED='\033[0;31m'
P_GREEN='\033[0;32m'
P_WHITE='\033[1;37m'
P_NC='\033[0m' # No Color

if [ $# -ne 1 ]; then
	echo "Usage: $0 (install|uninstall)" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root." >&2
	exit 1
fi

echo -e " ${P_GREEN}[*] ${P_WHITE}Executing LKRG's bootup installation script${P_NC}"

case "`readlink -e /proc/1/exe`" in
	/usr/lib/systemd/systemd | \
	/lib/systemd/systemd)
		exec "$P_LKRG_SYSTEMD" "$@"
		;;
	/sbin/openrc-init | \
	/sbin/init)
		exec "$P_LKRG_OPENRC" "$@"
		;;
	*)
		echo -e "  ${P_RED}[-] Unsupported init system?${P_NC}"
		;;
esac

# Normally unreached due to use of "exec" above
exit 1
