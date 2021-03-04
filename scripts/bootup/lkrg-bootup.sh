#!/bin/bash
#
# Bootup installation script for LKRG (main branch)
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

P_LKRG_SYSTEMD="scripts/bootup/systemd/lkrg-systemd.sh"

P_RED='\033[0;31m'
P_GREEN='\033[0;32m'
P_WHITE='\033[1;37m'
P_NC='\033[0m' # No Color

echo -e " ${P_GREEN}[*] ${P_WHITE}Executing LKRG's bootup installation script${P_NC}"

case "`readlink -e /proc/1/exe`" in
	/usr/lib/systemd/systemd | \
	/lib/systemd/systemd)
		exec "$P_LKRG_SYSTEMD" "$@"
		;;
	*)
		echo -e "  ${P_RED}[-] Unsupported init system: not systemd or not running as root?${P_NC}"
		;;
esac
