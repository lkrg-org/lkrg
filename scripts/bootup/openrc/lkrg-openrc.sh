#!/bin/bash
#
# OpenRC installation script for LKRG (main branch)
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
#  - Jakub 'mrl5' Kołodziejczak (https://github.com/mrl5)
##

set -eu

P_SYSCTL_DIR="/etc/sysctl.d"
P_INITD_DIR="/etc/init.d"
P_SCRIPT_DIR="$(dirname "$0")"
RUNLEVEL="boot"


P_RED='\033[0;31m'
P_GREEN='\033[0;32m'
P_WHITE='\033[1;37m'
P_YL='\033[1;33m'
P_NC='\033[0m' # No Color

if [ $# -ne 1 ]; then
	echo "Usage: $0 (install|uninstall)" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run as root." >&2
	exit 1
fi

echo -e "  ${P_GREEN}[+] ${P_WHITE}OpenRC detected${P_NC}"

if [ "$1" == "install" ]; then
	if [ -e "$P_INITD_DIR/lkrg" ]; then
		echo -e "       ${P_RED}ERROR! ${P_YL}lkrg${P_RED} already exists under ${P_YL}$P_INITD_DIR${P_RED} directory${P_NC}"
		exit 1
	else
		echo -e "       ${P_GREEN}Installing ${P_YL}lkrg${P_GREEN} file under ${P_YL}$P_INITD_DIR${P_GREEN} directory${P_NC}"
		install -pm 755 -o root -g root "${P_SCRIPT_DIR}/lkrg" "$P_INITD_DIR/lkrg"
		echo -e "       ${P_GREEN}To start ${P_YL}lkrg${P_GREEN} please use: ${P_YL}/etc/init.d/lkrg start${P_NC}"
		echo -e "       ${P_GREEN}To enable ${P_YL}lkrg${P_GREEN} on bootup please use: ${P_YL}rc-update add lkrg ${RUNLEVEL}${P_NC}"
	fi
	if [ -e "$P_SYSCTL_DIR/01-lkrg.conf" ]; then
		echo -e "       ${P_YL}01-lkrg.conf${P_GREEN} is already installed, skipping${P_NC}"
	else
		echo -e "       ${P_GREEN}Installing ${P_YL}01-lkrg.conf${P_GREEN} file under ${P_YL}$P_SYSCTL_DIR${P_GREEN} directory${P_NC}"
		install -pm 644 -o root -g root "${P_SCRIPT_DIR}/../lkrg.conf" "$P_SYSCTL_DIR/01-lkrg.conf"
	fi
elif [ "$1" == "uninstall" ]; then
	echo -e "       ${P_GREEN}Stopping ${P_YL}lkrg${P_NC}"
	/etc/init.d/lkrg stop
	echo -e "       ${P_GREEN}Disabling ${P_YL}lkrg${P_GREEN} on bootup${P_NC}"
	rc-update del lkrg ${RUNLEVEL}
	echo -e "       ${P_GREEN}Deleting ${P_YL}lkrg${P_GREEN} file from ${P_YL}$P_SYSTEMD_DIR${P_GREEN} directory${P_NC}"
	rm "$P_INITD_DIR/lkrg"
	if cmp -s "$P_SYSCTL_DIR/01-lkrg.conf" "${P_SCRIPT_DIR}/../lkrg.conf"; then
		echo -e "       ${P_GREEN}Deleting unmodified ${P_YL}01-lkrg.conf${P_GREEN} file from ${P_YL}$P_SYSCTL_DIR${P_GREEN} directory${P_NC}"
		rm "$P_SYSCTL_DIR/01-lkrg.conf"
	elif [ -e "$P_SYSCTL_DIR/01-lkrg.conf" ]; then
		echo -e "       ${P_YL}$P_SYSCTL_DIR/01-lkrg.conf${P_GREEN} was modified, preserving it as ${P_YL}$P_SYSCTL_DIR/01-lkrg.conf.saved${P_NC}"
		echo -e "       ${P_GREEN}If you do not need it anymore, delete it manually${P_NC}"
		mv "$P_SYSCTL_DIR/01-lkrg.conf"{,.saved}
	fi
else
	echo -e "      ${P_RED}ERROR! Unknown option!${P_NC}"
	exit 1
fi


echo -e "  ${P_GREEN}[+] ${P_WHITE}Done!${P_NC}"
