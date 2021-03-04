#!/bin/bash
#
# Systemd installation script for LKRG (main branch)
#
# Author:
#  - Adam 'pi3' Zabrocki (http://pi3.com.pl)
##

P_SYSTEMD_DIR="$(systemctl show -p UnitPath | cut -d " " -f5)"

case "$P_SYSTEMD_DIR" in
    \/run/*) P_SYSTEMD_DIR=/etc/systemd/system ;;
esac


P_RED='\033[0;31m'
P_GREEN='\033[0;32m'
P_WHITE='\033[1;37m'
P_YL='\033[1;33m'
P_NC='\033[0m' # No Color

echo -e "  ${P_GREEN}[+] ${P_WHITE}Systemd detected${P_NC}"

if [ "$1" == "install" ]; then
    if [ -f "$P_SYSTEMD_DIR/lkrg.service" ]; then
	echo -e "      ${P_RED}ERROR! ${P_YL}lkrg.service${P_RED} file already exists under ${P_YL}$P_SYSTEMD_DIR${P_RED} folder${P_NC}"
	exit 1
    else
	echo -e "       ${P_GREEN}Installing ${P_YL}lkrg.service${P_GREEN} file under ${P_YL}$P_SYSTEMD_DIR${P_GREEN} folder${P_NC}"
	cp -a scripts/bootup/systemd/lkrg.service "$P_SYSTEMD_DIR/lkrg.service"
	echo -e "       ${P_GREEN}Enabling ${P_YL}lkrg.service${P_GREEN} on bootup${P_NC}"
	systemctl enable lkrg.service
	echo -e "       ${P_GREEN}To start ${P_YL}lkrg.service${P_GREEN} please use: ${P_YL}systemctl start lkrg${P_NC}"
    fi
elif [ "$1" == "uninstall" ]; then
    echo -e "       ${P_GREEN}Stopping ${P_YL}lkrg.service${P_NC}"
    systemctl stop lkrg.service
    echo -e "       ${P_GREEN}Disabling ${P_YL}lkrg.service${P_GREEN} on bootup${P_NC}"
    systemctl disable lkrg.service
    echo -e "       ${P_GREEN}Deleting ${P_YL}lkrg.service${P_GREEN} file from the ${P_YL}$P_SYSTEMD_DIR${P_GREEN} folder${P_NC}"
    rm "$P_SYSTEMD_DIR/lkrg.service"
else
    echo -e "      ${P_RED}ERROR! Unknown option!${P_NC}"
    exit 1
fi


echo -e "  ${P_GREEN}[+] ${P_WHITE}Done!${P_NC}"
