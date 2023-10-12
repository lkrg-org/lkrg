#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Download daily Ubuntu mainline kernel from
#   https://wiki.ubuntu.com/Kernel/MainlineBuilds
#
# Copyright (c) 2021 Vitaly Chikunov <vt@altlinux.org>.
#

baseurl="https://kernel.ubuntu.com/~kernel-ppa"
baseurl="https://kernel.ubuntu.com"
for listurl in \
	"$baseurl/mainline/daily/" \
	"$baseurl/mainline/"
do
	echo >&2 "List $listurl"
	curl -s "$listurl" \
	| grep -Eio 'href="[^"]+"'   \
	| grep -Eo '"[^"]+"'         \
	| grep -Po '[v2][rc\.\d-]+'  \
	| sort -Vr \
	| while read subdir; do
		url="$listurl$subdir/amd64/"
		echo >&2 "Trying $url"
		if page=$(curl -s --fail "$url") &&
		   echo "$page" | grep -q 'generic.*_amd64\.deb'; then
			banner $subdir >&2
			# Show Ubuntu commit and build status.
			curl -so .yaml --fail "$url/aggregate.yaml" || \
			curl -so .yaml "$url/summary.yaml"
			cat .yaml
			[ -v GITHUB_ENV ] && sed -n '/^series:/{s/:\s*/=/p;q}' .yaml >> $GITHUB_ENV
			echo "$page" \
			| grep -Eio 'href="[^"]+"' \
			| grep -o "linux.*deb"     \
			| grep -v "lowlatency"     \
			| while read deb; do
				if [ ! -e "$deb" ]; then
					echo >&2 "Download $url$deb"
					curl -O "$url$deb"
				fi
			done
			# Signal success to upper shell.
			exit 22
		fi
	done
	# Exit if subshell succeeded.
	[ $? -eq 22 ] && exit
done
