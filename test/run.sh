#!/bin/bash

PACKAGES="qemu uml-utilities bridge-utils"

checkpackages()
{
	# Check through our package list to see if any
	# need installing.
	NEEDSINSTALL=0
	for PACKAGE in $PACKAGES; do
		dpkg -s $PACKAGE >/dev/null 2>/dev/null
		if [ $? -ne 0 ]; then
			NEEDSINSTALL=1
		fi
	done
	# If Any require installation, start the install process.
	if [ $NEEDSINSTALL -ne 0 ]; then
		echo -e "Installing prerequisite packages..."
		sudo apt-get update
		sudo apt-get -y install $PACKAGES
	fi
}

checkpackages

echo Starting QEMU emulation...
sudo qemu-system-x86_64 \
-kernel /boot/vmlinuz-`uname -r` \
-initrd initrd.img-custom \
--append "root=/ ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect supermanid=2" \
-m 512M \
-nographic \
-net nic,vlan=0 \
-net tap,vlan=0,ifname=tap0,script=run-ifup.sh \
-rtc base=localtime

#-device e1000,netdev=hn0,id=nic1 \
