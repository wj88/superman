#!/bin/bash

. ./common.sh

aptInstall "qemu uml-utilities bridge-utils"

startQemu()
{
	local NODE_ID="$1"

	echob Starting QEMU emulation for node ${NODE_ID}...
	sudo qemu-system-x86_64 \
	-kernel /boot/vmlinuz-`uname -r` \
	-initrd initrd.img-custom \
	--append "root=/ ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect supermanid=${NODE_ID}" \
	-m 512M \
	-nographic \
	-net nic,vlan=0 \
	-net tap,vlan=0,ifname=tap${NODE_ID},script=qemu-net-up.sh,downscript=qemu-net-down.sh \
	-rtc base=localtime

	# Use these for kernel debugging.
	# -s -S

	#-device e1000,netdev=hn0,id=nic1 \
}


if [ "$0" = "$BASH_SOURCE" ]; then
	NODE_ID="$1"
	if [ "${NODE_ID}" = "" ]; then
		NODE_ID=2
	fi
	startQemu "${NODE_ID}"
fi
