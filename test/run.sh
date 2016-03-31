#!/bin/bash

. ./common.sh

aptInstall "qemu uml-utilities bridge-utils gnome-terminal"

startQemu()
{
	local NODE_ID="$1"

	# To run in a QEMU window, set console=tty0 and remove -nographic
	# To run in a terminal window, set console=ttyS0 and add -nographic

	local QEMU_ARGS=$(echo \
	-kernel /boot/vmlinuz-`uname -r` \
	-initrd initrd.img-custom \
	--append \"root=/ ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect ipv6.disable=1 supermanid=${NODE_ID}\" \
	-m 512M \
	-net nic,vlan=0 \
	-net tap,vlan=0,ifname=tap${NODE_ID},script=qemu-net-up.sh,downscript=qemu-net-down.sh \
	-net dump,file=/tmp/superman-node${NODE_ID}.pcap -net user \
	-rtc base=localtime \
	-nographic \
	)
	# Use these for kernel debugging.
	# -s -S

	echob Starting QEMU emulation for node ${NODE_ID}...
	sudo gnome-terminal --disable-factory -e "qemu-system-x86_64 ${QEMU_ARGS}" 2&> /dev/null

	[ -e /tmp/superman-node${NODE_ID} ] && sudo chmod 666 /tmp/superman-node${NODE_ID}.pcap

}


if [ "$0" = "$BASH_SOURCE" ]; then
	NODE_ID="$1"
	[ "${NODE_ID}" = "" ] && NODE_ID="2"
	startQemu "${NODE_ID}"
fi
