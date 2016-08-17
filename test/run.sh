#!/bin/bash

. ./common.sh

aptInstall "qemu uml-utilities bridge-utils gnome-terminal"

startTerm()
{
	echob Starting QEMU emulation for node ${NODE_ID}...
	sudo gnome-terminal --disable-factory -e "bash ${BASH_SOURCE} $1 Y" 2&> /dev/null
}

startQemu()
{
	echo -en "\033]0;SUPERMAN Node ${NODE_ID} - \a"

	local NODE_ID="$1"
	local PADDED_NODE_ID="$(printf %02d ${NODE_ID})"

	# To run in a QEMU window, set console=tty0 and remove -nographic
	# To run in a terminal window, set console=ttyS0 and add -nographic

	local QEMU_ARGS=$(echo \
	-kernel /boot/vmlinuz-`uname -r` \
	-initrd /boot/initrd.img-`uname -r` \
	--append \"root=/dev/sda1 ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect ipv6.disable=1 supermanid=${NODE_ID}\" \
	-drive file=rootfs.qcow2 -snapshot \
	-m 512M \
	-net nic,vlan=0,macaddr=52:54:00:12:34:${PADDED_NODE_ID} \
	-net tap,vlan=0,ifname=tap${NODE_ID},script=qemu-net-up.sh,downscript=qemu-net-down.sh \
	-net dump,file=/tmp/superman-node${NODE_ID}.pcap -net user \
	-rtc base=localtime \
	-nographic \
	)
	# Use these for kernel debugging.
	# -s -S

	#qemu-img create -f qcow2 -b rootfs.qcow2 rootfs-${NODE_ID}.qcow2

	echob Starting QEMU emulation for node ${NODE_ID}...
	bash -c "qemu-system-x86_64 ${QEMU_ARGS}"

	#rm rootfs-${NODE_ID}.qcow2

	read -p "Press any key to exit..."

	[ -e /tmp/superman-node${NODE_ID} ] && sudo chmod 666 /tmp/superman-node${NODE_ID}.pcap
}


if [ "$0" = "$BASH_SOURCE" ]; then
	NODE_ID="$1"
	[ "${NODE_ID}" = "" ] && NODE_ID="2"

	if [ "$2" = "" ]; then
		startTerm "${NODE_ID}"
	else
		startQemu "${NODE_ID}"
	fi
fi
