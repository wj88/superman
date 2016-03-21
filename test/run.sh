#!/bin/bash

. ./common.sh

aptInstall "qemu uml-utilities bridge-utils"

echob Starting QEMU emulation...
sudo qemu-system-x86_64 \
-kernel /boot/vmlinuz-`uname -r` \
-initrd initrd.img-custom \
--append "root=/ ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect supermanid=2" \
-m 512M \
-nographic \
-net nic,vlan=0 \
-net tap,vlan=0,ifname=tap0,script=qemu-net.sh \
-rtc base=localtime

# Use these for kernel debugging.
# -s -S

#-device e1000,netdev=hn0,id=nic1 \
