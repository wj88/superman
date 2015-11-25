#!/bin/bash

echo Starting QEMU emulation...
qemu-system-x86_64 \
-kernel /boot/vmlinuz-`uname -r` \
-initrd initrd.img-custom \
--append "root=/ ip=dhcp rd.shell=1 console=ttyS0 raid=noautodetect" \
-m 512M \
-net nic,vlan=0 \
-net tap,vlan=0,ifname=tap0,script=ifup \
-rtc base=localtime \
-nographic
#-device e1000,netdev=hn0,id=nic1 \
