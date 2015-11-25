#!/bin/bash

echo Extracting...
if [ ! -d ./initrd ]; then
	mkdir initrd
fi
cd initrd
gunzip --stdout /boot/initrd.img-`uname -r` | cpio -id --quiet
cd ..
echo Done.

