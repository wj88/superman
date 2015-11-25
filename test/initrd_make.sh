#!/bin/bash

echo Buidling the SUPERMAN kernel module...
cd ../kernel-module
make
cd ../test
mkdir -p initrd-custom/lib/modules/`uname -r`/kernel/net/superman
cp ../kernel-module/superman.ko initrd-custom/lib/modules/`uname -r`/kernel/net/superman

echo Building the SUPERMAN daemon...
cd ../daemon
make
cd ../test
cp ../daemon/superman initrd-custom/bin

echo Preparing the initrd directory...
if [ -d ./initrd ]; then
	rm -R initrd
fi
mkdir initrd
cd initrd

echo Extracting the base initrd image...
gunzip --stdout /boot/initrd.img-`uname -r` | cpio -id --quiet

echo Integrating the changes....
cp -R ../initrd-custom/* ./

echo Creating the custom initrd image...
find . | cpio --quiet -H newc -o | gzip > ../initrd.img-custom

echo Done.
cd ..
rm -R initrd
