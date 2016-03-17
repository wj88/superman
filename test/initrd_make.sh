#!/bin/bash

if [[ ! -d ./initrd-prereqs ]]; then
	echo Preparing prerequisits...
	./prereq_install.sh
	./openssl_make.sh --no-local
fi

echo Buidling the SUPERMAN kernel module...
cd ../kernel-module
make
cd ../test

echo Building the SUPERMAN daemon...
cd ../daemon
make
cd ../test

echo Preparing the initrd directory...
if [[ -d ./initrd ]]; then
	rm -R initrd
fi
mkdir initrd
cd initrd

echo Extracting the base initrd image...
# Copy in the base ram based root fs
gunzip --stdout /boot/initrd.img-`uname -r` | cpio -id --quiet

echo Integrating the changes....

# Copy in the prereqs
cp -R ../initrd-prereqs/* ./

# Copy in customised tweaks to the root fs
cp -R ../initrd-tweaks/* ./

# Copy over the kernel modules (some are needed so grab them all)
mkdir -p ./lib/modules/`uname -r`
cp -R /lib/modules/`uname -r`/* ./lib/modules/`uname -r`/

# Copy over the SUPERMAN kernel module
mkdir -p ./lib/modules/`uname -r`/kernel/net/superman
cp ../../kernel-module/superman.ko ./lib/modules/`uname -r`/kernel/net/superman
echo kernel/net/superman/superman.ko: kernel/crypto/cryptd.ko >> ./lib/modules/`uname -r`/modules.dep

# Copy over the SUPERMAN daemon
cp ../../daemon/superman ./bin

echo Creating the custom initrd image...
find . | cpio --quiet -H newc -o | gzip > ../initrd.img-custom

echo Done.
cd ..
#rm -R initrd
