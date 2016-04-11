#!/bin/bash

. ./common.sh

if [ "$1" = "clean" ]; then
	echo Cleaning up...
	rm -Rf openssl pkgs initrd initrd-prereqs
	rm -f initrd.img-custom
	exit
fi

. ./prereq_install.sh
. ./openssl_install.sh

if [[ ! -d ./initrd-prereqs ]]; then
	echo Preparing prerequisits...
	prereqInstall ./initrd-prereqs
	opensslInstallInto ./initrd-prereqs
fi

aptInstall "libnl-3-dev libnl-genl-3-dev pigz"

#echob Building the SUPERMAN kernel module...
#cd ../kernel-module
#make
#cd ../test

#echob Building the SUPERMAN daemon...
#cd ../daemon
#make
#cd ../test

echo Preparing the initrd directory...
[ -d ./initrd ] && rm -R initrd

echo Extracting the base initrd image...
initrdExtract "/boot/initrd.img-`uname -r`" ./initrd

echo Integrating the changes....

# Copy in the prereqs
cp -R initrd-prereqs/* ./initrd/

# Copy in customised tweaks to the root fs
cp -R initrd-tweaks/* ./initrd/

# Copy over the kernel modules (some are needed so grab them all)
mkdir -p ./initrd/lib/modules/`uname -r`
cp -R /lib/modules/`uname -r`/* ./initrd/lib/modules/`uname -r`/

# Copy over the SUPERMAN kernel module
mkdir -p ./initrd/lib/modules/`uname -r`/kernel/net/superman
cp ../kernel-module/superman.ko ./initrd/lib/modules/`uname -r`/kernel/net/superman
echo kernel/net/superman/superman.ko: kernel/crypto/cryptd.ko >> ./initrd/lib/modules/`uname -r`/modules.dep

# Copy over the SUPERMAN daemon
cp ../daemon/superman ./initrd/bin

echo Creating the custom initrd image...
initrdCreate ./initrd ./initrd.img-custom

# echo Done.
#rm -R initrd
