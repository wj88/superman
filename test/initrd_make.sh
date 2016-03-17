#!/bin/bash

PACKAGES="libnl-3-dev libnl-genl-3-dev"

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

if [[ ! -d ./initrd-prereqs ]]; then
	echo Preparing prerequisits...
	./prereq_install.sh
	./openssl_make.sh --no-local
fi

# Install any prerequisite packages
checkpackages

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
