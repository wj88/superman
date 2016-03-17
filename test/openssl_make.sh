#!/bin/bash

INSTALL_LOCAL=0
if [[ ! "$1" = "--no-local" ]]; then
	read -p "Would you also like to install this version of OpenSSL into the local system? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		INSTALL_LOCAL=1
	fi
fi

if [[ ! -d openssl ]]; then
	echo Cloning the git repo...
	git clone git://git.openssl.org/openssl.git
	cd openssl

	echo Switching to v1.0.2d...
	#git pull 2>&1 >/dev/null
	git checkout -b JW_1_0_2d OpenSSL_1_0_2d 2>&1 >/dev/null

	echo Configuring the build process...
	./config --prefix=/usr/ 2>&1 >/dev/null

	echo Performing the Make...
	make 2>&1 >/dev/null
	cd ..
fi

cd openssl

if [[ INSTALL_LOCAL -eq 1 ]]; then
	echo Installing into the local system...
	sudo make install 2>&1 >/dev/null
fi

echo Installing OpenSSL into the initrd...
make INSTALL_PREFIX=${PWD}/../initrd-prereqs install 2>&1 >/dev/null
rm -R ../initrd-prereqs/usr/ssl/man 2>&1 >/dev/null
rm -R ../initrd-prereqs/usr/lib/pkgconfig 2>&1 >/dev/null
rm -R ../initrd-prereqs/usr/lib/engines 2>&1 >/dev/null

#echo Restoring the git repo state...
#git checkout master 2>&1 >/dev/null
#git branch -D JW_1_0_2d 2>&1 >/dev/null

cd ..
