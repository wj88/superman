#!/bin/bash

INSTALL_LOCAL=0
read -p "Would you also like to install this version of OpenSSL into the local system? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
	INSTALL_LOCAL=1
fi

cd openssl

echo Updating the OpenSSL git repo...
git pull 2>&1 >/dev/null
git checkout -b JW_1_0_2d OpenSSL_1_0_2d 2>&1 >/dev/null

echo Configuring the build process...
./config --prefix=/usr/ 2>&1 >/dev/null

echo Performing the Make...
make 2>&1 >/dev/null

if [[ INSTALL_LOCAL -eq 1 ]]; then
echo Installing into the local system...
make install 2>&1 >/dev/null
fi

echo Installing into the initrd...
make INSTALL_PREFIX=${PWD}/../initrd-custom install 2>&1 >/dev/null
rm -R ../initrd-custom/usr/ssl/man 2>&1 >/dev/null
rm -R ../initrd-custom/usr/lib/pkgconfig 2>&1 >/dev/null
rm -R ../initrd-custom/usr/lib/engines 2>&1 >/dev/null

echo Restoring the git repo state...
git checkout master 2>&1 >/dev/null
git branch -D JW_1_0_2d 2>&1 >/dev/null

cd ..
