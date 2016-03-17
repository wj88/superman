#!/bin/bash

PACKAGES="libc6 libnl-3-200 libnl-genl-3-200 libssl1.0.0 linux-image-`uname -r` openssl ifupdown"

if [[ ! -d ./initrd-prereqs ]]; then
	mkdir initrd-prereqs
fi

if [[ ! -d pkgs ]]; then
	mkdir pkgs;
fi
cd pkgs

echo Downloading the packages...
for PACKAGE in $PACKAGES; do
	apt-get download ${PACKAGE}
done

echo Extracting the packages...
for PACKAGE in $PACKAGES; do
	dpkg-deb --extract `ls ${PACKAGE}*.deb` ../initrd-prereqs
done

rm -R ../initrd-prereqs/boot
rm -R ../initrd-prereqs/usr/share/doc

rm *.deb
cd ..
rmdir pkgs



