#!/bin/bash

if [[ ! -d ./initrd-prereqs ]]; then
	mkdir initrd-prereqs
fi

if [[ ! -d pkgs ]]; then
	mkdir pkgs;
fi
cd pkgs

echo Downloading the packages...
apt-get download libc6
#apt-get download hostname
apt-get download libnl-3-200
apt-get download libnl-genl-3-200
apt-get download libssl1.0.0
apt-get download linux-image-`uname -r`
#apt-get download util-linux
#apt-get download busybox-initramfs
apt-get download openssl
apt-get download ifupdown

echo Extracting the packages...
dpkg-deb --extract `ls libc6*.deb` ../initrd-prereqs
#dpkg-deb --extract `ls hostname*.deb` ../initrd-prereqs
dpkg-deb --extract `ls libnl-3-200*.deb` ../initrd-prereqs
dpkg-deb --extract `ls libnl-genl-3-200*.deb` ../initrd-prereqs
dpkg-deb --extract `ls libssl1.0.0*.deb` ../initrd-prereqs
dpkg-deb --extract `ls linux-image-*.deb` ../initrd-prereqs
#dpkg-deb --extract `ls util-linux*.deb` ../initrd-prereqs
#dpkg-deb --extract `ls busybox-initramfs*.deb` ../initrd-prereqs
dpkg-deb --extract `ls openssl*.deb` ../initrd-prereqs
dpkg-deb --extract `ls ifupdown*.deb` ../initrd-prereqs

rm -R ../initrd-prereqs/boot
rm -R ../initrd-prereqs/usr/share/doc

rm *.deb
cd ..
rmdir pkgs



