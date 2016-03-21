#!/bin/bash

. ./common.sh

OPENSSL_INSTALL_LOCAL=0

opensslPrepareGit()
{
	[ -d openssl ] && rm -R openssl

	echob Cloning the git repo...
	git clone git://git.openssl.org/openssl.git
	cd openssl

	echob Switching to v1.0.2d...
	git checkout -b JW_1_0_2d OpenSSL_1_0_2d 2>&1 >/dev/null

	echob Configuring the build process...
	./config --prefix=/usr/ 2>&1 >/dev/null

	echob Performing the make...
	make 2>&1 >/dev/null
	cd ..
}

opensslInstallLocal()
{
	[ -d openssl ] || opensslPrepareGit

	echob Installing into the local system...
	cd openssl
	sudo make install 2>&1 >/dev/null
	cd ..
}

opensslQueryInstallLocal()
{
	read -p "Would you also like to install this version of OpenSSL into the local system? [y/N] " -n 1 -r
	echo
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		OPENSSL_INSTALL_LOCAL=1
	fi
}

opensslInstallInto()
{
	local TARGET_PATH="$1"
	local FULL_TARGET_PATH="$(readlink -f ${TARGET_PATH})"
	[ -d ${FULL_TARGET_PATH} ] || mkdir -p ${FULL_TARGET_PATH}
	[ -d openssl ] || opensslPrepareGit
	cd openssl

	echob Installing OpenSSL...
	make INSTALL_PREFIX=${FULL_TARGET_PATH} install 2>&1 >/dev/null
	rm -R ${FULL_TARGET_PATH}/usr/ssl/man ${FULL_TARGET_PATH}/usr/lib/pkgconfig ${FULL_TARGET_PATH}/usr/lib/engines
	cd ..
}

if [ "$0" = "$BASH_SOURCE" ]; then
	[[ ! "$1" = "--no-local" ]] && opensslQueryInstallLocal
	[[ OPENSSL_INSTALL_LOCAL -eq 1 ]] && opensslInstallLocal
	opensslInstallInto ./initrd-prereqs
fi

