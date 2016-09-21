#!/bin/bash

. ./common.sh

prereqInstall()
{
	local TARGET_PATH="$1"
	local INCLUDE_DBG_SYMBOLS=N
	local PACKAGES="libc6 libnl-3 libnl-genl-3 libssl linux-image-`uname -r` openssl iputils-ping iputils-arping iputils-tracepath libcap2"
	#local PACKAGES="%{PACKAGES} libtinfo5 coreutils login dash bash"

	if [ "${INCLUDE_DBG_SYMBOLS}" = "Y" ]; then
		PACKAGES="${PACKAGES} linux-image-$(uname -r)-dbgsym"
		aptAddDbgSymbolsRepo
	fi

	mkdir -p {${TARGET_PATH},pkgs}

	aptUpdate
	debDownload "${PACKAGES}" ./pkgs
	debExtract "${PACKAGES}" ./pkgs ${TARGET_PATH}

	echob Tidying up...
	rm -R ${TARGET_PATH}/boot ${TARGET_PATH}/usr/share/doc pkgs
}

[ "$0" = "$BASH_SOURCE" ] && prereqInstall ./initrd-prereqs
