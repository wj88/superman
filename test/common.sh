#!/bin/bash

# Update APT no more than every 24 hours
APT_UPDATE_FREQUENCY="$((24 * 60 * 60))"

# Name of the network bridge
BRIDGE_IF="br0"
LO_IF="lo:10"
#TAP_IF="tap0"

echob()
{
	echo -e "\e[1m${@}\e[0m"
}

aptUpdate()
{
	local forceUpdate="${1}"
	local -r lastUpdate="$(($(date +'%s') - $(stat -c %Y '/var/lib/apt/periodic/update-success-stamp')))"

	if [ "${forceUpdate}" = "true" ] || [ "${lastUpdate}" -gt "${APT_UPDATE_FREQUENCY}" ]; then
		echob Updating APT...
		sudo apt-get update -m
	fi
}

aptInstall()
{
	local -r PACKAGES="$1"
	for PACKAGE in $PACKAGES; do
		dpkg -s $PACKAGE >/dev/null 2>/dev/null
		if [ $? -ne 0 ]; then
			aptUpdate
			echob Installing package ${PACKAGE}...
			sudo apt-get -y install $PACKAGE
		fi
	done
}

debDownload()
{
	local -r PACKAGES="${1}"
	local -r TARGET_PATH="${2}"
	if [ ! "${TARGET_PATH}" = "" ]; then
		pushd ${TARGET_PATH} >/dev/null
	fi
	for PACKAGE in $PACKAGES; do
		aptUpdate
		echob Downloading package ${PACKAGE}...
		apt-get download ${PACKAGE}
	done
	if [ ! "${TARGET_PATH}" = "" ]; then
		popd >/dev/null
	fi
}

debExtract()
{
	local -r PACKAGES="${1}"
	local -r PACKAGE_PATH="${2}"
	local -r TARGET_PATH="${3}"
	for PACKAGE in $PACKAGES; do
		echob Extracting package ${PACKAGE}...
		dpkg-deb --extract `ls ${PACKAGE_PATH}/${PACKAGE}*.deb` ${TARGET_PATH}
	done
}

aptAddDbgSymbolsRepo()
{
	if [ "$(apt-cache search linux-image-$(uname -r)-dbgsym | wc -l)" == "0" ]; then
		echob Adding the debug symbols APT repo...		
		codename=$(lsb_release -c | awk  '{print $2}')
		sudo cat > /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename}          main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF
		sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ECDCAD72428D7C01
		aptUpdate "true"
	fi
}

initrdExtract()
{
	local SOURCE_IMG="$1"
	local FULL_SOURCE_IMG="$(readlink -f ${SOURCE_IMG})"
	local TARGET_PATH="$2"

	echob Extracting ${SOURCE_IMG}...
	[ -d ${TARGET_PATH} ] || mkdir -p ${TARGET_PATH}

	pushd ${TARGET_PATH} >/dev/null
	gunzip --stdout ${FULL_SOURCE_IMG} | cpio -id --quiet
	popd >/dev/null
}

initrdCreate()
{
	local SOURCE_PATH="$1"
	local TARGET_IMG="$2"
	local FULL_TARGET_IMG="$(readlink -f ${TARGET_IMG})"
	echob Creating ${TARGET_IMG}...
	if [ -d ${SOURCE_PATH} ]; then

		pushd ${SOURCE_PATH} >/dev/null
		find . | cpio --quiet -H newc -o | gzip > ${FULL_TARGET_IMG}
		popd >/dev/null
	fi
}

createBridge()
{
	local BRIDGE_IF="$1"
	local IP="$2"
	if ! brctl show | grep ${BRIDGE_IF} > /dev/null ; then
		echo Creating network bridge ${BRIDGE_IF}...
		sudo brctl addbr ${BRIDGE_IF}		
		sudo ifconfig ${BRIDGE_IF} ${IP} netmask 255.255.255.0 up
	fi
}

removeBridge()
{
	local BRIDGE_IF="$1"
	if brctl show | grep ${BRIDGE_IF} > /dev/null ; then
		echo Removing network bridge ${BRIDGE_IF}...
		sudo ip link set dev ${BRIDGE_IF} down	
		brctl show ${BRIDGE_IF} | tail -n +2 | awk '//{print $4}' | xargs -I '{}' brctl delif ${BRIDGE_IF} {}
		brctl delbr ${BRIDGE_IF}
	fi
}

maybeRemoveBridge()
{
	local BRIDGE_IF="$1"
	if [ "$(brctl show ${BRIDGE_IF} | tail -n +2 | awk '//{print $4}')" = "" ] ; then
		removeBridge ${BRIDGE_IF}
	fi
}

bridgeTap()
{
	local TAP_IF="$1"
	local BRIDGE_IF="$2"
	sudo brctl addif ${BRIDGE_IF} ${TAP_IF}
	sudo ip link set dev ${TAP_IF} up
}

unbridgeTap()
{
	local TAP_IF="$1"
	local BRIDGE_IF="$2"
	sudo ip link set dev ${TAP_IF} down
	sudo brctl delif ${BRIDGE_IF} ${TAP_IF}
}

createTap()
{
	local TAP_IF="$1"
	local BRIDGE_IF="$2"
	if ! ip tuntap | grep ${TAP_IF} > /dev/null ; then
		echo Creating a new network tap ${TAP_IF}...
		sudo ip tuntap add mode tap ${TAP_IF}
		bridgeTap ${TAP_IF} ${BRIDGE_IF}
	fi
}

removeTap()
{
	local TAP_IF="$1"
	local BRIDGE_IF="$2"
	if ip tuntap | grep ${TAP_IF} > /dev/null ; then
		echo Removing network tap ${TAP_IF}...
		sudo ip link set dev ${TAP_IF} down
		sudo brctl rmif ${BRIDGE_IF} ${TAP_IF}
		sudo ip tuntap del mode tap ${TAP_IF}
	fi
}

