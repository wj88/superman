#!/bin/bash

# Bring in some common functions.
. ./common.sh

if [ "$1" = "clean" ]; then
	echo Cleaning up...
	sudo rm -Rf openssl pkgs rootfs-prereqs rootfs-superman rootfs-base rootfs
	rm -f rootfs.qcow2
	exit
fi

# Required packages
aptInstall "debootstrap unionfs-fuse qemu-utils"

IMG_NAME="rootfs.qcow2"

# If we already have an image, we do have to worry about debootstrapping.
if [ ! -f ${IMG_NAME} ]; then

	# Generate a new base root filesystem
	if [ ! -d ./rootfs-base ]; then
		echob Preparing the base root filesystem...
		mkdir ./rootfs-base
		sudo debootstrap $(lsb_release -sc) ./rootfs-base http://archive.ubuntu.com/ubuntu
	fi
	ROOTFS_UNION=rootfs-base

fi

# Copy over the kernel modules (some are needed so grab them all)
if [ ! -d ./rootfs-superman ]; then
	echob Preparing the kernel modules...
	mkdir ./rootfs-superman
	sudo mkdir -p ./rootfs-superman/lib/modules/`uname -r`
	sudo cp -R /lib/modules/`uname -r`/* ./rootfs-superman/lib/modules/`uname -r`/
	sudo bash -c "echo kernel/net/superman/superman.ko: kernel/crypto/cryptd.ko >> ./rootfs-superman/lib/modules/`uname -r`/modules.dep"
fi

if [ "${ROOTFS_UNION}" = "" ]; then
	ROOTFS_UNION=rootfs-superman
else
	ROOTFS_UNION=rootfs-superman:${ROOTFS_UNION}
fi

# Copy over the SUPERMAN kernel module
echob Copying over the latest SUPERMAN kernel module...
sudo mkdir -p ./rootfs-superman/lib/modules/`uname -r`/kernel/net/superman
sudo cp ../kernel-module/superman.ko ./rootfs-superman/lib/modules/`uname -r`/kernel/net/superman

# Copy over the SUPERMAN daemon
echob Copying over the latest SUPERMAN daemon...
sudo mkdir -p ./rootfs-superman/bin
sudo cp ../daemon/superman ./rootfs-superman/bin/

# Install the prerequisites.
if [[ ! -d ./rootfs-prereqs ]]; then


	. ./prereq_install.sh

	echo Preparing prerequisits...
	prereqInstall ./rootfs-prereqs

fi
ROOTFS_UNION=rootfs-prereqs:${ROOTFS_UNION}

ROOTFS_UNION=rootfs-tweaks:${ROOTFS_UNION}

# Union the filesystems into one
[[ ! -d ./rootfs ]] && mkdir rootfs
sudo unionfs-fuse ${ROOTFS_UNION} rootfs

# sudo bash -c "cd rootfs; find . | cpio --create --format='newc' > ../rootfs.newc"

if [ ! -f ${IMG_NAME} ]; then

	echob Creating the disk image of the root filesystem...

	# Caculate the size of our rootfs and add 100MB for the image overheads.
	ROOTFS_SIZE=$(sudo bash -c "cd rootfs; du -sb | cut -f -1")
	IMG_SIZE=$(($ROOTFS_SIZE + 104857600))

	# Create the rootfs.qcow2 image.
	qemu-img create -f qcow2 ${IMG_NAME} ${IMG_SIZE} >/dev/null

	# Mount the qcow2 image to our dev listing
	sudo modprobe nbd
	sudo qemu-nbd -c /dev/nbd0 ${PWD}/${IMG_NAME}

	echob Partition and formatting the disk image partition...

	# Create the partition table with a single partition
	sudo sfdisk -q -uS /dev/nbd0 2>&1 >/dev/null << EOF
,,,-
EOF

	# Format the image partition as ext4
	sudo mkfs.ext4 /dev/nbd0p1 >/dev/null

	echob Copying over the root filesystem into the image partition...

else

	echob Updating the disk image of the root filesystem...

	# Mount the qcow2 image to our dev listing
	sudo modprobe nbd
	sudo qemu-nbd -c /dev/nbd0 ${PWD}/${IMG_NAME}

fi

# Mount the partition
[[ ! -d ./mountpoint ]] && mkdir mountpoint
sudo mount /dev/nbd0p1 mountpoint/

# Copy the root filesystem contents to the partition
sudo rsync -aAXv rootfs/ mountpoint/

# Unmount the mounted partition
sudo umount mountpoint
rmdir mountpoint

# Disconnect the qcow2 image from our dev listing
sudo qemu-nbd -d /dev/nbd0 >/dev/null

# Umount the root filesystem
sudo umount rootfs
