#!/bin/bash

if [ ! -d ./initrd ]; then
	exit
fi

cd initrd
find . | cpio -H newc -o | gzip > ../initrd.img-custom
cd ..

