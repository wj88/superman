#!/bin/sh

. ./common.sh

VNIC_IF="$1"

# Note: the tap was created by QEMU so we just need to unbridge it.
if [ -n "${VNIC_IF}" ]; then
	echo Unbridging ${VNIC_IF} to ${BRIDGE_IF}...
	unbridgeTap ${VNIC_IF} ${BRIDGE_IF}
	maybeRemoveBridge ${BRIDGE_IF}
        exit 0
else
        echo "Error: no interface specified"
        exit 1
fi

