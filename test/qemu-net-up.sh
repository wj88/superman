#!/bin/sh

. ./common.sh

VNIC_IF="$1"

# Make sure the bridge exists and is ready.
createBridge ${BRIDGE_IF} "10.0.0.1"

# Make sure we have been provided with a TAP.
# Note: the tap is created by QEMU so we just need to bridge to it.
if [ -n "${VNIC_IF}" ]; then
	echo Bridging ${VNIC_IF} to ${BRIDGE_IF}...
	bridgeTap ${VNIC_IF} ${BRIDGE_IF}
        exit 0
else
        echo "Error: no interface specified"
        exit 1
fi

