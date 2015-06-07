ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: build clean

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

else

$(info $(KERNELDIR))
$(info Building Superman with KERNELRELEASE = ${KERNELRELEASE})

obj-m := superman.o
superman-y := netfilter.o packet.o queue.o security_table.o proc.o netlink.o init.o

endif
