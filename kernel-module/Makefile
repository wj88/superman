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
superman-y := ../src/netfilter.o ../src/packet.o ../src/queue.o ../src/security_table.o ../src/proc.o ../src/netlink.o ../src/processor.o ../src/init.o

endif
