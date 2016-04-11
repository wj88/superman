ifeq ($(KERNELRELEASE),)

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: build clean

build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	-rm ../src/*.o

else

OBJS=$(patsubst %.c,%.o,$(shell cd $(M); find ../src/ -name '*.c'))

$(info Building SUPERMAN kernel module for kernel version ${KERNELRELEASE})

obj-m := superman.o
superman-y := $(OBJS)

endif
