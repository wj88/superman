define echob = 
bash -c '. ./test/common.sh; echob $1;'
endef

.DEFAULT_GOAL := all
.PHONY: clean-daemon clean-kernel-module clean-test clean-all test kernel-module daemon

kernel-module:
	@$(call echob,"Making the kernel-module...")
	@$(MAKE) -C kernel-module

daemon:
	@$(call echob,"Making the daemon...")
	@$(MAKE) -C daemon

test:
	@$(call echob,"Making the test environmet...")
	@$(MAKE) -C test

all: kernel-module daemon test

clean-daemon:
	@$(call echob,"Cleaning the daemon...")
	@$(MAKE) -C daemon clean

clean-kernel-module:
	@$(call echob,"Cleaning the kernel-module...")
	@$(MAKE) -C kernel-module clean

clean-test:
	@$(call echob,"Cleaning the test environment...")
	@$(MAKE) -C test clean

clean-all: clean-daemon clean-kernel-module clean-test
