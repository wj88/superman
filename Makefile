.PHONY: clean-daemon clean-kernel-module clean-test clean-all test kernel-module daemon

kernel-module:
	@echo Making the kernel-module...
	@$(MAKE) -C kernel-module

daemon:
	@echo Making the daemon...
	@$(MAKE) -C daemon

test:
	@echo Making the test environment...
	@{ cd test; ./initrd_make.sh; cd ..; }


all: kernel-module daemon test

clean-daemon:
	@echo Cleaning the daemon...
	@$(MAKE) -C daemon clean

clean-kernel-module:
	@echo Cleaning the kernel-module...
	@$(MAKE) -C kernel-module clean

clean-test:
	@echo Cleaning the test environment...
	@{ cd test; ./initrd_make.sh clean; cd ..; }

clean-all: clean-daemon clean-kernel-module clean-test
