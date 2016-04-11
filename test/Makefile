define echob = 
bash -c '. ./common.sh; echob $1;'
endef

.DEFAULT_GOAL := all
.PHONY: clean-daemon clean-kernel-module clean-test clean-all test kernel-module daemon sim

kernel-module:
	@$(call echob,"Making the kernel-module...")
	@$(MAKE) -C ../kernel-module

daemon:
	@$(call echob,"Making the daemon...")
	@$(MAKE) -C ../daemon

test: kernel-module daemon
	@$(call echob,"Making the test environmet...")
	@{ ./initrd_make.sh; }

sim: test
	@{ ./sim.sh; }

all: test

clean-daemon:
	@$(call echob,"Cleaning the daemon...")
	@$(MAKE) -C ../daemon clean

clean-kernel-module:
	@$(call echob,"Cleaning the kernel-module...")
	@$(MAKE) -C ../kernel-module clean

clean:
	@$(call echob,"Cleaning the test environment...")
	@{ ./initrd_make.sh clean; }

clean-all: clean-daemon clean-kernel-module clean

