define echob = 
bash -c '. ./test/common.sh; echob $1;'
endef

.DEFAULT_GOAL := all
.PHONY: clean-pkg clean-daemon clean-kernel-module clean-test clean-all pkg kernel-module daemon test

pkg:
	@$(call echob,"Making the APT package...")
	@$(MAKE) -C superman-1.0 pkg

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

clean-pkg:
	@$(call echob,"Cleaning the APT package...")
	@$(MAKE) -C superman-1.0 clean	

clean-daemon:
	@$(call echob,"Cleaning the daemon...")
	@$(MAKE) -C daemon clean

clean-kernel-module:
	@$(call echob,"Cleaning the kernel-module...")
	@$(MAKE) -C kernel-module clean

clean-test:
	@$(call echob,"Cleaning the test environment...")
	@$(MAKE) -C test clean

clean-all: clean-daemon clean-kernel-module clean-test clean-pkg
