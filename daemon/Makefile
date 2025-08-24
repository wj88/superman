define aptInstall =
bash -c '. ../test/common.sh; aptInstall $1;'
endef

BUILD ?= release  # Default to release if not specified

CC=gcc

ifeq ($(BUILD),debug)
    CDEBUGFLAGS= -g
else ifeq ($(BUILD),release)
    CDEBUGFLAGS=
endif
CFLAGS= -Wno-write-strings `pkg-config --cflags libnl-3.0 libnl-genl-3.0 openssl`
SRCS=$(shell find ../src/ -name '*.c')
OBJS=$(notdir $(patsubst %.c,%.o,$(SRCS)))
LIBS= `pkg-config --libs libnl-3.0 libnl-genl-3.0 openssl` -ldl
OUTPUT=superman

.DEFAULT_GOAL := all
.PHONY: clean top

$(info Building SUPERMAN daemon)

all: main-build

pre-build:
	@$(call aptInstall,"libnl-3-dev libnl-genl-3-dev libssl-dev")

main-build: pre-build
	@$(MAKE) --no-print-directory $(OUTPUT)

$(OUTPUT): $(OBJS)
	@echo '  LD      $(notdir $@)'
	@$(CC) $(CDEBUGFLAGS) $(CFLAGS) -o $@ $^  $(LIBS)

%.o: ../src/%.c
	@echo '  CC      $(notdir $^)'
	@$(CC) $(CDEBUGFLAGS) $(CFLAGS) -c -o $@ $^

clean:
	-rm -f *.o ../src/*.o *~ $(OUTPUT) core

