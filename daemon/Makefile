CC=gcc
CFLAGS= -Wno-write-strings `pkg-config --cflags libnl-3.0 libnl-genl-3.0 openssl` 
SRCS=$(shell find ../src/ -name '*.c')
OBJS=$(notdir $(patsubst %.c,%.o,$(SRCS)))
LIBS= `pkg-config --libs libnl-3.0 libnl-genl-3.0 openssl` -ldl
OUTPUT=superman

.DEFAULT_GOAL := all
.PHONY: clean top

$(info Building SUPERMAN daemon)

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	@echo '  LD      $(notdir $@)'
	@$(CC) $(CFLAGS) -o $@ $^  $(LIBS)

%.o: ../src/%.c
	@echo '  CC      $(notdir $^)'
	@$(CC) $(CFLAGS) -c -o $@ $^

clean:
	-rm -f *.o ../src/*.o *~ $(OUTPUT) core

