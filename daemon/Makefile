CC=gcc
CFLAGS= -Wno-write-strings `pkg-config --cflags libnl-3.0 libnl-genl-3.0 openssl` 
SRCS=$(shell find ../src/ -name '*.c')
#SRCS=$(wildcard *.c)
#OBJS=$(SRCS:.c=.o)
LIBS= `pkg-config --libs libnl-3.0 libnl-genl-3.0 openssl`
OUTPUT=superman

$(OUTPUT): $(SRCS)
	@echo 'Compiling $(SRCS)'
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

#$(OBJS): 
#	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o ../src/*.o *~ $(OUTPUT) core

