# Sample makefile - for now it only checks if sources compile

# Disable implicit rules
.SUFFIXES:

# keep objects
.PRECIOUS: %.o

examples := digest.c encrypt.c encrypt_aes_gcm.c key_exchange.c sign.c test.c

bins := $(basename $(examples))
objs := $(addsuffix .o, $(bins))
deps := $(addsuffix .d, $(bins))

common-objs := misc.o lorem.o
common-deps := misc.d lorem.d

LDFLAGS :=  -L../src
LIBS:= -lCryptoAPI $(shell pkg-config --libs openssl)
CFLAGS := $(shell pkg-config --cflags openssl) -I../api -Wall -MMD

all: build

build: $(bins)

%: %.o $(common-objs)
	gcc $(CFLAGS) $(LDFLAGS) $^ $(LIBS)  -o $@

clean:
	rm -f $(objs) $(deps) $(bins) $(common-objs) $(common-deps)


%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

-include $(deps)
