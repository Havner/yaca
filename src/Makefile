# Sample makefile - for now it only checks if sources compile
files := $(basename $(wildcard *.c))
objs := $(addsuffix .o, $(files))
deps := $(addsuffix .d, $(files))

libs := libCryptoAPI.so libCryptoAPI.a

LIBS := $(shell pkg-config --libs openssl)
CFLAGS := $(shell pkg-config --cflags openssl) -I../api -Wall -MMD -fPIC

.PHONY: all build clean
all: build

build: $(libs)

clean:
	rm -f $(objs) $(deps) $(libs)

%.so: $(objs)
	gcc $(LDFLAGS) $^ $(LIBS) -shared -o $@

%.a: $(objs)
	ar rcs $@ $<

%.o: %.c
	gcc $(CFLAGS) -c $< -o $@

-include $(deps)
