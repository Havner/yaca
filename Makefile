.PHONY: all build clean
all: build

build:
	make -C src
	make -C examples

clean:
	make -C src clean
	make -C examples clean
