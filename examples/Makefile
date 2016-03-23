# Sample makefile - for now it only checks if sources compile
files := $(basename $(wildcard *.c))
objs := $(addsuffix .o, $(files))
deps := $(addsuffix .d, $(files))

all: build

build: $(objs)

clean: 
	rm -f $(objs) $(deps)

%.o: %.c
	gcc -I../src/include -MMD -Wall -c $< -o $@

-include $(deps)
