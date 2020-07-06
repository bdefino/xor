CC := cc
CFLAGS := -Iinclude --std=c89 -Wall -Werror -Wpedantic

.PHONY: all clean

all: clean bin/xor

bin:
	mkdir -p bin

bin/xor: bin xor.c
	$(CC) $(CFLAGS) -o $@ xor.c

clean:
	rm -rf bin

