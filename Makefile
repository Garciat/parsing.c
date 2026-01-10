CC = clang
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c23 -g

.PHONY: all
all: build/rex build/pe

build/rex: rex.c
	mkdir -p build
	$(CC) $(CFLAGS) -o build/rex rex.c

build/pe: pe.c
	mkdir -p build
	$(CC) $(CFLAGS) -o build/pe pe.c

.PHONY: test
test: all resources/Main.dll resources/pe.out.expected
	./build/rex
	./build/pe | tee ./build/pe.out
	diff ./resources/pe.out.expected ./build/pe.out
