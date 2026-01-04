CC = clang
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c23 -g

.PHONY: all
all: build/rex build/pe

build:
	mkdir -p build

build/rex: build rex.c
	$(CC) $(CFLAGS) -o build/rex rex.c

build/pe: build pe.c
	$(CC) $(CFLAGS) -o build/pe pe.c

.PHONY: test
test: all resources/Main.dll resources/pe.out.expected
	./build/rex
	./build/pe | tee ./build/pe.out
	diff ./resources/pe.out.expected ./build/pe.out
