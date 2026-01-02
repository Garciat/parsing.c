CC = clang
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c23 -g

.PHONY: all
all: build/rex build/pe

build/rex: rex.c
	$(CC) $(CFLAGS) -o build/rex rex.c

build/pe: pe.c
	$(CC) $(CFLAGS) -o build/pe pe.c

.PHONY: test
test: all resources/Main.dll
	./build/rex
	./build/pe
