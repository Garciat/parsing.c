CC = clang
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c23 -g

all: build/rex build/pe

build/rex: rex.c
	$(CC) $(CFLAGS) -c rex.c -o build/rex

build/pe: pe.c
	$(CC) $(CFLAGS) -c pe.c -o build/pe
