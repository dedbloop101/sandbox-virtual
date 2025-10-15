CC=gcc
CFLAGS=-Wall -O2
OUT=sandbox_runner
LIBS=-ljansson -lseccomp

all:
	$(CC) $(CFLAGS) src/sandbox_runner.c -o $(OUT) $(LIBS)

clean:
	rm -f $(OUT)
