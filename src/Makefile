CFLAGS=
CC=gcc
OBJS=jforth.o

all: jforth
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

jforth: $(OBJS)
	$(CC) -I. $(CFLAGS) $(OBJS) -o $@

clean:
	rm -r jforth *.o

.PHONY: all clean

