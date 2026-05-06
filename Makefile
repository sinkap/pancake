CFLAGS ?= -O2 -Wall -Wextra
all: pivot-root

pivot-root: pivot-root.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pivot-root

.PHONY: all clean
