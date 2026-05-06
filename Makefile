CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
all: assix-swap assix-swap-rootfs

assix-swap: assix-swap.c
	$(CC) $(CFLAGS) -o $@ $<

assix-swap-rootfs: assix-swap-rootfs.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f assix-swap assix-swap-rootfs

.PHONY: all clean
