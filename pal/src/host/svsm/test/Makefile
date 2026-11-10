# Host-side tests of the svsm PAL's inline channel code. Not part of the
# meson build: `make -C pal/src/host/svsm/test check`.
CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=all

check: chan_accept_test
	./chan_accept_test

chan_accept_test: chan_accept_test.c ../pal_svsm_chan.h
	$(CC) $(CFLAGS) -o $@ chan_accept_test.c

clean:
	rm -f chan_accept_test

.PHONY: check clean
