# Host-side tests of the svsm PAL's inline code (channels, random bytes). Not part of the
# meson build: `make -C pal/src/host/svsm/test check`.
CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=all

check: chan_accept_test random_test
	./chan_accept_test
	./random_test

chan_accept_test: chan_accept_test.c ../pal_svsm_chan.h
	$(CC) $(CFLAGS) -o $@ chan_accept_test.c

random_test: random_test.c ../pal_svsm_random.h
	$(CC) $(CFLAGS) -mrdrnd -mrdseed -o $@ random_test.c

clean:
	rm -f chan_accept_test random_test

.PHONY: check clean
