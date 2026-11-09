# Host-side test of the LibOS's execve free loop (libos/include/libos_exec_free.h). Not part of
# the meson build: `make -C libos/test/host check`. Built twice: with the header's
# EXEC_FREE_RUN_MAX and with 1 (the old per-VMA call sequence).
CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Werror -fsanitize=undefined,address -fno-sanitize-recover=all
HDR      = ../../include/libos_exec_free.h

check: exec_free_test exec_free_test_cap1
	./exec_free_test
	./exec_free_test_cap1

exec_free_test: exec_free_test.c $(HDR)
	$(CC) $(CFLAGS) -I../../include -o $@ exec_free_test.c

exec_free_test_cap1: exec_free_test.c $(HDR)
	$(CC) $(CFLAGS) -DEXEC_FREE_RUN_MAX=1 -I../../include -o $@ exec_free_test.c

clean:
	rm -f exec_free_test exec_free_test_cap1

.PHONY: check clean
