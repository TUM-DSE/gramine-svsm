#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "elf.h"
#include "linux_socket.h"
#include "pal.h"

// TODO: remove from here and include only where they are used.
#include "linux_abi/fs.h"
#include "linux_abi/limits.h"
#include "linux_abi/poll.h"
#include "linux_abi/sched.h"
#include "linux_abi/signals.h"
#include "linux_abi/time.h"
#include "linux_abi/types.h"

typedef unsigned long int nfds_t;
typedef unsigned long int nlink_t;

typedef Elf64_auxv_t elf_auxv_t;

/* typedef for LibOS internal types */
typedef uint32_t IDTYPE;
#define IDTYPE_MAX UINT32_MAX

/* One greater than the largest pid. Linux's is 2^22; here it is 2^31: a forked
 * child's pid is its lineage name << 12 (lineage-vmid, 2026-10-20), names run
 * below 2^19, so pids are multiples of 4096 up to 2^31 - 4096 (the positive
 * range of pid_t). /proc/sys/kernel/pid_max reports this value. */
#define PID_MAX_LIMIT 2147483648u
#define PID_MAX (PID_MAX_LIMIT - 1)

typedef uint64_t HASHTYPE;

#define FILE_OFF_MAX INT64_MAX
typedef int64_t file_off_t;

struct libos_lock {
    PAL_HANDLE lock;
    IDTYPE owner;
};

/* maximum length of pipe/FIFO name (should be less than Linux sockaddr_un.sun_path = 108) */
#define PIPE_URI_SIZE 96
