/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * vaultfs: the on-region format of a lineage's filesystem.
 *
 * PLAN.md "vaultfs: a filesystem shared by a lineage". A lineage - the
 * host-made root vault, everything it forks, everything it exec's, and (once
 * Spawn exists) everything it spawns - shares ONE writable filesystem, which
 * is what POSIX means by fork: the address space is copy-on-write, the
 * filesystem is not.
 *
 * The monitor places the pages and maps them into every member. It does NOT
 * parse anything in here, deliberately: a writable-filesystem parser at VMPL0
 * over structures untrusted vaults write is the bug class that has
 * historically broken hypervisors, and the group boundary already gives
 * everything such a parser would buy. So this format is the LibOS's, in every
 * member, and the monitor's only promise is that these pages are mapped into
 * the live members of this lineage and into nothing else.
 *
 * What follows from that, and is not a defect: a buggy member can corrupt its
 * own lineage's filesystem. A lineage is one trust domain by construction -
 * every member is either the same program (fork, exec) or one the parent named
 * by measured digest - and a member that could corrupt the table could equally
 * have written nonsense into the files.
 *
 * Layout, from the base the monitor reports (which is the page AFTER the
 * monitor's own region header, so nothing here needs to know that format).
 * Everything is DERIVED from the region's size, so every member computes the
 * same layout without being told it:
 *
 *   page 0                    the superblock below
 *   bitmap_pages              one bit per data page
 *   table_pages               the entry table, 16 entries per page
 *   VFS_LOCK_PAGES            the POSIX byte-range locks (lock.c)
 *   the rest                  data pages, allocated by the bitmap
 *
 * The bitmap and table SCALE with the region because a fixed one-page bitmap
 * capped the filesystem at 96 MiB however much the manifest declared, and 128
 * entries is thin for a region of any size. See vfs_layout().
 *
 * The namespace is FLAT and keyed by the full path relative to the mount
 * root, with directories as entries of their own. A tree would be tidier;
 * a flat table is correct, is far less code to get right over shared memory,
 * and bounds a lookup to one linear scan of 128 fixed-size records. Both
 * readdir and lookup read it, so a file another member created is found - which
 * a dcache-backed namespace (tmpfs) could never do, because the dcache is
 * private to one vault.
 */

#ifndef LIBOS_FS_VAULT_H_
#define LIBOS_FS_VAULT_H_

#include <stdint.h>

#define VFS_MAGIC        0x3153465646564d55UL /* "UMVFVFS1" */
/* v2 added the lock area, the owner-carrying superblock lock, and vfs_entry's
 * generation. The region is memory, not a disk, so it never outlives the
 * lineage that formatted it - a version mismatch can only mean two different
 * builds in one lineage, which vfs_attach refuses rather than reinterprets. */
#define VFS_VERSION      2

#define VFS_ENTRY_SIZE   256
#define VFS_PATH_MAX     216
#define VFS_PAGE         4096

/* The lock area: four pages between the entry table and the data pages,
 * holding the POSIX byte-range locks of this lineage (see lock.c).
 *
 * Four pages is 256 records, and they are deliberately NOT zeroed when the
 * filesystem is formatted. The region is reserved address space whose pages
 * the monitor spends on first touch, so a lineage that never calls fcntl
 * never pays for this area - and it arrives zeroed from the monitor, which is
 * exactly `used == 0`, so there is nothing a format would have to write. */
#define VFS_LOCK_PAGES   4
#define VFS_FLOCK_SIZE   64
#define VFS_FLOCKS       ((VFS_LOCK_PAGES * VFS_PAGE) / VFS_FLOCK_SIZE)   /* 256 */

/* A lock holder whose serial we could not learn. The high bit is never a real
 * serial - the monitor hands them out from 1 and the roster holds sixteen - so
 * this is distinguishable from both "free" (0) and any live member, and it is
 * deliberately never judged dead. */
#define VFS_LOCK_ANON    (1UL << 63)

/* How long a member waits for the superblock lock before it asks whether the
 * holder still exists.
 *
 * Generous against every critical section in fs.c (a bounded table scan or one
 * memcpy) and tight against a wedge. Asking is cheap - the roster is sixteen
 * words the MONITOR wrote into the region's header page, so the question is a
 * 128-byte load and not a monitor call - which is why this is tens of
 * milliseconds and not seconds. It bounds only when we ASK; a holder the
 * roster still lists is never stolen from, however long it holds. */
#define VFS_LOCK_PATIENCE_US  50000

/* Entries per table page, and the table's size as a fraction of the region:
 * one entry per 512 data pages (2 MiB), floored and capped. A 1 MiB region
 * gets the floor, 128 entries; a 512 MiB one gets 1024. */
#define VFS_ENTRIES_PER_PAGE  (VFS_PAGE / VFS_ENTRY_SIZE)            /* 16 */
#define VFS_TABLE_PAGES_MIN   8                                      /* 128 entries */
#define VFS_TABLE_PAGES_MAX   64                                     /* 1024 entries */

/* Free, a regular file, a directory. */
#define VFS_FREE  0
#define VFS_FILE  1
#define VFS_DIR   2

/* One record. Fixed size so the table is an array and a scan needs no parsing:
 * an entry whose `type` is out of range is simply skipped. */
struct vfs_entry {
    uint32_t type;
    uint32_t mode;
    uint32_t first_page;   /* data page index, relative to the data area */
    uint32_t npages;       /* pages reserved; contiguous, see vfs_grow */
    uint64_t size;         /* bytes */
    uint64_t mtime;
    /* Bumped every time this SLOT is handed to a new file. A slot is reset in
     * place and reused, so a bare index is not a file's identity: a handle
     * held open across another member's unlink-and-create would otherwise name
     * whatever file now lives in the slot. (idx, gen) is the identity, and it
     * is what a byte-range lock is keyed by and what every open handle carries
     * so a recycled slot is noticed rather than followed. */
    uint64_t gen;
    char     path[VFS_PATH_MAX];   /* relative to the mount root, NUL-terminated */
};
_Static_assert(sizeof(struct vfs_entry) == VFS_ENTRY_SIZE, "vfs_entry must be 256 bytes");

/*
 * One POSIX byte-range lock, in the lock area. Fixed size for the same reason
 * the entry table is: the area is an array, a scan needs no parsing, and a
 * record whose `used` is 0 is simply skipped.
 *
 * Keyed by (idx, gen) rather than by path, because a lock follows the FILE: a
 * rename must not drop it and a slot recycled for a different file must not
 * inherit it. `owner` is the holder's lineage serial, which is what makes a
 * dead holder's locks reclaimable - the same trick as the superblock lock.
 * `pid` is carried only so F_GETLK can report l_pid.
 *
 * `end` is INCLUSIVE and UINT64_MAX means "to end of file", matching what
 * libos_fs_lock.c already does with struct libos_file_lock.
 */
struct vfs_flock {
    uint32_t used;         /* 0 = free; 1 = a lock */
    uint32_t type;         /* F_RDLCK or F_WRLCK; F_UNLCK never occupies a record */
    uint32_t idx;          /* entry index in the table */
    uint32_t pad;
    uint64_t gen;          /* that entry's generation when the lock was taken */
    uint64_t start;
    uint64_t end;          /* inclusive; UINT64_MAX = to EOF */
    uint64_t owner;        /* the holder's lineage serial */
    uint64_t pid;          /* the holder's pid, for F_GETLK's l_pid */
    uint64_t reserved;
};
_Static_assert(sizeof(struct vfs_flock) == VFS_FLOCK_SIZE, "vfs_flock must be 64 bytes");

/* Page 0. The bitmap follows at VFS_BITMAP_OFF, one bit per data page. */
struct vfs_super {
    uint64_t magic;        /* 0  */
    uint32_t version;      /* 8  - stays here so a v1 region is still READABLE
                                   enough to be refused by version rather than
                                   misparsed by layout */
    uint32_t entries;      /* 12 - recorded so a reader checks rather than derives twice */
    /*
     * 16: the lock every mutation takes, holding the OWNER's lineage serial
     * rather than a flag - 0 is free, anything else is held and says by whom.
     *
     * v1 was a plain test-and-set, which meant a member that died holding it
     * wedged its whole lineage forever: nothing could tell "held by someone
     * working" from "held by someone who no longer exists". A serial can be
     * asked about. `vfs_lock` spins as before, and only after a long bound
     * asks the monitor's member roster whether the holder is still alive; a
     * live holder is NEVER stolen from, however long it holds.
     *
     * This is still not priority inheritance and still not a monitor-arbitrated
     * lock - a descheduled holder still makes the others spin, which is the
     * acknowledged cost of keeping the filesystem out of VMPL0 (PLAN.md's risk
     * list). It is only the difference between a stall and a wedge.
     *
     * This field consumed v1's `initialized`, which was written once and never
     * read: `magic` already answers "has anybody formatted this".
     */
    uint64_t lock;
    uint32_t bitmap_pages; /* 24 */
    uint32_t table_pages;  /* 28 */
    uint32_t data_first;   /* 32 - page index of the first data page, from the base */
    uint32_t data_pages;   /* 36 */
    /* 40: bumped on every namespace change, so a member can tell whether what
     * it cached is still true without re-scanning. */
    uint64_t generation;
    uint32_t lock_first;   /* 48 - page index of the lock area, from the base */
    uint32_t lock_pages;   /* 52 */
    /* 56: handed to the next file to take any slot. Monotonic for the life of
     * the region and never reused, so (idx, gen) is unique within a lineage.
     * Starts at 1, so a zeroed `gen` in a handle means "never set". */
    uint64_t next_gen;
};

/* Where the superblock's own fields end and the first bitmap page begins.
 * The bitmap is NOT in the superblock page any more: at 3072 usable bytes it
 * covered 24576 pages = 96 MiB, which silently capped the filesystem however
 * much the manifest declared. */
#define VFS_BITMAP_PAGE  1

/* The layout of a region of `total` pages. Pure arithmetic, so every member
 * derives the same answer from the size the monitor reported it. */
struct vfs_layout {
    uint32_t total;
    uint32_t bitmap_pages;
    uint32_t table_pages;
    uint32_t entries;
    uint32_t lock_first;
    uint32_t lock_pages;
    uint32_t data_first;
    uint32_t data_pages;
};

static inline void vfs_layout(uint32_t total, struct vfs_layout* out) {
    /* Solved by iteration rather than algebra: the bitmap's size depends on
     * the data page count, which depends on the bitmap's size. Two passes
     * converge because each pass only ever shrinks the data area, and a
     * closed form here would be harder to check than the loop. */
    uint32_t table = VFS_TABLE_PAGES_MIN;
    uint32_t bitmap = 1;
    for (int pass = 0; pass < 8; pass++) {
        uint32_t overhead = 1 + bitmap + table + VFS_LOCK_PAGES;
        uint32_t data = (total > overhead) ? total - overhead : 0;
        uint32_t want_bitmap = (data + VFS_PAGE * 8 - 1) / (VFS_PAGE * 8);
        if (!want_bitmap)
            want_bitmap = 1;
        uint32_t want_table = data / 512;
        if (want_table < VFS_TABLE_PAGES_MIN)
            want_table = VFS_TABLE_PAGES_MIN;
        if (want_table > VFS_TABLE_PAGES_MAX)
            want_table = VFS_TABLE_PAGES_MAX;
        if (want_bitmap == bitmap && want_table == table)
            break;
        bitmap = want_bitmap;
        table = want_table;
    }
    out->total        = total;
    out->bitmap_pages = bitmap;
    out->table_pages  = table;
    out->entries      = table * VFS_ENTRIES_PER_PAGE;
    out->lock_first   = 1 + bitmap + table;
    out->lock_pages   = VFS_LOCK_PAGES;
    out->data_first   = out->lock_first + VFS_LOCK_PAGES;
    out->data_pages   = (total > out->data_first) ? total - out->data_first : 0;
}

#endif /* LIBOS_FS_VAULT_H_ */
