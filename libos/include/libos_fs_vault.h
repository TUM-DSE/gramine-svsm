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
 * monitor's own region header, so nothing here needs to know that format):
 *
 *   page 0                     the superblock below, then the page bitmap
 *   pages 1 .. VFS_TABLE_PAGES the entry table, VFS_ENTRIES entries
 *   the rest                   data pages, allocated by the bitmap
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
#define VFS_VERSION      1

#define VFS_TABLE_PAGES  8
#define VFS_ENTRY_SIZE   256
#define VFS_ENTRIES      (VFS_TABLE_PAGES * 4096 / VFS_ENTRY_SIZE)   /* 128 */
#define VFS_PATH_MAX     224
#define VFS_PAGE         4096

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
    char     path[VFS_PATH_MAX];   /* relative to the mount root, NUL-terminated */
};
_Static_assert(sizeof(struct vfs_entry) == VFS_ENTRY_SIZE, "vfs_entry must be 256 bytes");

/* Page 0. The bitmap follows at VFS_BITMAP_OFF, one bit per data page. */
struct vfs_super {
    uint64_t magic;
    uint32_t version;
    /* The lock every mutation takes. A plain test-and-set: the members of a
     * lineage are cooperative by construction, and there is no monitor
     * involvement to arbitrate. A member descheduled while holding it makes
     * the others spin, which is the known cost of choosing not to put the
     * filesystem in the monitor - see PLAN.md's risk list. */
    uint32_t lock;
    uint32_t initialized;  /* the first member seeds the tree, then sets this */
    uint32_t entries;      /* VFS_ENTRIES, recorded so a reader checks rather than assumes */
    uint32_t data_first;   /* page index of the first data page, from the base */
    uint32_t data_pages;
    /* Bumped on every namespace change, so a member can tell whether what it
     * cached is still true without re-scanning. */
    uint64_t generation;
};

#define VFS_BITMAP_OFF   0x400
#define VFS_BITMAP_MAX   ((VFS_PAGE - VFS_BITMAP_OFF) * 8)   /* 28672 pages */

#endif /* LIBOS_FS_VAULT_H_ */
