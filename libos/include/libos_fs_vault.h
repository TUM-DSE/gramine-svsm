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
#define VFS_VERSION      1

#define VFS_ENTRY_SIZE   256
#define VFS_PATH_MAX     224
#define VFS_PAGE         4096

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
    uint32_t entries;      /* recorded so a reader checks rather than derives twice */
    uint32_t bitmap_pages;
    uint32_t table_pages;
    uint32_t data_first;   /* page index of the first data page, from the base */
    uint32_t data_pages;
    /* Bumped on every namespace change, so a member can tell whether what it
     * cached is still true without re-scanning. */
    uint64_t generation;
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
        uint32_t overhead = 1 + bitmap + table;
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
    out->data_first   = 1 + bitmap + table;
    out->data_pages   = (total > out->data_first) ? total - out->data_first : 0;
}

#endif /* LIBOS_FS_VAULT_H_ */
