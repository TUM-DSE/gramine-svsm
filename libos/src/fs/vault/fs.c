/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * vaultfs: the filesystem a LINEAGE shares.
 *
 * PLAN.md "vaultfs: a filesystem shared by a lineage". One writable
 * filesystem per lineage - the host-made root vault, everything it forks,
 * everything it exec's - because that is what POSIX fork means: the address
 * space is copy-on-write, the filesystem is not. Before this, a forked child
 * got a copy-on-write SNAPSHOT of its parent's tmpfs and its writes never
 * reached the parent, which is a silent divergence from Linux that breaks
 * ported code in the worst way - the data is simply absent, with no error.
 *
 * The pages come from the monitor (the LineageFs process call), which maps
 * them into every member and never looks inside. The format is
 * libos_fs_vault.h; the comment there says why the monitor stays out.
 *
 * This is NOT modelled on tmpfs, although it does the same job for one
 * process. tmpfs keeps its namespace in the dcache and its data in
 * `malloc`'d LibOS heap (libos_fs_mem.c), both private to one vault by
 * construction, so a file another member created could never be found. It is
 * modelled on chroot instead, which has the same problem shape: the truth is
 * outside, so `lookup` and `readdir` must go and read it rather than trust
 * what this process happens to remember.
 */

#include "api.h"
#include "libos_fs.h"
#include "libos_fs_vault.h"
#include "libos_handle.h"
#include "libos_lock.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "pal.h"
#include "pal_error.h"
#include "perm.h"
#include "stat.h"
#include "vault_internal.h"

#define USEC_IN_SEC 1000000

/* The region, as this member sees it. One per process: every mount of
 * vaultfs in one vault is the same lineage region (the monitor's call is
 * idempotent), so there is nothing to key this by. */
struct vfs_super* g_vfs;
struct vfs_entry* g_vfs_table;
static char* g_vfs_data;
static uint32_t g_vfs_data_pages;
/* Derived from the region's size by vfs_layout(), so every member agrees
   without being told. Both scale with the region: a fixed one-page bitmap
   capped the filesystem at 96 MiB however much the manifest declared. */
uint32_t g_vfs_entries;
static uint8_t* g_vfs_bitmap;
/* The lock area (v2). Pages the monitor places and never reads, like the rest
 * of the region; what lives in them is lock.c's business. */
struct vfs_flock* g_vfs_locks;


/* ---------------------------------------------------------------- the lock */

/*
 * This member's own serial, or VFS_LOCK_ANON if the monitor would not say.
 *
 * NOT CACHED, and that is not an oversight. A copy-on-write fork hands the
 * child every byte of its parent's memory, so a serial memoised in a LibOS
 * global would be the PARENT's - and a child that signed a lock with it would
 * be indistinguishable from its parent to everyone, including itself: it could
 * take a lock its parent holds, and its parent's death would look like its
 * own. _PalLineageSelf carries the same warning for the same reason.
 *
 * The cost of not caching is a read of a word in this process's own channel
 * directory, which the monitor maps per-process. Against the table scan every
 * caller is about to do, it does not register.
 */
uint64_t vfs_self(void) {
    uint64_t me = 0;
    if (PalLineageSelf(&me) < 0 || !me) {
        /* We do not know who we are, so nobody may ever conclude we died.
         * The high bit is never a real serial, and vfs_holder_dead() treats
         * any such value as alive - which degrades this lock to exactly v1's
         * behaviour for this member, spinning forever on a dead holder. That
         * is the honest answer: a steal decided on an unknown identity is
         * worse than a stall. */
        return VFS_LOCK_ANON;
    }
    return me;
}

/* Has the member holding the lock stopped existing?
 *
 * Only ever asked after a long bound, and answered by the MONITOR's roster of
 * this lineage's live members, not by anything a vault wrote - a member that
 * could lie here could lie about the table too, but the roster is the one
 * thing in the region that VMPL0 writes and nobody else can. */
bool vfs_holder_dead(uint64_t holder) {
    if (!holder || (holder & VFS_LOCK_ANON))
        return false;   /* free, or a holder whose identity we cannot judge */
    bool alive = true;
    if (PalLineageMemberAlive(holder, &alive) < 0)
        return false;   /* no answer is not a death certificate */
    return !alive;
}

/*
 * The lock every mutation takes, held across a table mutation.
 *
 * Still a spin, and still not arbitrated by the monitor: the members of a
 * lineage are cooperative by construction, every critical section below is a
 * bounded scan or a memcpy with no monitor call inside it, and a member
 * descheduled while holding it makes the others burn their slice until it runs
 * again. That is the acknowledged price of keeping the filesystem out of VMPL0
 * (PLAN.md's risk list).
 *
 * What v2 adds is that the word says WHO holds it, so "descheduled" and "gone"
 * are no longer the same observation. After VFS_LOCK_PATIENCE_US of failing to
 * take it - orders of magnitude longer than any critical section here - we ask
 * the monitor whether the holder still exists, and only if it does not do we
 * take the lock from it. A live holder is never stolen from, however long it
 * holds, so a slow member is never raced; only a dead one is stepped over.
 */
void vfs_lock(void) {
    uint64_t me = vfs_self();
    uint64_t waited_from = 0;

    for (;;) {
        uint64_t free_word = 0;
        if (__atomic_compare_exchange_n(&g_vfs->lock, &free_word, me, /*weak=*/false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return;

        /* `free_word` now holds whoever has it. Spin first; ask questions only
         * after the wait stops looking like contention. */
        uint64_t now = 0;
        if (PalSystemTimeQuery(&now) < 0) {
            CPU_RELAX();
            continue;   /* no clock, no bound: spin, exactly as v1 did */
        }
        if (!waited_from) {
            waited_from = now;
            CPU_RELAX();
            continue;
        }
        if (now - waited_from < VFS_LOCK_PATIENCE_US) {
            CPU_RELAX();
            continue;
        }

        if (vfs_holder_dead(free_word)) {
            /* Take it from the dead holder by CAS, not by a store: another
             * member may have reached this conclusion in the same moment, and
             * exactly one of us may win. The loser sees the winner's serial
             * and starts its patience over, which is right - the winner is
             * alive and is now doing the work. */
            uint64_t dead = free_word;
            if (__atomic_compare_exchange_n(&g_vfs->lock, &dead, me, /*weak=*/false,
                                            __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                /* The table may be mid-mutation. Every mutation below is
                 * ordered so that an interrupted one leaves the table
                 * consistent for a reader - type is published last on create
                 * and first on remove, precisely because lookups run unlocked
                 * - so there is nothing to repair here. What a dead holder CAN
                 * leave behind is its byte-range locks, and those are reclaimed
                 * by owner in lock.c, not here. */
                /* log_ERROR, not a warning, and the level is the reason: a
                 * measured manifest runs at log_level = "error" because a
                 * console write costs a monitor call, so a warning here would
                 * never be seen by anyone - which would make it not a log but
                 * a comment. And it deserves the level: it only ever prints
                 * when a member died holding its lineage's filesystem. */
                log_error("vaultfs: took the superblock lock from member %lu, "
                          "which the monitor says is gone", dead);
                return;
            }
        }
        waited_from = now;
        CPU_RELAX();
    }
}

void vfs_unlock(void) {
    __atomic_store_n(&g_vfs->lock, 0, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------- the page allocator */

static uint8_t* vfs_bitmap(void) {
    return g_vfs_bitmap;
}

static bool vfs_page_taken(uint32_t i) {
    return (vfs_bitmap()[i / 8] >> (i % 8)) & 1;
}

static void vfs_take_page(uint32_t i) {
    vfs_bitmap()[i / 8] |= (uint8_t)(1u << (i % 8));
}

static void vfs_drop_page(uint32_t i) {
    vfs_bitmap()[i / 8] &= (uint8_t)~(1u << (i % 8));
}

/* `n` contiguous free data pages, or -1. Contiguous so a file is one extent
 * and a read is one memcpy; the cost is that growth may have to move a file,
 * which `vfs_grow` does by doubling so the copying stays amortised. */
static int64_t vfs_alloc_run(uint32_t n) {
    assert(n > 0);
    uint32_t run = 0;
    for (uint32_t i = 0; i < g_vfs_data_pages; i++) {
        if (vfs_page_taken(i)) {
            run = 0;
            continue;
        }
        run++;
        if (run == n) {
            uint32_t start = i + 1 - n;
            for (uint32_t k = 0; k < n; k++)
                vfs_take_page(start + k);
            return start;
        }
    }
    return -1;
}

static void vfs_free_run(uint32_t start, uint32_t n) {
    for (uint32_t k = 0; k < n; k++)
        vfs_drop_page(start + k);
}

static char* vfs_page_at(uint32_t i) {
    return g_vfs_data + (size_t)i * VFS_PAGE;
}

/* ------------------------------------------------------------ the namespace */

/* The path of a dentry relative to the mount root, which is the table's key.
 * The root itself is "", and that is a real entry: a readdir of the mount
 * point has to find its children, and a lookup of "/" has to succeed. */
static int vfs_path_of(struct libos_dentry* dent, char* out) {
    char* path = NULL;
    size_t size = 0;
    int ret = dentry_rel_path(dent, &path, &size);
    if (ret < 0)
        return ret;
    /* `size` is the BUFFER size and includes the terminator, so measure
       rather than trust it: reading it as a length would copy one byte too
       many and write the terminator past the end of the name. */
    size_t len = strlen(path);
    if (len >= VFS_PATH_MAX) {
        free(path);
        return -ENAMETOOLONG;
    }
    memcpy(out, path, len + 1);
    free(path);
    return 0;
}

/* Linear scan. 128 fixed-size records, so this is one pass over 32 KiB with
 * no pointer chasing and no parsing - an entry whose type is out of range is
 * skipped rather than trusted. Called under the lock by every mutation, and
 * without it by lookup, where a torn read can only produce a miss or a stale
 * size, both of which the caller already has to tolerate. */
static struct vfs_entry* vfs_find(const char* path) {
    for (uint32_t i = 0; i < g_vfs_entries; i++) {
        struct vfs_entry* e = &g_vfs_table[i];
        if (e->type != VFS_FILE && e->type != VFS_DIR)
            continue;
        if (!strncmp(e->path, path, VFS_PATH_MAX))
            return e;
    }
    return NULL;
}

static struct vfs_entry* vfs_free_slot(void) {
    for (uint32_t i = 0; i < g_vfs_entries; i++)
        if (g_vfs_table[i].type == VFS_FREE)
            return &g_vfs_table[i];
    return NULL;
}

/* Is `path` a direct child of `dir`? `dir` is "" for the mount root. Used by
 * readdir, which is why the flat table can present a tree. */
static bool vfs_is_child_of(const char* path, const char* dir, const char** out_name) {
    size_t dlen = strlen(dir);
    if (dlen) {
        if (strncmp(path, dir, dlen) || path[dlen] != '/')
            return false;
        path += dlen + 1;
    }
    if (!*path)
        return false;
    if (strchr(path, '/'))
        return false;    /* a grandchild, not a child */
    *out_name = path;
    return true;
}

static uint64_t vfs_now(void) {
    uint64_t time_us;
    if (PalSystemTimeQuery(&time_us) < 0)
        return 0;
    return 315532800 + time_us / USEC_IN_SEC;
}

/* -------------------------------------------------------------- inode glue */

/*
 * What an inode carries: the entry pointer, so read and write do not re-scan,
 * plus the (idx, gen) that says WHICH FILE that slot held when this inode was
 * made.
 *
 * The pointer alone was not an identity. It stays valid for as long as the
 * region does - the table is a fixed array in memory that is never remapped,
 * and a slot is reset in place rather than moved, the same property the
 * monitor's process store relies on for the same reason - but validity is not
 * identity. A slot whose file another member unlinks is handed to the next
 * file created, and an inode still pointing at it then named that other file:
 * a read on a handle opened before the recycle returned the new file's bytes,
 * and (once there are byte-range locks) a lock keyed on the slot would have
 * been inherited by whoever got it next.
 *
 * So the generation is captured here and rechecked on every use. `type !=
 * VFS_FREE` was never enough on its own, because a recycled slot is not free.
 */
struct vfs_ino {
    struct vfs_entry* e;
    uint32_t idx;      /* index in the table; derived, kept for lock.c's key */
    uint64_t gen;      /* that entry's generation when this inode was made */
};

/* The entry this inode names, or NULL.
 *
 * NULL means one of two things, and both callers below already handle it the
 * same way: the mount root, which has no entry in the region at all, or a slot
 * that has since been handed to a different file. The second is logged because
 * it is rare and surprising; the first is the common case and silent. */
static struct vfs_entry* vfs_entry_of(struct libos_inode* inode) {
    if (!inode || !inode->data)
        return NULL;                 /* the mount root */
    struct vfs_ino* ino = inode->data;
    uint64_t gen = __atomic_load_n(&ino->e->gen, __ATOMIC_ACQUIRE);
    if (gen != ino->gen) {
        log_debug("vaultfs: entry %u is generation %lu, this handle holds %lu - "
                  "the file it was opened on is gone", ino->idx, gen, ino->gen);
        return NULL;
    }
    return ino->e;
}

/*
 * The file identity behind an open handle, for lock.c.
 *
 * The HANDLE's inode and never the dentry's, which is the distinction that
 * matters: a dentry is a name and its inode can be replaced under it - another
 * member unlinks the file, a lookup re-runs, and `dent->inode` is a different
 * file - while a handle's inode is the file the caller opened and holds open.
 * A lock belongs to the second. Gramine's own lock API is keyed on the dentry,
 * which is why every dispatch site passes the handle it already has rather
 * than letting the dentry decide.
 *
 * Does NOT check that the file is still live; lock.c does that under the
 * superblock lock, where the answer cannot go stale between test and use.
 */
bool vaultfs_handle_fileid(struct libos_handle* hdl, struct vfs_fileid* out) {
    if (!hdl || hdl->type != TYPE_VAULTFS)
        return false;
    if (!hdl->inode || !hdl->inode->data)
        return false;   /* the mount root: a directory with no entry to lock */
    struct vfs_ino* ino = hdl->inode->data;
    out->idx = ino->idx;
    out->gen = ino->gen;
    return true;
}

/* Frees what vfs_setup_dentry allocated. The mount root's inode has no
 * vfs_ino, so NULL is normal here and not an error. */
static void vaultfs_idrop(struct libos_inode* inode) {
    free(inode->data);
    inode->data = NULL;
}
/* The mount root: a directory that exists because the mount does, with no
   entry in the region behind it. See the comment in vaultfs_lookup. */
static int vfs_setup_root(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct libos_inode* inode = get_new_inode(dent->mount, S_IFDIR, PERM_rwxrwxrwx);
    if (!inode)
        return -ENOMEM;
    inode->data = NULL;
    dent->inode = inode;
    return 0;
}

static int vfs_setup_dentry(struct libos_dentry* dent, struct vfs_entry* e) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct vfs_ino* ino = malloc(sizeof(*ino));
    if (!ino)
        return -ENOMEM;
    ino->e   = e;
    ino->idx = (uint32_t)(e - g_vfs_table);
    /* Read AFTER the entry was found, so a slot recycled in between is named
     * by its new generation rather than its old one. That is not a hole: this
     * inode then simply names a file that this lookup did not find, and the
     * first use of it fails the generation check like any other stale handle.
     * Lookups are deliberately unlocked - see vfs_find. */
    ino->gen = __atomic_load_n(&e->gen, __ATOMIC_ACQUIRE);

    mode_t type = (e->type == VFS_DIR) ? S_IFDIR : S_IFREG;
    struct libos_inode* inode = get_new_inode(dent->mount, type, e->mode & 07777);
    if (!inode) {
        free(ino);
        return -ENOMEM;
    }
    inode->data = ino;
    inode->size = e->size;
    inode->ctime = e->mtime;
    inode->mtime = e->mtime;
    inode->atime = e->mtime;
    dent->inode = inode;
    return 0;
}

/* ------------------------------------------------------------- attachment */

/*
 * Attach to the lineage's region, formatting it if nobody has yet.
 *
 * LAZY, and that is load-bearing rather than thrifty. A vault's heavy init -
 * the PAL, this LibOS, every mount - runs in its ZYGOTE, which is then cloned
 * copy-on-write into each instance. A region acquired at mount time would
 * therefore be acquired by the zygote and inherited by every instance of it,
 * so two unrelated invocations of the same function would share one
 * filesystem. Asking on first ACCESS instead means the asker is the running
 * instance, which is the lineage root it ought to be.
 *
 * The monitor refuses a zygote outright, so if this is ever reached from one
 * the answer is a clean -ENODEV rather than a shared filesystem. Belt and
 * braces, because the failure it guards against is silent.
 */
int vfs_attach(void) {
    if (g_vfs)
        return 0;

    int64_t want = g_pal_public_state->lineage_fs.pages;
    if (want < 0)
        return -ENODEV;    /* the manifest did not ask for a lineage region */

    void* base = NULL;
    size_t size = 0;
    int ret = PalLineageFsAttach((uint64_t)want, &base, &size);
    if (ret < 0)
        return pal_to_unix_errno(ret);
    /* The smallest region that can hold a superblock, one bitmap page, the
       minimum table, and a data page to put something in. */
    if (!base ||
        size < (size_t)(1 + 1 + VFS_TABLE_PAGES_MIN + VFS_LOCK_PAGES + 1) * VFS_PAGE) {
        log_error("vaultfs: the lineage region is too small (%lu bytes)", size);
        return -ENODEV;
    }
    /* And never LARGER than this manifest asked for.
     *
     * The monitor only ever clamps `want` down - it caps and it rounds, it
     * does not grow a request - so an answer bigger than the ask is not a
     * generous monitor, it is an answer about somebody else's region. That
     * happened: `lineage_extent` matched on a window that is always 0 for a
     * lineage, so it returned the first lineage region of this purpose in the
     * VM whoever asked, and a vault with a small reservation was told a large
     * neighbour's size. It then laid this filesystem out over that number and
     * died on its first write past its own last page - a silent failure three
     * steps from its cause.
     *
     * Fixed in the monitor; refused here as well, because a filesystem laid
     * out over memory that is not there is worth two checks, and this one
     * costs a comparison. The data area is one page short of the ask (page 0
     * is the monitor's header), so `>` is the right test, not `>=`. */
    if (size > (size_t)want * VFS_PAGE) {
        log_error("vaultfs: the monitor answered %lu bytes for a %ld page ask - "
                  "that region is not this lineage's", size, (long)want);
        return -EINVAL;
    }

    struct vfs_super* sb = base;
    struct vfs_layout L;
    vfs_layout((uint32_t)(size / VFS_PAGE), &L);
    if (!L.data_pages) {
        log_error("vaultfs: a %lu byte region leaves no room for data", size);
        return -EINVAL;
    }

    /* The FIRST member formats; the others find it formatted. The region
     * arrives zeroed from the monitor, so "the magic is not ours" is exactly
     * "nobody has been here yet" - and the lock covers the TEST as well as the
     * write, because two members can reach this in the same moment. */
    g_vfs = sb;    /* vfs_lock needs it */
    vfs_lock();
    if (sb->magic != VFS_MAGIC) {
        /* Zeroing the bitmap and the table is what COMMITS their pages: the
         * region is reserved address space and the monitor spends a page when
         * one is touched, so a 512 MiB filesystem costs its own metadata and
         * nothing else until a file is written. */
        memset(sb, 0, VFS_PAGE);
        /* That memset just zeroed the word we are holding, which is to say it
         * released a lock we still need. Put ourselves back in it before
         * writing anything else: another member reaching vfs_lock() in this
         * window would otherwise find the lock free and format the region a
         * second time, underneath us. (In v1 this was invisible, because the
         * lock was a flag that the memset cleared and the unlock cleared
         * again. With an owner in the word it is a real handover.) */
        __atomic_store_n(&sb->lock, vfs_self(), __ATOMIC_RELAXED);
        sb->version      = VFS_VERSION;
        sb->entries      = L.entries;
        sb->bitmap_pages = L.bitmap_pages;
        sb->table_pages  = L.table_pages;
        sb->lock_first   = L.lock_first;
        sb->lock_pages   = L.lock_pages;
        sb->data_first   = L.data_first;
        sb->data_pages   = L.data_pages;
        sb->generation   = 1;
        /* 1, not 0, so a handle carrying gen 0 is recognisably one that was
         * never given an identity rather than one naming the first file. */
        sb->next_gen     = 1;
        memset((char*)base + VFS_BITMAP_PAGE * VFS_PAGE, 0,
               (size_t)L.bitmap_pages * VFS_PAGE);
        memset((char*)base + (size_t)(VFS_BITMAP_PAGE + L.bitmap_pages) * VFS_PAGE, 0,
               (size_t)L.table_pages * VFS_PAGE);
        /* The lock area is deliberately NOT zeroed. It arrives zeroed from the
         * monitor, and touching it here would spend its pages on every
         * lineage - including the overwhelming majority that never call
         * fcntl. See VFS_LOCK_PAGES. */
        /* The root directory is an entry like any other, so a readdir of the
         * mount point and a lookup of "/" need no special case. */
        struct vfs_entry* root =
            (struct vfs_entry*)((char*)base
                                + (size_t)(VFS_BITMAP_PAGE + L.bitmap_pages) * VFS_PAGE);
        root->type = VFS_DIR;
        root->mode = PERM_rwxrwxrwx;
        root->gen  = sb->next_gen++;
        root->path[0] = '\0';
        /* Last, with a release, so no member can mistake a half-formatted
         * superblock for a formatted one. */
        __atomic_store_n(&sb->magic, VFS_MAGIC, __ATOMIC_RELEASE);
    } else if (sb->version != VFS_VERSION || sb->data_pages != L.data_pages) {
        vfs_unlock();
        log_error("vaultfs: region says version %u / %u data pages, this build derives %u / %u",
                  sb->version, sb->data_pages, VFS_VERSION, L.data_pages);
        g_vfs = NULL;
        return -EINVAL;
    }
    vfs_unlock();

    g_vfs_bitmap     = (uint8_t*)base + VFS_BITMAP_PAGE * VFS_PAGE;
    g_vfs_table      = (struct vfs_entry*)((char*)base
                         + (size_t)(VFS_BITMAP_PAGE + sb->bitmap_pages) * VFS_PAGE);
    g_vfs_locks      = (struct vfs_flock*)((char*)base
                         + (size_t)sb->lock_first * VFS_PAGE);
    g_vfs_data       = (char*)base + (size_t)sb->data_first * VFS_PAGE;
    g_vfs_data_pages = sb->data_pages;
    g_vfs_entries    = sb->entries;
    log_debug("vaultfs: %u data pages (%u MiB) at %p, %u entries, %u bitmap pages",
              g_vfs_data_pages, g_vfs_data_pages / 256, base, g_vfs_entries,
              sb->bitmap_pages);
    return 0;
}

/* ------------------------------------------------------------------- mount */

static int vaultfs_mount(struct libos_mount_params* params, void** mount_data) {
    __UNUSED(params);
    __UNUSED(mount_data);
    /* Nothing here on purpose - see vfs_attach. The mount must SUCCEED in the
     * zygote, or no instance cloned from it would have a /tmp at all; it is
     * the first access that has to happen in the instance. */
    return 0;
}

/* ------------------------------------------------------------------ lookup */

static int vaultfs_lookup(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    /* The mount ROOT, answered WITHOUT the region.
     *
     * `mount_fs_at_dentry` looks the mount root up the moment the mount is
     * made, and that moment is in the ZYGOTE - where there is no region and
     * the monitor refuses to make one. The first version let that lookup
     * attach, so it returned the refusal as EACCES, the mount failed, and
     * `libos_init` killed the vault before it ran a line: "Failed to look up
     * mount root /tmp: Permission denied". Every vault with a vaultfs mount
     * died at startup.
     *
     * So the root is a plain directory inode with no entry behind it, exactly
     * as tmpfs does for its own root. It costs nothing and it means the mount
     * never needs the region: only the first access to something INSIDE the
     * mount does, which is in the instance, which is the whole point.
     *
     * It carries no `vfs_ino`, so `vfs_entry_of` answers NULL for it and
     * every user below already handles that (a read or write of a directory
     * is refused anyway). */
    if (!dent->parent)
        return vfs_setup_root(dent);

    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    char path[VFS_PATH_MAX];
    ret = vfs_path_of(dent, path);
    if (ret < 0)
        return ret;

    /* The REGION is the truth, not this process's dcache - which is the whole
     * reason this filesystem exists. A file another member created a moment
     * ago is found here; tmpfs, whose namespace IS the dcache, answers -ENOENT
     * for it forever. */
    struct vfs_entry* e = vfs_find(path);
    if (!e)
        return -ENOENT;
    return vfs_setup_dentry(dent, e);
}

/* ------------------------------------------------------- create and remove */

static int vfs_make(struct libos_dentry* dent, uint32_t type, mode_t perm,
                    struct vfs_entry** out) {
    int ret = vfs_attach();
    if (ret < 0)
        return ret;
    char path[VFS_PATH_MAX];
    ret = vfs_path_of(dent, path);
    if (ret < 0)
        return ret;

    vfs_lock();
    if (vfs_find(path)) {
        vfs_unlock();
        return -EEXIST;   /* another member got there first */
    }
    struct vfs_entry* e = vfs_free_slot();
    if (!e) {
        vfs_unlock();
        log_error("vaultfs: all %u entries are in use", g_vfs_entries);
        return -ENOSPC;
    }
    e->mode       = perm;
    e->first_page = 0;
    e->npages     = 0;
    e->size       = 0;
    e->mtime      = vfs_now();
    /* A new identity for this slot, under the lock, before the type is
     * published - so no member can ever see a live entry with the previous
     * file's generation still in it. Anything still holding the old (idx, gen)
     * now fails to match, which is the point: it is holding a file that no
     * longer exists. */
    e->gen        = g_vfs->next_gen++;
    /* Nothing this slot owed its previous file can still be owed. Belt and
     * braces against the records above: unlink is where they should go, this
     * is what makes it impossible for them to stay. */
    vfs_flock_drop_slot_locked((uint32_t)(e - g_vfs_table));
    memcpy(e->path, path, strlen(path) + 1);
    /* type LAST: a scan by another member must not see a slot with a path but
     * no type, or one with a type and a stale path. */
    __atomic_store_n(&e->type, type, __ATOMIC_RELEASE);
    g_vfs->generation++;
    vfs_unlock();
    *out = e;
    return 0;
}

static void vaultfs_do_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    __UNUSED(dent);
    __UNUSED(flags);
    hdl->type = TYPE_VAULTFS;
    hdl->seekable = true;
    hdl->pos = 0;
}

static int vaultfs_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);
    vaultfs_do_open(hdl, dent, flags);
    return 0;
}

static int vaultfs_creat(struct libos_handle* hdl, struct libos_dentry* dent, int flags,
                         mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct vfs_entry* e = NULL;
    int ret = vfs_make(dent, VFS_FILE, perm, &e);
    if (ret < 0)
        return ret;
    ret = vfs_setup_dentry(dent, e);
    if (ret < 0)
        return ret;
    vaultfs_do_open(hdl, dent, flags);
    return 0;
}

static int vaultfs_mkdir(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    assert(!dent->inode);

    struct vfs_entry* e = NULL;
    int ret = vfs_make(dent, VFS_DIR, perm, &e);
    if (ret < 0)
        return ret;
    return vfs_setup_dentry(dent, e);
}

static int vaultfs_unlink(struct libos_dentry* dent) {
    assert(locked(&g_dcache_lock));
    assert(dent->inode);
    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    char path[VFS_PATH_MAX];
    ret = vfs_path_of(dent, path);
    if (ret < 0)
        return ret;

    vfs_lock();
    struct vfs_entry* e = vfs_find(path);
    if (!e) {
        vfs_unlock();
        return 0;   /* another member removed it: the end state is the same */
    }
    if (e->type == VFS_DIR) {
        /* Emptiness is asked of the REGION, not of this process's dcache: a
         * child another member created still makes the directory non-empty. */
        for (uint32_t i = 0; i < g_vfs_entries; i++) {
            struct vfs_entry* o = &g_vfs_table[i];
            const char* name;
            if (o == e || (o->type != VFS_FILE && o->type != VFS_DIR))
                continue;
            if (vfs_is_child_of(o->path, path, &name)) {
                vfs_unlock();
                return -ENOTEMPTY;
            }
        }
    }
    /* Type FIRST, then the extent - which is what the comment here always
     * claimed and what the code did backwards.
     *
     * Mutations are serialised by the lock, but LOOKUPS and reads are not:
     * vfs_find and vaultfs_read walk the table without it, by design. Freeing
     * the run first opened a window in which an unlocked reader saw a live
     * VFS_FILE entry whose pages the allocator had already handed to somebody
     * else - so a read returned another file's bytes. Publishing VFS_FREE
     * first closes it: a reader either sees the file intact, or sees it gone. */
    uint32_t first = e->first_page, npages = e->npages;
    __atomic_store_n(&e->type, VFS_FREE, __ATOMIC_RELEASE);
    e->npages = 0;
    e->size = 0;
    if (npages)
        vfs_free_run(first, npages);
    /* And its byte-range locks, which are keyed by (idx, gen) and would
     * otherwise be unreachable by anybody and freed by nothing. */
    vfs_flock_drop_slot_locked((uint32_t)(e - g_vfs_table));
    g_vfs->generation++;
    vfs_unlock();
    return 0;
}

static int vaultfs_rename(struct libos_dentry* old, struct libos_dentry* new) {
    assert(locked(&g_dcache_lock));
    assert(old->inode);
    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    char from[VFS_PATH_MAX], to[VFS_PATH_MAX];
    ret = vfs_path_of(old, from);
    if (ret < 0)
        return ret;
    ret = vfs_path_of(new, to);
    if (ret < 0)
        return ret;

    vfs_lock();
    struct vfs_entry* e = vfs_find(from);
    if (!e) {
        vfs_unlock();
        return -ENOENT;
    }
    struct vfs_entry* victim = vfs_find(to);
    if (victim && victim != e) {
        /* Type first, then the extent - see vaultfs_unlink for why the other
         * order let an unlocked reader read another file's pages. */
        uint32_t vfirst = victim->first_page, vnpages = victim->npages;
        __atomic_store_n(&victim->type, VFS_FREE, __ATOMIC_RELEASE);
        victim->npages = 0;
        victim->size = 0;
        if (vnpages)
            vfs_free_run(vfirst, vnpages);
        vfs_flock_drop_slot_locked((uint32_t)(victim - g_vfs_table));
    }
    /* `e` keeps its slot and its generation, so it keeps its locks: a lock
     * follows the FILE, and a rename does not make a new one. */
    memset(e->path, 0, VFS_PATH_MAX);
    memcpy(e->path, to, strlen(to) + 1);
    e->mtime = vfs_now();
    g_vfs->generation++;
    vfs_unlock();
    return 0;
}

static int vaultfs_chmod(struct libos_dentry* dent, mode_t perm) {
    assert(locked(&g_dcache_lock));
    if (!dent->inode)
        return -ENODEV;
    /* The mount root has no entry behind it; its mode is the mount's. A slot
     * recycled under this dentry is the same answer for a different reason:
     * the file this chmod names is gone, so changing nothing is correct. */
    struct vfs_entry* e = vfs_entry_of(dent->inode);
    if (!e)
        return 0;
    e->mode = perm;
    return 0;
}

static int vaultfs_fchmod(struct libos_handle* hdl, mode_t perm) {
    struct vfs_entry* e = vfs_entry_of(hdl->inode);
    if (!e)
        return -ENODEV;
    e->mode = perm;
    return 0;
}

/* ----------------------------------------------------------------- readdir */

static int vaultfs_readdir(struct libos_dentry* dent, readdir_callback_t callback, void* arg) {
    assert(locked(&g_dcache_lock));
    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    char path[VFS_PATH_MAX];
    ret = vfs_path_of(dent, path);
    if (ret < 0)
        return ret;

    /* Over the REGION, not the dcache - `generic_readdir` would list only what
     * this process created. Under the lock, so the table does not change
     * shape mid-walk; the callback only copies a name out. */
    vfs_lock();
    for (uint32_t i = 0; i < g_vfs_entries; i++) {
        struct vfs_entry* e = &g_vfs_table[i];
        const char* name;
        if (e->type != VFS_FILE && e->type != VFS_DIR)
            continue;
        if (!vfs_is_child_of(e->path, path, &name))
            continue;
        ret = callback(name, arg);
        if (ret < 0) {
            vfs_unlock();
            return ret;
        }
    }
    vfs_unlock();
    return 0;
}

/* ------------------------------------------------------------ read / write */

/* Make `e` able to hold `want` bytes. Doubling, so a file written in small
 * pieces does not pay a copy per piece: contiguous extents mean growth MOVES
 * the file, and without doubling an 8 MB gif written 4 KiB at a time would be
 * quadratic in page count. */
static int vfs_grow(struct vfs_entry* e, uint64_t want) {
    uint32_t need = (uint32_t)((want + VFS_PAGE - 1) / VFS_PAGE);
    if (need <= e->npages)
        return 0;

    uint32_t take = e->npages ? e->npages : 1;
    while (take < need) {
        if (take > g_vfs_data_pages / 2) {
            take = need;
            break;
        }
        take *= 2;
    }

    int64_t start = vfs_alloc_run(take);
    if (start < 0) {
        /* No contiguous run that big. Ask for exactly what is needed before
         * giving up: a fragmented region may still have a tight fit. */
        if (take != need)
            start = vfs_alloc_run(need);
        if (start < 0)
            return -ENOSPC;
        take = need;
    }
    if (e->npages) {
        memcpy(vfs_page_at((uint32_t)start), vfs_page_at(e->first_page),
               (size_t)e->npages * VFS_PAGE);
        vfs_free_run(e->first_page, e->npages);
    }
    e->first_page = (uint32_t)start;
    e->npages = take;
    return 0;
}

static ssize_t vaultfs_read(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos) {
    assert(hdl->type == TYPE_VAULTFS);
    struct vfs_entry* e = vfs_entry_of(hdl->inode);
    if (!e)
        return -ENODEV;

    vfs_lock();
    if (e->type != VFS_FILE) {
        vfs_unlock();
        return -EISDIR;
    }
    uint64_t size = e->size;
    if ((uint64_t)*pos >= size) {
        vfs_unlock();
        return 0;
    }
    size_t n = count;
    if ((uint64_t)*pos + n > size)
        n = (size_t)(size - (uint64_t)*pos);
    memcpy(buf, vfs_page_at(e->first_page) + *pos, n);
    vfs_unlock();

    *pos += n;
    /* The inode's size is this process's cached copy of the entry's; another
     * member may have grown the file since the last lookup. */
    lock(&hdl->inode->lock);
    hdl->inode->size = size;
    unlock(&hdl->inode->lock);
    return (ssize_t)n;
}

static ssize_t vaultfs_write(struct libos_handle* hdl, const void* buf, size_t count,
                             file_off_t* pos) {
    assert(hdl->type == TYPE_VAULTFS);
    struct vfs_entry* e = vfs_entry_of(hdl->inode);
    if (!e)
        return -ENODEV;
    if (!count)
        return 0;

    vfs_lock();
    if (e->type != VFS_FILE) {
        vfs_unlock();
        return -EISDIR;
    }
    /* O_APPEND, under the lock, which is the only place it can be right.
     *
     * Nothing else in this LibOS honours it - Gramine's generic write path
     * does not seek to the end, and neither tmpfs nor chroot does it for
     * itself - so an append landed at offset 0 and overwrote the start of the
     * file. That is a pre-existing gap, but a SHARED filesystem is exactly
     * where it matters: two members appending to one log is the ordinary
     * reason to open a file this way, and each of them has its own `pos`.
     *
     * The end is read from the ENTRY, not from the handle's cached inode
     * size, because another member may have grown the file since this one
     * last looked - and inside the lock, so it cannot grow again between
     * deciding where to write and writing. */
    if (hdl->flags & O_APPEND)
        *pos = (file_off_t)e->size;
    uint64_t end = (uint64_t)*pos + count;
    int ret = vfs_grow(e, end);
    if (ret < 0) {
        vfs_unlock();
        return ret;
    }
    /* A seek past the end leaves a hole, which must read as zeroes rather
     * than as whatever the last tenant of those pages wrote. */
    if ((uint64_t)*pos > e->size)
        memset(vfs_page_at(e->first_page) + e->size, 0, (size_t)((uint64_t)*pos - e->size));
    memcpy(vfs_page_at(e->first_page) + *pos, buf, count);
    if (end > e->size)
        e->size = end;
    e->mtime = vfs_now();
    uint64_t size = e->size;
    vfs_unlock();

    *pos = (file_off_t)end;
    lock(&hdl->inode->lock);
    hdl->inode->size = size;
    unlock(&hdl->inode->lock);
    return (ssize_t)count;
}

static int vaultfs_truncate(struct libos_handle* hdl, file_off_t size) {
    assert(hdl->type == TYPE_VAULTFS);
    struct vfs_entry* e = vfs_entry_of(hdl->inode);
    if (!e)
        return -ENODEV;

    vfs_lock();
    if (e->type != VFS_FILE) {
        vfs_unlock();
        return -EISDIR;
    }
    int ret = vfs_grow(e, (uint64_t)size);
    if (ret < 0) {
        vfs_unlock();
        return ret;
    }
    if ((uint64_t)size > e->size)
        memset(vfs_page_at(e->first_page) + e->size, 0, (size_t)((uint64_t)size - e->size));
    e->size = (uint64_t)size;
    e->mtime = vfs_now();
    vfs_unlock();

    lock(&hdl->inode->lock);
    hdl->inode->size = size;
    unlock(&hdl->inode->lock);
    return 0;
}

static int vaultfs_flush(struct libos_handle* hdl) {
    /* Nothing is buffered: a write lands in the shared pages, which is where
     * every other member reads. */
    __UNUSED(hdl);
    return 0;
}

struct libos_fs_ops vault_fs_ops = {
    .mount    = &vaultfs_mount,
    .flush    = &vaultfs_flush,
    .read     = &vaultfs_read,
    .write    = &vaultfs_write,
    .seek     = &generic_inode_seek,
    .hstat    = &generic_inode_hstat,
    .truncate = &vaultfs_truncate,
    .poll     = &generic_inode_poll,
    .fchmod   = &vaultfs_fchmod,
};

struct libos_d_ops vault_d_ops = {
    .open    = &vaultfs_open,
    .idrop   = &vaultfs_idrop,
    .lookup  = &vaultfs_lookup,
    .creat   = &vaultfs_creat,
    .mkdir   = &vaultfs_mkdir,
    .stat    = &generic_inode_stat,
    .readdir = &vaultfs_readdir,
    .unlink  = &vaultfs_unlink,
    .rename  = &vaultfs_rename,
    .chmod   = &vaultfs_chmod,
};

struct libos_fs vault_builtin_fs = {
    .name   = "vaultfs",
    .fs_ops = &vault_fs_ops,
    .d_ops  = &vault_d_ops,
};
