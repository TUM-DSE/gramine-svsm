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

#define USEC_IN_SEC 1000000

/* The region, as this member sees it. One per process: every mount of
 * vaultfs in one vault is the same lineage region (the monitor's call is
 * idempotent), so there is nothing to key this by. */
static struct vfs_super* g_vfs;
static struct vfs_entry* g_vfs_table;
static char* g_vfs_data;
static uint32_t g_vfs_data_pages;

/* ---------------------------------------------------------------- the lock */

/*
 * A test-and-set over shared memory, held across a table mutation.
 *
 * The members of a lineage are cooperative by construction, and no monitor
 * call arbitrates this - so there is no priority inheritance and no owner
 * death detection. A member descheduled while holding it makes the others
 * spin. That is the acknowledged cost of keeping the filesystem out of VMPL0
 * (PLAN.md's risk list), and it is bounded in practice because every critical
 * section here is a bounded scan or memcpy with no monitor call inside it.
 */
static void vfs_lock(void) {
    while (__atomic_exchange_n(&g_vfs->lock, 1, __ATOMIC_ACQUIRE) != 0) {
        /* A plain spin. Every critical section below is a bounded scan or a
         * memcpy with no monitor call in it, so the hold time is short and
         * yielding would cost more than it saves - but this IS a spin, and a
         * member descheduled while holding the lock makes the others burn
         * their slice until it runs again. That is the acknowledged price of
         * keeping the filesystem out of VMPL0. */
        CPU_RELAX();
    }
}

static void vfs_unlock(void) {
    __atomic_store_n(&g_vfs->lock, 0, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------- the page allocator */

static uint8_t* vfs_bitmap(void) {
    return (uint8_t*)g_vfs + VFS_BITMAP_OFF;
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
    for (uint32_t i = 0; i < VFS_ENTRIES; i++) {
        struct vfs_entry* e = &g_vfs_table[i];
        if (e->type != VFS_FILE && e->type != VFS_DIR)
            continue;
        if (!strncmp(e->path, path, VFS_PATH_MAX))
            return e;
    }
    return NULL;
}

static struct vfs_entry* vfs_free_slot(void) {
    for (uint32_t i = 0; i < VFS_ENTRIES; i++)
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

/* The inode carries the entry pointer, so read and write do not re-scan. It
 * is a pointer into shared memory and stays valid for as long as the entry
 * does: the table is a fixed array in a region that is never remapped, and a
 * slot is reset in place rather than moved - the same property the monitor's
 * process store relies on for the same reason. An entry freed by another
 * member becomes type VFS_FREE, which every user below rechecks. */
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

    mode_t type = (e->type == VFS_DIR) ? S_IFDIR : S_IFREG;
    struct libos_inode* inode = get_new_inode(dent->mount, type, e->mode & 07777);
    if (!inode)
        return -ENOMEM;
    inode->data = e;
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
static int vfs_attach(void) {
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
    if (!base || size < (size_t)(1 + VFS_TABLE_PAGES + 1) * VFS_PAGE) {
        log_error("vaultfs: the lineage region is too small (%lu bytes)", size);
        return -ENODEV;
    }

    struct vfs_super* sb = base;
    uint32_t total = (uint32_t)(size / VFS_PAGE);
    uint32_t data_pages = total - 1 - VFS_TABLE_PAGES;
    if (data_pages > VFS_BITMAP_MAX) {
        log_error("vaultfs: %u data pages is more than the bitmap holds", data_pages);
        return -EINVAL;
    }

    /* The FIRST member formats; the others find it formatted. The region
     * arrives zeroed from the monitor, so "the magic is not ours" is exactly
     * "nobody has been here yet" - and the lock covers the TEST as well as the
     * write, because two members can reach this in the same moment. */
    g_vfs = sb;    /* vfs_lock needs it */
    vfs_lock();
    if (sb->magic != VFS_MAGIC) {
        memset(sb, 0, VFS_PAGE);
        sb->version     = VFS_VERSION;
        sb->entries     = VFS_ENTRIES;
        sb->data_first  = 1 + VFS_TABLE_PAGES;
        sb->data_pages  = data_pages;
        sb->generation  = 1;
        memset((char*)base + VFS_PAGE, 0, (size_t)VFS_TABLE_PAGES * VFS_PAGE);
        /* The root directory is an entry like any other, so a readdir of the
         * mount point and a lookup of "/" need no special case. */
        struct vfs_entry* root = (struct vfs_entry*)((char*)base + VFS_PAGE);
        root->type = VFS_DIR;
        root->mode = PERM_rwxrwxrwx;
        root->path[0] = '\0';
        /* Last, with a release, so no member can mistake a half-formatted
         * superblock for a formatted one. */
        __atomic_store_n(&sb->magic, VFS_MAGIC, __ATOMIC_RELEASE);
    } else if (sb->version != VFS_VERSION || sb->data_pages != data_pages) {
        vfs_unlock();
        log_error("vaultfs: region says version %u / %u data pages, this build wants %u / %u",
                  sb->version, sb->data_pages, VFS_VERSION, data_pages);
        g_vfs = NULL;
        return -EINVAL;
    }
    vfs_unlock();

    g_vfs_table      = (struct vfs_entry*)((char*)base + VFS_PAGE);
    g_vfs_data       = (char*)base + (size_t)sb->data_first * VFS_PAGE;
    g_vfs_data_pages = data_pages;
    log_debug("vaultfs: %u data pages at %p, %u entries", data_pages, base, VFS_ENTRIES);
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
     * Its `inode->data` is NULL, and every user of that pointer already
     * checks (a read or write of a directory is refused anyway). */
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
        log_error("vaultfs: all %u entries are in use", VFS_ENTRIES);
        return -ENOSPC;
    }
    e->mode       = perm;
    e->first_page = 0;
    e->npages     = 0;
    e->size       = 0;
    e->mtime      = vfs_now();
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
        for (uint32_t i = 0; i < VFS_ENTRIES; i++) {
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
    if (e->npages)
        vfs_free_run(e->first_page, e->npages);
    /* type first, so no scan sees a freed extent still owned. */
    __atomic_store_n(&e->type, VFS_FREE, __ATOMIC_RELEASE);
    e->npages = 0;
    e->size = 0;
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
        if (victim->npages)
            vfs_free_run(victim->first_page, victim->npages);
        __atomic_store_n(&victim->type, VFS_FREE, __ATOMIC_RELEASE);
        victim->npages = 0;
        victim->size = 0;
    }
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
    /* The mount root has no entry behind it; its mode is the mount's. */
    if (!dent->inode->data)
        return 0;
    struct vfs_entry* e = dent->inode->data;
    e->mode = perm;
    return 0;
}

static int vaultfs_fchmod(struct libos_handle* hdl, mode_t perm) {
    if (!hdl->inode || !hdl->inode->data)
        return -ENODEV;
    struct vfs_entry* e = hdl->inode->data;
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
    for (uint32_t i = 0; i < VFS_ENTRIES; i++) {
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
    struct vfs_entry* e = hdl->inode->data;
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
    struct vfs_entry* e = hdl->inode->data;
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
    struct vfs_entry* e = hdl->inode->data;
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
