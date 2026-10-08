/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * vaultfs: POSIX byte-range locks, in the lineage's own memory.
 *
 * Why this exists at all. Gramine's POSIX locks (libos_fs_lock.c) are held in
 * the LEADER process and reached over IPC: every F_SETLK, F_GETLK and every
 * clean process exit is a round trip to another process. That design is right
 * for Gramine, whose processes are separate VMs with no shared memory. Here it
 * is both unnecessary and expensive - the members of a lineage already share
 * writable pages, and the measured cost of the IPC worker in this LibOS was
 * 30 seconds per fork, because every exit blocks on a file_lock_clear_pid
 * round trip that nobody is there to answer.
 *
 * So a lineage's locks live where its filesystem lives: four pages the monitor
 * places and never reads, between the entry table and the data area. Taking a
 * lock is a scan of 256 fixed-size records under the superblock lock, with no
 * IPC, no leader and no worker thread.
 *
 * What a vault gets from that, and what it does not. It gets POSIX locks that
 * work across fork and exec within one lineage, which is what a program that
 * locks a file it then hands to a child actually needs. It does not get locks
 * that mean anything to anyone outside the lineage - there is nothing outside
 * the lineage that can see these pages, which is the point of the lineage.
 *
 * Three invariants hold the design up, and every function below preserves
 * them:
 *
 *   1. One owner's records on one file never overlap. Insertion clips the
 *      owner's existing records over the range first, so the only record
 *      covering a byte for a given owner is the newest one. This is what makes
 *      the split analysis in `clip_own` sound - at most ONE record can
 *      strictly contain a range on both sides.
 *   2. A record is keyed by (idx, gen), never by path or by slot alone. A
 *      rename keeps the lock, because a rename keeps the slot and the
 *      generation; a slot recycled for a different file does NOT inherit the
 *      locks, because the generation changed.
 *   3. Space is reserved before anything is mutated. An operation that needs a
 *      split and an insert checks for both free records up front and returns
 *      -ENOLCK having changed nothing, rather than discovering the area is
 *      full halfway through and leaving a half-applied lock.
 *
 * And one acknowledged cost, the same one the rest of vaultfs carries: these
 * are a lineage's own pages, so a member that corrupts them corrupts its own
 * lineage's locks. A lineage is one trust domain by construction. A member
 * that could scribble on this area could equally have ignored the locks.
 *
 * Nothing calls any of this yet. It is landed separately from the dispatch in
 * libos_fs_lock.c on purpose: a mistake in the format or in the superblock
 * lock fails rows that have nothing to do with locking, and finding that out
 * with the dispatch already in place would confuse two bisections into one.
 */

#include "api.h"
#include "assert.h"
#include "libos_fs.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"
#include "pal.h"
#include "vault_internal.h"

/* ------------------------------------------------------------- the records */

/* Is this record in use and about this file? */
static bool rec_is(const struct vfs_flock* r, const struct vfs_fileid* id) {
    return r->used && r->idx == id->idx && r->gen == id->gen;
}

/* Inclusive ranges overlap. */
static bool overlaps(uint64_t as, uint64_t ae, uint64_t bs, uint64_t be) {
    return as <= be && bs <= ae;
}

/* Overlapping OR exactly adjacent, which is what merging needs. Written to
 * avoid the overflow at UINT64_MAX that `ae + 1` would hit for a lock held to
 * end of file - the one value this filesystem uses for "to EOF" and therefore
 * the one that would have been wrong. */
static bool touches(uint64_t as, uint64_t ae, uint64_t bs, uint64_t be) {
    if (ae != UINT64_MAX && ae + 1 < bs)
        return false;
    if (be != UINT64_MAX && be + 1 < as)
        return false;
    return true;
}

/* A read lock shares with a read lock and with nothing else. */
static bool types_conflict(uint32_t a, uint32_t b) {
    return a == F_WRLCK || b == F_WRLCK;
}

static uint32_t free_records(void) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < VFS_FLOCKS; i++)
        if (!g_vfs_locks[i].used)
            n++;
    return n;
}

static struct vfs_flock* take_record(void) {
    for (uint32_t i = 0; i < VFS_FLOCKS; i++)
        if (!g_vfs_locks[i].used)
            return &g_vfs_locks[i];
    return NULL;
}

static void drop_record(struct vfs_flock* r) {
    /* `used` last, with a release, so nobody can ever see a record that claims
     * to be live with another record's range already written over it. The area
     * is only read under the superblock lock today, so this is belt and
     * braces - but it is the discipline the entry table uses for the same
     * reason, and the cost is nothing. */
    r->idx = 0;
    r->gen = 0;
    r->owner = 0;
    __atomic_store_n(&r->used, 0, __ATOMIC_RELEASE);
}

/*
 * A byte-range lock needs an identity it does not SHARE, and VFS_LOCK_ANON is
 * shared by construction: every member that cannot learn its own serial uses
 * it. Two such members would be one owner to this code - each free to clip the
 * other's records and to believe it holds what the other holds - so a lock is
 * refused rather than taken under a borrowed name.
 *
 * Unreachable in practice: every entry point here attaches first, and a member
 * holding a lineage region has a stamped channel directory. The superblock
 * lock can live with ANON because sharing it there only costs a stall (two
 * ANON members spin at each other and neither is ever judged dead); sharing an
 * OWNER would cost correctness, which is the difference.
 */
static bool owner_is_usable(uint64_t me) {
    if (me && !(me & VFS_LOCK_ANON))
        return true;
    log_error("vaultfs: this member has no lineage serial, so it cannot hold a byte-range "
              "lock without borrowing another's identity - refusing");
    return false;
}

/* Does the file this id names still exist? A lock on a file that is gone is
 * not an error to be reported later, it is -ESTALE now: the handle that asked
 * is holding an identity the region no longer has. */
static bool file_is_live(const struct vfs_fileid* id) {
    if (id->idx >= g_vfs_entries)
        return false;
    struct vfs_entry* e = &g_vfs_table[id->idx];
    if (__atomic_load_n(&e->gen, __ATOMIC_ACQUIRE) != id->gen)
        return false;
    return e->type == VFS_FILE || e->type == VFS_DIR;
}

/* ------------------------------------------------------------- reclamation */

/* How many distinct owners the verdict cache holds. Sixteen because that is
 * the width of the roster the monitor publishes - a lineage cannot have more
 * live members than it has roster slots, so this covers every owner a live
 * record can name. An owner beyond it is simply asked about again, which costs
 * a second 128-byte read and is not wrong. */
#define FLOCK_OWNER_CACHE  16

/* Caller holds the superblock lock. */
static uint32_t reclaim_dead_locked(void) {
    uint32_t freed = 0;
    /* Only ever reached from the two slow paths that would otherwise have to
     * give a wrong answer - a conflict, and an exhausted area - so the roster
     * reads are paid for by the contended case and never by an ordinary lock.
     * There is no caller that sweeps for its own sake; a sweep with nothing
     * waiting on it is work nobody asked for. */
    /* Cache the verdict per owner: a dead member usually holds several
     * records, and the roster read is the same answer every time. Sixteen is
     * the roster's own width, so this covers every owner there can be. */
    uint64_t asked[FLOCK_OWNER_CACHE];
    bool     dead[FLOCK_OWNER_CACHE];
    uint32_t nasked = 0;

    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (!r->used)
            continue;
        bool is_dead = false;
        bool known = false;
        for (uint32_t k = 0; k < nasked; k++) {
            if (asked[k] == r->owner) {
                is_dead = dead[k];
                known = true;
                break;
            }
        }
        if (!known) {
            is_dead = vfs_holder_dead(r->owner);
            if (nasked < FLOCK_OWNER_CACHE) {
                asked[nasked] = r->owner;
                dead[nasked] = is_dead;
                nasked++;
            }
        }
        if (is_dead) {
            drop_record(r);
            freed++;
        }
    }
    return freed;
}

/*
 * Every record naming this SLOT, whatever generation, dropped.
 *
 * Caller holds the superblock lock, because the two callers in fs.c already do
 * and because the entry they are about to change must not move underneath this.
 *
 * Why by slot and not by (idx, gen): a record is keyed by the file, so a record
 * for a file that no longer exists matches nothing and is reachable by nobody -
 * `rec_is` needs the generation, and the generation is gone. Left alone it
 * would occupy a record for the life of the region. A member that locks a file
 * and unlinks it is the ordinary way to get there, and 256 of them is -ENOLCK
 * for everybody.
 *
 * Called from BOTH ends of a slot's life. At unlink, because that is where the
 * file stops existing and where the records should go. At create, because that
 * makes the leak structurally impossible rather than dependent on every future
 * path through unlink remembering - a slot being handed to a new file cannot,
 * by construction, still owe anything to the old one.
 */
void vfs_flock_drop_slot_locked(uint32_t idx) {
    if (!g_vfs_locks)
        return;
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (r->used && r->idx == idx)
            drop_record(r);
    }
}

/*
 * Say that a sweep happened - AFTER the superblock lock is released, never
 * under it.
 *
 * A console write in this LibOS is a monitor call, and holding the lock across
 * one would make every other member of the lineage wait on the console. That
 * is the same mistake as printing from a service loop, which cost multi-second
 * gaps once already. So the count is carried out of the critical section and
 * reported here.
 *
 * log_error, not a warning, for the reason the superblock steal is: a measured
 * manifest runs at log_level = "error", and this only ever prints when a
 * member died holding locks its lineage had to clean up after.
 */
static void report_swept(uint32_t n) {
    if (n)
        log_error("vaultfs: reclaimed %u byte-range lock(s) from members the monitor "
                  "no longer lists", n);
}

/* --------------------------------------------------------------- conflicts */

/* The first record that would prevent `type` over [start, end] from being
 * taken by `me`. Our own records never conflict with us: POSIX says a process
 * replaces its own locks rather than deadlocking against them. */
static struct vfs_flock* find_conflict(const struct vfs_fileid* id, uint64_t me, uint32_t type,
                                       uint64_t start, uint64_t end) {
    if (type == F_UNLCK)
        return NULL;
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (!rec_is(r, id))
            continue;
        if (r->owner == me)
            continue;
        if (!types_conflict(type, r->type))
            continue;
        if (!overlaps(start, end, r->start, r->end))
            continue;
        return r;
    }
    return NULL;
}

/* ------------------------------------------------------------- the mutators */

/*
 * Split any record of ours that STRADDLES the range - extends past it at both
 * ends - into the part before and the part after. Afterwards every record of
 * ours is wholly inside the range, wholly outside it, or clipped at one end
 * only, which is what lets `clip_own` below run without ever allocating.
 *
 * This is the only step that needs a free record, and it is deliberately
 * first, because it is the only step that can be interrupted harmlessly: one
 * record split into two covering exactly the same bytes, with the same owner
 * and the same type, is the SAME LOCK STATE. So returning -ENOLCK from the
 * middle of this loop has changed how the locks are stored and not what they
 * are - which is why there is no unwinding here and no half-applied lock.
 *
 * Invariant 1 (one owner's records on one file never overlap) means at most
 * one record can straddle, so in practice this allocates once or not at all.
 * It is written as a loop anyway: if that invariant were ever broken the loop
 * still terminates and still produces the right lock state, where an
 * `assert(n)` on a counted-once-up-front allocation would have written through
 * a null pointer.
 */
static int split_straddling(const struct vfs_fileid* id, uint64_t me, uint64_t start,
                            uint64_t end) {
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (!rec_is(r, id) || r->owner != me)
            continue;
        if (!(r->start < start && r->end > end))
            continue;
        /* start >= 1 because r->start < start; end < UINT64_MAX because
         * r->end > end. So neither arithmetic below can wrap. */
        struct vfs_flock* n = take_record();
        if (!n)
            return -ENOLCK;    /* nothing mutated yet for this record */

        /* SHRINK FIRST, then publish the tail. The other order - publish, then
         * shrink - leaves a moment in which two records of ours both claim
         * [end+1, old_end], and `clip_own` below is only correct while one
         * owner's records do not overlap: given r1 = [0,100] and r2 = [50,100]
         * it would clip r1 to [0,59] and lose [71,100] from it. Nobody can
         * observe either order (the whole area is read under the superblock
         * lock), so this is about what is left behind if this member dies
         * mid-split: a transient GAP means we hold less than we think, which
         * the next taker discovers, and a transient OVERLAP silently breaks
         * every later operation on this file. */
        uint64_t tail_end = r->end;
        r->end = start - 1;
        n->type  = r->type;
        n->idx   = r->idx;
        n->pad   = 0;
        n->gen   = r->gen;
        n->start = end + 1;
        n->end   = tail_end;
        n->owner = r->owner;
        n->pid   = r->pid;
        n->reserved = 0;
        __atomic_store_n(&n->used, 1, __ATOMIC_RELEASE);
    }
    return 0;
}

/*
 * Remove [start, end] from everything `me` holds on this file.
 *
 * Allocates NOTHING: `split_straddling` has already run, so every record of
 * ours that overlaps the range needs only to be clipped at one end or dropped
 * entirely. That is what makes this step unable to fail, and therefore what
 * makes an interrupted F_SETLK impossible - by the time anything is removed,
 * every allocation the operation needs has already succeeded.
 */
static void clip_own(const struct vfs_fileid* id, uint64_t me, uint64_t start, uint64_t end) {
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (!rec_is(r, id) || r->owner != me)
            continue;
        if (!overlaps(start, end, r->start, r->end))
            continue;

        if (r->start < start) {
            /* Cannot also extend past `end`: split_straddling removed that
             * case, and it ran under this same hold of the superblock lock. */
            r->end = start - 1;
        } else if (r->end > end) {
            r->start = end + 1;
        } else {
            drop_record(r);
        }
    }
}

/* Coalesce `r` with our adjacent or overlapping records of the SAME type on
 * this file, so a program that locks a file byte by byte ends up with one
 * record rather than one per byte. Different types are never merged: they mean
 * different things and the area is not large enough to pretend otherwise. */
static void merge_own(const struct vfs_fileid* id, uint64_t me, struct vfs_flock* r) {
    bool again = true;
    while (again) {
        again = false;
        for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
            struct vfs_flock* o = &g_vfs_locks[i];
            if (o == r || !rec_is(o, id) || o->owner != me || o->type != r->type)
                continue;
            if (!touches(r->start, r->end, o->start, o->end))
                continue;
            if (o->start < r->start)
                r->start = o->start;
            if (o->end > r->end)
                r->end = o->end;
            drop_record(o);
            again = true;
        }
    }
}

/* ------------------------------------------------------------- the interface */

int vfs_flock_set(const struct vfs_fileid* id, uint32_t type, uint64_t start, uint64_t end,
                  uint64_t pid) {
    if (type != F_RDLCK && type != F_WRLCK && type != F_UNLCK)
        return -EINVAL;
    if (start > end)
        return -EINVAL;

    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    uint64_t me = vfs_self();
    if (!owner_is_usable(me))
        return -ENOLCK;

    vfs_lock();

    if (!file_is_live(id)) {
        vfs_unlock();
        return -ESTALE;
    }

    /* A conflict is where the dead are swept, and ONLY there: the scan costs a
     * roster read per distinct owner, so it is paid by the contended case and
     * not by every lock. A member that died holding a lock therefore blocks
     * nobody - the first member it would have blocked clears it. */
    uint32_t swept = 0;
    struct vfs_flock* c = find_conflict(id, me, type, start, end);
    if (c && vfs_holder_dead(c->owner)) {
        swept += reclaim_dead_locked();
        c = find_conflict(id, me, type, start, end);
    }
    if (c) {
        vfs_unlock();
        report_swept(swept);
        return -EAGAIN;
    }

    /* The ONLY step that can run out of space, and the only one that is safe
     * to abandon half-done - see split_straddling. */
    ret = split_straddling(id, me, start, end);
    if (ret < 0) {
        /* Out of records. Sweep the dead and try the whole step again, for the
         * same reason a conflict sweeps them: an area filled by members that
         * no longer exist would otherwise refuse every lock in the lineage
         * forever, which is the wedge this design exists to avoid. ONCE - a
         * second sweep would find the same records, so a loop would only hide
         * a real exhaustion behind a scan. */
        uint32_t n = reclaim_dead_locked();
        swept += n;
        if (n)
            ret = split_straddling(id, me, start, end);
        if (ret < 0) {
            vfs_unlock();
            report_swept(swept);
            log_warning("vaultfs: the lock area is full (%u records), refusing a lock on entry %u",
                        (unsigned)VFS_FLOCKS, id->idx);
            return ret;
        }
    }

    /* Ask for the insert's record BEFORE anything is removed. clip_own only
     * frees records, so a free one seen here is still free after it - which is
     * what makes the take_record() below unable to fail, and what keeps an
     * F_SETLK from unlocking a range it then cannot relock. */
    if (type != F_UNLCK && !free_records()) {
        uint32_t n = reclaim_dead_locked();
        swept += n;
        if (!n) {
            vfs_unlock();
            report_swept(swept);
            log_warning("vaultfs: the lock area is full (%u records), refusing a lock on entry %u",
                        (unsigned)VFS_FLOCKS, id->idx);
            return -ENOLCK;
        }
    }

    clip_own(id, me, start, end);

    if (type != F_UNLCK) {
        struct vfs_flock* r = take_record();
        if (!r) {
            /* Unreachable: the count above saw a free record and clip_own only
             * ever frees more. Checked rather than asserted because the
             * alternative is a write through a null pointer, and because
             * -ENOLCK here is at worst an unlock that reports a failure. */
            vfs_unlock();
            report_swept(swept);
            return -ENOLCK;
        }
        r->type  = type;
        r->idx   = id->idx;
        r->pad   = 0;
        r->gen   = id->gen;
        r->start = start;
        r->end   = end;
        r->owner = me;
        r->pid   = pid;
        r->reserved = 0;
        __atomic_store_n(&r->used, 1, __ATOMIC_RELEASE);
        merge_own(id, me, r);
    }

    vfs_unlock();
    report_swept(swept);
    return 0;
}

int vfs_flock_get(const struct vfs_fileid* id, uint32_t type, uint64_t start, uint64_t end,
                  struct vfs_flock* out) {
    if (type != F_RDLCK && type != F_WRLCK)
        return -EINVAL;
    if (start > end)
        return -EINVAL;

    int ret = vfs_attach();
    if (ret < 0)
        return ret;

    uint64_t me = vfs_self();
    if (!owner_is_usable(me))
        return -ENOLCK;

    vfs_lock();

    if (!file_is_live(id)) {
        vfs_unlock();
        return -ESTALE;
    }

    uint32_t swept = 0;
    struct vfs_flock* c = find_conflict(id, me, type, start, end);
    if (c && vfs_holder_dead(c->owner)) {
        swept += reclaim_dead_locked();
        c = find_conflict(id, me, type, start, end);
    }
    /* A copy, because the caller reads it after the lock is released and the
     * record is shared memory that another member may reuse the moment we let
     * go. `used` of 0 is "the range is free", not "there is no such record". */
    if (c)
        *out = *c;
    else
        memset(out, 0, sizeof(*out));

    vfs_unlock();
    report_swept(swept);
    return 0;
}

void vfs_flock_clear_file(const struct vfs_fileid* id) {
    if (vfs_attach() < 0)
        return;
    uint64_t me = vfs_self();
    if (!me || (me & VFS_LOCK_ANON))
        return;   /* we can hold nothing - see owner_is_usable */
    vfs_lock();
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (rec_is(r, id) && r->owner == me)
            drop_record(r);
    }
    vfs_unlock();
}

void vfs_flock_clear_self(void) {
    /* Deliberately does NOT call vfs_attach(): this runs at process exit, and
     * a member that never touched the filesystem must not acquire a lineage
     * region on its way out. If g_vfs is NULL there is nothing of ours in an
     * area we never attached to. */
    if (!g_vfs || !g_vfs_locks)
        return;
    uint64_t me = vfs_self();
    if (!me || (me & VFS_LOCK_ANON))
        return;   /* we can hold nothing - see owner_is_usable */
    vfs_lock();
    for (uint32_t i = 0; i < VFS_FLOCKS; i++) {
        struct vfs_flock* r = &g_vfs_locks[i];
        if (r->used && r->owner == me)
            drop_record(r);
    }
    vfs_unlock();
}

/* ===================================================================
 * The dispatch: how an ordinary fcntl() reaches the lines above.
 *
 * Gramine's POSIX locks live in the LEADER process and are reached by IPC.
 * These three functions are offered to the five places that take or drop a
 * lock, and each answers the same question first: is this handle's file in a
 * lineage filesystem? If it is, the operation is carried out here and the
 * caller does NOT fall through - whatever the answer, including a failure.
 *
 * That last part is the load-bearing half. A vaultfs lock that failed and then
 * fell through to gramine's path would be granted out of this process's own
 * copy of the leader's tables: the caller would be told it holds a lock that
 * no other member of its lineage can see, which is worse than being told no.
 * So -ENOLCK and -ESTALE are returned as results, never treated as "not
 * handled".
 * =================================================================== */

#include "libos_handle.h"
#include "libos_process.h"
#include "libos_thread.h"
#include "libos_fs_lock.h"

/* How long F_SETLKW waits between re-tests. There is no wait list in the lock
 * area, deliberately: a queue in shared memory that a dying member can leave a
 * node in is a second reclamation problem, and what it would buy -
 * wake-on-release instead of a poll - is not worth that at this scale. One
 * millisecond is orders of magnitude longer than any critical section here and
 * orders of magnitude shorter than a caller notices. */
#define FLOCK_RETEST_US  1000

/* flock(2) on a vaultfs file is NOT handled here, and the reason is an
 * identity: a BSD lock's owner is `hdl->id`, which is unique within ONE
 * process and says nothing across a lineage - two members would be one owner
 * and each could drop the other's lock. Rather than implement something that
 * looks like flock and is not, these fall through to gramine's own path, which
 * is correct within a single process and is what every existing caller gets
 * today. Said once, because a program that uses flock will do it often. */
static void warn_flock_once(void) {
    static bool said = false;
    if (said)
        return;
    said = true;
    log_warning("vaultfs: flock() on a lineage filesystem is handled per-process, not "
                "per-lineage - its owner (the handle id) is not unique across members. "
                "fcntl() byte-range locks ARE lineage-wide.");
}

/* F_SETLK, or F_SETLKW as a bounded re-test. */
static int flock_set_waiting(const struct vfs_fileid* id, struct libos_file_lock* fl, bool wait) {
    uint64_t who = vfs_self();

    for (;;) {
        int ret = vfs_flock_set(id, (uint32_t)fl->type, fl->start, fl->end, fl->pid);
        if (ret != -EAGAIN || !wait)
            return ret;

        /* Did we become a different process while waiting? A copy-on-write
         * fork returns in the child inside this loop, with the parent's stack
         * and the parent's intent - and the child must not go on to acquire,
         * under its own serial, a lock its parent asked for. -ERESTARTSYS
         * sends it back out to retry as itself. */
        if (vfs_self() != who)
            return -ERESTARTSYS;

        /* prepare BEFORE wait, as every other waiter in this LibOS does: the
         * scheduler event is level-triggered, so an event left set by an
         * earlier wakeup makes thread_wait return at once and turns this
         * bounded re-test into a hot spin on the superblock lock. */
        thread_prepare_wait();
        uint64_t timeout = FLOCK_RETEST_US;
        ret = thread_wait(&timeout, /*ignore_pending_signals=*/false);
        if (ret == -EINTR)
            return -ERESTARTSYS;
        /* -ETIMEDOUT is the ordinary case: the wait elapsed, test again. A
         * plain 0 is a spurious wakeup, and testing again is also right. */
    }
}

bool vaultfs_lock_set(struct libos_handle* hdl, struct libos_file_lock* fl, bool wait, int* out) {
    struct vfs_fileid id;
    if (!vaultfs_handle_fileid(hdl, &id))
        return false;
    if (fl->family != FILE_LOCK_POSIX) {
        warn_flock_once();
        return false;
    }

    int ret = flock_set_waiting(&id, fl, wait);
    /* An unlock of a file that is already gone is not a failure: the end state
     * the caller asked for is the state the region is in. This matters at
     * close, where every handle is unlocked over its whole range and the file
     * may have been unlinked by another member first. */
    if (ret == -ESTALE && fl->type == F_UNLCK)
        ret = 0;
    *out = ret;
    return true;
}

bool vaultfs_lock_get(struct libos_handle* hdl, struct libos_file_lock* fl,
                      struct libos_file_lock* out_fl, int* out) {
    struct vfs_fileid id;
    if (!vaultfs_handle_fileid(hdl, &id))
        return false;
    if (fl->family != FILE_LOCK_POSIX) {
        warn_flock_once();
        return false;
    }

    struct vfs_flock found;
    int ret = vfs_flock_get(&id, (uint32_t)fl->type, fl->start, fl->end, &found);
    if (ret < 0) {
        *out = ret;
        return true;
    }
    if (!found.used) {
        out_fl->family = FILE_LOCK_POSIX;
        out_fl->type   = F_UNLCK;        /* nothing blocks it */
    } else {
        out_fl->family = FILE_LOCK_POSIX;
        out_fl->type   = (int)found.type;
        out_fl->start  = found.start;
        out_fl->end    = found.end;
        /* The HOLDER's pid, which is what F_GETLK reports - and why the record
         * carries one at all, since the owner it is keyed by is a serial. */
        out_fl->pid    = (IDTYPE)found.pid;
    }
    *out = 0;
    return true;
}

/*
 * Every lock this member holds, anywhere, dropped.
 *
 * Called at exit UNCONDITIONALLY, beside gramine's own file_lock_clear_pid,
 * and not only when this process is known to hold something. A conditional
 * purge needs a flag, a flag has to be maintained across fork and exec, and
 * the cost of being wrong is a lock no survivor can tell from a live one until
 * the reclaim scan happens to look at it. The purge is a scan of 256 records
 * under a lock nobody is contending at exit, so there is nothing to save.
 *
 * It is also what makes the reclaim path in vfs_flock_set a backstop rather
 * than the mechanism: an orderly exit cleans up after itself, and the roster
 * is only consulted for members that had no chance to.
 */
void vaultfs_lock_clear_self(void) {
    vfs_flock_clear_self();
}
