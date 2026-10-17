/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Pipes inside a vault.
 *
 * On other hosts a pipe is a kernel object and the two ends may be in
 * different processes. A vault is exactly one process with no host to ask, so
 * a pipe here is a pair of rings in its own memory: `pipe.srv:<name>` records
 * a name, `pipe:<name>` connects to it, and PalStreamWaitForClient hands back
 * the other end.
 *
 * This existed as a stub - open succeeded and read and write returned
 * NOTIMPLEMENTED - which was invisible for as long as nothing could start a
 * second thread. It stops being invisible the moment one can: LibOS builds
 * its pollable events out of a non-blocking pipe pair (libos_pollable_event.c
 * writes a byte to set one and drains it to clear), and the async worker -
 * which reaps exited threads and runs timers - waits on one. With the pipe
 * faked, the worker took a NOTIMPLEMENTED from PalStreamsWaitEvents on its
 * first pass and killed the process.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"
#include "pal_monitor_call.h"

#define PIPE_RING_SIZE   4096
/* create_pollable_event connects and accepts back to back, so one is really
 * enough; the rest are slack for LibOS's own IPC pipes at startup. */
#define PIPE_PENDING_MAX 8

struct pal_svsm_pipe_ring {
    size_t head;                    /* next byte to read */
    size_t used;                    /* bytes in the ring */
    char   data[PIPE_RING_SIZE];
};

struct pal_svsm_pipe_pair {
    /* dir[s] is what side s wrote and side !s reads. */
    struct pal_svsm_pipe_ring dir[2];
    /* How many HANDLES hold each end, not whether one does.
     *
     * A count because a fork gives the child a copy of every handle: with a
     * bool, the first close in either process would report end-of-file to a
     * reader whose peer is still very much there. A reader on side s sees
     * EOF when holders[!s] reaches zero and the ring it reads is empty,
     * which is what a pipe means. */
    int    holders[2];
    /* holders[0] + holders[1], kept as ONE word because it is what decides
     * who frees the pair. Two releases of different sides - a parent closing
     * `r` while its child exits closing `w`, on two processors - could both
     * read 0/0 from the two words and both free the slot, the second after a
     * new pipe had already claimed it. Whoever takes this to 0 frees it, and
     * that happens once. */
    int    refs;
    int    in_use;                  /* 0 = this arena slot is free */
};

/*
 * Where a pair lives, and why it is not the heap.
 *
 * A pipe used to be `calloc`ed, which is correct for exactly as long as a
 * vault is one process. It stopped being one the moment fork worked: a
 * copy-on-write fork gives parent and child a ring each, so nothing written
 * in one is visible in the other and no close in one is visible in the
 * other either. Measured: a child wrote fourteen bytes and exited, and its
 * parent read nothing and waited for end-of-file that could not come -
 * which is exactly how `subprocess` hangs, since CPython learns that exec
 * succeeded by its error pipe reaching EOF.
 *
 * So pairs live in a LINEAGE region: memory the monitor shares with a
 * vault's descendants rather than copying (`fork_share`, and
 * `finalize_pages` skips the slot - the comment there calls skipping it
 * "not an optimisation, the feature"). Its own region rather than the
 * filesystem's, because the LibOS sizes a whole filesystem to that one.
 *
 * A fixed pool rather than an allocator: the region is shared by processes
 * that cannot agree about a heap, and a bitmap over fixed slots is
 * something two of them can race on safely with one atomic.
 *
 * 1024 pairs, which is more than the LibOS lets one process hold ends of
 * (its default RLIMIT_NOFILE, 900), so a single process meets the limit it
 * would on Linux - EMFILE - before this one. The arena is the LINEAGE's,
 * though: several members holding hundreds each can still exhaust it, and
 * that is logged (pair_new). It was 32 for the whole lineage, and a
 * pipe a program never closed is held for as long as its process lives: a
 * vault that left one end open per invocation (pipe-fork-test.py's parent
 * never closes `r`) had its subprocess.run fail with ENOMEM at invocation
 * 30 - three pairs short - and its own pipe() at 33, on every LibOS.
 *
 * The size costs nothing until it is used. The monitor RESERVES a lineage
 * region and commits a page, zeroed, the first time a member touches it
 * (`lineage_commit`), and a pair is taken lowest-first, so what a lineage
 * pays for is its high-water mark of pairs held at once - about 8 KiB each.
 * Which is also why nothing here clears the pairs: a memset of all of them
 * would commit 8 MiB to say what fresh pages already say.
 */
#define PIPE_ARENA_PAIRS 1024
#define PIPE_ARENA_MAGIC 0x45504950534D564DULL   /* "MVMSPIPE" */

/*
 * Where two processes find each other by NAME.
 *
 * A pipe pair being shared is not enough to connect across a fork: the
 * rendezvous is by name, and `g_pending` below is this process's own memory,
 * so a connect in one process registers a name the listener in another
 * cannot see. That is what stops the LibOS's IPC worker from working - it
 * listens on `pipe:<vmid>` and waits for a peer that can never arrive - and
 * it is nothing to do with the commented-out `RUN_INIT(init_ipc_worker)`.
 *
 * So the table lives with the pairs, in the region the monitor shares with a
 * vault's descendants. A LINEAGE is the boundary, which is the right one and
 * is the same one its filesystem already has: these are one tenant's
 * processes, and a name is only visible to a process that holds the region.
 *
 * `state` is the whole protocol: a listener claims a slot and says
 * LISTENING; a connector finds that name, takes a pair, and posts a second
 * slot saying PENDING; the listener's accept takes it and frees it.
 */
#define PIPE_RDV_NAME   96      /* the LibOS's PIPE_URI_SIZE */
#define PIPE_RDV_SLOTS  16

/* A listener that asked to be reachable across processes but had no arena to
 * say so in. It is not an error and it is the NORMAL case for the IPC worker:
 * `libos_init` runs in the ZYGOTE, and the monitor gives a zygote no lineage
 * region - one zygote's region would be inherited by every vault made from it.
 * So the listener remembers that it wants publishing and the first poll in the
 * trustlet does it. Without this the leader's listener was never published, a
 * child's connect fell back to the process-local table, and the child talked
 * to its own inherited copy of its parent's listener - answering its own
 * questions out of its own copied tables. */
#define PIPE_RDV_WANTED (-2)

#define RDV_FREE      0u
#define RDV_LISTENING 1u
#define RDV_PENDING   2u

struct pipe_rdv {
    uint32_t state;
    uint32_t pair_idx;              /* which arena pair, when PENDING */
    char     name[PIPE_RDV_NAME];
};

/* The rendezvous table FIRST: it is scanned on every cross-process connect
 * and every poll of a published listener, and in front of the pairs it shares
 * the first pages with the header instead of sitting past the last pair. */
struct pipe_arena {
    uint64_t magic;
    uint32_t pairs;
    uint32_t rdvs;
    struct pipe_rdv rdv[PIPE_RDV_SLOTS];
    struct pal_svsm_pipe_pair pair[PIPE_ARENA_PAIRS];
};

static struct pipe_arena* g_arena;

/* Set from [svsm.pipes] in the measured manifest (pal_main.c). */
bool g_pal_svsm_pipes_shared;

/* Every pipe handle this process holds, so a forked child can tell the pairs
 * it inherited that they have another holder. The LIST is process-local and
 * copied by the fork, which is what makes it the right list: it is exactly
 * the set of handles the child now has. */
/* Ends, so twice the arena's pairs: a process may hold both ends of every
 * pair it can get. */
#define PIPE_LIVE_MAX (2 * PIPE_ARENA_PAIRS)
static PAL_HANDLE g_live[PIPE_LIVE_MAX];

/* Defined below, beside the arena it asks about. */
static bool from_arena(const struct pal_svsm_pipe_pair* p);

/*
 * Registering a handle can FAIL, and it must not fail quietly.
 *
 * A handle that is not in this list is one `pal_svsm_pipes_fork_hold` will
 * not count, so the child never takes its holder reference: the parent's
 * close and the child's close then drive the pair's holder count to zero
 * while a live handle still points at it, the arena slot is marked free, the
 * next pipe claims it and memsets the rings - and the first reader gets
 * somebody else's bytes with no end-of-file. That is what it did: an
 * invocation read 40 bytes of a foreign structure where fourteen bytes of
 * its child's message should have been.
 *
 * So the overflow is reported, and `pair_new` refuses the ARENA for a handle
 * it could not register - a private heap pair does not survive a fork, which
 * is wrong in the old way rather than corrupting.
 */
static bool live_add(PAL_HANDLE h) {
    /* Only a pair in the ARENA. `pal_svsm_pipes_fork_hold` skips every other
     * kind, so a heap pair in here is an entry that can never be used - and
     * it is not harmless: the LibOS's own pipes are heap pairs and they never
     * leave this list, because their only destructor is `pipe_destroy` behind
     * PalObjectDestroy, which was a no-op when this was written. Registering
     * them filled the table and then the refusal below failed THREAD
     * CREATION, which is what one pollable event per thread means. */
    if (!h->pipe.pair || !from_arena(h->pipe.pair))
        return true;
    for (size_t i = 0; i < PIPE_LIVE_MAX; i++)
        if (!g_live[i]) { g_live[i] = h; return true; }
    log_error("pipe: %d live SHARED pipe handles is the limit and all are "
              "taken; this pipe cannot be shared with a fork", PIPE_LIVE_MAX);
    return false;
}

static void live_del(PAL_HANDLE h) {
    for (size_t i = 0; i < PIPE_LIVE_MAX; i++)
        if (g_live[i] == h) { g_live[i] = NULL; return; }
}

static struct pipe_arena* arena(void) {
    if (g_arena)
        return g_arena;
    /* Not declared, so not provided. A vault whose manifest is silent gets
     * the pipes it always had - private to the process that made them - and
     * pays nothing: no region, no memory reachable by its children, and not
     * even a monitor call to find out. */
    if (!g_pal_svsm_pipes_shared)
        return NULL;
    void* base = NULL;
    size_t size = 0;
    uint64_t pages = (sizeof(struct pipe_arena) + 4095) / 4096;
    pal_svsm_lineage_fs(pages, PAL_SVSM_LINEAGE_PIPES, &base, &size);
    if (!base || size < sizeof(struct pipe_arena))
        return NULL;
    struct pipe_arena* a = base;
    /* One writer wins the initialisation; everyone else finds it done. A
     * child never initialises - it inherits a region its parent already
     * filled in - but two siblings opening their first pipe at once could
     * both arrive here. */
    uint64_t empty = 0;
    if (__atomic_compare_exchange_n(&a->magic, &empty, PIPE_ARENA_MAGIC, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* The pairs are NOT cleared: the region's pages are zero when they
         * are committed, and clearing would commit all of them (see
         * PIPE_ARENA_PAIRS). The table is one page and is cleared anyway. */
        memset(a->rdv, 0, sizeof(a->rdv));
        a->pairs = PIPE_ARENA_PAIRS;
        a->rdvs  = PIPE_RDV_SLOTS;
        __atomic_thread_fence(__ATOMIC_RELEASE);
    } else if (__atomic_load_n(&a->magic, __ATOMIC_ACQUIRE) != PIPE_ARENA_MAGIC) {
        return NULL;
    }
    g_arena = a;
    return a;
}

struct pipe_pending {
    char* name;
    struct pal_svsm_pipe_pair* pair;
};
static struct pipe_pending g_pending[PIPE_PENDING_MAX];

/*
 * The shared table's five operations. Each claims its slot with one CAS on
 * `state`, so two processes racing for the last slot cannot both win; the
 * name is written after the claim and read only by a scan that has already
 * seen a non-FREE state, which the acquire/release pair orders.
 */
static int rdv_claim(struct pipe_arena* a, const char* name, uint32_t want,
                     uint32_t pair_idx) {
    if (strlen(name) >= PIPE_RDV_NAME)
        return -1;
    for (uint32_t i = 0; i < a->rdvs && i < PIPE_RDV_SLOTS; i++) {
        uint32_t free_ = RDV_FREE;
        if (!__atomic_compare_exchange_n(&a->rdv[i].state, &free_, want, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        a->rdv[i].pair_idx = pair_idx;
        memset(a->rdv[i].name, 0, PIPE_RDV_NAME);
        memcpy(a->rdv[i].name, name, strlen(name));
        /* The name must be visible before anyone acts on the state they can
         * already see, so publish it with a release store of the state. */
        __atomic_store_n(&a->rdv[i].state, want, __ATOMIC_RELEASE);
        return (int)i;
    }
    return -1;
}

static void rdv_free(struct pipe_arena* a, int idx) {
    if (idx < 0 || idx >= PIPE_RDV_SLOTS)
        return;
    a->rdv[idx].name[0] = '\0';
    __atomic_store_n(&a->rdv[idx].state, RDV_FREE, __ATOMIC_RELEASE);
}

/* Is anybody in this lineage listening on `name`? */
static bool rdv_listening(struct pipe_arena* a, const char* name) {
    for (uint32_t i = 0; i < a->rdvs && i < PIPE_RDV_SLOTS; i++) {
        if (__atomic_load_n(&a->rdv[i].state, __ATOMIC_ACQUIRE) != RDV_LISTENING)
            continue;
        if (!strncmp(a->rdv[i].name, name, PIPE_RDV_NAME))
            return true;
    }
    return false;
}

/* A connection posted for `name` and not yet accepted. */
static bool rdv_pending(struct pipe_arena* a, const char* name) {
    for (uint32_t i = 0; i < a->rdvs && i < PIPE_RDV_SLOTS; i++) {
        if (__atomic_load_n(&a->rdv[i].state, __ATOMIC_ACQUIRE) != RDV_PENDING)
            continue;
        if (!strncmp(a->rdv[i].name, name, PIPE_RDV_NAME))
            return true;
    }
    return false;
}

/* Publish a listener that has been waiting for the arena to exist. Cheap and
 * idempotent: once published it is a single compare. */
static void rdv_publish_if_wanted(PAL_HANDLE h) {
    if (h->pipe.rdv != PIPE_RDV_WANTED || !h->pipe.name)
        return;
    struct pipe_arena* a = arena();
    if (!a)
        return;                 /* still too early; the next poll tries again */
    int idx = rdv_claim(a, h->pipe.name, RDV_LISTENING, 0);
    if (idx >= 0)
        h->pipe.rdv = idx;
}

/* Take one, if there is one: returns the pair or NULL. */
static struct pal_svsm_pipe_pair* rdv_take(struct pipe_arena* a, const char* name) {
    for (uint32_t i = 0; i < a->rdvs && i < PIPE_RDV_SLOTS; i++) {
        if (__atomic_load_n(&a->rdv[i].state, __ATOMIC_ACQUIRE) != RDV_PENDING)
            continue;
        if (strncmp(a->rdv[i].name, name, PIPE_RDV_NAME))
            continue;
        uint32_t idx = a->rdv[i].pair_idx;
        if (idx >= PIPE_ARENA_PAIRS)
            continue;               /* a posting this build cannot interpret */
        /* Claim it: whoever flips PENDING -> FREE owns the pair. Two threads
         * accepting the same listener must not both get it. */
        uint32_t pend = RDV_PENDING;
        if (!__atomic_compare_exchange_n(&a->rdv[i].state, &pend, RDV_FREE, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        return &a->pair[idx];
    }
    return NULL;
}

/* The arena IF IT ALREADY EXISTS. `arena()` creates the lineage region as a
 * side effect, which is right when something has asked for a shared pipe and
 * wrong for a question - and asking was costing every vault a region and a
 * monitor call for pipes that are entirely its own. */
static struct pipe_arena* arena_existing(void) {
    return g_arena;
}

/* Is this pair one of the arena's, or an ordinary heap one? Asked by
 * address rather than by a flag in the pair, because the answer has to be
 * right even for a pair this process did not allocate. */
static bool from_arena(const struct pal_svsm_pipe_pair* p) {
    return g_arena && p >= &g_arena->pair[0] && p < &g_arena->pair[PIPE_ARENA_PAIRS];
}

/* Asked from outside, by poll: can ANOTHER PROCESS change what this handle
 * would report? If so the poll has to bound its wait and look again, because
 * `pal_svsm_poll_wake` only reaches threads in this process.
 *
 * Two kinds qualify. A connected PIPE whose pair is in the arena - another
 * process may write it. And a published PIPESRV - another process may post a
 * connection for it into the shared rendezvous, which is exactly how the IPC
 * worker is reached; without this its accept slept through every arrival and
 * a child's exit notification was sent to a parent that never read it. */
bool pal_svsm_pipe_is_shared(PAL_HANDLE handle) {
    if (handle->hdr.type == PAL_TYPE_PIPESRV)
        return handle->pipe.rdv >= 0;
    return handle->hdr.type == PAL_TYPE_PIPE && handle->pipe.pair
           && from_arena(handle->pipe.pair);
}

/* `shareable` is PAL_OPTION_INHERITABLE from the caller: only a pipe that a
 * forked child may inherit belongs in the arena. The LibOS's own pipes - one
 * pollable event PER THREAD, plus the async and IPC workers - do not ask, and
 * that is the whole reason the arena does not fill up: none of them is an fd,
 * so `detach_all_fds` never closes them, and PalObjectDestroy (their only
 * other destructor) was a no-op when the arena was built. Every fork added a
 * holder to each of them for ever. That stub is fixed, so they are released
 * now - and they still do not belong here: the arena is the lineage's, every
 * process in it draws on the same pairs, and a per-thread wakeup object never
 * crosses a fork. */
static struct pal_svsm_pipe_pair* pair_new(bool shareable) {
    struct pipe_arena* a = shareable ? arena() : NULL;
    if (!a) {
        /* No arena, and that is ordinary rather than an error. Either this
         * pipe is not one a child can inherit (see `shareable` above), or the
         * manifest did not ask for shared pipes, or it did and this is too
         * early: the LibOS
         * builds its pollable events out of a pipe pair during init, and
         * init runs in the ZYGOTE - which the monitor will not give a
         * lineage region to, because a zygote's region would be inherited
         * by every vault made from it and they would all share one set of
         * pipes.
         *
         * So those early pipes stay on the heap, exactly as they were. They
         * are the ones that never cross a fork: what crosses is the pipes a
         * program opens for a child, and by then the process is a trustlet
         * and the arena is there. A heap pair in a forked child is the old
         * behaviour - a private copy - which is wrong but no more wrong
         * than it was, and is confined to pipes nobody forks. */
        struct pal_svsm_pipe_pair* p = calloc(1, sizeof(*p));
        if (!p)
            return NULL;
        p->holders[0] = 1;
        p->holders[1] = 1;
        p->refs = 2;
        p->in_use = 1;
        return p;
    }
    /* Both bounds: `pairs` is in the region every member can write, and a
     * value past the array would be writes past the region. */
    for (uint32_t i = 0; i < a->pairs && i < PIPE_ARENA_PAIRS; i++) {
        int free_ = 0;
        if (!__atomic_compare_exchange_n(&a->pair[i].in_use, &free_, 1, false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        struct pal_svsm_pipe_pair* p = &a->pair[i];
        memset(&p->dir, 0, sizeof(p->dir));
        p->holders[0] = 1;
        /* Side 1 does not exist until somebody accepts; until then side 0
         * must not see EOF, only "nothing yet". */
        p->holders[1] = 1;
        __atomic_store_n(&p->refs, 2, __ATOMIC_RELEASE);
        return p;
    }
    /* Said, once a process: this used to be a bare ENOMEM, which the LibOS
     * reports as "pipe connection failure" and Python as "Cannot allocate
     * memory" - neither of which says what ran out. */
    static bool said;
    if (!__atomic_exchange_n(&said, true, __ATOMIC_RELAXED))
        log_error("pipe: all %u shared pipe pairs of this lineage are held - a pipe a "
                  "child can inherit is refused (ENOMEM) until one is closed",
                  PIPE_ARENA_PAIRS);
    return NULL;
}

/* Give up one hold on `side`. The pair returns to the arena only when both
 * ends have none, which with a fork in the picture can be a process other
 * than the one that made it - and it is the release that takes `refs` to 0
 * that returns it, so exactly one does. The side's own count goes first:
 * by the time the pair can be reused, nobody still has a decrement of it to
 * make. */
static void pair_release(struct pal_svsm_pipe_pair* p, unsigned side) {
    if (!p)
        return;
    __atomic_sub_fetch(&p->holders[side], 1, __ATOMIC_ACQ_REL);
    if (__atomic_sub_fetch(&p->refs, 1, __ATOMIC_ACQ_REL) > 0)
        return;
    if (from_arena(p))
        __atomic_store_n(&p->in_use, 0, __ATOMIC_RELEASE);
    else
        free(p);
}

/* A fork is about to give the child a copy of every handle in `g_live`. The
 * pairs are SHARED, so each of them gains a holder - and gains it NOW, in the
 * parent, before the copy (`delta` +1), or back again if the fork failed
 * (`delta` -1).
 *
 * It used to be the CHILD that counted, once it first ran. The parent does
 * not wait for that: it returns from the fork and closes its copies at once
 * - subprocess closes the child's ends of all three pipes before it reads one
 * - and a close that found the count at 1 took it to 0. A reader then saw
 * end-of-file before its child had run at all, and the child's output went
 * into a ring nobody read: `subprocess.run` returned rc 0 with stdout '',
 * about once in a hundred runs. A parent that closed BOTH ends in that window
 * freed the pair outright, and the child's late increment landed on a pair
 * the next pipe() could claim and clear.
 *
 * Called from _PalProcessFork after the lock drain and with nothing between
 * it and the monitor call that could yield - PAL text is never preempted - so
 * the list counted is exactly the list the child gets. */
void pal_svsm_pipes_fork_hold(int delta) {
    for (size_t i = 0; i < PIPE_LIVE_MAX; i++) {
        PAL_HANDLE h = g_live[i];
        if (!h || !h->pipe.pair || h->pipe.released)
            continue;
        /* Only the shared ones. A heap pair in the child is a private copy
         * - counting a holder on it would say something true about a pair
         * the parent cannot see. */
        if (!from_arena(h->pipe.pair))
            continue;
        __atomic_add_fetch(&h->pipe.pair->holders[h->pipe.side], delta, __ATOMIC_ACQ_REL);
        __atomic_add_fetch(&h->pipe.pair->refs, delta, __ATOMIC_ACQ_REL);
    }
}

/* In the child, right after the fork: forget the connections pending in the
 * copied `g_pending`, WITHOUT releasing them.
 *
 * Every pipe(2) passes through it - create_pipes connects (an arena pair,
 * parked here) and then accepts it - and only that connecting thread ever
 * consumes the entry, by accepting it or closing its listener. A fork from
 * another thread can land in between; that thread does not exist in the
 * child, so the child's copy would never be consumed. Its hold was not
 * counted for the child (`pal_svsm_pipes_fork_hold` counts handles), so it is
 * dropped as it is: releasing it would give back the parent's, and counting
 * it would leave a hold nobody gives back. */
void pal_svsm_pipes_child_after_fork(void) {
    /* The names are not freed either: nothing at fork return should depend
     * on an allocator, and it is at most PIPE_PENDING_MAX short strings. */
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        g_pending[i].name = NULL;
        g_pending[i].pair = NULL;
    }
}

static size_t ring_write(struct pal_svsm_pipe_ring* r, const char* buf, size_t len) {
    size_t space = PIPE_RING_SIZE - r->used;
    if (len > space)
        len = space;
    for (size_t i = 0; i < len; i++)
        r->data[(r->head + r->used + i) % PIPE_RING_SIZE] = buf[i];
    r->used += len;
    return len;
}

static size_t ring_read(struct pal_svsm_pipe_ring* r, char* buf, size_t len) {
    if (len > r->used)
        len = r->used;
    for (size_t i = 0; i < len; i++)
        buf[i] = r->data[(r->head + i) % PIPE_RING_SIZE];
    r->head = (r->head + len) % PIPE_RING_SIZE;
    r->used -= len;
    return len;
}

/* The ring this handle reads from, and the one it writes to. */
static struct pal_svsm_pipe_ring* in_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[1 - h->pipe.side];
}
static struct pal_svsm_pipe_ring* out_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[h->pipe.side];
}

size_t pal_svsm_pipe_readable(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return 0;
    return in_ring(handle)->used;
}

bool pal_svsm_pipe_writable(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return false;
    return out_ring(handle)->used < PIPE_RING_SIZE;
}

bool pal_svsm_pipe_peer_gone(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return true;
    return __atomic_load_n(&handle->pipe.pair->holders[1 - handle->pipe.side],
                           __ATOMIC_ACQUIRE) <= 0;
}

bool pal_svsm_pipesrv_pending(PAL_HANDLE handle) {
    if (!handle->pipe.name)
        return false;
    rdv_publish_if_wanted(handle);
    if (handle->pipe.rdv >= 0) {
        struct pipe_arena* a = arena();
        return a && rdv_pending(a, handle->pipe.name);
    }
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++)
        if (g_pending[i].name && !strcmp(g_pending[i].name, handle->pipe.name))
            return true;
    return false;
}

static int pipe_listen(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(hdl, PAL_TYPE_PIPESRV);
    hdl->pipe.name = strdup(name);
    if (!hdl->pipe.name) {
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    hdl->pipe.rdv = -1;
    /* A listener that asks to be INHERITABLE is one whose peer may be another
     * process, so its name goes in the shared table where that peer can find
     * it. One that does not ask stays entirely local - which is every
     * pollable event, and is why 16 shared slots is plenty. */
    if (options & PAL_OPTION_INHERITABLE) {
        hdl->pipe.rdv = PIPE_RDV_WANTED;
        rdv_publish_if_wanted(hdl);     /* a no-op in a zygote; retried later */
    }
    *handle = hdl;
    return 0;
}

static int pipe_connect(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    /* Is the listener in THIS process or another one? The shared table
     * answers, and the answer decides both where the pair lives and where the
     * connection is posted: a cross-process peer can read neither this
     * process's heap nor its `g_pending`. Asked FIRST, because the local
     * pending table below is not a resource a cross-process connect needs. */
    struct pipe_arena* a = arena_existing();
    if (a && rdv_listening(a, name)) {
        PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
        if (!hdl)
            return -PAL_ERROR_NOMEM;
        hdl->pipe.rdv = -1;
        struct pal_svsm_pipe_pair* pair = pair_new(/*shareable=*/true);
        if (!pair) {
            free(hdl);
            return -PAL_ERROR_NOMEM;
        }
        uint32_t idx = (uint32_t)(pair - &a->pair[0]);
        if (rdv_claim(a, name, RDV_PENDING, idx) < 0) {
            log_error("pipe: no shared rendezvous slot to connect to '%s'", name);
            pair_release(pair, 1);   /* the pending hold the accept would take */
            pair_release(pair, 0);
            free(hdl);
            return -PAL_ERROR_NOMEM;
        }
        init_handle_hdr(hdl, PAL_TYPE_PIPE);
        hdl->pipe.pair        = pair;
        hdl->pipe.side        = 0;
        hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
        if (!live_add(hdl)) {
            free(hdl);
            return -PAL_ERROR_NOMEM;
        }
        *handle = hdl;
        return 0;
    }

    /* The process-local path, unchanged: both ends are made here, so the
     * rendezvous can be a pointer in this process's own table. */
    size_t slot = PIPE_PENDING_MAX;
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        if (!g_pending[i].name) {
            slot = i;
            break;
        }
    }
    if (slot == PIPE_PENDING_MAX)
        return -PAL_ERROR_NOMEM;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl)
        return -PAL_ERROR_NOMEM;
    hdl->pipe.rdv = -1;

    struct pal_svsm_pipe_pair* pair = pair_new(!!(options & PAL_OPTION_INHERITABLE));
    char* copy = strdup(name);
    if (!pair || !copy) {
        free(copy);
        pair_release(pair, 0);
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_PIPE);
    hdl->pipe.pair        = pair;
    hdl->pipe.side        = 0;
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    /* Refuse rather than hold an end nothing can account for across a fork:
     * an unregistered handle is one the child will not count, and that ends
     * in a pair released while it is still held. ENOMEM is what a program
     * with too many pipes open should see. */
    if (!live_add(hdl)) {
        free(copy);
        pair_release(pair, 0);
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }

    g_pending[slot].name = copy;
    g_pending[slot].pair = pair;
    /* The pending entry holds side 1 until somebody accepts it: pair_new
       already counted the hold that becomes the accepted handle's. */

    *handle = hdl;
    return 0;
}

static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                     pal_share_flags_t share, enum pal_create_mode create,
                     pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);

    if (!strcmp(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, uri, options);

    if (!strcmp(type, URI_TYPE_PIPE))
        return pipe_connect(handle, uri, options);

    return -PAL_ERROR_INVAL;
}

static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client,
                              pal_stream_options_t options) {
    if (handle->hdr.type != PAL_TYPE_PIPESRV || !handle->pipe.name)
        return -PAL_ERROR_BADHANDLE;

    /* A cross-process listener is served from the shared table. Checked
     * first, and only for a listener that published itself there, so a
     * process-local pipe never pays for the scan. */
    /* The poll is what gives a zygote-born listener its first chance to be
     * published: by here the process is a trustlet and the arena exists. */
    rdv_publish_if_wanted(handle);
    if (handle->pipe.rdv >= 0) {
        struct pipe_arena* a = arena();
        /* TRYAGAIN when nothing has arrived, and deliberately NOT a wait.
         *
         * Blocking here looks right - `PalStreamWaitForClient` with no options
         * is supposed to wait for a client - and it wedges the IPC worker,
         * which is the only caller: that one thread both accepts connections
         * and reads every message on every connection, so a wait inside accept
         * stops it answering anything. It waited for a client that was not
         * coming while the reply its own process was blocked on sat unread.
         *
         * The worker polls before it accepts, so TRYAGAIN means only that the
         * poll was stale by a few microseconds, and the loop comes back. */
        struct pal_svsm_pipe_pair* pair = a ? rdv_take(a, handle->pipe.name) : NULL;
        if (!pair)
            return -PAL_ERROR_TRYAGAIN;
        PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
        if (!hdl) {
            /* Give it back rather than drop it: the connector is waiting and
             * its pair would otherwise be held by nobody. */
            pair_release(pair, 1);
            return -PAL_ERROR_NOMEM;
        }
        init_handle_hdr(hdl, PAL_TYPE_PIPE);
        hdl->pipe.pair        = pair;   /* takes the pending hold on side 1 */
        hdl->pipe.side        = 1;
        hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
        hdl->pipe.rdv         = -1;
        if (!live_add(hdl)) {
            free(hdl);
            pair_release(pair, 1);
            return -PAL_ERROR_NOMEM;
        }
        *client = hdl;
        return 0;
    }

    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        if (!g_pending[i].name || strcmp(g_pending[i].name, handle->pipe.name))
            continue;

        PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
        if (!hdl)
            return -PAL_ERROR_NOMEM;
        init_handle_hdr(hdl, PAL_TYPE_PIPE);
        hdl->pipe.pair        = g_pending[i].pair;   /* takes the pending hold */
        hdl->pipe.side        = 1;
        hdl->pipe.rdv         = -1;   /* calloc gives 0, which reads as slot 0 */
        hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
        /* Same as the connect side: an end this process cannot register is
         * an end a fork would lose track of. The pending hold stays where it
         * is, so the listener still owns it and a later accept can succeed. */
        if (!live_add(hdl)) {
            free(hdl);
            return -PAL_ERROR_NOMEM;
        }

        free(g_pending[i].name);
        g_pending[i].name = NULL;
        g_pending[i].pair = NULL;

        *client = hdl;
        return 0;
    }

    /* Nobody has connected. There is no other thread of execution that could
     * connect while we sit here unless it is one of ours, and blocking for a
     * connection that never comes would be a deadlock, so say so instead. */
    return -PAL_ERROR_TRYAGAIN;
}

/*
 * How long a blocking wait on a SHARED pipe may sleep before looking again.
 *
 * `pal_svsm_poll_wake` walks THIS process's thread list, so it reaches a
 * reader parked in this process and nobody else. That is the whole truth
 * about a pipe until the pair is shared; after a fork the writer is another
 * process, its wake never arrives, and a reader that waited with no deadline
 * waited for ever. The PAL said so itself - "deadlock: every thread is
 * blocked and nothing can wake them" - as soon as `subprocess` ran ffmpeg
 * and read its output with an ordinary blocking read.
 *
 * The indefinite wait is not simply wrong, it is unreachable here: an
 * un-deadlined block parks on words the MONITOR watches, and parking needs a
 * service slot, which an ordinary vault does not have. So a shared pipe
 * polls. 200 us is below the cost of the fork and exec that put the peer
 * there, and a reader that has nothing to do is costing its own invoke's
 * time and no one else's.
 */

/* NULL for a private pair - its only writer is in this process, so a wake is
 * certain and waiting for one is free. */
static const uint64_t* shared_poll_deadline(PAL_HANDLE handle, uint64_t* store) {
    if (!from_arena(handle->pipe.pair))
        return NULL;
    *store = pal_svsm_now_usec() + PAL_SVSM_SHARED_PIPE_POLL_US;
    return store;
}

static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE || !handle->pipe.pair)
        return -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    while (in_ring(handle)->used == 0) {
        if (pal_svsm_pipe_peer_gone(handle))
            return 0;   /* end of stream */
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        uint64_t dl;
        enum pal_svsm_wait_result wr =
            pal_svsm_poll_block(shared_poll_deadline(handle, &dl));
        if (wr == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
        /* A timeout is not an answer, it is permission to look again: the
         * loop re-tests the ring and the holder count. */
    }

    size_t n = ring_read(in_ring(handle), buffer, len);
    /* Space freed: a writer that filled the ring may now proceed. */
    pal_svsm_poll_wake();
    return (int64_t)n;
}

static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, uint64_t len, const void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE || !handle->pipe.pair)
        return -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    while (out_ring(handle)->used == PIPE_RING_SIZE) {
        if (pal_svsm_pipe_peer_gone(handle))
            return -PAL_ERROR_CONNFAILED;
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        uint64_t dl;
        enum pal_svsm_wait_result wr =
            pal_svsm_poll_block(shared_poll_deadline(handle, &dl));
        if (wr == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
        /* Same as the read side: a writer blocked on a full ring is waiting
         * for a reader that may be in another process. */
    }

    size_t n = ring_write(out_ring(handle), buffer, len);
    /* This is what makes a pollable event pollable: whoever is parked in
     * _PalStreamsWaitEvents has to be told there is something to see. */
    pal_svsm_poll_wake();
    return (int64_t)n;
}

static int pipe_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    memset(attr, 0, sizeof(*attr));
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->pipe.nonblocking;
    attr->pending_size = handle->hdr.type == PAL_TYPE_PIPE ? pal_svsm_pipe_readable(handle) : 0;
    return 0;
}

static int pipe_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    handle->pipe.nonblocking = attr->nonblocking;
    return 0;
}

/* One end let go, from whichever of the two paths got there first.
 *
 * `live_del` belongs HERE and not only in `pipe_destroy`, which is what it
 * used to be: for a long time `pipe_destroy` was reached only through
 * PalObjectDestroy, and that was `return; // ignore` in this tree, so nothing
 * ever took a closed handle out of the list. It filled with handles whose
 * pairs were long gone, new handles could not be registered, and a pair was
 * released while still held. The list has to shrink where the holder count
 * does, and `released` makes both callers idempotent. */
static void pipe_let_go(PAL_HANDLE handle) {
    live_del(handle);
    if (handle->pipe.pair && !handle->pipe.released) {
        handle->pipe.released = true;
        pair_release(handle->pipe.pair, handle->pipe.side);
    }
}

/* The LAST thing that happens to a pipe handle: after this the memory is
 * gone, so nothing may hold the pointer. `live_del` above is what makes that
 * true for the one list that does. */
static void pipe_destroy(PAL_HANDLE handle) {
    /* A published listener stops being reachable the moment it goes, or the
     * next connect to that name posts a pair nobody will ever accept. */
    if (handle->hdr.type == PAL_TYPE_PIPESRV && handle->pipe.rdv >= 0) {
        struct pipe_arena* a = arena();
        if (a)
            rdv_free(a, handle->pipe.rdv);
        handle->pipe.rdv = -1;
    }
    pipe_let_go(handle);
    if (handle->pipe.pair) {
        /* A reader parked on this end's peer has to see the close. */
        pal_svsm_poll_wake();
        handle->pipe.pair = NULL;
    }
    /* Only a listener has a name; the connected ends carry NULL. */
    free(handle->pipe.name);
    handle->pipe.name = NULL;
    free(handle);
}

static int pipe_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    __UNUSED(delete_mode);
    /* Closing the listener drops any connection nobody accepted; the
     * connecting end is still a valid handle, it just has no peer. */
    if (handle->hdr.type == PAL_TYPE_PIPESRV && handle->pipe.name) {
        for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
            if (g_pending[i].name && !strcmp(g_pending[i].name, handle->pipe.name)) {
                pair_release(g_pending[i].pair, 1);
                free(g_pending[i].name);
                g_pending[i].name = NULL;
                g_pending[i].pair = NULL;
            }
        }
        return 0;
    }
    pipe_let_go(handle);
    pal_svsm_poll_wake();
    return 0;
}

struct handle_ops g_pipe_ops = {
    .open           = &pipe_open,
    .waitforclient  = &pipe_waitforclient,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .destroy        = &pipe_destroy,
    .delete         = &pipe_delete,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};
