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
#include "pal_svsm_chan.h"
#include "pal_svsm_pipe_ring.h"

/* create_pollable_event connects and accepts back to back, so one is really
 * enough; the rest are slack for LibOS's own IPC pipes at startup. */
#define PIPE_PENDING_MAX 8

struct pal_svsm_pipe_pair {
    /* dir[s] is what side s wrote and side !s reads: a ring each, with a lock
     * per end, because an arena pair's ends can be held by processes running
     * at the same time on different processors (pal_svsm_pipe_ring.h). */
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
    /* shutdown(2) of one side, which keeps its holds: shut_wr[s] - side s
     * writes no more (its peer reads end-of-file once the ring is empty);
     * shut_rd[s] - side s reads no more (its peer's writes fail EPIPE). A
     * pipe never sets them; an AF_UNIX socket, which is a pipe here
     * (net/unix.c), does (pipe_delete). Per side, so every holder of that
     * side sees it - as a shutdown of a socket shared across fork is. */
    int    shut_wr[2];
    int    shut_rd[2];
    /* Held by more than one process: a fork counted a hold on it, or it was
     * made by a connect to another process's listener. Only then can a write
     * or a close come from outside this process, so only then do its waits
     * poll and look for dead holders (pal_svsm_pipe_is_shared). An arena pair
     * that never crossed - most AF_UNIX socketpairs, asyncio's self-pipe -
     * waits like a heap pair, for this process's own wake.
     *
     * Never cleared while the pair lives (only pair_new resets it): once a
     * process has forked, every pair it held then keeps the polled wait even
     * after the child has let go of it, because nothing tells the parent the
     * last foreign hold is gone short of a sweep - which is what the poll
     * costs to begin with. */
    int    crossed;
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
/* "MVMSPIP2". The layout's version as much as a marker: a process of a PAL
 * built before the ring had head/tail and per-end locks would read `tail` as
 * the old `used` and write without a lock, so an arena laid out by one is not
 * one the other may touch. Whoever finds the other's magic is told there is
 * no arena (arena()) and keeps its pipes private, as a vault that never
 * declared [svsm.pipes] does. It was "MVMSPIPE" (0x45504950534D564D). */
#define PIPE_ARENA_MAGIC 0x32504950534D564DULL

/* Grepped for in libpal.so by the UnixBench harness: the prefix "pipe: SPSC
 * ring" says a pipe across fork is the race-free ring above, so the harness
 * drops its caveat for the pipe tests. Logged once, by whoever lays out the
 * arena, which is also what keeps the string in the binary. */
static const char g_pipe_ring_marker[] = "pipe: SPSC ring (serial-tagged end locks)";

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

/*
 * WHO holds what: a ledger row per member of the lineage.
 *
 * `holders` says how many handles hold each end, which is all a reader needs
 * - until a holder dies without closing anything. A process the monitor
 * deletes or kills runs no exit path, so its holds were never given back: the
 * pair never freed, and a reader whose writer it was waited for an
 * end-of-file that could not come. A count cannot say whose holds to take
 * back; this can. Every member writes down, in its own row, what it holds -
 * per pair, per end - and a survivor that finds a row whose serial the
 * monitor no longer lists (the roster in the region header, which only the
 * monitor writes and which drops a member in `drop_mapper`) gives those
 * holds back for it (ledger_sweep).
 *
 * The serial and not the id: an id is a process-table slot and is reissued,
 * a serial never is. A forked child's row is filled by its PARENT before the
 * fork, from the same list the hold counts come from, and carries the
 * parent's serial until it is stamped with the child's - which both sides do
 * at once after the fork, the parent with the serial the monitor hands back.
 * So a row is never without a living owner it could be swept with.
 *
 * `tag` is the row's state and a generation, in one word, so that claiming,
 * stamping and sweeping are each one compare-and-swap, and a stamp meant for
 * one use of a row cannot land on the next.
 */
#define PIPE_LEDGER_ROWS 32

#define LEDGER_FREE     0u      /* nobody's */
#define LEDGER_CLAIMING 1u      /* being taken; `serial` not yet written */
#define LEDGER_FILLING  2u      /* filled for a child; `serial` is the forker's */
#define LEDGER_STAMPING 3u      /* `serial` changing to the child's */
#define LEDGER_LIVE     4u      /* `serial` holds what the row says */
#define LEDGER_SWEEPING 5u      /* its holds being given back */
#define LEDGER_TAG(gen, state) (((uint64_t)(gen) << 8) | (state))
#define LEDGER_STATE(tag)      ((uint32_t)((tag) & 0xff))
#define LEDGER_GEN(tag)        ((tag) >> 8)

struct pipe_ledger {
    uint64_t tag;
    uint64_t serial;
    uint16_t held[PIPE_ARENA_PAIRS][2];
};

/* The rendezvous table FIRST: it is scanned on every cross-process connect
 * and every poll of a published listener, and in front of the pairs it shares
 * the first pages with the header instead of sitting past the last pair. The
 * ledger is next: a row is committed when a member first takes one. */
struct pipe_arena {
    uint64_t magic;
    uint32_t pairs;
    uint32_t rdvs;
    struct pipe_rdv rdv[PIPE_RDV_SLOTS];
    uint32_t ledgers;
    uint32_t ledger_pad;
    struct pipe_ledger ledger[PIPE_LEDGER_ROWS];
    struct pal_svsm_pipe_pair pair[PIPE_ARENA_PAIRS];
};

/* The most a lineage region holds: the monitor's clamp in lineage_fs
 * (ipc/mod.rs), MAX_WINDOWS_PER_REGION (256) windows of IPC_WINDOW_SIZE
 * (2 MiB) less its header page. A bigger arena would be clamped to a region
 * arena() then refuses, and every pipe would quietly stop crossing a fork.
 * Mirrored by hand, like the status codes in pal_svsm.h: change the monitor
 * and change this. */
#define PIPE_REGION_MAX_BYTES (256UL * (2UL << 20) - 4096UL)
_Static_assert(sizeof(struct pipe_arena) <= PIPE_REGION_MAX_BYTES,
               "the pipe arena no longer fits a lineage region");

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
        a->pairs   = PIPE_ARENA_PAIRS;
        a->rdvs    = PIPE_RDV_SLOTS;
        a->ledgers = PIPE_LEDGER_ROWS;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        log_debug("%s", g_pipe_ring_marker);
    } else if (__atomic_load_n(&a->magic, __ATOMIC_ACQUIRE) != PIPE_ARENA_MAGIC) {
        return NULL;
    }
    g_arena = a;
    return a;
}

/* This process's ledger row; NULL until it first holds a shared pipe, and
 * for good if every row was taken (its holds are then counted but not
 * written down: a death of this process leaks them, as every death did). */
static struct pipe_ledger* g_ledger;
static bool g_ledger_full_said;
/* The row a fork in progress filled for its child, and which use of it. */
static struct pipe_ledger* g_fork_ledger;
static uint64_t g_fork_gen;

/* Read every time: a copy-on-write child has every byte of its parent's
 * memory, so a cached serial would be the parent's (_PalLineageSelf). */
static uint64_t self_serial(void) {
    return pal_chan_u64(PAL_CHAN_DIR_VADDR, PAL_CHAN_DIR_SERIAL);
}

/* The region header: one page in front of the arena, written only by the
 * monitor (page_is_writable_by refuses page 0 of a lineage region). */
static uintptr_t arena_header(void) {
    return (uintptr_t)g_arena - PAGE_SIZE;
}

static bool member_alive(uint64_t serial) {
    uintptr_t hdr = arena_header();
    for (unsigned i = 0; i < PAL_CHAN_MAX_MEMBERS; i++)
        if (pal_chan_u64(hdr, PAL_CHAN_HDR_MEMBERS + i * 8) == serial)
            return true;
    return false;
}

static bool ledger_sweep(void);
static struct pipe_ledger* ledger_claim_once(struct pipe_arena* a, uint64_t serial,
                                             uint32_t state, uint64_t* out_gen);

/* Take a free row for `serial`, ending in `state` (LIVE or FILLING). */
static struct pipe_ledger* ledger_claim(struct pipe_arena* a, uint64_t serial, uint32_t state,
                                        uint64_t* out_gen) {
    if (!serial)
        return NULL;
    /* Twice at most: the second time after giving back the rows of members
     * the monitor no longer lists. A row is otherwise freed only by a sweep,
     * and a sweep runs only when a reader is still waiting on a dead member
     * - so without this, ~32 children that ended cleanly (no reader ever
     * waiting) used up every row, and the next killed child leaked again. */
    for (int pass = 0; pass < 2; pass++) {
        struct pipe_ledger* r = ledger_claim_once(a, serial, state, out_gen);
        if (r)
            return r;
        if (!ledger_sweep())
            break;
    }
    if (!__atomic_exchange_n(&g_ledger_full_said, true, __ATOMIC_RELAXED))
        log_warning("pipe: all %u ledger rows of this lineage are taken - this process's "
                    "shared pipe holds are not recorded, and a kill of it leaks them",
                    PIPE_LEDGER_ROWS);
    return NULL;
}

static struct pipe_ledger* ledger_claim_once(struct pipe_arena* a, uint64_t serial,
                                             uint32_t state, uint64_t* out_gen) {
    for (uint32_t i = 0; i < a->ledgers && i < PIPE_LEDGER_ROWS; i++) {
        struct pipe_ledger* r = &a->ledger[i];
        uint64_t t = __atomic_load_n(&r->tag, __ATOMIC_ACQUIRE);
        if (LEDGER_STATE(t) != LEDGER_FREE)
            continue;
        uint64_t gen = LEDGER_GEN(t) + 1;
        if (!__atomic_compare_exchange_n(&r->tag, &t, LEDGER_TAG(gen, LEDGER_CLAIMING), false,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        /* A row goes back FREE only with its counts at zero (ledger_sweep,
         * pal_svsm_pipes_fork_failed), and a fresh page is zero. */
        __atomic_store_n(&r->serial, serial, __ATOMIC_RELEASE);
        __atomic_store_n(&r->tag, LEDGER_TAG(gen, state), __ATOMIC_RELEASE);
        if (out_gen)
            *out_gen = gen;
        return r;
    }
    return NULL;
}

/* This process's own row, taken the first time it is needed. */
static struct pipe_ledger* ledger_self(void) {
    if (!g_ledger && g_arena)
        g_ledger = ledger_claim(g_arena, self_serial(), LEDGER_LIVE, NULL);
    return g_ledger;
}

/* This process gained (+1) or gave up (-1) one hold on `side` of `p`. Every
 * change to `holders` that is this process's own goes through here, in the
 * same direction, so the row and the counts it explains agree. */
static void ledger_add(struct pal_svsm_pipe_pair* p, unsigned side, int delta) {
    if (!p || !from_arena(p))
        return;
    struct pipe_ledger* r = ledger_self();
    if (!r)
        return;
    uint16_t* c = &r->held[(size_t)(p - &g_arena->pair[0])][side];
    if (delta > 0) {
        __atomic_add_fetch(c, 1, __ATOMIC_ACQ_REL);
        return;
    }
    /* Never below zero: a hold this row never recorded - taken while every
     * row was in use, and closed after one came free - is not one to take
     * off it. Wrapped, it would read as 65535 holds to the sweep. */
    uint16_t v = __atomic_load_n(c, __ATOMIC_ACQUIRE);
    while (v && !__atomic_compare_exchange_n(c, &v, (uint16_t)(v - 1), false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        ;
    static bool said;
    if (!v && !__atomic_exchange_n(&said, true, __ATOMIC_RELAXED))
        log_warning("pipe: gave up a shared pipe hold this process's ledger row did not record "
                    "(said once)");
}

/* Give back `n` holds on `side` of `p` that were somebody else's. */
static void pair_put_n(struct pal_svsm_pipe_pair* p, unsigned side, int n) {
    int end = __atomic_sub_fetch(&p->holders[side], n, __ATOMIC_ACQ_REL);
    int left = __atomic_sub_fetch(&p->refs, n, __ATOMIC_ACQ_REL);
    if (left == 0)
        __atomic_store_n(&p->in_use, 0, __ATOMIC_RELEASE);
    static bool said;
    if ((left < 0 || end < 0) && !__atomic_exchange_n(&said, true, __ATOMIC_RELAXED))
        log_error("pipe: pair %ld given back below zero (end %d, pair %d) - said once",
                  (long)(p - &g_arena->pair[0]), end, left);
}

/*
 * Give back, for the members the monitor no longer lists, every hold their
 * rows say they had. Returns whether anything was given back.
 *
 * Every row, every time - and that is cheap: a free row is one load, and a
 * row in use is sixteen more, against a roster of at most sixteen. It used to
 * stop early when the roster matched the one this process had last swept
 * against, and that missed the case it exists for: a parent whose child was
 * forked AND deleted between two of its looks saw the same roster twice and
 * never looked at the rows. Each row is judged against a FRESH read of the
 * roster, made after the row's own: the monitor puts a child on the roster
 * during the fork, before its parent can stamp the child's serial anywhere,
 * so a row's serial read first cannot be newer than the roster read after it.
 *
 * Two survivors can come here for the same dead member at once (one in a
 * read, one in pair_new); the CAS to SWEEPING is the claim, and only its
 * winner gives anything back.
 */
static bool ledger_sweep(void) {
    struct pipe_arena* a = g_arena;
    if (!a)
        return false;
    bool any = false;
    for (uint32_t i = 0; i < a->ledgers && i < PIPE_LEDGER_ROWS; i++) {
        struct pipe_ledger* r = &a->ledger[i];
        uint64_t t = __atomic_load_n(&r->tag, __ATOMIC_ACQUIRE);
        /* Never used, so neither is any row after it: rows are taken
         * lowest-first, and a claim in progress has already moved this tag
         * off zero. Stopping here keeps a sweep off the pages of rows the
         * lineage never needed - each row is a page of its own. */
        if (t == 0)
            break;
        uint32_t st = LEDGER_STATE(t);
        if (st != LEDGER_LIVE && st != LEDGER_FILLING)
            continue;
        uint64_t serial = __atomic_load_n(&r->serial, __ATOMIC_ACQUIRE);
        if (!serial || member_alive(serial))
            continue;
        if (!__atomic_compare_exchange_n(&r->tag, &t, LEDGER_TAG(LEDGER_GEN(t), LEDGER_SWEEPING),
                                         false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        unsigned n = 0;
        for (uint32_t k = 0; k < a->pairs && k < PIPE_ARENA_PAIRS; k++) {
            for (unsigned side = 0; side < 2; side++) {
                uint16_t c = __atomic_exchange_n(&r->held[k][side], 0, __ATOMIC_ACQ_REL);
                if (c) {
                    pair_put_n(&a->pair[k], side, c);
                    n += c;
                }
            }
        }
        __atomic_store_n(&r->serial, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&r->tag, LEDGER_TAG(LEDGER_GEN(t), LEDGER_FREE), __ATOMIC_RELEASE);
        if (n)
            log_warning("pipe: gave back %u shared pipe hold(s) of member %lu, which the "
                        "monitor no longer lists", n, serial);
        any = true;
    }
    if (any)
        pal_svsm_poll_wake();   /* a reader here may now see its end-of-file */
    return any;
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

/* Has another process ever held this pair (see `crossed`)? */
static bool pair_crossed(const struct pal_svsm_pipe_pair* p) {
    return __atomic_load_n(&p->crossed, __ATOMIC_ACQUIRE) != 0;
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
           && from_arena(handle->pipe.pair) && pair_crossed(handle->pipe.pair);
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
        return p;   /* calloc: no side shut */
    }
    /* Twice at most: the second pass after giving back what dead members
     * held, which a full arena is the likeliest sign of. */
    for (int pass = 0; pass < 2; pass++) {
        /* Both bounds: `pairs` is in the region every member can write, and a
         * value past the array would be writes past the region. */
        for (uint32_t i = 0; i < a->pairs && i < PIPE_ARENA_PAIRS; i++) {
            int free_ = 0;
            if (!__atomic_compare_exchange_n(&a->pair[i].in_use, &free_, 1, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                continue;
            struct pal_svsm_pipe_pair* p = &a->pair[i];
            memset(&p->dir, 0, sizeof(p->dir));
            memset(p->shut_wr, 0, sizeof(p->shut_wr));
            memset(p->shut_rd, 0, sizeof(p->shut_rd));
            __atomic_store_n(&p->crossed, 0, __ATOMIC_RELEASE);
            p->holders[0] = 1;
            /* Side 1 does not exist until somebody accepts; until then side 0
             * must not see EOF, only "nothing yet". */
            p->holders[1] = 1;
            __atomic_store_n(&p->refs, 2, __ATOMIC_RELEASE);
            /* Both are this process's until it says otherwise
             * (pipe_connect hands side 1 to the rendezvous). */
            ledger_add(p, 0, +1);
            ledger_add(p, 1, +1);
            return p;
        }
        if (!ledger_sweep())
            break;
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
static void pair_put(struct pal_svsm_pipe_pair* p, unsigned side) {
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

/* One of THIS process's holds: out of its ledger row first, then out of the
 * count. pair_put alone is for a hold that was nobody's row's - the one a
 * cross-process connect leaves with the rendezvous. */
static void pair_release(struct pal_svsm_pipe_pair* p, unsigned side) {
    ledger_add(p, side, -1);
    pair_put(p, side);
}

/* A fork is about to give the child a copy of every handle in `g_live`. The
 * pairs are SHARED, so each of them gains a holder - and gains it NOW, in the
 * parent, before the copy, and loses it again if the fork failed
 * (pal_svsm_pipes_fork_failed).
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
 * The same walk fills the child's LEDGER row: what it counts is exactly what
 * the child will hold, and the row is how those holds come back if the child
 * is killed. It carries this process's serial until the fork returns and the
 * child's is stamped on it (pal_svsm_pipes_fork_parent and _child_after_fork,
 * whichever runs first), so a sweep never finds it without a living owner.
 *
 * Called from _PalProcessFork after the lock drain and with nothing between
 * it and the monitor call that could yield - PAL text is never preempted - so
 * the list counted is exactly the list the child gets. */
static void fork_count(int delta) {
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
        if (delta > 0)
            __atomic_store_n(&h->pipe.pair->crossed, 1, __ATOMIC_RELEASE);
        if (delta > 0 && g_fork_ledger) {
            size_t idx = (size_t)(h->pipe.pair - &g_arena->pair[0]);
            __atomic_add_fetch(&g_fork_ledger->held[idx][h->pipe.side], 1, __ATOMIC_ACQ_REL);
        }
    }
}

void pal_svsm_pipes_fork_prepare(void) {
    /* A row only for a child that will hold something: one that holds no
     * shared pipe has nothing to give back, and claiming anyway cost a row
     * per fork until something swept it. */
    bool any = false;
    for (size_t i = 0; i < PIPE_LIVE_MAX && !any; i++) {
        PAL_HANDLE h = g_live[i];
        any = h && h->pipe.pair && !h->pipe.released && from_arena(h->pipe.pair);
    }
    g_fork_ledger = any ? ledger_claim(g_arena, self_serial(), LEDGER_FILLING, &g_fork_gen)
                        : NULL;
    fork_count(+1);
}

/* There is no child to hold anything: the counts come back off, and the row
 * goes back free with its counts at zero. */
void pal_svsm_pipes_fork_failed(void) {
    fork_count(-1);
    struct pipe_ledger* r = g_fork_ledger;
    g_fork_ledger = NULL;
    if (!r)
        return;
    memset(r->held, 0, sizeof(r->held));
    __atomic_store_n(&r->serial, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&r->tag, LEDGER_TAG(g_fork_gen, LEDGER_FREE), __ATOMIC_RELEASE);
}

/* On a clean exit: this process's row back to free, if it holds nothing.
 *
 * The LibOS has closed every fd by now (detach_all_fds), so normally it does.
 * Left LIVE under a dead serial the row would wait for a sweep - which comes
 * only when somebody needs a row or waits on a pipe - and a lineage whose
 * workers end cleanly, one after another, would run out. A row with holds
 * left is left for a sweep, which gives them back too. */
void pal_svsm_pipes_exit(void) {
    struct pipe_ledger* r = g_ledger;
    if (!r)
        return;
    for (size_t k = 0; k < PIPE_ARENA_PAIRS; k++)
        if (__atomic_load_n(&r->held[k][0], __ATOMIC_ACQUIRE)
                || __atomic_load_n(&r->held[k][1], __ATOMIC_ACQUIRE))
            return;
    uint64_t t = __atomic_load_n(&r->tag, __ATOMIC_ACQUIRE);
    if (LEDGER_STATE(t) != LEDGER_LIVE || __atomic_load_n(&r->serial, __ATOMIC_ACQUIRE)
                                              != self_serial())
        return;
    /* SWEEPING first, as a sweep would: a sweeper that read the row before
     * this cannot also act on it. */
    if (!__atomic_compare_exchange_n(&r->tag, &t, LEDGER_TAG(LEDGER_GEN(t), LEDGER_SWEEPING),
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    __atomic_store_n(&r->serial, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&r->tag, LEDGER_TAG(LEDGER_GEN(t), LEDGER_FREE), __ATOMIC_RELEASE);
    g_ledger = NULL;
}

/* Put the child's serial on the row filled for it. Parent and child both do
 * it, the first one wins and the other finds it done; a stamp for a use of
 * the row that is over (the generation moved on) does nothing. Returns
 * whether the row is now `child_serial`'s. */
static bool ledger_stamp(struct pipe_ledger* r, uint64_t gen, uint64_t child_serial) {
    if (!r || !child_serial)
        return false;
    uint64_t t = LEDGER_TAG(gen, LEDGER_FILLING);
    if (__atomic_compare_exchange_n(&r->tag, &t, LEDGER_TAG(gen, LEDGER_STAMPING), false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&r->serial, child_serial, __ATOMIC_RELEASE);
        __atomic_store_n(&r->tag, LEDGER_TAG(gen, LEDGER_LIVE), __ATOMIC_RELEASE);
        return true;
    }
    /* The other side got there first. It stamps the same serial - parent and
     * child both stamp the child's - so a stamp in progress is as good as
     * done, and a sweep leaves a STAMPING row alone.
     *
     * The one way that is wrong: the stamper is torn down between its CAS and
     * its LIVE store - two stores of PAL text, which the monitor does not
     * preempt; a delete waits for the vault to leave it. The row would then
     * stay STAMPING, never swept, its holds kept until the lineage ends: a
     * leak, never a double release. */
    if (t == LEDGER_TAG(gen, LEDGER_STAMPING))
        return true;
    if (t == LEDGER_TAG(gen, LEDGER_LIVE))
        return __atomic_load_n(&r->serial, __ATOMIC_ACQUIRE) == child_serial;
    return false;                       /* swept, or reused: not this fork's any more */
}

void pal_svsm_pipes_fork_parent(uint64_t child_serial) {
    /* The fork just made pairs CROSS (fork_count), and a thread of ours may
     * be waiting on one with no deadline - right until now its only writer
     * was in this process. Woken, every waiter looks again and bounds its
     * wait from here on. */
    pal_svsm_poll_wake();
    /* A monitor older than the one that returns it hands back the FLAGS this
     * call passed in that register. A real child serial is always newer than
     * its parent's - serials are issued in order and the child was made
     * after - so anything else is left for the child, which stamps its own. */
    /* Only with a row to stamp: self_serial() reads the directory page,
     * which a process holding no region and no channel does not have. */
    if (g_fork_ledger && child_serial > self_serial())
        (void)ledger_stamp(g_fork_ledger, g_fork_gen, child_serial);
    g_fork_ledger = NULL;
}

/* In the child, right after the fork: its row is the one its parent filled,
 * and the pending connections in the copied `g_pending` are forgotten,
 * WITHOUT releasing them.
 *
 * Every pipe(2) passes through `g_pending` - create_pipes connects (an arena
 * pair, parked here) and then accepts it - and only that connecting thread
 * ever consumes the entry, by accepting it or closing its listener. A fork
 * from another thread can land in between; that thread does not exist in the
 * child, so the child's copy would never be consumed. Its hold was not
 * counted for the child (fork_count counts handles), so it is dropped as it
 * is: releasing it would give back the parent's, and counting it would leave
 * a hold nobody gives back.
 *
 * A row that is not the child's to stamp - every row was taken, or its holds
 * were already given back because its parent died before either could stamp
 * it - leaves the child with handles whose holds are not its to release: they
 * are marked released, so its closes give back nothing a second time. */
void pal_svsm_pipes_child_after_fork(uint64_t from_fork) {
    /* The serial from this process's own directory, as every other user of
     * one reads it; the one the fork call handed back only if that is not
     * there. A monitor that left the register 0 would otherwise make every
     * stamp fail - and the loop below cut every inherited pipe. */
    struct pipe_ledger* r = g_fork_ledger;
    /* Only with a row: a child of a parent that held no region (no shared
     * pipes, no channel) has no directory page to read - the monitor gives
     * it one only for a parent that held something (fork_share). */
    uint64_t self = r ? (self_serial() ?: from_fork) : 0;
    /* The names are not freed either: nothing at fork return should depend
     * on an allocator, and it is at most PIPE_PENDING_MAX short strings. */
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        g_pending[i].name = NULL;
        g_pending[i].pair = NULL;
    }
    for (size_t i = 0; i < PIPE_LIVE_MAX; i++)
        if (g_live[i])
            g_live[i]->pipe.inherited = true;
    bool mine = ledger_stamp(r, g_fork_gen, self);
    g_fork_ledger = NULL;
    /* The parent's row is not this process's to write in, whatever happens. */
    g_ledger = mine ? r : NULL;
    if (r && !mine) {
        /* Detached, not only marked: the pairs may already be free and taken
         * by somebody's next pipe(), and a handle that still pointed at one
         * would read and write a stranger's. A detached end reads end-of-file
         * and fails writes, as the end of a pipe nobody holds would. */
        for (size_t i = 0; i < PIPE_LIVE_MAX; i++) {
            PAL_HANDLE h = g_live[i];
            if (h && h->pipe.pair && from_arena(h->pipe.pair)) {
                h->pipe.released = true;
                h->pipe.pair = NULL;
                g_live[i] = NULL;
            }
        }
        log_warning("pipe: this child's shared pipe holds were given back before it ran");
    }
}

/* The roster answers whether a lock's holder can still let go of it
 * (pal_pipe_lock). */
static bool ring_holder_alive(uint64_t serial, void* arg) {
    __UNUSED(arg);
    return member_alive(serial);
}

/*
 * Take the lock of one end of `h`'s pair - `&ring->wlock` to write,
 * `&ring->rlock` to read - and say whether it was got. `*out_self` is what to
 * give back to ring_unlock.
 *
 * Only an ARENA pair has anyone to share an end with. A heap pair is this
 * process's alone, its threads take turns on one processor, and none of them
 * leaves PAL text inside a copy (nothing between the lock and the unlock
 * blocks), so it is not locked - and it could not be by serial anyway: a
 * process that holds no region may have no directory to read one from.
 *
 * A pair this process never shared is locked all the same: it costs one
 * uncontended CAS, and asking whether it is shared yet would be a race with
 * the fork that shares it.
 */
static bool ring_lock(PAL_HANDLE h, uint64_t* lock, uint64_t* out_self) {
    *out_self = 0;
    if (!from_arena(h->pipe.pair))
        return true;
    uint64_t self = self_serial();
    uint64_t from = 0;
    enum pal_pipe_lock_result r = pal_pipe_lock(lock, self, ring_holder_alive, NULL, &from);
    if (r == PAL_PIPE_LOCK_BUSY)
        return false;
    if (r == PAL_PIPE_LOCK_STOLEN)
        log_warning("pipe: took over pair %ld's %s lock from member %lu, which the monitor "
                    "no longer lists", (long)(h->pipe.pair - &g_arena->pair[0]),
                    lock == &h->pipe.pair->dir[h->pipe.side].wlock ? "write" : "read", from);
    *out_self = self;
    return true;
}

static void ring_unlock(PAL_HANDLE h, uint64_t* lock, uint64_t self) {
    if (!from_arena(h->pipe.pair))
        return;
    /* Taken over while this process was inside a copy: the monitor dropped
     * a process that was running, which the steal rests on never happening.
     * Said, because the stream may now be wrong and nothing else would. */
    if (!pal_pipe_unlock(lock, self))
        log_error("pipe: pair %ld's lock was taken over from this process while it held it",
                  (long)(h->pipe.pair - &g_arena->pair[0]));
}

/* The ring this handle reads from, and the one it writes to. */
static struct pal_svsm_pipe_ring* in_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[1 - h->pipe.side];
}
static struct pal_svsm_pipe_ring* out_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[h->pipe.side];
}

size_t pal_svsm_pipe_readable(PAL_HANDLE handle) {
    /* Released is as good as detached: the pair may be someone else's now. */
    if (!handle->pipe.pair || handle->pipe.released)
        return 0;
    return pal_pipe_ring_used(in_ring(handle));
}

static bool pipe_write_refused(PAL_HANDLE handle, bool sweep);

bool pal_svsm_pipe_writable(PAL_HANDLE handle) {
    /* A detached end (pal_svsm_pipes_child_after_fork) is "writable" so that
     * a writer that polls first gets to its write and its EPIPE, instead of
     * polling for ever. */
    if (!handle->pipe.pair || handle->pipe.released)
        return handle->pipe.released;
    /* Likewise an end whose write would be refused (no reader, or shut). */
    return pal_pipe_ring_room(out_ring(handle)) || pipe_write_refused(handle, false);
}

/* The far end has no holder left - or, on a shared pipe, has none once the
 * holds of members that died without closing are given back. Readers and
 * writers that wait re-ask this every PAL_SVSM_SHARED_PIPE_POLL_US, and the
 * sweep costs a load per free ledger row when nobody has died. */
bool pal_svsm_pipe_peer_gone(PAL_HANDLE handle) {
    struct pal_svsm_pipe_pair* p = handle->pipe.pair;
    if (!p || handle->pipe.released)
        return true;
    unsigned far_side = 1 - handle->pipe.side;
    /* The far side said it writes no more (shutdown SHUT_WR), or this side
     * said it reads no more: end-of-file once the ring is empty. */
    if (__atomic_load_n(&p->shut_wr[far_side], __ATOMIC_ACQUIRE)
            || __atomic_load_n(&p->shut_rd[handle->pipe.side], __ATOMIC_ACQUIRE))
        return true;
    int* far = &p->holders[far_side];
    if (__atomic_load_n(far, __ATOMIC_ACQUIRE) <= 0)
        return true;
    if (!from_arena(p) || !pair_crossed(p) || !ledger_sweep())
        return false;
    return __atomic_load_n(far, __ATOMIC_ACQUIRE) <= 0;
}

/* Nobody holds the other end (poll's hang-up), or this end can neither read
 * nor write any more. No sweep: a poll asks this every time.
 *
 * The second is Linux's unix_poll, which says EPOLLHUP once a socket's
 * shutdown mask is full - its own shutdowns together with the mirror of its
 * peer's (a peer's SHUT_WR is this end's SHUT_RD, and the other way round).
 * A shutdown of one direction alone is not a hang-up. A pipe never sets the
 * flags, so for a pipe this is holders only. */
bool pal_svsm_pipe_hung_up(PAL_HANDLE handle) {
    struct pal_svsm_pipe_pair* p = handle->pipe.pair;
    if (!p || handle->pipe.released)
        return true;
    unsigned side = handle->pipe.side, far_side = 1 - side;
    bool rd_done = __atomic_load_n(&p->shut_rd[side], __ATOMIC_ACQUIRE)
                   || __atomic_load_n(&p->shut_wr[far_side], __ATOMIC_ACQUIRE);
    bool wr_done = __atomic_load_n(&p->shut_wr[side], __ATOMIC_ACQUIRE)
                   || __atomic_load_n(&p->shut_rd[far_side], __ATOMIC_ACQUIRE);
    if (rd_done && wr_done)
        return true;
    return __atomic_load_n(&p->holders[far_side], __ATOMIC_ACQUIRE) <= 0;
}

/* Would a write to this end fail with EPIPE? No reader: the far side has no
 * holder, or shut its reading (SHUT_RD), or this side shut its writing
 * (SHUT_WR). `sweep`: also give back dead members' holds first - for a
 * writer that is about to WAIT, not on the write's hot path. */
static bool pipe_write_refused(PAL_HANDLE handle, bool sweep) {
    struct pal_svsm_pipe_pair* p = handle->pipe.pair;
    unsigned far_side = 1 - handle->pipe.side;
    if (__atomic_load_n(&p->shut_rd[far_side], __ATOMIC_ACQUIRE)
            || __atomic_load_n(&p->shut_wr[handle->pipe.side], __ATOMIC_ACQUIRE))
        return true;
    int* far = &p->holders[far_side];
    if (__atomic_load_n(far, __ATOMIC_ACQUIRE) <= 0)
        return true;
    if (!sweep || !from_arena(p) || !pair_crossed(p) || !ledger_sweep())
        return false;
    return __atomic_load_n(far, __ATOMIC_ACQUIRE) <= 0;
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
        /* Its other end is in another process (the listener's). */
        __atomic_store_n(&pair->crossed, 1, __ATOMIC_RELEASE);
        if (rdv_claim(a, name, RDV_PENDING, idx) < 0) {
            log_error("pipe: no shared rendezvous slot to connect to '%s'", name);
            pair_release(pair, 1);   /* the pending hold the accept would take */
            pair_release(pair, 0);
            free(hdl);
            return -PAL_ERROR_NOMEM;
        }
        /* The pending hold on side 1 is the rendezvous's now: whoever
         * accepts takes it into their own row, and a death of this process
         * must not give it back from under them. */
        ledger_add(pair, 1, -1);
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
             * its pair would otherwise be held by nobody. It was never in this
             * process's row. */
            pair_put(pair, 1);
            return -PAL_ERROR_NOMEM;
        }
        ledger_add(pair, 1, +1);        /* the rendezvous's hold is ours now */
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
    if (!from_arena(handle->pipe.pair) || !pair_crossed(handle->pipe.pair))
        return NULL;
    *store = pal_svsm_now_usec() + PAL_SVSM_SHARED_PIPE_POLL_US;
    return store;
}

/*
 * Wait for `r` to move: for bytes when `reading`, for room otherwise. Counted
 * in the ring's waiters for that direction, and the ring tested AGAIN after
 * the count is up (pal_pipe_wait_begin) - so a writer in another process that
 * publishes and then looks at the count either is seen here or sees this
 * waiter. Nothing looks yet; the cross-process wake that will is a monitor
 * call this PAL does not make yet, and until it does a shared pair's wait is
 * bounded by shared_poll_deadline.
 *
 * `busy`: the end's lock was held by a member that is still listed. That is a
 * wait for a holder, possibly in another process, so it is bounded whatever
 * the pair - a private one included, where it can only mean the holder was
 * this process and something is badly wrong.
 */
static enum pal_svsm_wait_result ring_wait(PAL_HANDLE handle, struct pal_svsm_pipe_ring* r,
                                           bool reading, bool busy) {
    uint64_t dl;
    const uint64_t* dlp = shared_poll_deadline(handle, &dl);
    if (busy && !dlp) {
        dl  = pal_svsm_now_usec() + PAL_SVSM_SHARED_PIPE_POLL_US;
        dlp = &dl;
    }
    uint32_t* waiters = reading ? &r->rwait : &r->wwait;
    pal_pipe_wait_begin(waiters);
    bool ready = reading ? pal_pipe_ring_used(r) != 0 : pal_pipe_ring_room(r) != 0;
    enum pal_svsm_wait_result wr = PAL_SVSM_WAIT_WOKEN;
    if (busy || !ready)
        wr = pal_svsm_poll_block(dlp);
    pal_pipe_wait_end(waiters);
    return wr;
}

static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE)
        return -PAL_ERROR_BADHANDLE;
    if (!handle->pipe.pair || handle->pipe.released)   /* detached, or let go */
        return handle->pipe.released ? 0 : -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    struct pal_svsm_pipe_ring* r = in_ring(handle);
    while (1) {
        bool busy = false;
        if (pal_pipe_ring_used(r)) {
            uint64_t self;
            if (ring_lock(handle, &r->rlock, &self)) {
                size_t n = pal_pipe_ring_read(r, buffer, len);
                ring_unlock(handle, &r->rlock, self);
                if (n) {
                    /* Space freed: a writer that filled the ring may now
                     * proceed. */
                    pal_svsm_poll_wake();
                    return (int64_t)n;
                }
                /* Another reader of this end - a process that holds it too -
                 * took them first. Nothing to read after all. */
            } else {
                busy = true;
            }
        } else if (pal_svsm_pipe_peer_gone(handle)) {
            /* End of stream only if the ring is STILL empty. A writer
             * publishes its last bytes before its close gives up its hold, so
             * once the count says gone a second look sees everything it
             * wrote - and the first look, taken before the count, may have
             * been before the last write. */
            if (!pal_pipe_ring_used(r))
                return 0;
            continue;
        }
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        if (ring_wait(handle, r, /*reading=*/true, busy) == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
        /* A timeout is not an answer, it is permission to look again: the
         * loop re-tests the ring and the holder count. */
    }
}

static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, uint64_t len, const void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE)
        return -PAL_ERROR_BADHANDLE;
    if (!handle->pipe.pair || handle->pipe.released)   /* detached, or let go */
        return handle->pipe.released ? -PAL_ERROR_CONNFAILED_PIPE : -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    /* A reader gone is EPIPE now, as on Linux - not only once the ring has
     * filled (the loop below). No sweep here: a write is the hot path, and
     * the ledger sweep belongs to a writer that has to WAIT. A far side that
     * only shut its WRITING (SHUT_WR) still reads - an AF_UNIX client that
     * shuts down and waits for the reply, which the first version of this
     * check refused with EPIPE. */
    if (pipe_write_refused(handle, /*sweep=*/false))
        return -PAL_ERROR_CONNFAILED_PIPE;
    struct pal_svsm_pipe_ring* r = out_ring(handle);
    while (1) {
        bool busy = false;
        if (pal_pipe_ring_room(r)) {
            uint64_t self;
            if (ring_lock(handle, &r->wlock, &self)) {
                size_t n = pal_pipe_ring_write(r, buffer, len);
                ring_unlock(handle, &r->wlock, self);
                if (n) {
                    /* This is what makes a pollable event pollable: whoever
                     * is parked in _PalStreamsWaitEvents has to be told there
                     * is something to see. */
                    pal_svsm_poll_wake();
                    return (int64_t)n;
                }
                /* Another writer of this end filled it first. */
            } else {
                busy = true;
            }
        }
        if (pipe_write_refused(handle, /*sweep=*/true))
            return -PAL_ERROR_CONNFAILED_PIPE;   /* EPIPE, and the LibOS sends SIGPIPE */
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        /* Same as the read side: a writer blocked on a full ring is waiting
         * for a reader that may be in another process. */
        if (ring_wait(handle, r, /*reading=*/false, busy) == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
    }
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
    /* shutdown(2) of ONE direction keeps this end's hold - the pair is still
     * this side's, and the other direction still works. It used to drop the
     * whole hold whatever the mode: a client that shut its writing and
     * waited for the reply had let go of its READ end too, so the server's
     * reply over a ring's worth failed EPIPE, and the server's close could
     * free the pair under the client's handle. */
    struct pal_svsm_pipe_pair* p = handle->pipe.pair;
    if (p && !handle->pipe.released
            && (delete_mode == PAL_DELETE_WRITE || delete_mode == PAL_DELETE_READ)) {
        int* flag = delete_mode == PAL_DELETE_WRITE ? &p->shut_wr[handle->pipe.side]
                                                    : &p->shut_rd[handle->pipe.side];
        __atomic_store_n(flag, 1, __ATOMIC_RELEASE);
        pal_svsm_poll_wake();
        return 0;
    }
    pipe_let_go(handle);
    pal_svsm_poll_wake();
    return 0;
}

/*
 * At execve: give back the share of every shared pipe end this process holds
 * that the LibOS no longer lists.
 *
 * What it catches is a forked child's copy of a handle that no fd of the child
 * names: an end another thread of the parent was in the middle of creating
 * (pipe(2) between its connect and the fds being installed), or one that only
 * that thread still had a reference to. That thread does not run in the child
 * (pal_svsm_threads_child_after_fork), so nothing would ever close the copy -
 * and the child's hold counted, so a reader in the parent waited for an
 * end-of-file for as long as whatever the child exec'd ran. On Linux the
 * child would have the fd, and O_CLOEXEC would close it here; this is that.
 *
 * Only handles this process INHERITED: one it made itself after the fork -
 * an IPC connection of its own, say - is whatever the LibOS uses it for, fd
 * or not. Shares only: the handles stay allocated, because whatever still
 * points at one is in an old image nobody runs, and freeing under it gains
 * nothing.
 */
int _PalStreamsKeepOnly(PAL_HANDLE* keep, size_t count) {
    unsigned n = 0;
    for (size_t i = 0; i < PIPE_LIVE_MAX; i++) {
        PAL_HANDLE h = g_live[i];
        if (!h || !h->pipe.pair || h->pipe.released || !h->pipe.inherited
                || !from_arena(h->pipe.pair))
            continue;
        bool kept = false;
        for (size_t k = 0; k < count && !kept; k++)
            kept = keep[k] == h;
        if (kept)
            continue;
        pipe_let_go(h);
        n++;
    }
    if (n) {
        log_warning("execve: let go of %u shared pipe end(s) that no fd names", n);
        pal_svsm_poll_wake();
    }
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
