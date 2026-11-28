/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Threads inside a vault.
 *
 * A vault is one CPL3 process with one VMSA. The monitor runs that VMSA on
 * one vCPU and refuses a second entrant to it - "two vCPUs inside one VMSA is
 * undefined behavior" (process_runtime/invoke.rs) - so there is exactly one
 * thread of execution here and no amount of PAL code can make a second one.
 * Before this file, that meant `pthread_create` failed: _PalThreadCreate
 * returned NOTIMPLEMENTED, so anything that wanted a thread did not run at
 * all, including LibOS's own async and IPC workers.
 *
 * What this gives instead is several contexts sharing that one thread of
 * execution, switched at the points where a thread would otherwise have
 * blocked or spun. That is enough for everything whose threads are *waiting*
 * rather than computing: a futex under contention, a worker parked on a
 * queue, time.sleep, and CPython in general, whose GIL means its threads
 * never run at once anyway. It is not parallelism, and it will not become
 * parallelism: two threads never execute simultaneously, so a compute-bound
 * thread starves its siblings until it calls something that yields. A vault
 * has interrupts disabled and an IDT with three vectors, so there is no timer
 * to preempt it with. Real parallelism is a monitor project - a VMSA per
 * thread, a scheduler in place of the invoke loop, a second vCPU - and is
 * deliberately not attempted here.
 *
 * Mechanically this is the classic arrangement: a ring of contexts, a saved
 * stack pointer per parked context, and a switch stub (arch/x86_64/pal_switch.S)
 * that moves callee-saved registers and the GS base between two stacks. No
 * locking, because with one thread of execution there is nothing to race
 * with - a spinlock here can only ever be uncontended, and a lock held across
 * a yield would be a deadlock no lock could fix.
 */

#include "api.h"
#include "assert.h"
#include "cpu.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_rtld.h"
#include "pal_svsm.h"
#include "pal_svsm_chan.h"
#include "pal_svsm_wake.h"   /* O1-WAKE.md policy; pw_wake_ready is included again below */

/* Same shape as the Linux PAL's: 64 KiB is enough for LibOS and PAL frames,
 * and an application thread runs on the stack its clone() named, not this
 * one. */
#define SVSM_THREAD_STACK_SIZE (64 * 1024)

/* The stack a fault is delivered on, per thread. It cannot be the stack the
 * fault interrupted: the LibOS answers a memory-fault upcall by writing the
 * application's signal frame below the interrupted rsp, over anything the
 * PAL had put there. See the note in pal_svsm.h. 32 KiB carries the PAL
 * entry, the LibOS upcall and the signal delivery under it. */
#define SVSM_ALT_STACK_SIZE (32 * 1024)

/* How long the idle loop spins between monitor calls. Interrupts are off in a
 * vault, so a spin produces no exits at all: without these the monitor could
 * not take the core back on its 10 ms slice, its invoke watchdog could not
 * fire and the host ring would not be served for the whole of a sleep. Often
 * enough to keep all three alive, rare enough not to turn a one-second sleep
 * into a million monitor calls. */
#define SVSM_IDLE_SLICE_US 100
/* Pauses between looks at the watched handles inside that slice: what a
 * blocking socket call spun between looks at its ring when it waited by
 * itself (PAL_SOCK_SPINS), so a wait the scheduler now does for it sees its
 * data as soon as it did then. */
#define SVSM_IDLE_TEST_PAUSES 200

/* void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base) */
void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base);

static void refresh_preempt_wanted(void);

static PAL_HANDLE g_current = NULL;  /* the running context; NULL until init */
static size_t g_thread_cnt = 0;

/* A thread cannot free the stack it is standing on, so it leaves it here and
 * whoever runs next does it. Only ever one deep: the handover happens inside
 * the switch that follows. */
static void* g_stack_to_reap = NULL;

/*
 * The exiting thread's `clear_child_tid`, cleared by whoever runs NEXT.
 *
 * LibOS's `cleanup_thread` spins on this word and then calls `put_thread`,
 * which destroys the PAL handle. So the store IS the handover, and it used to
 * happen at the top of `_PalThreadExit` - before `state = ZOMBIE`, before
 * `ring_remove(self)`, before reading `self->thread.stack`, and before
 * `pick_next()` walks the ring. Every one of those touches the handle after
 * LibOS has been told it may free it.
 *
 * That was harmless for as long as PalObjectDestroy was `return; // ignore`,
 * because then nothing freed anything. It is not harmless now: a preemption
 * in that window lets the async worker run, free the handle, and leave the
 * exiting context walking its own freed memory - an intermittent hang in a
 * second threads run on a warm vault, which is how it showed up.
 *
 * `g_dead_rsp` above exists for exactly this reason one step later ("Its
 * handle may be destroyed by LibOS the moment we are off it, so we do not
 * write into that"). This is the same rule applied to the handover itself:
 * the thread has exited when the PAL has stopped touching it, not when it has
 * decided to.
 */
static int* g_tid_to_clear = NULL;

/* Somewhere for the switch stub to write the outgoing stack pointer of a
 * context that is never coming back. Its handle may be destroyed by LibOS the
 * moment we are off it, so we do not write into that. */
static void* g_dead_rsp = NULL;

static inline PAL_HANDLE current_thread(void) {
    return pal_get_svsm_tcb()->handle;
}

#define PAL_SVSM_STACKS_DEFERRED 16
static void* g_stacks_deferred[PAL_SVSM_STACKS_DEFERRED];
static int   g_stacks_deferred_n;

/*
 * Thread reuse (MicroVault notes/libos/THREAD-REUSE.md, D; owner 2026-11-23).
 *
 * A thread's block (alt stack + stack + TCB, _PalThreadCreate) is bigger than
 * the slab's top class, so every malloc of one was a VirtAlloc and every free
 * a VirtFree: ~84 us of monitor calls per thread, and the DSB C++ handlers
 * start three threads per request (std::async). An exited thread's block now
 * goes here, up to [svsm] thread_cache of them, and the next create takes it.
 *
 * What may be reused: only blocks this process's own threads released. The
 * list is this process's memory; a fork child inherits a copy and the LibOS
 * empties it in the child (thread_cache_after_cow_fork -> PalThreadCacheTrim).
 * A zygote's list is in every clone, as all of the zygote's memory is; a clone
 * then reuses what the zygote's threads released, which it holds anyway, and
 * never anything of a sibling's.
 *
 * Scrubbed on reuse: _PalThreadCreate zeroes the whole block it takes, cached
 * or new, as it always did, so a reused block reads exactly as a fresh one.
 * In a debug vault a block is poisoned on the way in, and the way out counts
 * whether the poison was there and whether any of it survived the zeroing -
 * which is what the lane's thread_kit_scrubbed row reads.
 *
 * No lock: like g_stacks_deferred, this is PAL thread code, which is never
 * preempted, on the process's one scheduler. Pushing needs no bookkeeping
 * upcall, so it is safe inside an upcall too, where a free is not.
 */
#define SVSM_THREAD_BLOCK_SIZE (SVSM_ALT_STACK_SIZE + SVSM_THREAD_STACK_SIZE + sizeof(PAL_SVSM_TCB))
#define SVSM_THREAD_CACHE_POISON 0xA5
static void*    g_tc[PAL_SVSM_THREAD_CACHE_MAX];
static int      g_tc_n;
static int      g_tc_cap = PAL_SVSM_THREAD_CACHE_DEFAULT;
static bool     g_tc_poison;
static uint64_t g_tc_stat[PAL_THREAD_CACHE_NSTATS];

void pal_svsm_thread_cache_init(int cap, bool poison) {
    if (cap < 0)
        cap = 0;
    if (cap > PAL_SVSM_THREAD_CACHE_MAX)
        cap = PAL_SVSM_THREAD_CACHE_MAX;
    g_tc_cap    = cap;
    g_tc_poison = poison;
}

static bool thread_cache_push(void* block) {
    if (g_tc_n >= g_tc_cap) {
        g_tc_stat[PAL_THREAD_CACHE_FULL]++;
        return false;
    }
    if (g_tc_poison)
        memset(block, SVSM_THREAD_CACHE_POISON, SVSM_THREAD_BLOCK_SIZE);
    g_tc[g_tc_n++] = block;
    return true;
}

static char* thread_cache_pop(void) {
    if (!g_tc_n) {
        g_tc_stat[PAL_THREAD_CACHE_MISSES]++;
        return NULL;
    }
    char* block = g_tc[--g_tc_n];
    g_tc[g_tc_n] = NULL;
    g_tc_stat[PAL_THREAD_CACHE_HITS]++;
    if (g_tc_poison && (uint8_t)block[0] == SVSM_THREAD_CACHE_POISON
            && (uint8_t)block[SVSM_THREAD_BLOCK_SIZE - 1] == SVSM_THREAD_CACHE_POISON)
        g_tc_stat[PAL_THREAD_CACHE_POISON_SEEN]++;
    return block;
}

/* After the scrub: any byte that is not zero is residue (debug vaults only;
 * the scan is a read of the block, ~100 KiB). */
static void thread_cache_check_scrub(const char* block) {
    if (!g_tc_poison)
        return;
    const uint64_t* w = (const uint64_t*)block;
    for (size_t i = 0; i < SVSM_THREAD_BLOCK_SIZE / 8; i++) {
        if (w[i]) {
            g_tc_stat[PAL_THREAD_CACHE_RESIDUE]++;
            return;
        }
    }
    for (size_t i = SVSM_THREAD_BLOCK_SIZE & ~7ul; i < SVSM_THREAD_BLOCK_SIZE; i++) {
        if (block[i]) {
            g_tc_stat[PAL_THREAD_CACHE_RESIDUE]++;
            return;
        }
    }
}

void _PalThreadCacheTrim(void) {
    /* A free is the LibOS's VMA bookkeeping (see reap_stack): never from an
     * upcall. The next ordinary trim gets them. */
    PAL_HANDLE cur = g_current ? current_thread() : NULL;
    if (cur && cur->thread.in_upcall)
        return;
    while (g_tc_n) {
        void* block = g_tc[--g_tc_n];
        g_tc[g_tc_n] = NULL;
        free(block);
        g_tc_stat[PAL_THREAD_CACHE_TRIMMED]++;
    }
}

void _PalThreadCacheStats(uint64_t out[PAL_THREAD_CACHE_NSTATS]) {
    for (int i = 0; i < PAL_THREAD_CACHE_NSTATS; i++)
        out[i] = g_tc_stat[i];
    out[PAL_THREAD_CACHE_CAP]    = (uint64_t)g_tc_cap;
    out[PAL_THREAD_CACHE_CACHED] = (uint64_t)g_tc_n;
}

static void reap_stack(void) {
    /* The handover first, and unconditionally: a thread with no stack of its
     * own to free still has a LibOS waiter to release. */
    int* tid = g_tid_to_clear;
    if (tid) {
        g_tid_to_clear = NULL;
        __atomic_store_n(tid, 0, __ATOMIC_RELEASE);
    }
    /* A stack is a large allocation, and freeing it is the LibOS's VMA
     * bookkeeping (pal_memory.c bkeep upcalls) - which a thread inside a
     * preemption upcall may have been interrupted in, holding its lock, so
     * it would spin on itself (review by jamie). Such a thread only queues
     * the stack; the next reap from ordinary context frees it. */
    void* stack = g_stack_to_reap;
    g_stack_to_reap = NULL;
    /* Kept for the next create when there is room (thread reuse, above);
     * pushing is safe here even inside an upcall. */
    if (stack && thread_cache_push(stack))
        stack = NULL;
    if (current_thread()->thread.in_upcall) {
        if (stack) {
            if (g_stacks_deferred_n < PAL_SVSM_STACKS_DEFERRED)
                g_stacks_deferred[g_stacks_deferred_n++] = stack;
            /* else: leaked, not freed in the wrong place - a 1-in-never
             * pile-up of more exits than slots, all inside upcalls. */
        }
        return;
    }
    if (stack)
        free(stack);
    while (g_stacks_deferred_n)
        free(g_stacks_deferred[--g_stacks_deferred_n]);
}

/* How long a park waits when nobody asked for a deadline: insurance, not
 * a wait anybody requested. A missed wake then costs a late dispatch
 * instead of a vault that never runs again - the same trade the
 * scheduler's own device watch makes. The shorter one is for a park that
 * could not arm everything it wanted to. */
#define SVSM_PARK_FALLBACK_US  1000000UL
#define SVSM_PARK_PARTIAL_US     20000UL

/* Is any blocked thread's watched handle ready? Read-only in the sense
 * pal_svsm_poller_ready is: ring loads, no switch. */
static bool any_watch_ready(void) {
    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.n_watch
                && pal_svsm_poller_ready(t))
            return true;
        t = t->thread.next;
    } while (t != g_current);
    return false;
}

/*
 * The words that would make any blocked thread runnable, gathered for a
 * Park or a Sleep - so at most PAL_SVSM_PARK_ARMS, and only the kinds those
 * take (pal_chan_arm_parkable).
 *
 * The PAL's scheduler is the thing that actually gives the processor
 * back, but the thread that knows WHY it is waiting is the one that
 * blocked. So a blocking thread leaves its arms on its own handle and
 * this collects them. A thread that had more waitable channels than it
 * could arm sets `arms_partial`, and so does an overflow here, and so does
 * an arm left out for its kind, because all three mean the same thing
 * downstream: a wake may be missed, so the park needs a bounded fallback.
 */
/* `lineage`: for a LineageWait (the run-set idle, fork fix 3), which also
 * takes a lineage word (LWORD) and a child arm - a fork-shared pipe's ring
 * word is one (pal_pipes.c ring_wait). A Park or a Sleep takes neither. */
static bool arm_lineage_kind(uint64_t arm) {
    unsigned which = (unsigned)(arm >> 28) & 0xF;
    return which == PAL_SVSM_LW_ARM_CHILD || which == PAL_SVSM_LW_ARM_LWORD_PIPES
           || which == PAL_SVSM_LW_ARM_LWORD_FS;
}

/* The O(1) wake (O1-WAKE.md) is OFF by default (owner 2026-11-28): the media knee probes put O1's knee at
 * 580 against the old scheduler's 640 (nginx parks ~35% more per request under it). `[svsm] o1_wake = true`
 * opts in. The two mux-credit routings it brought (a67a819d, 864f12ef) are correctness fixes and are NOT
 * behind this switch - they stay on for every vault. */
bool g_pal_svsm_o1_wake = false;
/* C (notify-covered parks) is OFF by default (owner 2026-11-27): with it the DSB
 * smokes showed stalls of 0.3-1 s in 3 of 7 R200 reps and none without it, and
 * with A a partial park costs one ready-only re-test per 20 ms - little left for
 * C to save. svsm.o1_cover = true turns it on (O1-WAKE.md, the open question). */
bool g_pal_svsm_o1_cover = false;
uint64_t g_pal_svsm_poll_scan_us = PW_SCAN_INTERVAL_US_DEFAULT;
uint64_t g_pal_svsm_o1_audit_us = 0;
uint64_t g_pal_svsm_park_linger_us = 0;
/* The poll token (see pal_svsm_poll_block): defined here because pick_next's
 * missed-test audit compares against it. */
static const char g_poll_token_storage;
#define POLL_TOKEN ((PAL_HANDLE)(void*)&g_poll_token_storage)

/* Step 3 of the O1 stall hunt (2026-11-28; the bd profile, DIAGNOSIS ONLY): when a thread became
 * runnable, so the switch that runs it can say how long it waited for the vCPU (PROF_ROW_RQ(b): [1 us << b,
 * 1 us << (b+1)), b 15 = 32.8 ms and over), and how long a WATCHLESS block - an event, mutex or condvar,
 * anything not on the poll token - took to be woken (PROF_ROW_WL(b): [64 us << b, 64 us << (b+1)), b 15 =
 * 2 s and over; PROF_ROW_WL_DEADLINE those that ended on their deadline). Rows: pal_svsm_prof_rows.h. */
#ifdef PROF_ROW_GATHER
#define PROF_RUNNABLE(t) do { if (__builtin_expect(g_pal_svsm_prof_on, 0)) (t)->thread.prof_runnable_us = pal_svsm_now_usec(); } while (0)
static inline unsigned prof_log2_bucket(uint64_t v, uint64_t base) {
    unsigned b = 0;
    while (b < 15 && v >= (base << (b + 1)))
        b++;
    return b;
}
#else
#define PROF_RUNNABLE(t) do { } while (0)
#endif
static uint64_t g_last_o1_audit_us;

/* `skip_covered`: for a PARK only (O1-WAKE.md C) - a Notify ends a Park, so a
 * thread whose every wait is notified needs no arm there. The Sleep fallback and
 * the lineage wait keep every arm: that a Notify ends them is not relied on. */
static size_t gather_arms_for(uint64_t* arms, size_t max, bool* partial, bool lineage,
                              bool skip_covered) {
    size_t n = 0;
    *partial = false;
    PAL_HANDLE t = g_current;
    do {
        if (skip_covered && t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.notify_covered) {
            t = t->thread.next;
            continue;
        }
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED) {
            if (t->thread.arms_partial)
                *partial = true;
            for (unsigned i = 0; i < t->thread.n_arms; i++) {
                if (!pal_chan_arm_parkable(t->thread.arms[i])
                        && !(lineage && arm_lineage_kind(t->thread.arms[i]))) {
                    *partial = true;
                    continue;
                }
                if (n == max) {
                    *partial = true;
                    break;
                }
                arms[n++] = t->thread.arms[i];
            }
        }
        t = t->thread.next;
    } while (t != g_current);
    return n;
}

/*
 * Give the processor back until one of `arms` moves or `usec` passes.
 *
 * Park (0x4FFFFFE1), not Sleep (0x4FFFFFDE), and the difference is the
 * whole of why a LibOS application can be a resident service at all. A
 * Park issued inside a host invoke RETURNS GETRESULT to the host: the
 * invoke ends, the vault becomes parked and resident, and the scheduler
 * dispatches it again when one of these words changes, when a peer
 * notifies it, when a peer goes, or when the timeout expires. Sleep is
 * refused in that position on purpose (channel_calls.rs:148), which is
 * why everything here used to spin instead.
 *
 * Refused for a vault that never declared a service name, because the
 * scheduler has no slot to park it in. That is not an error: it is an
 * ordinary vault doing an ordinary invoke, and the caller falls back to
 * what it did before.
 */
/* Once per process, before the first Park/Sleep of an app (g_pal_svsm_is_app).
 * The zygote never parks, so a clone starts with it undone; a fork child
 * inherits "done" and parks as a service, as before (RESIDENT-APPS-R1-DELTA
 * D2: its app children are a follow-up). A refusal is said once and the
 * vault parks as a service if it is one. */
static bool g_app_done = false;
void pal_svsm_app_ensure(void) {
    extern bool g_pal_svsm_is_app;
    extern bool g_pal_svsm_app_dedicated;
    if (!g_pal_svsm_is_app || g_app_done)
        return;
    int64_t st = pal_svsm_app_resident();
    /* -13 RETRY: this is the zygote, which is no app - and whose "done" every
     * trustlet would inherit (the trustlets then parked as services: jamie
     * pin smoke 2026-11-14). Left undone, so each trustlet makes its own. */
    if (st == -13)
        return;
    g_app_done = true;
    /* A dedicated app never runs as a service on shared processors: a refusal
     * (a pin that is not its assigned core, the host's limit, ...) ends it. */
    if (st != 0 && st != -3 && g_pal_svsm_app_dedicated)
        pal_svsm_fail("svsm.app.dedicated: the monitor refused AppResident", (int)st);
    if (st != 0 && st != -3)
        log_warning("svsm.app: the monitor refused AppResident (%ld); parking as before", (long)st);
}

static bool park_on(const uint64_t* arms, size_t n, uint64_t usec) {
    /* Only a vault whose MEASURED manifest declared a service. For
     * anything else a Park would end the host invoke it is sitting in
     * and hand the host a GETRESULT for a result nobody has written -
     * which is exactly why Sleep refuses in that position. The manifest
     * is the only signal available here that says "this vault means to
     * be resident", and being measured is what makes it a safe one. */
    extern bool g_pal_svsm_is_app;
    if (!g_pal_svsm_is_service && !g_pal_svsm_is_app)
        return false;
    return pal_svsm_park(n ? arms : NULL, n, usec) >= 0;
}

/* gather_arms_for for a non-lineage wait, counted by the profile (mc 0x08). */
static size_t gather_arms_counted(uint64_t* arms, size_t max, bool* partial, bool skip_covered) {
    if (__builtin_expect(!g_pal_svsm_prof_on, 1))
        return gather_arms_for(arms, max, partial, /*lineage=*/false, skip_covered);
    uint64_t t0 = pal_svsm_prof_now();
    size_t n = gather_arms_for(arms, max, partial, /*lineage=*/false, skip_covered);
    pal_svsm_prof_mc(PROF_ROW_GATHER, 1, pal_svsm_prof_now() - t0);
    return n;
}

/* The words the vault's blocked contexts wait on, for a wait elsewhere that
 * must also wake on them (the lineage wait for a child, pal_process.c). */
static size_t gather_arms(uint64_t* arms, size_t max, bool* partial) {
    return gather_arms_counted(arms, max, partial, /*skip_covered=*/false);
}

/* The arms for a Park (idle_until, pick_next): the covered threads' left out. */
static size_t gather_park_arms(uint64_t* arms, size_t max, bool* partial) {
    return gather_arms_counted(arms, max, partial,
                               /*skip_covered=*/g_pal_svsm_o1_wake && g_pal_svsm_o1_cover);
}

size_t pal_svsm_gather_arms(uint64_t* arms, size_t max, bool* partial) {
    return gather_arms(arms, max, partial);
}

static void stall_report(uint64_t now);   /* svsm.stall_report, below */

/* Give the vCPU back until `deadline_us`, in slices, so that the monitor and
 * the host both still get a turn while this vault has nothing to run. */
static void idle_until(uint64_t deadline_us) {
    while (1) {
        uint64_t now = pal_svsm_now_usec();
        if (now >= deadline_us)
            return;
        uint64_t left = deadline_us - now;
        stall_report(now);

        /* Every context is blocked, so there is nothing for this vault
         * to do with a processor. Ask the monitor for it back, WATCHING
         * whatever words would make a blocked thread runnable - without
         * them this waits out the whole deadline even though the peer
         * may have sent in the first microsecond, which is what a
         * poll-based service spent its life doing.
         *
         * Park rather than Sleep, because a Park in this position is
         * what makes the vault resident (see park_on). If the vault has
         * no service slot the monitor refuses, and then the Sleep and
         * the spin that were here before are still what happens. */
        uint64_t arms[PAL_SVSM_PARK_ARMS];
        bool partial = false;
        size_t n = gather_park_arms(arms, PAL_SVSM_PARK_ARMS, &partial);
        /* Partial: a word that was left out can move unseen, so the park is
         * bounded the way the Sleep below is. Before the gather stopped at
         * the monitor's three, a fourth arm got the whole park refused, and
         * this bound was never needed here. */
        /* In a lineage run set (fork fix 3): block IN THE LINEAGE, on the
         * same words. That is what hands the processor to the rest of the
         * lineage - inside a host invoke Park and Sleep are refused, and the
         * spin below would keep a parent's own child from ever running (at
         * seat cap 1 the child runs only when the root blocks). LineageWait
         * takes Park's channel arms; one it cannot take (a device word) or
         * no drive here refuses it, and the paths below run as before. */
        if (g_svsm_in_run_set) {
            /* Gathered again for the lineage: its own kinds as well - a
             * fork-shared pipe's ring word (UnixBench fix 2) - and its four
             * arms rather than Park's three. */
            uint64_t larms[PAL_SVSM_LINEAGE_ARMS];
            bool lpartial = false;
            size_t ln = gather_arms_for(larms, PAL_SVSM_LINEAGE_ARMS, &lpartial, /*lineage=*/true,
                                        /*skip_covered=*/false);
            uint64_t lw = lpartial && left > SVSM_PARK_PARTIAL_US ? SVSM_PARK_PARTIAL_US : left;
            if (pal_svsm_lineage_wait(ln ? larms : NULL, ln, 0, lw, NULL) >= 0) {
                pal_svsm_poll_wake();
                return;
            }
        }
        uint64_t pp0 = (__builtin_expect(g_pal_svsm_prof_on, 0) && partial) ? pal_svsm_prof_now() : 0;
        bool parked = park_on(arms, n, partial && left > SVSM_PARK_PARTIAL_US ? SVSM_PARK_PARTIAL_US
                                                                              : left);
        if (pp0)
            pal_svsm_prof_mc(PROF_ROW_PARTIAL_PARK, 1, pal_svsm_prof_now() - pp0);
        if (parked) {
            /* RETURN, do not loop. A park can end because a watched word
             * moved, and that is a state change the waiter has to see -
             * looping here would re-park until the deadline passed and
             * throw away the very wake this was armed for. Every poller
             * becomes runnable and re-tests its handles; the ones that
             * are still not ready block again, which is one more park
             * and is correct. */
            pal_svsm_poll_wake();
            return;
        }
        /* The Sleep below takes every thread's arms (O1-WAKE.md C covers a
         * Park only). */
        if (g_pal_svsm_o1_wake)
            n = gather_arms(arms, PAL_SVSM_PARK_ARMS, &partial);
        /* The Park was refused: no service slot, so this vault has
         * nothing the scheduler could park it in. Sleep instead - but
         * sleep the SAME WAY, watching the same words and bounded, so a
         * missed wake costs a slice rather than the whole wait.
         *
         * `pal_svsm_sleep(left)` was here: no arms, and the entire
         * remaining deadline. Sleep takes arms in exactly the format Park
         * does, so there was never a reason for that; nothing could end
         * it early, and a poller underneath it waited out its own
         * timeout. */
        uint64_t slice = left;
        if (n || partial) {
            uint64_t cap = partial ? SVSM_PARK_PARTIAL_US : SVSM_PARK_FALLBACK_US;
            if (slice > cap)
                slice = cap;
        }
        if (pal_svsm_sleep_arms(n ? arms : NULL, n, slice) >= 0) {
            /* As in the Park branch: a watched word may have moved, and
             * that is a state change every poller has to see. Return
             * rather than loop, so `pick_next` runs them. */
            pal_svsm_poll_wake();
            return;
        }

        /* The monitor refused the Sleep as well, which is what happens
         * to a vault inside a HOST INVOKE: a park in that position would
         * end the invoke and hand the host a GETRESULT for a result
         * nobody wrote, so `park_common` refuses anything the scheduler
         * did not dispatch. An ordinary client vault - which is what
         * every socket application is - therefore spins its wait out.
         *
         * Spin a SLICE and hand control back, rather than spinning the
         * whole deadline here. The loop was internal to this function,
         * so nothing re-tested a thread blocked in poll() until the
         * deadline passed: a client with `settimeout(5)` burned five
         * seconds of its own vCPU and then found the reply that had been
         * in the ring since the first millisecond. `pick_next` re-tests
         * blocked pollers on every pass, so returning here is what turns
         * this into a 100 us poll interval instead of a 5 s one. */
        uint64_t until = now + (left < SVSM_IDLE_SLICE_US ? left : SVSM_IDLE_SLICE_US);
        /* Bare pause, not CPU_RELAX: yielding from the idle loop would come
         * straight back here. Looking at the watched handles every few
         * hundred: a socket call that blocks waits HERE now, not in a spin
         * of its own, and a whole slice before it looks again would make
         * every reply inside an invoke up to 100 us late. pick_next makes
         * the ready one runnable. */
        uint64_t sp0 = __builtin_expect(g_pal_svsm_prof_on, 0) ? pal_svsm_prof_now() : 0;
        while (pal_svsm_now_usec() < until) {
            for (int i = 0; i < SVSM_IDLE_TEST_PAUSES; i++)
                __asm__ volatile("pause");
            if (any_watch_ready()) {
                if (sp0)
                    pal_svsm_prof_mc(PROF_ROW_IDLE_SPIN, 1, pal_svsm_prof_now() - sp0);
                return;
            }
        }
        if (sp0)
            pal_svsm_prof_mc(PROF_ROW_IDLE_SPIN, 1, pal_svsm_prof_now() - sp0);
        pal_svsm_nop();
        /* One round per slice spun here. A slice is at most
         * SVSM_IDLE_SLICE_US, so the count bounds how long a client sat
         * waiting for its peer with nowhere to give the processor back to. */
        PAL_SVSM_NET_CTR_INC(idle_rounds);
        return;
    }
}

bool g_pal_svsm_stall_report = false;
static uint64_t g_stall_last_us;

#define STALL_AFTER_US  (5UL * 1000 * 1000)
#define STALL_EVERY_US  (30UL * 1000 * 1000)
#define STALL_MAX_LINES 400

/* An address as `map+offset` against the nearest map at or below it, or NULL
 * if no map is within 64 MiB below it (not code we know about). */
static const struct pal_svsm_dbg_map* stall_map_of(uint64_t a) {
    const struct pal_svsm_dbg_map* best = NULL;
    for (size_t i = 0; i < g_pal_svsm_dbg_maps_n; i++) {
        uintptr_t b = g_pal_svsm_dbg_maps[i].addr ? g_pal_svsm_dbg_maps[i].addr : 0x400000;
        if (a >= b && a - b < (64UL << 20) && (!best || b > (best->addr ? best->addr : 0x400000)))
            best = &g_pal_svsm_dbg_maps[i];
    }
    return best;
}

/* The LibOS's per-thread block (libos_tcb.h), as far as this reads it: the
 * PAL cannot include the LibOS headers, so the offsets are pinned here and
 * by a static_assert next to struct libos_tcb. */
#define LIBOS_TCB_REGS_OFF   32
#define LIBOS_TCB_NR_OFF     40
#define LIBOS_TCB_PREFIX_OFF 72

/* An auto-clear event was just taken by the running context: remember who, so
 * a stall on it can name its holder even when the lock is inside a heap
 * object and even when the holder has since exited (stall_report). */
void pal_svsm_stall_note_taker(PAL_HANDLE ev) {
    PAL_HANDLE me = g_current;
    ev->event.taker = me;
    ev->event.taker_nr = -1;
    ev->event.taker_prefix[0] = '\0';
    PAL_TCB* pt = me ? (PAL_TCB*)me->thread.tcb : NULL;
    if (pt) {
        const char* lt = (const char*)pt->libos_tcb;
        memcpy(&ev->event.taker_nr, lt + LIBOS_TCB_NR_OFF, sizeof(long));
        memcpy(ev->event.taker_prefix, lt + LIBOS_TCB_PREFIX_OFF, sizeof(ev->event.taker_prefix) - 1);
        ev->event.taker_prefix[sizeof(ev->event.taker_prefix) - 1] = '\0';
    }
}

/* A parked context's call chain, as far as a scan can say: the words between
 * its saved rsp and the top of the stack it is on (the LibOS's per-thread
 * stack while in a syscall) that fall in the LibOS image or the PAL's text,
 * as libos+off / pal+off for addr2line against libsysdb.so / libpal.so. */
extern char __text_start;
extern char __text_end;
static void stall_chain(PAL_HANDLE t) {
    uintptr_t base, lo, hi;
    pal_entrypoint_range(&base, &lo, &hi);
    uintptr_t sp = (uintptr_t)t->thread.rsp, top = 0;
    PAL_TCB* pt = (PAL_TCB*)t->thread.tcb;
    if (pt)
        memcpy(&top, (const char*)pt->libos_tcb + 24, sizeof top);   /* libos_stack_bottom */
    if (!sp || (sp & 7))
        return;
    if (!top || top <= sp || top - sp > (64UL << 10))
        top = sp + (16UL << 10);
    char b[400];
    size_t bl = 0;
    unsigned n = 0;
    for (uintptr_t a = sp; a + 8 <= top && n < 48; a += 8) {
        uint64_t w = *(const uint64_t*)a;
        const char* tag = NULL;
        uint64_t off = 0;
        if (w >= lo && w < hi) {
            tag = "libos";
            off = w - base;
        } else if (w >= (uint64_t)&__text_start && w < (uint64_t)&__text_end) {
            tag = "pal";
            off = w;
        }
        if (!tag)
            continue;
        bl += snprintf(b + bl, sizeof(b) - bl, " %s+%#lx", tag, (unsigned long)off);
        n++;
        if (bl > sizeof(b) - 32) {
            log_error("stall-report: chain %p:%s", t, b);
            bl = 0;
            b[0] = '\0';
        }
    }
    if (bl)
        log_error("stall-report: chain %p:%s", t, b);
}

/*
 * svsm.stall_report: when a thread has been blocked STALL_AFTER_US and the
 * last report is STALL_EVERY_US old, say for every such thread what it is in:
 * its LibOS prefix (process:thread), the syscall and its first three
 * arguments, the user rip/rsp it entered with, what the PAL has it waiting on
 * (an event, or the sockets a poll watches and whether each is readable NOW -
 * which is the difference between a peer that never answered and a wake that
 * was lost), and the return addresses on its user stack that fall in a known
 * map, as map+offset for addr2line. Diagnosis only (the socialNetwork pilot's
 * wedge, 2026-11-19); at ERROR level because service manifests log at error.
 */
static void stall_report(uint64_t now) {
    if (!g_pal_svsm_stall_report || now - g_stall_last_us < STALL_EVERY_US)
        return;
    size_t total = 0, stalled = 0;
    PAL_HANDLE t = g_current;
    do {
        total++;
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED
                && now - t->thread.blocked_at_us >= STALL_AFTER_US)
            stalled++;
        t = t->thread.next;
    } while (t != g_current);
    if (!stalled)
        return;
    g_stall_last_us = now;
    log_error("stall-report: %lu threads, %lu blocked >= 5 s; pal anchor stall_report=%p",
              (unsigned long)total, (unsigned long)stalled, (void*)&stall_report);
    for (size_t i = 0; i < g_pal_svsm_dbg_maps_n; i++)
        log_error("stall-report: map %#lx %s", (unsigned long)g_pal_svsm_dbg_maps[i].addr,
                  g_pal_svsm_dbg_maps[i].name);
    /* The event most of the stalled wait on, if it is a LibOS lock's: a
     * `struct libos_lock` is { PAL_HANDLE lock; unsigned int owner; }, so the
     * word after the handle's address in the LibOS image is the owner's tid -
     * who is holding it - and the offset from the LibOS base names the lock
     * (nm libsysdb.so). A lock inside a heap object is not found this way. */
    {
        PAL_HANDLE top = NULL;
        uint32_t top_w = 0;
        PAL_HANDLE u = g_current;
        do {
            PAL_HANDLE on = u->thread.state == PAL_SVSM_THREAD_BLOCKED ? u->thread.waiting_on : NULL;
            if (on && on->hdr.type == PAL_TYPE_EVENT && on->event.waiters_cnt > top_w) {
                top = on;
                top_w = on->event.waiters_cnt;
            }
            u = u->thread.next;
        } while (u != g_current);
        uintptr_t base, lo, hi;
        pal_entrypoint_range(&base, &lo, &hi);
        log_error("stall-report: libos base %#lx image %#lx..%#lx; busiest event %p waiters %u",
                  (unsigned long)base, (unsigned long)lo, (unsigned long)hi, top, top_w);
        if (top) {
            bool alive = false;
            PAL_HANDLE v = g_current;
            do {
                if (v == top->event.taker)
                    alive = true;
                v = v->thread.next;
            } while (v != g_current);
            log_error("stall-report: busiest event last taken by ctx %p %s (nr %ld then), %s; "
                      "now state %d", top->event.taker, top->event.taker_prefix,
                      top->event.taker_nr, alive ? "still on the ring" : "NO LONGER ON THE RING",
                      alive ? (int)top->event.taker->thread.state : -1);
            if (alive && top->event.taker != g_current)
                stall_chain(top->event.taker);
        }
        if (top && lo && hi > lo) {
            unsigned hits = 0;
            for (uintptr_t a = ALIGN_UP(lo, 8); a + 16 <= hi && hits < 4; a += 8) {
                if (*(const uint64_t*)a != (uint64_t)top)
                    continue;
                hits++;
                log_error("stall-report: busiest event held at libos+%#lx owner tid %u",
                          (unsigned long)(a - base), *(const uint32_t*)(a + 8));
            }
            if (!hits)
                log_error("stall-report: busiest event not in the LibOS image (a heap lock)");
        }
    }
    size_t lines = 0;
    t = g_current;
    do {
        /* EVERY context, not only the stalled: the one holding what the
         * stalled wait for is usually not stalled itself (runnable, or in a
         * wait it keeps re-entering). */
        bool stalled_t = t->thread.state == PAL_SVSM_THREAD_BLOCKED
                         && now - t->thread.blocked_at_us >= STALL_AFTER_US;
        if (lines++ >= STALL_MAX_LINES) {
            log_error("stall-report: ... more not shown");
            break;
        }
        PAL_TCB* pt = (PAL_TCB*)t->thread.tcb;
        const char* lt = pt ? (const char*)pt->libos_tcb : NULL;
        char prefix[33] = "?";
        long nr = -1;
        PAL_CONTEXT* regs = NULL;
        if (lt) {
            memcpy(prefix, lt + LIBOS_TCB_PREFIX_OFF, 32);
            prefix[32] = '\0';
            memcpy(&nr, lt + LIBOS_TCB_NR_OFF, sizeof nr);
            memcpy(&regs, lt + LIBOS_TCB_REGS_OFF, sizeof regs);
        }
        char w[160] = "";
        size_t wl = 0;
        for (size_t i = 0; i < t->thread.n_watch && i < 3 && t->thread.watch_handles; i++) {
            PAL_HANDLE h = t->thread.watch_handles[i];
            if (!h)
                continue;
            bool sock = h->hdr.type == PAL_TYPE_SOCKET;
            wl += snprintf(w + wl, sizeof(w) - wl, " w%lu:type%d%s",
                           (unsigned long)i, (int)h->hdr.type,
                           sock ? (pal_svsm_sock_readable(h) ? ":READABLE" : ":empty") : "");
            if (wl >= sizeof(w))
                break;
        }
        char f[320] = "";
        size_t fl = 0;
        unsigned found = 0;
        if (regs && regs->rsp && (regs->rsp & 7) == 0) {
            const uint64_t* sp = (const uint64_t*)regs->rsp;
            /* 2 KiB: a thread's frames are well inside it, and a read past the
             * top of a mapped stack would fault the vault. */
            for (size_t k = 0; k < 256 && found < 10 && fl < sizeof(f) - 40; k++) {
                const struct pal_svsm_dbg_map* m = stall_map_of(sp[k]);
                if (!m)
                    continue;
                uintptr_t b = m->addr ? m->addr : 0;
                fl += snprintf(f + fl, sizeof(f) - fl, " %s+%#lx", m->name[0] ? m->name : "?",
                               (unsigned long)(sp[k] - b));
                found++;
            }
        }
        PAL_SVSM_TCB* st = (PAL_SVSM_TCB*)t->thread.tcb;
        PAL_HANDLE on = t->thread.waiting_on;
        char ev[48] = "";
        if (on && on->hdr.type == PAL_TYPE_EVENT)
            snprintf(ev, sizeof ev, " ev sig %u waiters %u%s",
                     (unsigned)__atomic_load_n(&on->event.signaled, __ATOMIC_RELAXED),
                     (unsigned)on->event.waiters_cnt, on->event.auto_clear ? " auto" : "");
        log_error("stall-report: %s%s ctx %p state %u holds %ld/%ld blocked %lu ms on %p(type %d)%s "
                  "deadline %ld ms nr %ld args %#lx %#lx %#lx rip %#lx rsp %#lx arms %u%s watch %lu%s |%s",
                  stalled_t ? "STALLED " : "", prefix, t, (unsigned)t->thread.state,
                  st ? (long)st->lock_holds : -1L, st ? (long)st->paused_holds : -1L,
                  t->thread.state == PAL_SVSM_THREAD_BLOCKED
                      ? (unsigned long)((now - t->thread.blocked_at_us) / 1000) : 0UL,
                  on, on ? (int)on->hdr.type : -1, ev,
                  t->thread.has_deadline ? (long)((int64_t)(t->thread.deadline_us - now) / 1000)
                                         : -1L,
                  nr, regs ? (unsigned long)regs->rdi : 0UL, regs ? (unsigned long)regs->rsi : 0UL,
                  regs ? (unsigned long)regs->rdx : 0UL, regs ? (unsigned long)regs->rip : 0UL,
                  regs ? (unsigned long)regs->rsp : 0UL, (unsigned)t->thread.n_arms,
                  t->thread.arms_partial ? "+" : "", (unsigned long)t->thread.n_watch, w, f);
        t = t->thread.next;
    } while (t != g_current);
}

/*
 * The next context to run, or NULL when nothing will ever be runnable again.
 * Expires deadlines on the way past, and waits for the nearest one if that is
 * the only thing that can change the answer.
 */
/* O1-WAKE.md B: when the blocked pollers were last re-tested. */
static uint64_t g_last_poll_scan_us;

/* Can anything other than a blocked context run - the current one, or another
 * already runnable? (A state load per context; no re-test.) */
static bool others_runnable(void) {
    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE || t->thread.state == PAL_SVSM_THREAD_RUNNING)
            return true;
        t = t->thread.next;
    } while (t != g_current);
    return false;
}

/* Is a blocked thread waiting notify-covered (O1-WAKE.md C)? */
static bool any_covered_waiter(void) {
    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.notify_covered)
            return true;
        t = t->thread.next;
    } while (t != g_current);
    return false;
}

static PAL_HANDLE pick_next(void) {
    assert(g_current);

    while (1) {
        uint64_t now = pal_svsm_now_usec();
        uint64_t earliest = 0;
        bool have_deadline = false;

        /* O1-WAKE.md B: while another context can run, the blocked pollers
         * are re-tested at most every svsm.poll_scan_us; with none - the only
         * case that can end in a park - every pass. */
        bool scan = true;
        if (g_pal_svsm_o1_wake) {
            scan = pw_scan_due(now, g_last_poll_scan_us, g_pal_svsm_poll_scan_us, others_runnable());
            if (scan)
                g_last_poll_scan_us = now;
        }
        const bool prof = __builtin_expect(g_pal_svsm_prof_on, 0);
        uint64_t scan0 = prof ? pal_svsm_prof_now() : 0, tests = 0;
        /* The missed-test audit (diagnosis, svsm.o1_audit_us): once per interval,
         * every blocked watched poller the test below calls not ready is woken
         * anyway, as the old wake-all did, and checks in its own context. */
#ifdef PROF_ROW_GATHER
        static bool o1_marked;
        if (!o1_marked && g_pal_svsm_prof_on) {
            o1_marked = true;
            pal_svsm_prof_mc(PROF_ROW_MARKER, 1, 0);   /* the missed-test check is in this vault */
            pal_svsm_prof_mc(PROF_ROW_LAYOUT, 2, 0);   /* the rows are pal_svsm_prof_rows.h layout 2 */
        }
#endif
        bool audit = false;
        if (g_pal_svsm_o1_wake && g_pal_svsm_o1_audit_us && scan
                && now - g_last_o1_audit_us >= g_pal_svsm_o1_audit_us) {
            audit = true;
            g_last_o1_audit_us = now;
        }
        PAL_HANDLE t = g_current;
        do {
            if (prof && scan && t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.n_watch)
                tests++;
            /* A poller whose handles have become ready is runnable NOW,
             * whatever its deadline says. Nothing else re-tests it: a
             * peer's send runs no code in this vault, and the only other
             * place that looks is `idle_until`, which a vault with an
             * async worker never reaches. Plain loads from the ring's
             * control words - no monitor call - so this costs two loads
             * per watched socket per scheduler pass, and only while
             * something is actually blocked in poll(). */
            if (scan && t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.n_watch
                    && pal_svsm_poller_ready(t)) {
                PAL_SVSM_NET_CTR_INC(pollers_ready);
                t->thread.waiting_on = NULL;
                t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                PROF_RUNNABLE(t);
                pal_svsm_preempt_update(true);
            } else if (audit && t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.n_watch
                       && t->thread.waiting_on == POLL_TOKEN) {
                PAL_SVSM_NET_CTR_INC(o1_audits);
#ifdef PROF_ROW_GATHER
                pal_svsm_prof_mc(PROF_ROW_AUDITS, 1, 0);
#endif
                t->thread.o1_audit   = true;
                t->thread.waiting_on = NULL;
                t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                PROF_RUNNABLE(t);
                pal_svsm_preempt_update(true);
            }
            if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.has_deadline) {
                if (now >= t->thread.deadline_us) {
                    t->thread.o1_timeout_scanned = g_pal_svsm_o1_wake && scan && t->thread.n_watch;
                    t->thread.timed_out  = true;
                    t->thread.waiting_on = NULL;
                    t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                    PROF_RUNNABLE(t);
                    pal_svsm_preempt_update(true);
                } else if (!have_deadline || t->thread.deadline_us < earliest) {
                    earliest      = t->thread.deadline_us;
                    have_deadline = true;
                }
            }
            t = t->thread.next;
        } while (t != g_current);
        if (prof && scan) {   /* a pass that re-tested (O1-WAKE.md B skips some) */
            pal_svsm_prof_mc(PROF_ROW_SCHED_PASS, 1, pal_svsm_prof_now() - scan0);
            pal_svsm_prof_mc(PROF_ROW_POLLER_TEST, tests, 0);
        }

        /* Round robin: start after whoever ran last, so a thread that yields
         * goes to the back. */
        PAL_HANDLE start = g_current->thread.next;
        t = start;
        do {
            if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE)
                return t;
            t = t->thread.next;
        } while (t != start);

        /* Nobody else wants it and we are still able to run: carry on. */
        if (g_current->thread.state == PAL_SVSM_THREAD_RUNNING)
            return g_current;

        /* The park linger (svsm.park_linger_us, default 0 = off; owner GO 2026-11-28): nothing can run, so
         * before giving the processor back re-test the blocked waiters - their watch sets and deadlines - for
         * up to the linger. A waiter found ready is made runnable and the loop picks it; otherwise the park
         * below happens as before, `linger_us` later. Loads only (pal_svsm_poller_ready), no monitor call. */
        if (g_pal_svsm_park_linger_us) {
            uint64_t l0 = pal_svsm_now_usec(), ln = l0;
            bool found = false;
            while (!found && pw_linger_more(ln, l0, g_pal_svsm_park_linger_us)) {
                PAL_SVSM_NET_CTR_INC(linger_rounds);
                PAL_HANDLE w = g_current;
                do {
                    if (w->thread.state == PAL_SVSM_THREAD_BLOCKED) {
                        if (w->thread.has_deadline && ln >= w->thread.deadline_us) {
                            found = true;            /* the loop's deadline pass takes it */
                        } else if (w->thread.n_watch && pal_svsm_poller_ready(w)) {
                            w->thread.waiting_on = NULL;
                            w->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                            found = true;
                        }
                    }
                    w = w->thread.next;
                } while (w != g_current && !found);
                if (!found) {
                    __asm__ volatile("pause");
                    ln = pal_svsm_now_usec();
                }
            }
#ifdef PROF_ROW_GATHER
            pal_svsm_prof_mc(found ? PROF_ROW_LINGER_FOUND : PROF_ROW_LINGER_PARKED, 1, 0);
            pal_svsm_prof_mc(PROF_ROW_LINGER_US, pal_svsm_now_usec() - l0, 0);
#endif
            if (found) {
                PAL_SVSM_NET_CTR_INC(linger_found);
                pal_svsm_preempt_update(true);
                continue;
            }
            PAL_SVSM_NET_CTR_INC(linger_parked);
        }

        if (!have_deadline) {
            /* No deadline. Before this that was a deadlock by
             * definition, and for a vault with no channels it still is -
             * but a thread waiting on a ring has something that can wake
             * it, and `epoll_wait(-1)` on a channel socket is the
             * ordinary shape of a server rather than a bug. */
            stall_report(now);
            uint64_t arms[PAL_SVSM_PARK_ARMS];
            bool partial = false;
            size_t n = gather_park_arms(arms, PAL_SVSM_PARK_ARMS, &partial);
            /* Nothing armed, nothing partial: with o1_wake that is also a
             * vault whose every waiter is notify-covered - parked on the
             * fallback bound, woken by its writers' Notify. Without any
             * covered thread it is the deadlock it always was. */
            if (!n && !partial && !(g_pal_svsm_o1_wake && g_pal_svsm_o1_cover && any_covered_waiter()))
                return NULL;
            uint64_t pq0 = (prof && partial) ? pal_svsm_prof_now() : 0;
            bool parked = park_on(arms, n, partial ? SVSM_PARK_PARTIAL_US
                                                   : SVSM_PARK_FALLBACK_US);
            if (pq0)
                pal_svsm_prof_mc(PROF_ROW_PARTIAL_PARK, 1, pal_svsm_prof_now() - pq0);
            if (parked) {
                pal_svsm_poll_wake();
                continue;
            }
            /* No service slot, so this vault cannot be parked and a wait
             * with no deadline really is one that nothing can end. */
            return NULL;
        }

        idle_until(earliest);
    }
}

/* Nothing runnable and nothing that can become runnable. */
static noreturn void die_deadlocked(void) {
    /* Loud, because the alternative is a vault that sits there doing nothing
     * until the monitor's invoke watchdog kills it 600 seconds later with no
     * explanation of what it was waiting for. */
    pal_svsm_fail("deadlock: every thread is blocked and nothing can wake them",
                  (int)g_thread_cnt);
    die_or_inf_loop();
}

/* Hand the CPU to whoever should have it, and return once this context runs
 * again. Not for a context that is exiting - that has its own path, because
 * it must leave the ring before it lets go. */
static void schedule(void) {
    PAL_HANDLE prev = g_current;
    assert(prev->thread.state != PAL_SVSM_THREAD_ZOMBIE);

    PAL_HANDLE next = pick_next();
    if (!next)
        die_deadlocked();

    if (next == prev) {
        assert(prev->thread.state == PAL_SVSM_THREAD_RUNNING);
        reap_stack();
        refresh_preempt_wanted();
        return;
    }

    if (prev->thread.state == PAL_SVSM_THREAD_RUNNING)
        prev->thread.state = PAL_SVSM_THREAD_RUNNABLE;
        PROF_RUNNABLE(prev);
    next->thread.state = PAL_SVSM_THREAD_RUNNING;
    g_current = next;

    /*
     * FS is the *application's* thread pointer - glibc's TLS block, which is
     * where pthread_self() and therefore Python's threading.get_ident() read
     * from - and it is per thread just as GS is. The switch stub moves GS
     * because the stack canary is read through it and there must be no
     * instruction where the two disagree; FS has no such constraint, so each
     * context saves its own here and puts it back when it is next run.
     *
     * Leaving it out is not a subtle bug. Every thread then sees whichever
     * thread ran last as itself: Thread.join() answers "cannot join current
     * thread", and anything else keyed on thread identity is silently wrong.
     */
    prev->thread.fsbase = rdfsbase();

    if (__builtin_expect(g_pal_svsm_prof_on, 0)) {
        pal_svsm_prof_switch(prev->thread.tcb, next->thread.tcb);
#ifdef PROF_ROW_GATHER
        uint64_t sw_now = pal_svsm_now_usec();
        if (next->thread.prof_runnable_us) {
            uint64_t d = sw_now - next->thread.prof_runnable_us;
            next->thread.prof_runnable_us = 0;
            pal_svsm_prof_mc(PROF_ROW_RQ(prof_log2_bucket(d, 1)), 1, 0);
        }
        /* prev's slice, by how it ended: still runnable (a yield or a preemption) or not */
        if (prev->thread.prof_slice_us) {
            unsigned sb = prof_slice_bucket(sw_now - prev->thread.prof_slice_us);
            pal_svsm_prof_mc(prev->thread.state == PAL_SVSM_THREAD_RUNNABLE ? PROF_ROW_SLICE_RUNNABLE(sb)
                                                                            : PROF_ROW_SLICE_BLOCKED(sb), 1, 0);
        }
        prev->thread.prof_slice_us = 0;
        next->thread.prof_slice_us = sw_now;
#endif
    }
    pal_svsm_ctx_switch(&prev->thread.rsp, next->thread.rsp, (uint64_t)next->thread.tcb);

    /* Back on prev's stack, however long later. */
    wrfsbase(prev->thread.fsbase);
    reap_stack();
    refresh_preempt_wanted();
}

/* Where a new context starts. Reached by the switch stub's `ret`, so GS -
 * and therefore the TCB, the canary and current_thread() - is already this
 * thread's. */
__attribute_no_stack_protector
static noreturn void thread_trampoline(void) {
    /* Zero until LibOS gives this thread its TLS; see the note in
     * schedule() about why FS travels with the context. */
    wrfsbase(current_thread()->thread.fsbase);
    reap_stack();

    PAL_SVSM_TCB* tcb = pal_get_svsm_tcb();
    int (*callback)(void*) = tcb->callback;
    void* param = tcb->param;

    callback(param);

    _PalThreadExit(/*clear_child_tid=*/NULL);
}

/*
 * Whether anything other than the running context has any prospect of
 * running.
 *
 * The monitor reads this to decide whether preempting is worth a frame and
 * a round trip: a vault with one context has nothing to switch to, and
 * interrupting it to find that out is pure cost.
 *
 * A thread waiting on a deadline counts, and that is not a detail. The
 * only thing that ever notices a deadline has passed is the scheduler, and
 * the scheduler only runs when somebody yields - so during a computation
 * that never yields, a sleeping sibling would stay asleep for ever, its
 * timer would never fire, and counting only RUNNABLE contexts would say
 * there was nothing to preempt for and make that permanent. Being
 * preempted is precisely how the deadline comes to be noticed.
 *
 * Recomputed whenever the ring's population or a context's state changes,
 * which is cheap: a vault has a handful of contexts, not thousands.
 */
static void refresh_preempt_wanted(void) {
    if (!g_current) {
        pal_svsm_preempt_update(false);
        return;
    }
    PAL_HANDLE t = g_current->thread.next;
    while (t != g_current) {
        if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE
                || (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.has_deadline)) {
            pal_svsm_preempt_update(true);
            return;
        }
        t = t->thread.next;
    }
    pal_svsm_preempt_update(false);
}

static void ring_insert_after(PAL_HANDLE at, PAL_HANDLE node) {
    node->thread.next = at->thread.next;
    at->thread.next   = node;
    g_thread_cnt++;
    refresh_preempt_wanted();
}

/* Caller must not leave g_current pointing at `node`: every walk starts
 * there and an unlinked node is no longer on any ring. */
static void ring_remove(PAL_HANDLE node) {
    assert(g_thread_cnt > 1);
    PAL_HANDLE prev = node->thread.next;
    while (prev->thread.next != node)
        prev = prev->thread.next;
    prev->thread.next = node->thread.next;
    node->thread.next = NULL;
    g_thread_cnt--;
    /* Deliberately NOT refreshing here. This runs with g_current still
     * pointing at the node being unlinked, whose `next` has just been
     * cleared, and every walk of the ring starts at g_current - so a walk
     * from here leaves the ring immediately and reads whatever it lands
     * on. The caller refreshes once it has re-pointed g_current. */
}

/* Installed as g_cpu_relax_yield: see the comment on CPU_RELAX in cpu.h. */
static void cpu_relax_yield(void) {
    _PalThreadYieldExecution();
}

int pal_svsm_threading_init(PAL_HANDLE* out_first_thread) {
    assert(!g_current);

    PAL_HANDLE handle = calloc(1, HANDLE_SIZE(thread));
    if (!handle)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(handle, PAL_TYPE_THREAD);

    /* The first thread runs on the stack the monitor gave the vault and on
     * the TCB already in GS, so it owns neither: stack stays NULL so nothing
     * ever frees it. */
    handle->thread.stack = NULL;
    handle->thread.tcb   = pal_get_tcb();
    handle->thread.state = PAL_SVSM_THREAD_RUNNING;
    handle->thread.next  = handle;

    /* The first thread's stack is the monitor's, so its alternate stack has
     * to be found somewhere; every other thread carves one out of its own
     * block. Without it this thread cannot be delivered a fault at all. */
    void* alt = malloc(SVSM_ALT_STACK_SIZE);
    if (!alt) {
        free(handle);
        return -PAL_ERROR_NOMEM;
    }
    memset(alt, 0, SVSM_ALT_STACK_SIZE);

    PAL_SVSM_TCB* tcb = pal_get_svsm_tcb();
    tcb->handle         = handle;
    tcb->alt_stack_top  = (char*)alt + SVSM_ALT_STACK_SIZE;
    tcb->alt_stack_size = SVSM_ALT_STACK_SIZE;
    /* lock_holds is NOT reset here: this is the TCB pal_main installed,
       zeroed, and any hold already counted on it is still owed. */

    g_current    = handle;
    g_thread_cnt = 1;

    /* From here on a spin that waits on another thread has to give that
     * thread a turn. LibOS installs its own copy of this once it has read
     * pal_public_state::cooperative_threading. */
    g_cpu_relax_yield = cpu_relax_yield;

    *out_first_thread = handle;
    return 0;
}

int _PalThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), void* param) {
    if (!g_current)
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(thread));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    /*
     * One block: the stack, with the TCB sitting at the top of it.
     *
     *   stack +--> +-------------------+  low
     *              |  alternate stack  |  SVSM_ALT_STACK_SIZE, grows down
     *              +-------------------+
     *              |                   |
     *              |   thread stack    |  SVSM_THREAD_STACK_SIZE, grows down
     *              |                   |
     *       tcb +--> +-----------------+
     *              |   PAL_SVSM_TCB    |
     *              +-------------------+  high
     *
     * The alternate stack sits below the thread stack so that running off
     * the bottom of the latter lands in a region of this block rather than
     * in whatever malloc handed out next.
     */
    size_t block = SVSM_THREAD_BLOCK_SIZE;
    /* An exited thread's block when there is one (thread reuse, above). The
     * memset below is its scrub, as it is a fresh block's zeroing. */
    char* stack = thread_cache_pop();
    if (!stack)
        stack = malloc(block);
    if (!stack) {
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }
    memset(stack, 0, block);
    thread_cache_check_scrub(stack);

    PAL_SVSM_TCB* tcb = (PAL_SVSM_TCB*)(stack + SVSM_ALT_STACK_SIZE + SVSM_THREAD_STACK_SIZE);
    tcb->common.self  = &tcb->common;
    /* The same canary the creating thread uses, as glibc does for its own
     * threads. A per-thread random one is a hardening nicety, but it has to
     * be installed by the new context itself, and every frame that straddles
     * the change would then check the wrong value. */
    pal_tcb_arch_set_stack_canary(&tcb->common, pal_get_tcb()->stack_protector_canary);
    tcb->handle         = hdl;
    tcb->alt_stack_top  = stack + SVSM_ALT_STACK_SIZE;
    tcb->alt_stack_size = SVSM_ALT_STACK_SIZE;
    tcb->callback       = callback;
    tcb->param          = param;
    tcb->lock_holds     = 0;

    /*
     * The frame pal_svsm_ctx_switch will unwind into. It pops six registers
     * and returns, so the top of the new stack has to look like the middle of
     * that stub: six saved registers below a return address.
     *
     * The alignment is the SysV rule read backwards - a function is entered
     * with rsp % 16 == 8, because the call that reached it pushed 8 bytes
     * onto a 16-aligned stack - so the null word below pins the trampoline's
     * entry to exactly that. The null doubles as a return address that
     * terminates a backtrace.
     */
    uint64_t* sp = (uint64_t*)ALIGN_DOWN_PTR(tcb, 16);
    *--sp = 0;                                 /* backstop return address */
    *--sp = (uint64_t)thread_trampoline;       /* what the stub returns into */
    for (int i = 0; i < 6; i++)
        *--sp = 0;                             /* rbp, rbx, r12, r13, r14, r15 */

    init_handle_hdr(hdl, PAL_TYPE_THREAD);
    hdl->thread.stack = stack;
    hdl->thread.tcb   = tcb;
    hdl->thread.rsp   = sp;
    hdl->thread.state = PAL_SVSM_THREAD_RUNNABLE;
    PROF_RUNNABLE(hdl);

    ring_insert_after(g_current, hdl);

    *handle = hdl;
    return 0;
}

/*
 * In a copy-on-write fork's child, right after the fork: the forker is the
 * only thread.
 *
 * Every other context on the ring is a copy of one of the PARENT's threads -
 * its stack, its registers, its place in whatever it was doing - and the ring
 * is this process's own memory, so the copy was runnable here. It ran: a
 * parent thread blocked in a read went on reading in the child too, a worker
 * went on working, and the LibOS's exit and exec waited on them as its own
 * (kill_other_threads). POSIX's fork gives the child the calling thread and
 * nothing else, and so does this, before the child can pick anything else
 * to run - it is called on the forker's way out of the fork.
 *
 * Unlinked, not freed: the stacks are copies nobody will run on again, and a
 * leak of them is cheaper than being wrong about who still points into one.
 * A copy cannot be holding a PAL lock either: PAL text is never preempted,
 * and the one PAL lock a thread waits under (an event's) is let go before it
 * blocks. A LibOS lock it held stays held in the child: the fork waits for
 * such holds to drain and, if they do not, goes ahead and counts it
 * (_PalProcessFork, FORK_FOREIGN_HOLDS).
 */
void pal_svsm_threads_child_after_fork(void) {
    PAL_HANDLE self = g_current;
    if (!self)
        return;
    PAL_HANDLE t = self->thread.next;
    while (t && t != self) {
        PAL_HANDLE next = t->thread.next;
        t->thread.next  = NULL;
        /* Anything that still finds this handle - nothing should - finds a
         * thread that has ended, which _PalThreadResume leaves alone. */
        t->thread.state = PAL_SVSM_THREAD_ZOMBIE;
        t = next;
    }
    self->thread.next = self;
    g_thread_cnt = 1;
    refresh_preempt_wanted();
}

void _PalThreadYieldExecution(void) {
    /* Before threading is up - and it is up before anything can block - there
     * is nothing to yield to. CPU_RELAX lands here from very early code. */
    if (!g_current)
        return;
    schedule();
}

noreturn void _PalThreadExit(int* clear_child_tid) {
    PAL_HANDLE self = g_current;
    assert(self && self == current_thread());

    /*
     * Telling LibOS the thread is gone is DEFERRED to whoever runs next, with
     * the stack (see g_tid_to_clear): the store hands LibOS permission to free
     * this handle, and the code below is still using it.
     *
     * LibOS waits for exactly this by spinning (bookkeep/libos_thread.c:483,
     * ipc/libos_ipc_worker.c:419), and those spins end because CPU_RELAX
     * yields back into this scheduler - which still works when the store comes
     * one switch later: this context is runnable until it switches away, so it
     * always gets to finish, and the context it switches to does the store.
     */
    self->thread.state = PAL_SVSM_THREAD_ZOMBIE;

    if (g_thread_cnt == 1) {
        /* Nothing else was ever started, or everything else has gone. A
         * process with no threads left is a process that has ended. Nobody
         * will run next, so the handover happens here or not at all - and it
         * is safe here precisely because no other context can act on it. */
        if (clear_child_tid)
            __atomic_store_n(clear_child_tid, 0, __ATOMIC_RELEASE);
        _PalProcessExit(0);
    }

    /*
     * Leave the ring before letting go of the CPU. The handle is LibOS's to
     * destroy the moment this thread has exited, so it must not still be
     * linked when that happens - and pick_next() walks the ring starting at
     * g_current, so g_current has to name a thread that is still in it.
     *
     * The stack outlives us by exactly one switch: it is still underfoot
     * until pal_svsm_ctx_switch has moved to another one, so whoever runs
     * next frees it (reap_stack).
     */
    PAL_HANDLE succ = self->thread.next;
    assert(succ != self);
    ring_remove(self);
    assert(!g_stack_to_reap);
    assert(!g_tid_to_clear);
    g_stack_to_reap = self->thread.stack;
    g_tid_to_clear  = clear_child_tid;
    g_current = succ;
    /* Now that g_current is a node that is still in the ring. */
    refresh_preempt_wanted();

    PAL_HANDLE next = pick_next();
    if (!next)
        die_deadlocked();

    next->thread.state = PAL_SVSM_THREAD_RUNNING;
    g_current = next;

    /* Nowhere to come back to, so the outgoing stack pointer goes to a
     * scratch word rather than into a handle that may already be freed, and
     * this context's FS is not worth saving. The thread we switch to puts
     * its own back on the far side of its own switch. */
    if (__builtin_expect(g_pal_svsm_prof_on, 0))
        pal_svsm_prof_switch(NULL, next->thread.tcb);
    pal_svsm_ctx_switch(&g_dead_rsp, next->thread.rsp, (uint64_t)next->thread.tcb);

    die_or_inf_loop();
}

int _PalThreadResume(PAL_HANDLE thread_handle) {
    if (!thread_handle || thread_handle->hdr.type != PAL_TYPE_THREAD)
        return -PAL_ERROR_INVAL;

    /* What this means on other hosts is "interrupt whatever it is blocked in,
     * there is a signal for it". Sticky, because the signal may arrive just
     * before the thread blocks. */
    thread_handle->thread.interrupted = true;
    if (thread_handle->thread.state == PAL_SVSM_THREAD_BLOCKED) {
        thread_handle->thread.waiting_on = NULL;
        thread_handle->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
        PROF_RUNNABLE(thread_handle);
        refresh_preempt_wanted();
    }
    return 0;
}

/*
 * The sticky flag above, read and cleared for the thread that is running.
 *
 * A thread that blocks finds a pending signal through its wait returning
 * PAL_SVSM_WAIT_INTERRUPTED, and the LibOS delivers it on the way out of the
 * syscall. A thread that never blocks - dhry2reg's loop, UnixBench's hanoi
 * and arith, anything that waits for SIGALRM by computing - never gets
 * there, so the preemption path asks instead (next.md 170.4). Clearing is a
 * separate call because the flag must survive a tick on which the signal
 * could NOT be delivered (the thread was inside the LibOS): the blocking
 * path or the next tick still owes it.
 */
bool pal_svsm_current_interrupted(void) {
    return g_current && g_current->thread.interrupted;
}

void pal_svsm_current_clear_interrupted(void) {
    if (g_current)
        g_current->thread.interrupted = false;
}

/* The arms and the watch belonged to the wait that set them. Anything that
 * runs now re-tests what it is waiting for, so a stale word would only make
 * the next park end early - but it would also make it end early for a
 * DIFFERENT thread's wait, which is a bug that would look like a spurious
 * wake and be very hard to see. And the watch points into the waiter's own
 * frame, which is about to go: left set, the next wait that sets none (an
 * event's) has the scheduler re-test handles through a dead stack. */
static void wait_forget(PAL_HANDLE self) {
    self->thread.n_arms        = 0;
    self->thread.arms_partial  = false;
    self->thread.notify_covered = false;
    self->thread.n_watch       = 0;
    self->thread.watch_handles = NULL;
    self->thread.watch_events  = NULL;
}

enum pal_svsm_wait_result pal_svsm_thread_block(PAL_HANDLE waiting_on,
                                                const uint64_t* deadline_us) {
    PAL_HANDLE self = g_current;
    assert(self);

    if (self->thread.interrupted) {
        /* Before blocking, too: the caller set its arms and watch first. */
        wait_forget(self);
        self->thread.interrupted = false;
        return PAL_SVSM_WAIT_INTERRUPTED;
    }

    self->thread.waiting_on   = waiting_on;
    self->thread.has_deadline = deadline_us != NULL;
    self->thread.deadline_us  = deadline_us ? *deadline_us : 0;
    self->thread.timed_out    = false;
    self->thread.state        = PAL_SVSM_THREAD_BLOCKED;
    if (g_pal_svsm_stall_report)
        self->thread.blocked_at_us = pal_svsm_now_usec();
    refresh_preempt_wanted();
#ifdef PROF_ROW_GATHER
    uint64_t wl0 = (g_pal_svsm_prof_on && waiting_on != POLL_TOKEN) ? pal_svsm_now_usec() : 0;
#endif

    schedule();

#ifdef PROF_ROW_GATHER
    if (wl0) {
        pal_svsm_prof_mc(PROF_ROW_WL(prof_log2_bucket(pal_svsm_now_usec() - wl0, 64)), 1, 0);
        if (self->thread.timed_out)
            pal_svsm_prof_mc(PROF_ROW_WL_DEADLINE, 1, 0);
    }
#endif
    self->thread.waiting_on   = NULL;
    self->thread.has_deadline = false;
    wait_forget(self);

    if (self->thread.interrupted) {
        self->thread.interrupted = false;
        return PAL_SVSM_WAIT_INTERRUPTED;
    }
    if (self->thread.timed_out) {
        self->thread.timed_out = false;
        return PAL_SVSM_WAIT_TIMEOUT;
    }
    return PAL_SVSM_WAIT_WOKEN;
}

/*
 * Waiting on something pollable.
 *
 * A poll watches a set of handles, so it cannot park against one of them.
 * The sentinel below stands for "anything pollable moved"; a woken poller
 * re-tests its whole set, which it has to do anyway because another thread
 * may have consumed what it was woken for. It is never dereferenced - only
 * compared - and never handed to anything that would.
 */
/* (POLL_TOKEN is defined above, before pick_next, which the audit needs it in.) */

enum pal_svsm_wait_result pal_svsm_poll_block(const uint64_t* deadline_us) {
    /* Counted into the WAITERS of every socket ring this thread waits to read
     * before it blocks (NOTIFY-ELISION.md): the writers then Notify only
     * while someone waits. The watch set is read here because
     * pal_svsm_thread_block clears it on the way out. */
    struct pal_svsm_waiter marks[PAL_SVSM_WAITER_MARKS];
    size_t nmarks = 0;
    if (g_current && g_current->thread.n_watch)
        nmarks = pal_svsm_sock_waiters_add(g_current->thread.watch_handles,
                                           g_current->thread.watch_events,
                                           g_current->thread.n_watch, marks,
                                           PAL_SVSM_WAITER_MARKS);
    /* O1-WAKE.md C: does every handle of this wait wake the vault by itself?
     * Read before blocking, from the same watch set the count was made from. */
    if (g_pal_svsm_o1_wake && g_pal_svsm_o1_cover && g_current && g_current->thread.n_watch) {
        bool covered = true;
        for (size_t i = 0; i < g_current->thread.n_watch && covered; i++) {
            PAL_HANDLE h = g_current->thread.watch_handles[i];
            uint32_t ev  = g_current->thread.watch_events[i];
            if (!h)
                continue;
            enum pw_entry_kind kind = PW_ENTRY_OTHER;
            bool counted = false;
            switch (h->hdr.type) {
                case PAL_TYPE_SOCKET:
                    kind = PW_ENTRY_SOCKET;
                    counted = pal_svsm_sock_waiter_counted(h);
                    break;
                case PAL_TYPE_PIPE:
                case PAL_TYPE_PIPECLI:
                    kind = pal_svsm_pipe_is_shared(h) ? PW_ENTRY_OTHER : PW_ENTRY_LOCAL;
                    break;
                case PAL_TYPE_EVENTFD:
                    kind = PW_ENTRY_LOCAL;
                    break;
                default:
                    break;
            }
            covered = pw_entry_covered(kind, ev & PAL_WAIT_READ, ev & PAL_WAIT_WRITE, counted);
        }
        g_current->thread.notify_covered = covered;
    }
    /* The missed-test check needs the watch set after the block, which
     * pal_svsm_thread_block forgets; the arrays are the caller's and live on. */
    PAL_HANDLE self = g_current;
    PAL_HANDLE* wh = self ? self->thread.watch_handles : NULL;
    const uint32_t* we = self ? self->thread.watch_events : NULL;
    size_t wn = self ? self->thread.n_watch : 0;
    /* the wait's start: for the missed-test check (O1) and for the blocked-time histogram (the profile) */
    uint64_t t0 = ((g_pal_svsm_o1_wake || g_pal_svsm_prof_on) && wn) ? pal_svsm_now_usec() : 0;
    if (self) {
        self->thread.o1_audit = false;
        self->thread.o1_timeout_scanned = false;
    }
    enum pal_svsm_wait_result r = pal_svsm_thread_block(POLL_TOKEN, deadline_us);
    /* O1-WAKE.md, 2026-11-27: the scheduler's test said "not ready" and this
     * thread was woken anyway (the audit) or by its deadline. A handle its own
     * look calls ready that the scheduler-context test, run just before, still
     * calls not ready is a MISSED TEST: under the ready-only wake it would have
     * slept on to its deadline (or for ever). Counted by kind, never acted on. */
    if (self && wn && (self->thread.o1_audit
                       || (r == PAL_SVSM_WAIT_TIMEOUT && self->thread.o1_timeout_scanned))) {
        self->thread.o1_audit = false;
        self->thread.o1_timeout_scanned = false;
        PAL_SVSM_NET_CTR_INC(o1_checked);
#ifdef PROF_ROW_GATHER
        pal_svsm_prof_mc(PROF_ROW_LOOKS, 1, 0);   /* looked (so "0 misses" is not "never looked") */
        uint64_t adv0[4];
        pal_svsm_sock_advances(adv0);
#endif
        int k = pal_svsm_watch_miss_kind(wh, we, wn);
#ifdef PROF_ROW_GATHER
        /* What this look ADVANCED (the discriminator): mc 0x2A a pending connect completed, 0x2B a
         * shared-channel frame routed, 0x2C a credit sent, 0x2D an owed FIN sent - work only a look
         * does, which the old wake-all's runs supplied for free. Counted once per look that did it. */
        uint64_t adv1[4];
        pal_svsm_sock_advances(adv1);
        for (unsigned i = 0; i < 4; i++)
            if (adv1[i] != adv0[i])
                pal_svsm_prof_mc(PROF_ROW_ADV(i), 1, 0);
#endif
        if (k >= 0 && k < O1K_N) {
            uint64_t late = pal_svsm_now_usec() - t0;
            PAL_SVSM_NET_CTR_INC(o1_miss[k]);
            uint64_t m = __atomic_load_n(&g_pal_svsm_net_ctr.o1_miss_max_us, __ATOMIC_RELAXED);
            if (late > m)
                __atomic_store_n(&g_pal_svsm_net_ctr.o1_miss_max_us, late, __ATOMIC_RELAXED);
#ifdef PROF_ROW_GATHER
            /* the diagnostic gramine: live, per vault, in the monitor's VAULT_PROF */
            pal_svsm_prof_mc(PROF_ROW_MISS((unsigned)k), 1, 0);
            pal_svsm_prof_mc(PROF_ROW_MISS_US((unsigned)k), late, 0);
#endif
        }
    }
#ifdef PROF_ROW_GATHER
    /* The blocked-time histogram (the O1 stall hunt, 2026-11-28; DIAGNOSIS ONLY): every watched wait,
     * by its kind (its first handle's), how it ended and how long it took. Where the time goes in a
     * partial breakdown, whether or not the scheduler's test was wrong:
     *   rows: pal_svsm_prof_rows.h (layout 2) - PROF_ROW_BT_DEADLINE / _NODL / PROF_ROW_BT(kind, bucket) */
    if (self && wn && t0 && g_pal_svsm_prof_on) {
        uint64_t us = pal_svsm_now_usec() - t0;
        unsigned k = (unsigned)pal_svsm_watch_kind(wh, wn) & 7;
        pal_svsm_prof_mc(PROF_ROW_BT(k, prof_bt_bucket(us)), 1, 0);
        if (r == PAL_SVSM_WAIT_TIMEOUT)
            pal_svsm_prof_mc(PROF_ROW_BT_DEADLINE(k), 1, 0);
        if (!deadline_us)
            pal_svsm_prof_mc(PROF_ROW_BT_NODL(k), 1, 0);
    }
#endif
    pal_svsm_sock_waiters_drop(marks, nmarks);
    return r;
}

/*
 * What this thread is about to wait on, in words the monitor can watch.
 *
 * Called just before blocking, by whoever knows what the wait is for.
 * `partial` says the caller had more it wanted watched than it could
 * fit, which the scheduler turns into a bounded fallback rather than an
 * indefinite park.
 */
void pal_svsm_thread_arm(const uint64_t* arms, size_t count, bool partial) {
    if (!g_current)
        return;
    if (count > PAL_SVSM_THREAD_ARMS) {
        count   = PAL_SVSM_THREAD_ARMS;
        partial = true;
    }
    for (size_t i = 0; i < count; i++)
        g_current->thread.arms[i] = arms[i];
    g_current->thread.n_arms       = (uint8_t)count;
    g_current->thread.arms_partial = partial;
}

/*
 * The handles a thread about to block in poll() is waiting on.
 *
 * Stored rather than copied: these point into the caller's frame, which
 * is alive for exactly as long as the thread is blocked in it, and
 * `pal_svsm_thread_block` clears them on the way out.
 */
void pal_svsm_thread_watch(size_t count, PAL_HANDLE* handles, pal_wait_flags_t* events) {
    if (!g_current)
        return;
    g_current->thread.watch_handles = handles;
    g_current->thread.watch_events  = events;
    g_current->thread.n_watch       = handles && events ? count : 0;
}

bool pal_svsm_others_runnable(uint64_t now_us, uint64_t* next_us) {
    if (!g_current)
        return false;
    for (PAL_HANDLE t = g_current->thread.next; t != g_current; t = t->thread.next) {
        if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE)
            return true;
        if (t->thread.state != PAL_SVSM_THREAD_BLOCKED)
            continue;
        if (t->thread.n_watch && pal_svsm_poller_ready(t))
            return true;
        if (t->thread.has_deadline) {
            if (now_us >= t->thread.deadline_us)
                return true;
            if (t->thread.deadline_us < *next_us)
                *next_us = t->thread.deadline_us;
        }
    }
    return false;
}

/* O1-WAKE.md A: ready the pollers that have something - each tested in place,
 * two loads per watched socket - and leave the others blocked. It used to ready
 * every one (wake_all of the token), and each unready poller was switched in,
 * re-tested its set, re-armed and blocked again: a herd per wake. */
#define PW_T                  PAL_HANDLE
#define PW_NEXT(t)            ((t)->thread.next)
#define PW_IS_POLLWAIT(t)     ((t)->thread.state == PAL_SVSM_THREAD_BLOCKED \
                               && (t)->thread.waiting_on == POLL_TOKEN)
#define PW_HAS_WATCH(t)       ((t)->thread.n_watch != 0)
#define PW_READY(t)           pal_svsm_poller_ready(t)
#define PW_DEADLINE_DUE(t, n) ((t)->thread.has_deadline && (n) >= (t)->thread.deadline_us)
#define PW_MAKE_RUNNABLE(t)   do { (t)->thread.waiting_on = NULL; \
                                   (t)->thread.state = PAL_SVSM_THREAD_RUNNABLE; PROF_RUNNABLE(t); } while (0)
#include "pal_svsm_wake.h"

void pal_svsm_poll_wake(void) {
    if (!g_pal_svsm_o1_wake) {
        pal_svsm_thread_wake_all(POLL_TOKEN);
        return;
    }
    if (!g_current)
        return;
    if (pw_wake_ready(g_current, pal_svsm_now_usec()))
        refresh_preempt_wanted();
}

void pal_svsm_thread_wake_all(PAL_HANDLE waiting_on) {
    if (!g_current || !waiting_on)
        return;

    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.waiting_on == waiting_on) {
            t->thread.waiting_on = NULL;
            t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
            PROF_RUNNABLE(t);
        }
        t = t->thread.next;
    } while (t != g_current);
    refresh_preempt_wanted();
}

/* One CPU, and it is not ours to hand out: the monitor decides which vCPU
 * runs this vault. Reporting the single online CPU keeps callers that read an
 * affinity mask working rather than failing. */
int _PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    __UNUSED(thread);
    if (!cpu_mask_len)
        return -PAL_ERROR_INVAL;
    /* Refuse a mask that excludes the only CPU there is, rather than pretend. */
    if (!(cpu_mask[0] & 1))
        return -PAL_ERROR_INVAL;
    return 0;
}

int _PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    __UNUSED(thread);
    if (!cpu_mask_len)
        return -PAL_ERROR_INVAL;
    memset(cpu_mask, 0, cpu_mask_len * sizeof(*cpu_mask));
    cpu_mask[0] = 1;
    return 0;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};

/* svsm.fork_report (pal_main.c): set from the manifest, read at each fork. */
bool g_pal_svsm_fork_report = false;

/* Every OTHER context on the ring, at the moment a fork is about to copy the
 * address space: its state, the LibOS lock holds it carries (counted, and
 * paused across a blocking wait - both invisible to the child's owner-less
 * copy of the lock), and where it is parked: its saved rsp and the first
 * words of its stack, which are the return addresses of whatever made it
 * yield. Symbolise against the image's maps. Diagnosis only.
 *
 * At ERROR level: the manifests it is meant for (SeBS, the fork fixtures)
 * set log_level = "error", which dropped every warning-level line of the
 * first run of it (q41: no report at all). */
void pal_svsm_threads_report_holds(int64_t foreign) {
    PAL_HANDLE me = g_current;
    log_error("fork-report: forker %p holds %ld paused %ld; foreign holds after the quiesce %ld",
                me, (long)pal_get_svsm_tcb()->lock_holds, (long)pal_get_svsm_tcb()->paused_holds,
                (long)foreign);
    for (PAL_HANDLE t = me->thread.next; t && t != me; t = t->thread.next) {
        PAL_SVSM_TCB* tt = (PAL_SVSM_TCB*)t->thread.tcb;
        const uint64_t* sp = (const uint64_t*)t->thread.rsp;
        log_error("fork-report: ctx %p state %d holds %ld paused %ld rsp %#lx stack "
                    "%#lx %#lx %#lx %#lx %#lx %#lx", t, (int)t->thread.state,
                    tt ? (long)tt->lock_holds : -1L, tt ? (long)tt->paused_holds : -1L,
                    (unsigned long)t->thread.rsp,
                    sp ? sp[0] : 0, sp ? sp[1] : 0, sp ? sp[2] : 0,
                    sp ? sp[3] : 0, sp ? sp[4] : 0, sp ? sp[5] : 0);
    }
}
