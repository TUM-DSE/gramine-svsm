/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * The O(1)-wake policy for many-thread vaults (MicroVault notes/libos/O1-WAKE.md;
 * owner GO 2026-11-27): the decisions only, inline, so that the host-side tests
 * (test/wake_test.c) run the very code the scheduler runs.
 *
 * Measured before it (the DSB media breakdown, compose-review-service, a Thrift
 * TThreadedServer with one thread per connection, ~18-38 of them blocked in
 * poll): pick_next's re-test of every blocked poller was 89% (R50) / 64% (R700)
 * of the vault's syscall-layer CPU, and every park was partial (bounded 20 ms).
 *
 *  A. A wake readies only the pollers whose handles ARE ready (pw_wake_ready),
 *     where it used to ready every one of them (wake_all of the poll token):
 *     each unready one was switched in, re-tested its set, re-armed and blocked
 *     again - a herd of context switches per wake.
 *  B. While another context is runnable, the blocked pollers are re-tested at
 *     most every `interval` us (pw_scan_due); with none runnable - the only
 *     time the vault can park - always. Nothing parks without a full re-test.
 *  C. A blocked thread whose every waited handle wakes this vault by itself
 *     (pw_entry_covered) leaves its arms out of the park, so a vault of many
 *     such threads is no longer "partial" and parks on the fallback bound only.
 *
 * The includer defines, for its thread pointer type PW_T:
 *   PW_NEXT(t)             the next context on the round-robin ring
 *   PW_IS_POLLWAIT(t)      blocked on the poll token (a poll() or a socket wait)
 *   PW_HAS_WATCH(t)        it left a watch set (poll, a socket wait); the token's
 *                          OTHER waiters - a pipe's ring_wait, an eventfd - have
 *                          none and re-test only in their own context
 *   PW_READY(t)            is anything it watches ready now (loads only)
 *   PW_DEADLINE_DUE(t, n)  it has a deadline and `n` is past it
 *   PW_MAKE_RUNNABLE(t)    unblock it (its re-test in its own context follows)
 */
/* Two parts, each guarded on its own: the policy (always), and pw_wake_ready,
 * which needs the accessors - included again once PW_T is defined. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PAL_SVSM_WAKE_POLICY_H
#define PAL_SVSM_WAKE_POLICY_H

/* B's interval: a poller whose data arrives while the vault is busy is seen at
 * most this late. 0 = every pass, as before. svsm.poll_scan_us overrides. */
#define PW_SCAN_INTERVAL_US_DEFAULT 20


/* B: re-test the blocked pollers on this pass? Always when nothing else can
 * run (the pass may end in a park), else once per `interval` us. */
static inline bool pw_scan_due(uint64_t now_us, uint64_t last_us, uint64_t interval_us,
                               bool others_runnable) {
    if (!others_runnable || !interval_us)
        return true;
    return now_us - last_us >= interval_us;
}

/* C: does one waited entry wake this vault on its own, so that its arm is not
 * needed for the park? */
enum pw_entry_kind {
    PW_ENTRY_SOCKET,      /* a channel socket */
    PW_ENTRY_LOCAL,       /* an in-process pipe or eventfd: only a thread of this
                             vault can make it ready, and that thread runs */
    PW_ENTRY_OTHER,       /* a shared pipe, a listener, anything else */
};

static inline bool pw_entry_covered(enum pw_entry_kind kind, bool want_read, bool want_write,
                                    bool waiter_counted) {
    switch (kind) {
        case PW_ENTRY_SOCKET:
            /* Its writer Notifies while this thread counts in WAITERS
             * (NOTIFY-ELISION.md) - for READ. Room to WRITE comes from the
             * reader's consumer index, which nothing notifies. */
            return want_read && !want_write && waiter_counted;
        case PW_ENTRY_LOCAL:
            return true;
        default:
            return false;
    }
}
#endif /* PAL_SVSM_WAKE_POLICY_H */

#if defined(PW_T) && !defined(PAL_SVSM_WAKE_READY_H)
#define PAL_SVSM_WAKE_READY_H
/* A: ready the pollers that have something, and nobody else. Returns how many.
 * A poller whose deadline has passed is readied too, so a wake never costs it
 * its timeout. `start` is any context of the ring (the current one). */
static inline unsigned pw_wake_ready(PW_T start, uint64_t now) {
    unsigned n = 0;
    PW_T t = start;
    do {
        /* A waiter with no watch set cannot be tested here, so it is woken as
         * every token waiter was before (vault_fork_inflight, 2026-11-27: a pipe
         * writer waiting for room was never woken by the reader's poll_wake). */
        if (PW_IS_POLLWAIT(t) && (!PW_HAS_WATCH(t) || PW_READY(t) || PW_DEADLINE_DUE(t, now))) {
            PW_MAKE_RUNNABLE(t);
            n++;
        }
        t = PW_NEXT(t);
    } while (t != start);
    return n;
}
#endif
