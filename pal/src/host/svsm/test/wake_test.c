/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Host-side test of the O(1)-wake policy (pal_svsm_wake.h; MicroVault
 * notes/libos/O1-WAKE.md): the scheduler's decisions on an imitation of the
 * PAL's thread ring.
 *
 *   make -C pal/src/host/svsm/test check
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { RUNNING, RUNNABLE, BLOCKED, ZOMBIE };

struct thr {
    struct thr* next;
    int state;
    int pollwait;        /* blocked on the poll token */
    int nowatch;         /* a token waiter with no watch set (pipe ring_wait, eventfd) */
    int ready;           /* what poller_ready would say */
    int has_deadline;
    unsigned long deadline;
    int switched_in;     /* how often a wake would have run it */
};

#define PW_T                   struct thr*
#define PW_NEXT(t)             ((t)->next)
#define PW_IS_POLLWAIT(t)      ((t)->state == BLOCKED && (t)->pollwait)
#define PW_HAS_WATCH(t)        (!(t)->nowatch)
#define PW_READY(t)            ((t)->ready)
#define PW_DEADLINE_DUE(t, n)  ((t)->has_deadline && (n) >= (t)->deadline)
#define PW_MAKE_RUNNABLE(t)    ((t)->state = RUNNABLE, (t)->switched_in++)
#include "../pal_svsm_wake.h"

static int g_fail, g_pass;
#define CHECK(c, ...) do { if (c) g_pass++; else { g_fail++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static struct thr* ring(size_t n) {
    struct thr* t = calloc(n, sizeof(*t));
    for (size_t i = 0; i < n; i++) {
        t[i].next = &t[(i + 1) % n];
        t[i].state = BLOCKED;
        t[i].pollwait = 1;
    }
    t[0].state = RUNNING;
    t[0].pollwait = 0;
    return t;
}

static int count_state(struct thr* t, size_t n, int st) {
    int c = 0;
    for (size_t i = 0; i < n; i++)
        c += t[i].state == st;
    return c;
}

int main(void) {
    /* A: many pollers, one ready - exactly that one is readied (the herd
     * readied all 256 and switched each in). */
    {
        size_t n = 257;
        struct thr* t = ring(n);
        t[123].ready = 1;
        unsigned w = pw_wake_ready(&t[0], 1000);
        CHECK(w == 1, "woke %u, want 1", w);
        CHECK(t[123].state == RUNNABLE, "the ready poller is not runnable");
        CHECK(count_state(t, n, BLOCKED) == 255, "others not left blocked: %d", count_state(t, n, BLOCKED));
        CHECK(t[0].state == RUNNING, "the running context changed");
        free(t);
    }
    /* A: none ready - nobody woken, nobody switched in */
    {
        size_t n = 64;
        struct thr* t = ring(n);
        unsigned w = pw_wake_ready(&t[0], 1000);
        int sw = 0;
        for (size_t i = 0; i < n; i++)
            sw += t[i].switched_in;
        CHECK(w == 0 && sw == 0, "woke %u / switched %d with nothing ready", w, sw);
        free(t);
    }
    /* A: a deadline past is a wake too (a poll that timed out meanwhile) */
    {
        size_t n = 8;
        struct thr* t = ring(n);
        t[5].has_deadline = 1; t[5].deadline = 999;
        t[6].has_deadline = 1; t[6].deadline = 2000;
        unsigned w = pw_wake_ready(&t[0], 1000);
        CHECK(w == 1 && t[5].state == RUNNABLE && t[6].state == BLOCKED, "deadline wake: %u", w);
        free(t);
    }
    /* A: a thread blocked on something else (an event, a mutex) is not a poller
     * and is never touched by a poll wake */
    {
        size_t n = 4;
        struct thr* t = ring(n);
        t[2].pollwait = 0; t[2].ready = 1;
        pw_wake_ready(&t[0], 0);
        CHECK(t[2].state == BLOCKED, "a non-poller was woken");
        free(t);
    }
    /* a token waiter with NO watch set (a pipe writer waiting for room, an eventfd)
     * cannot be tested in place: it is woken, as every token waiter was before -
     * the vault_fork_inflight hang (2026-11-27) was this one left blocked */
    {
        size_t n = 6;
        struct thr* t = ring(n);
        t[3].nowatch = 1;            /* not "ready" by any test - must be woken anyway */
        unsigned w = pw_wake_ready(&t[0], 0);
        CHECK(w == 1 && t[3].state == RUNNABLE, "a watchless token waiter was left blocked (woke %u)", w);
        CHECK(count_state(t, n, BLOCKED) == 4, "watched, unready pollers were woken too");
        free(t);
    }
    /* close-while-waiting: a parked recv whose socket another thread closed
     * reads as ready (sock_wait_ready: rd_over) - the wake must ready it */
    {
        size_t n = 3;
        struct thr* t = ring(n);
        t[1].ready = 1;      /* closed: its own test says ready */
        CHECK(pw_wake_ready(&t[0], 0) == 1 && t[1].state == RUNNABLE, "closed socket's waiter not woken");
        free(t);
    }
    /* fork child: one context left on the ring (pal_svsm_threads_child_after_fork)
     * - the wake walks just it, and a running context is never a poller */
    {
        struct thr self = { .state = RUNNING };
        self.next = &self;
        CHECK(pw_wake_ready(&self, 0) == 0 && self.state == RUNNING, "fork child: the forker changed");
    }
    /* B: the scan is due always with nothing else runnable (a park may follow),
     * else once per interval; interval 0 = every pass (the old behaviour) */
    CHECK(pw_scan_due(100, 99, 20, false), "no runnable: must scan");
    CHECK(!pw_scan_due(100, 90, 20, true), "runnable, 10 us since: must skip");
    CHECK(pw_scan_due(110, 90, 20, true), "runnable, 20 us since: must scan");
    CHECK(pw_scan_due(100, 99, 0, true), "interval 0: every pass");
    /* the park linger: off at 0, on for exactly linger_us */
    CHECK(!pw_linger_more(100, 100, 0), "linger 0 must not linger");
    CHECK(pw_linger_more(129, 100, 30), "29 us into a 30 us linger: go on");
    CHECK(!pw_linger_more(130, 100, 30), "30 us into a 30 us linger: park");
    /* C: which waits cover themselves */
    CHECK(pw_entry_covered(PW_ENTRY_SOCKET, 1, 0, 1), "counted READ socket must be covered");
    CHECK(!pw_entry_covered(PW_ENTRY_SOCKET, 1, 0, 0), "uncounted socket (no channel, listener) covered");
    CHECK(!pw_entry_covered(PW_ENTRY_SOCKET, 1, 1, 1), "READ|WRITE socket covered (room is not notified)");
    CHECK(!pw_entry_covered(PW_ENTRY_SOCKET, 0, 1, 0), "WRITE-only socket covered");
    CHECK(pw_entry_covered(PW_ENTRY_LOCAL, 1, 1, 0), "in-process pipe/eventfd must be covered");
    CHECK(!pw_entry_covered(PW_ENTRY_OTHER, 1, 0, 0), "shared pipe / other covered");

    printf("wake_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
