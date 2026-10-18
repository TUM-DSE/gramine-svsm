/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include <stdbool.h>

#include "assert.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "pal.h"

static inline bool lock_created(struct libos_lock* l) {
    return l->lock != NULL;
}

static inline void clear_lock(struct libos_lock* l) {
    l->lock  = NULL;
    l->owner = 0;
}

static inline bool create_lock(struct libos_lock* l) {
    l->owner = 0;
    return PalEventCreate(&l->lock, /*init_signaled=*/true, /*auto_clear=*/true) == 0;
}

static inline void destroy_lock(struct libos_lock* l) {
    PalObjectDestroy(l->lock);
    clear_lock(l);
}

/*
 * Real locks again. c8faaf17 ("update locks", 2025-01) made lock() and
 * unlock() no-ops - correct while the SVSM PAL ran one context and nothing
 * could interrupt LibOS code, and while _PalEventWait could not block. Both
 * have changed: the PAL schedules several contexts and the monitor's tick
 * preempts the LibOS anywhere outside the PAL's own text (signals.rs), on
 * the assumption that the LibOS "holds real locks", and _PalEventWait parks
 * a context until _PalEventSet. With no-op locks a tick between two list
 * operations corrupted `async_list` (libos_async.c): a cleanup event freed
 * while still linked, re-found by the async worker on every pass - the
 * vault_threads livelock, about 1 vault in 30 (2026-10-17).
 */
/*
 * Each hold is also counted by the PAL (PalLockHold), before the wait and
 * after the release, so that a CoW fork can wait until no other thread holds
 * a lock - a lock held by another thread at the instant memory is copied would
 * be held for ever in the child.
 */
static inline void lock(struct libos_lock* l) {
    assert(l->lock);

    PalLockHold(NULL, 1);
    while (PalEventWait(l->lock, /*timeout=*/NULL) < 0)
        /* nop */;

    l->owner = get_cur_tid();
}

static inline void unlock(struct libos_lock* l) {
    assert(l->lock);
    l->owner = 0;
    PalEventSet(l->lock);
    PalLockHold(NULL, -1);
}

/*
 * A blocking wait made while holding `n` locks: for its length they are not
 * counted for the fork (lock_holds_pause), and counted again after it
 * (lock_holds_resume).
 *
 * Counted, a lock held across a wait that may never end - a socket's
 * recv_lock while recv waits for data, its locks while connect waits for the
 * network service - was a hold that never drained: every fork from the
 * process waited the drain's whole bound (100 ms) and went ahead with it.
 * Only the WAIT is uncounted, so the bookkeeping either side of it (the peek
 * buffer) is still waited out by a fork. A fork that lands in the wait copies
 * the locks held, so whoever owns such locks makes the child fresh ones
 * (sockets_after_cow_fork) - the thread that held them does not exist in the
 * child. It also copies the socket as the wait left it: a connect's paused
 * span writes the addresses (and a unix socket's PAL handle), so a child
 * forked during a connect has a socket that is neither connected nor quite
 * new - as on Linux, a socket shared across fork mid-connect is the
 * program's to sort out, and the child should not reuse it.
 */
/*
 * lock(), but counted for the fork only once it is HELD - for a lock another
 * thread may hold across a long wait (a socket's, above). A thread queued
 * behind such a holder would otherwise be a hold for as long as the holder
 * waits, and every fork would wait its bound again. A fork that lands while
 * this waits copies the lock held; its owner's child remakes it. Released
 * with the ordinary unlock().
 */
static inline void lock_count_held(struct libos_lock* l) {
    assert(l->lock);
    while (PalEventWait(l->lock, /*timeout=*/NULL) < 0)
        /* nop */;
    PalLockHold(NULL, 1);
    l->owner = get_cur_tid();
}

static inline void lock_holds_pause(int n) {
    while (n-- > 0)
        PalLockHold(NULL, -1);
}

static inline void lock_holds_resume(int n) {
    while (n-- > 0)
        PalLockHold(NULL, 1);
}

#ifdef DEBUG
static inline bool locked(struct libos_lock* l) {
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}
#endif // DEBUG
