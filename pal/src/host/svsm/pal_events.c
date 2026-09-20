/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "assert.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"
#include "spinlock.h"

int _PalEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear) {
    PAL_HANDLE handle = calloc(1, HANDLE_SIZE(event));
    if (!handle) {
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(handle, PAL_TYPE_EVENT);
    spinlock_init(&handle->event.lock);
    handle->event.auto_clear = auto_clear;
    handle->event.waiters_cnt = 0;
    __atomic_store_n(&handle->event.signaled, init_signaled ? 1 : 0, __ATOMIC_RELEASE);

    *handle_ptr = handle;
    return 0;
}

void _PalEventSet(PAL_HANDLE handle) {
    spinlock_lock(&handle->event.lock);
    __atomic_store_n(&handle->event.signaled, 1, __ATOMIC_RELEASE);
    bool need_wake = handle->event.waiters_cnt > 0;
    spinlock_unlock(&handle->event.lock);
    if (need_wake) {
        /* Everyone parked on this handle, not just one, even for an
         * auto-clear event: they re-test the flag on the way out of
         * pal_svsm_thread_block and whoever loses goes straight back to
         * sleep. Waking one would mean tracking which, and with a handful of
         * contexts on one CPU that bookkeeping costs more than the extra
         * pass round the ring. */
        pal_svsm_thread_wake_all(handle);
    }
}

void _PalEventClear(PAL_HANDLE handle) {
    spinlock_lock(&handle->event.lock);
    __atomic_store_n(&handle->event.signaled, 0, __ATOMIC_RELEASE);
    spinlock_unlock(&handle->event.lock);
}

/*
 * Wait for the event, for `*timeout_us` microseconds, or until interrupted.
 *
 * This used to spin forever inside log_error("Sleep not implemented"), and
 * because each log line is a monitor call it flooded the console while doing
 * it. It also never looked at `timeout_us`. Everything that blocks in LibOS
 * comes through here - the futex (sys/libos_futex.c) and nanosleep
 * (sys/libos_sleep.c) among them - so until now time.sleep() hung a vault and
 * no lock could ever be waited on.
 *
 * On return `*timeout_us` is what is left of the timeout, and -TRYAGAIN means
 * it ran out: the same contract as the Linux PAL, which LibOS relies on.
 */
int _PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    int ret = 0;
    uint64_t deadline_us = 0;
    if (timeout_us)
        deadline_us = pal_svsm_now_usec() + *timeout_us;

    spinlock_lock(&handle->event.lock);
    handle->event.waiters_cnt++;

    while (1) {
        bool needs_sleep = false;
        if (handle->event.auto_clear) {
            needs_sleep = __atomic_exchange_n(&handle->event.signaled, 0, __ATOMIC_ACQ_REL) == 0;
        } else {
            needs_sleep = __atomic_load_n(&handle->event.signaled, __ATOMIC_ACQUIRE) == 0;
        }

        if (!needs_sleep) {
            ret = 0;
            break;
        }

        /* Unlocked across the park, so that whoever is going to signal this
         * event can take the lock when the scheduler gives them the CPU. A
         * lock held across a switch would deadlock outright: there is one
         * CPU, so the holder is the only thread that can release it. */
        spinlock_unlock(&handle->event.lock);
        enum pal_svsm_wait_result wr =
            pal_svsm_thread_block(handle, timeout_us ? &deadline_us : NULL);
        spinlock_lock(&handle->event.lock);

        if (wr == PAL_SVSM_WAIT_TIMEOUT) {
            ret = -PAL_ERROR_TRYAGAIN;
            break;
        }
        if (wr == PAL_SVSM_WAIT_INTERRUPTED) {
            ret = -PAL_ERROR_INTERRUPTED;
            break;
        }
        /* Woken: round again and re-test, because another waiter may have
         * taken the signal first. */
    }

    handle->event.waiters_cnt--;
    spinlock_unlock(&handle->event.lock);

    if (timeout_us) {
        uint64_t now = pal_svsm_now_usec();
        *timeout_us = now >= deadline_us ? 0 : deadline_us - now;
        assert(ret != -PAL_ERROR_TRYAGAIN || *timeout_us == 0);
    }
    return ret;
}

static void event_destroy(PAL_HANDLE handle) {
    /* noop */
}

struct handle_ops g_event_ops = {
    .destroy = event_destroy,
};
