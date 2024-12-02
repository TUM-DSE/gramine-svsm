/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "assert.h"
#include "pal_error.h"
#include "pal_internal.h"
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
        log_error("Need Wake not implemented");
    }
}

void _PalEventClear(PAL_HANDLE handle) {
    spinlock_lock(&handle->event.lock);
    __atomic_store_n(&handle->event.signaled, 0, __ATOMIC_RELEASE);
    spinlock_unlock(&handle->event.lock);
}

int _PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    int ret;

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

        spinlock_unlock(&handle->event.lock);

        log_error("Sleep not implemented");

        spinlock_lock(&handle->event.lock);

    }

    handle->event.waiters_cnt--;
    spinlock_unlock(&handle->event.lock);

    return ret;
}

static void event_destroy(PAL_HANDLE handle) {
    /* noop */
}

struct handle_ops g_event_ops = {
    .destroy = event_destroy,
};
