/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of Drawbridge event synchronization APIs.
 */

#include "assert.h"
#include "pal_error.h"
#include "pal_internal.h"

int _PalEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

void _PalEventSet(PAL_HANDLE handle) {
    assert(0);
}

void _PalEventClear(PAL_HANDLE handle) {
    assert(0);
}

int _PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void event_destroy(PAL_HANDLE handle) {
    /* noop */
}

struct handle_ops g_event_ops = {
    .destroy = event_destroy,
};

/* No fork that copies memory on this host, so nothing to count: only the add. */
int64_t _PalLockHold(int64_t* word, int64_t delta) {
    return word ? __atomic_fetch_add(word, delta, __ATOMIC_SEQ_CST) : 0;
}

bool _PalLockHoldTry(void) {
    return true;    /* nothing gated, nothing counted */
}

void _PalLockHoldPause(int64_t n) {
    __UNUSED(n);    /* nothing counted */
}
