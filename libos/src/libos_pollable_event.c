/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "libos_internal.h"
#include "libos_pollable_event.h"
#include "libos_thread.h"
#include "libos_utils.h"
#include "log.h"
#include "pal.h"

/*
 * Thread reuse (MicroVault notes/libos/THREAD-REUSE.md, B; owner 2026-11-23).
 *
 * Every thread has a pollable event, a PAL pipe pair whose two 4 KiB rings put it past the PAL
 * slab's top class: a VirtAlloc to make and a VirtFree to destroy, per thread. A destroyed event
 * is now kept, up to [svsm] thread_cache of them, and the next create takes it.
 *
 * Drained on the way in: what is left in the pipe is set_pollable_event's wake bytes (it writes a
 * single 0 and nothing else ever writes these handles), so an undrained event would be a spurious
 * wake for its next owner, never anybody's data. The pair is private to this process (no options:
 * no shared rendezvous slot, so it never crosses a fork - pal_pipes.c pair_new), and a fork child
 * drops its copies (thread_cache_after_cow_fork).
 */
#define EVENT_CACHE_MAX 64
static spinlock_t g_ev_lock = INIT_SPINLOCK_UNLOCKED;
static struct libos_pollable_event g_ev_cache[EVENT_CACHE_MAX];
static int g_ev_n;
static struct pollable_event_cache_stats g_ev_stat;

/* Read until the pipe says there is nothing left; how many bytes, or -1 on a real error. */
static long drain_pollable_event(struct libos_pollable_event* event) {
    long total = 0;
    while (1) {
        char buf[0x100];
        size_t size = sizeof(buf);
        int ret = PalStreamRead(event->read_handle, /*offset=*/0, &size, buf);
        if (ret == -PAL_ERROR_INTERRUPTED)
            continue;
        if (ret == -PAL_ERROR_TRYAGAIN)
            return total;
        if (ret < 0 || size == 0)
            return -1;
        total += (long)size;
    }
}

static bool pollable_event_cache_pop(struct libos_pollable_event* event) {
    bool got = false;
    spinlock_lock(&g_ev_lock);
    if (g_ev_n) {
        g_ev_n--;
        event->read_handle  = g_ev_cache[g_ev_n].read_handle;
        event->write_handle = g_ev_cache[g_ev_n].write_handle;
        g_ev_cache[g_ev_n].read_handle  = NULL;
        g_ev_cache[g_ev_n].write_handle = NULL;
        g_ev_stat.hits++;
        got = true;
    } else {
        g_ev_stat.misses++;
    }
    spinlock_unlock(&g_ev_lock);
    if (got) {
        spinlock_init(&event->read_lock);
        spinlock_init(&event->write_lock);
    }
    return got;
}

static bool pollable_event_cache_push(struct libos_pollable_event* event) {
    if (!event->read_handle || !event->write_handle)
        return false;
    long drained = drain_pollable_event(event);
    if (drained < 0)
        return false;   /* not a pipe that reads as expected: destroyed, not reused */
    bool kept = false;
    spinlock_lock(&g_ev_lock);
    g_ev_stat.drained += (uint64_t)drained;
    if (g_ev_n < thread_cache_cap() && g_ev_n < EVENT_CACHE_MAX) {
        g_ev_cache[g_ev_n].read_handle  = event->read_handle;
        g_ev_cache[g_ev_n].write_handle = event->write_handle;
        g_ev_n++;
        kept = true;
    } else {
        g_ev_stat.full++;
    }
    spinlock_unlock(&g_ev_lock);
    if (kept) {
        event->read_handle  = NULL;
        event->write_handle = NULL;
    }
    return kept;
}

size_t pollable_event_cache_trim(void) {
    size_t freed = 0;
    while (1) {
        PAL_HANDLE r = NULL, w = NULL;
        spinlock_lock(&g_ev_lock);
        if (g_ev_n) {
            g_ev_n--;
            r = g_ev_cache[g_ev_n].read_handle;
            w = g_ev_cache[g_ev_n].write_handle;
            g_ev_cache[g_ev_n].read_handle  = NULL;
            g_ev_cache[g_ev_n].write_handle = NULL;
            g_ev_stat.trimmed++;
        }
        spinlock_unlock(&g_ev_lock);
        if (!r && !w)
            break;
        PalObjectDestroy(r);
        PalObjectDestroy(w);
        freed++;
    }
    return freed;
}

void pollable_event_cache_stats(struct pollable_event_cache_stats* out) {
    spinlock_lock(&g_ev_lock);
    *out = g_ev_stat;
    out->cached = (uint64_t)g_ev_n;
    spinlock_unlock(&g_ev_lock);
}

int create_pollable_event(struct libos_pollable_event* event) {
    if (pollable_event_cache_pop(event))
        return 0;

    char uri[PIPE_URI_SIZE];
    PAL_HANDLE srv_handle;
    /* No options: a pollable event is a thread-wakeup object, made and used
     * inside one process, and must not spend a shared rendezvous slot. */
    int ret = create_pipe(/*name=*/NULL, uri, sizeof(uri), &srv_handle,
                          /*use_vmid_for_name=*/false, /*options=*/0);
    if (ret < 0) {
        log_error("create_pipe failed: %s", unix_strerror(ret));
        return ret;
    }

    PAL_HANDLE write_handle;
    do {
        ret = PalStreamOpen(uri, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                            PAL_OPTION_NONBLOCK, &write_handle);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0) {
        log_error("PalStreamOpen failed: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    PAL_HANDLE read_handle;
    do {
        ret = PalStreamWaitForClient(srv_handle, &read_handle, PAL_OPTION_NONBLOCK);
    } while (ret == -PAL_ERROR_INTERRUPTED);
    if (ret < 0) {
        log_error("PalStreamWaitForClient failed: %s", pal_strerror(ret));
        PalObjectDestroy(write_handle);
        ret = pal_to_unix_errno(ret);
        goto out;
    }

    event->read_handle = read_handle;
    event->write_handle = write_handle;
    spinlock_init(&event->read_lock);
    spinlock_init(&event->write_lock);
    ret = 0;

out:;
    int tmp_ret = pal_to_unix_errno(PalStreamDelete(srv_handle, PAL_DELETE_ALL));
    PalObjectDestroy(srv_handle);
    if (!ret && tmp_ret) {
        PalObjectDestroy(read_handle);
        PalObjectDestroy(write_handle);
        /* Clearing just for sanity. */
        event->read_handle = NULL;
        event->write_handle = NULL;
    }
    return ret ?: tmp_ret;
}

void destroy_pollable_event(struct libos_pollable_event* event) {
    if (pollable_event_cache_push(event))
        return;
    PalObjectDestroy(event->read_handle);
    PalObjectDestroy(event->write_handle);
}

int set_pollable_event(struct libos_pollable_event* event) {
    int ret;

    spinlock_lock(&event->write_lock);

    do {
        char c = 0;
        size_t size = sizeof(c);
        ret = PalStreamWrite(event->write_handle, /*offset=*/0, &size, &c);
        ret = pal_to_unix_errno(ret);
        if (ret == 0 && size == 0) {
            ret = -EINVAL;
        }
        if (ret == -EAGAIN) {
            /* Pipe full - event already set. */
            ret = 0;
        }
    } while (ret == -EINTR);

    spinlock_unlock(&event->write_lock);
    return ret;
}

int clear_pollable_event(struct libos_pollable_event* event) {
    int ret = 0;

    spinlock_lock(&event->read_lock);

    do {
        char buf[0x100];
        size_t size = sizeof(buf);
        ret = PalStreamRead(event->read_handle, /*offset=*/0, &size, buf);
        ret = pal_to_unix_errno(ret);
        if (ret == 0 && size == 0) {
            ret = -EINVAL;
        }
        if (ret == -EAGAIN) {
            /* Event not set. */
            ret = 0;
        }
    } while (ret == -EINTR);

    spinlock_unlock(&event->read_lock);
    return ret;
}
