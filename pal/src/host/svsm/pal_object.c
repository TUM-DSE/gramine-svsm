/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for closing or polling PAL handles.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"

/* What is true of this handle right now, out of what was asked about. */
static pal_wait_flags_t poll_one(PAL_HANDLE handle, pal_wait_flags_t want) {
    pal_wait_flags_t got = 0;

    switch (handle->hdr.type) {
        case PAL_TYPE_PIPE:
            if ((want & PAL_WAIT_READ) && pal_svsm_pipe_readable(handle))
                got |= PAL_WAIT_READ;
            if ((want & PAL_WAIT_WRITE) && pal_svsm_pipe_writable(handle))
                got |= PAL_WAIT_WRITE;
            /* A peer that has gone is reported as readable so the reader
             * gets its zero-length read and sees the end of the stream,
             * which is what poll(2) does with POLLHUP. */
            if ((want & PAL_WAIT_READ) && pal_svsm_pipe_peer_gone(handle))
                got |= PAL_WAIT_READ;
            break;

        case PAL_TYPE_SOCKET:
            /* Two loads from the ring's control words, no monitor call -
             * which is what makes a poll over many sockets cheap. A peer
             * that has gone reads as readable, so the caller gets its
             * zero-length recv and sees the end of the stream. */
            if ((want & PAL_WAIT_READ) && pal_svsm_sock_readable(handle))
                got |= PAL_WAIT_READ;
            if ((want & PAL_WAIT_WRITE) && pal_svsm_sock_writable(handle))
                got |= PAL_WAIT_WRITE;
            break;

        case PAL_TYPE_PIPESRV:
            if ((want & PAL_WAIT_READ) && pal_svsm_pipesrv_pending(handle))
                got |= PAL_WAIT_READ;
            break;

        default:
            /* Files, the console and the pseudo-devices are never not ready,
             * the same answer Linux gives for a regular file. Reporting them
             * as never ready instead would hang anything that polls one. */
            got = want;
            break;
    }
    return got;
}

/*
 * Is anything this blocked thread is polling ready now?
 *
 * Called by the scheduler, for a thread that is not the running one, so it
 * must only read: `poll_one` is loads from rings and ring headers and does
 * nothing else.
 */
bool pal_svsm_poller_ready(PAL_HANDLE thread) {
    for (size_t i = 0; i < thread->thread.n_watch; i++) {
        PAL_HANDLE h = thread->thread.watch_handles[i];
        if (h && poll_one(h, thread->thread.watch_events[i]))
            return true;
    }
    return false;
}

/*
 * Wait until one of these handles has one of these events, or the timeout
 * runs out.
 *
 * This returned NOTIMPLEMENTED until now, which nothing noticed because
 * nothing that uses it could run: LibOS's async worker - the thread that
 * reaps exited threads and fires timers - is the main caller, and it could
 * not be started at all while _PalThreadCreate was a stub. With threads it
 * starts, and the first thing it does is call this.
 *
 * -TRYAGAIN means the timeout ran out, 0 means something is ready; both are
 * expected by the callers. `*timeout_us` is left holding what is unused.
 */
int _PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                          pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
    uint64_t deadline_us = 0;
    if (timeout_us)
        deadline_us = pal_svsm_now_usec() + *timeout_us;

    int ret = 0;
    while (1) {
        bool any = false;
        for (size_t i = 0; i < count; i++) {
            ret_events[i] = 0;
            if (!handle_array[i])
                continue;
            ret_events[i] = poll_one(handle_array[i], events[i]);
            if (ret_events[i])
                any = true;
        }
        if (any)
            break;

        /* Nothing yet, so say WHAT would change that before giving the
         * processor back. Without this the vault parks blind and wakes
         * on its own timeout - a server polling ten sockets learns about
         * a request when its poll expires, not when the request
         * arrives - and `epoll_wait(-1)` had nothing that could ever
         * end it, which the PAL used to call a deadlock and die on.
         *
         * A socket already readable contributes nothing: it is ready,
         * and `any` above would have seen it. More sockets than arms is
         * not an error, it is `partial`, and the scheduler turns that
         * into a bounded park. */
        uint64_t arms[PAL_SVSM_THREAD_ARMS];
        size_t n_arms = 0;
        bool partial = false;
        for (size_t i = 0; i < count; i++) {
            if (!handle_array[i] || handle_array[i]->hdr.type != PAL_TYPE_SOCKET)
                continue;
            uint64_t arm;
            if (!pal_svsm_sock_arm(handle_array[i], events[i], &arm))
                continue;
            if (n_arms == PAL_SVSM_THREAD_ARMS) {
                partial = true;
                break;
            }
            arms[n_arms++] = arm;
        }
        pal_svsm_thread_arm(arms, n_arms, partial);
        /* And leave the set itself where the scheduler can re-test it, for
         * the far more common case where this vault keeps running (an
         * async worker, another thread) and so never parks at all. */
        pal_svsm_thread_watch(count, handle_array, events);

        enum pal_svsm_wait_result wr = pal_svsm_poll_block(timeout_us ? &deadline_us : NULL);
        if (wr == PAL_SVSM_WAIT_TIMEOUT) {
            ret = -PAL_ERROR_TRYAGAIN;
            break;
        }
        if (wr == PAL_SVSM_WAIT_INTERRUPTED) {
            ret = -PAL_ERROR_INTERRUPTED;
            break;
        }
    }

    if (timeout_us) {
        uint64_t now = pal_svsm_now_usec();
        *timeout_us = now >= deadline_us ? 0 : deadline_us - now;
    }
    return ret;
}
