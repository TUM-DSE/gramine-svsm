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
            /* And a hang-up when nobody holds the other end any more - as
             * poll(2) says POLLHUP for a pipe whose writers have all closed -
             * or when shutdowns have closed both directions of a socket. Not
             * for a shutdown of one direction (the peer is still there). The
             * write end of a pipe turns this into POLLERR (fs/pipe). */
            if (pal_svsm_pipe_hung_up(handle))
                got |= PAL_WAIT_HANG_UP;
            break;

        case PAL_TYPE_SOCKET:
            /* A blocking send or recv waiting in the scheduler: its own test,
             * and nothing it did not ask for (pal_svsm.h). */
            if (want & PAL_SVSM_WAIT_SOCK)
                return pal_svsm_sock_wait_ready(handle, want);
            /* Two loads from the ring's control words, no monitor call -
             * which is what makes a poll over many sockets cheap. A peer
             * that has gone reads as readable, so the caller gets its
             * zero-length recv and sees the end of the stream. */
            if ((want & PAL_WAIT_READ) && pal_svsm_sock_readable(handle))
                got |= PAL_WAIT_READ;
            if ((want & PAL_WAIT_WRITE) && pal_svsm_sock_writable(handle))
                got |= PAL_WAIT_WRITE;
            /* And SAY it is a hang-up, which readable alone does not.
             *
             * PAL_WAIT_HANG_UP is not reported on request - poll(2) and
             * epoll(2) both deliver POLLHUP/EPOLLHUP whether or not the
             * caller asked - so this is set outside the `want` tests above.
             * Two consumers were already written for it and had never been
             * given one: libos/src/sys/libos_epoll.c turns it into EPOLLHUP
             * (plus EPOLLRDHUP when asked), and socket/fs.c's post_poll uses
             * it to decide whether a non-blocking connect that is still in
             * progress FAILED. Without it such a connect saw its socket go
             * readable and concluded it had succeeded. */
            if (pal_svsm_sock_peer_gone(handle))
                got |= PAL_WAIT_HANG_UP;
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
int g_pal_svsm_sched_ctx;
bool g_pal_svsm_sched_deferred;

bool pal_svsm_poller_ready(PAL_HANDLE thread) {
    /* SCHEDULER context: on the way here from a preemption upcall the
     * interrupted thread may be anywhere in the LibOS or the application, on
     * its alternate stack. What a re-test does must therefore be safe at any
     * instruction boundary of theirs - no heap (pal_svsm_sched_ctx, read by
     * the socket router). */
    g_pal_svsm_sched_ctx++;
    g_pal_svsm_sched_deferred = false;
    bool ready = false;
    for (size_t i = 0; i < thread->thread.n_watch && !ready; i++) {
        PAL_HANDLE h = thread->thread.watch_handles[i];
        if (h && poll_one(h, thread->thread.watch_events[i]))
            ready = true;
    }
    g_pal_svsm_sched_ctx--;
    /* A re-test that needed the heap and did without it (a pool buffer not
     * yet allocated, the scratch buffer) cannot tell whether this thread's
     * handle is ready. So it is woken: it looks again in its own context,
     * where the heap is safe, and allocates there. Otherwise the frame would
     * wait at the head for a deadline - or for ever, under a poll() with
     * none (review by jamie). */
    if (!ready && g_pal_svsm_sched_deferred)
        ready = true;
    return ready;
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

        /* A SHARED pipe has no arm and no wake that reaches here. Its
         * writer may be another process - that is what [svsm.pipes] is for
         * - and `pal_svsm_poll_wake` only walks THIS process's threads, so
         * nothing in this vault will ever signal the poller. Arming is not
         * an option either: only sockets have an address the monitor can
         * watch, and parking at all needs a service slot an ordinary vault
         * does not have. So such a poll looks again on a short deadline,
         * the same way a blocking read on one does (pal_pipes.c).
         *
         * Without it `subprocess.communicate()` is a deadlock: CPython
         * selects on the child's stdout and the child writing it is not a
         * thread of this process. */
        uint64_t eff_deadline;
        const uint64_t* dl = timeout_us ? &deadline_us : NULL;
        bool shared_pipe = false;
        for (size_t i = 0; i < count; i++) {
            if (handle_array[i] && pal_svsm_pipe_is_shared(handle_array[i])) {
                shared_pipe = true;
                break;
            }
        }
        if (shared_pipe) {
            eff_deadline = pal_svsm_now_usec() + PAL_SVSM_SHARED_PIPE_POLL_US;
            if (!dl || eff_deadline < *dl)
                dl = &eff_deadline;
        }

        enum pal_svsm_wait_result wr = pal_svsm_poll_block(dl);
        if (wr == PAL_SVSM_WAIT_TIMEOUT) {
            /* Only the CALLER's deadline ends this. The one above is an
             * invitation to re-test, and reporting it as the caller's would
             * turn a poll with no timeout into one that returns TRYAGAIN
             * every 200 us. */
            if (timeout_us && pal_svsm_now_usec() >= deadline_us) {
                ret = -PAL_ERROR_TRYAGAIN;
                break;
            }
            continue;
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
