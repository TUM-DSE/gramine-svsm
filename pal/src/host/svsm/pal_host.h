/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#pragma once

#include <stdint.h>
#include "spinlock.h"

struct pal_svsm_pipe_pair;
#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

/* Named, unlike the other hosts' anonymous version, because a thread handle
 * links to the next one in the scheduler's ring (see pal_threading.c). */
struct pal_handle_inner;
typedef struct pal_handle_inner* PAL_HANDLE;

struct pal_handle_inner {
    /* TSAI: Here we define the internal types of PAL_HANDLE in PAL design, user has not to access
     * the content inside the handle, also there is no need to allocate the internal handles, so we
     * hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;
    uint32_t flags;

    /*
     * PAL has different kinds of handles, so you probably want to add an union with data specific
     * for following types:
     * - file,
     * - pipe,
     * - eventfd,
     * - dev,
     * - dir,
     * - sock,
     * - process,
     * - thread,
     * - event.
     * Note that this is just a hint, not a requirement. You can check the Linux PAL for a sample
     * implementation.
     */
    union {
        struct {
            spinlock_t lock;
            uint32_t waiters_cnt;
            uint32_t signaled;
            bool auto_clear;
        } event;

        /* A cooperative context, not a vCPU: the monitor runs one VMSA per
         * vault and refuses a second entrant into it, so everything here is
         * scheduled by the PAL itself inside that one thread of execution.
         * See pal_threading.c. */
        struct {
            void*      stack;        /* the malloc'd block, NULL for the first
                                        thread (its stack is the monitor's) */
            void*      rsp;          /* where the context sits while not running */
            uint64_t   fsbase;       /* the application's thread pointer (glibc TLS) */
            void*      tcb;          /* PAL_SVSM_TCB, at the top of the block */
            PAL_HANDLE next;         /* round-robin ring, never NULL */
            PAL_HANDLE waiting_on;   /* what it is parked on, NULL if nothing */
            uint64_t   deadline_us;  /* absolute wake time, 0 = no deadline */
            uint32_t   state;        /* enum pal_svsm_thread_state */
            bool       has_deadline;
            bool       interrupted;  /* _PalThreadResume landed */
            bool       timed_out;
        } thread;

        struct {
            PAL_IDX fd;
        } console;

        /* Both ends of a pipe live in this address space - a vault is one
         * process - so a pipe is a pair of rings rather than anything the
         * host knows about. See pal_pipes.c. */
        struct {
            struct pal_svsm_pipe_pair* pair;
            char*    name;       /* PIPESRV only: what a connect must match */
            unsigned side;       /* which end of the pair this handle is */
            bool     nonblocking;
        } pipe;

        struct {
            PAL_IDX fd;
            char* realpath;
            bool seekable; /* regular files are seekable, FIFO pipes are not */
        } file;

        struct {
            PAL_IDX fd;
            char* realpath;
            char* buf;
            bool endofstream;
        } dir;
    };

};

/* These two flags indicate whether the underlying host fd of `PAL_HANDLE` is readable and/or
 * writable respectively. If none of these is set, then the handle has no host-level fd. */
#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2
/* Set if an error was seen on this handle. */
#define PAL_HANDLE_FD_ERROR     4
/* Set if a hang-up was seen on this handle. */
#define PAL_HANDLE_FD_HANG_UP   8
