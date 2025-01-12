/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#pragma once

#include <stdint.h>
#include "spinlock.h"
#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

typedef struct pal_handle {
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

        struct {
            PAL_IDX fd;
        } console;

        struct {
            PAL_IDX fd;
            char* realpath;
            bool seekable; /* regular files are seekable, FIFO pipes are not */
            void *ptr; // pointer to the file data
            size_t size; // size of the file
            // for trusted files
            void * chunk_hashes; // array of hashes of file
                                 // chunks
        } file;

        struct {
            PAL_IDX fd;
            char* realpath;
            char* buf;
            bool endofstream;
        } dir;
    };

}* PAL_HANDLE;

/* These two flags indicate whether the underlying host fd of `PAL_HANDLE` is readable and/or
 * writable respectively. If none of these is set, then the handle has no host-level fd. */
#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2
/* Set if an error was seen on this handle. */
#define PAL_HANDLE_FD_ERROR     4
/* Set if a hang-up was seen on this handle. */
#define PAL_HANDLE_FD_HANG_UP   8

extern bool g_pal_preload_file;
