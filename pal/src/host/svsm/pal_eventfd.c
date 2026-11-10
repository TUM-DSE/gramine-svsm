/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019 Intel Corporation */

/*
 * This file contains operations to handle streams with URIs that have "eventfd:".
 *
 * In the SVSM PAL an eventfd is an in-process counter (DSB bring-up,
 * 2026-11-10: mongod's asio and memcached's libevent need one, and every
 * eventfd2 answered ENOSYS here - mongod aborted at startup). Both LibOS
 * modes open one of these: passthrough uses it as THE eventfd, the default
 * emulation as a "dummy" it writes to and reads from only to make a
 * poll/epoll/select see the object change. Either way the semantics are
 * eventfd(2)'s: 8-byte reads and writes; a read returns the count and zeroes
 * it (or 1 and decrements, EFD_SEMAPHORE) and waits while it is 0; a write
 * adds and waits while the sum would pass 0xfffffffffffffffe; readable when
 * the count is not 0, writable while it is below that. A change wakes this
 * process's waiters (pal_svsm_poll_wake), which is all a waiter can be.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"

#define EFD_MAX 0xfffffffffffffffeULL

/* `type` must be eventfd, `uri` & `access` & `share` are unused, `create` holds eventfd's initval,
 * `options` holds eventfd's flags */
static int eventfd_pal_open(PAL_HANDLE* handle, const char* type, const char* uri,
                            enum pal_access access, pal_share_flags_t share,
                            enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);
    if (strcmp(type, URI_TYPE_EVENTFD) != 0 || *uri != '\0')
        return -PAL_ERROR_INVAL;
    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(eventfd));
    if (!hdl)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(hdl, PAL_TYPE_EVENTFD);
    hdl->eventfd.val         = 0;   /* the LibOS writes the initial count */
    hdl->eventfd.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    hdl->eventfd.semaphore   = !!(options & PAL_OPTION_EFD_SEMAPHORE);
    *handle = hdl;
    return 0;
}

/* offset does not apply here. */
static int64_t eventfd_pal_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;
    if (handle->hdr.type != PAL_TYPE_EVENTFD)
        return -PAL_ERROR_NOTCONNECTION;
    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;
    for (;;) {
        uint64_t v = __atomic_load_n(&handle->eventfd.val, __ATOMIC_ACQUIRE);
        if (v) {
            uint64_t take = handle->eventfd.semaphore ? 1 : v;
            if (!__atomic_compare_exchange_n(&handle->eventfd.val, &v, v - take, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                continue;
            memcpy(buffer, &take, sizeof(take));
            pal_svsm_poll_wake();   /* room for a writer that was full */
            return sizeof(take);
        }
        if (handle->eventfd.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        if (pal_svsm_poll_block(NULL) == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
    }
}

/* offset does not apply here. */
static int64_t eventfd_pal_write(PAL_HANDLE handle, uint64_t offset, uint64_t len,
                                 const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;
    if (handle->hdr.type != PAL_TYPE_EVENTFD)
        return -PAL_ERROR_NOTCONNECTION;
    if (len < sizeof(uint64_t))
        return -PAL_ERROR_INVAL;
    uint64_t add;
    memcpy(&add, buffer, sizeof(add));
    if (add == UINT64_MAX)
        return -PAL_ERROR_INVAL;
    for (;;) {
        uint64_t v = __atomic_load_n(&handle->eventfd.val, __ATOMIC_ACQUIRE);
        if (add <= EFD_MAX - v) {
            if (!__atomic_compare_exchange_n(&handle->eventfd.val, &v, v + add, false,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                continue;
            if (add)
                pal_svsm_poll_wake();
            return sizeof(add);
        }
        if (handle->eventfd.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        if (pal_svsm_poll_block(NULL) == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
    }
}

bool pal_svsm_eventfd_readable(PAL_HANDLE handle) {
    return __atomic_load_n(&handle->eventfd.val, __ATOMIC_ACQUIRE) != 0;
}

bool pal_svsm_eventfd_writable(PAL_HANDLE handle) {
    return __atomic_load_n(&handle->eventfd.val, __ATOMIC_ACQUIRE) < EFD_MAX;
}

/* gets used for polling(query) on eventfd from LibOS. */
static int eventfd_pal_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->eventfd.nonblocking;
    attr->pending_size = pal_svsm_eventfd_readable(handle) ? sizeof(uint64_t) : 0;
    return 0;
}

static int eventfd_pal_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    handle->eventfd.nonblocking = attr->nonblocking;
    return 0;
}

static void eventfd_pal_destroy(PAL_HANDLE handle) {
    free(handle);
}

struct handle_ops g_eventfd_ops = {
    .open           = &eventfd_pal_open,
    .read           = &eventfd_pal_read,
    .write          = &eventfd_pal_write,
    .destroy        = &eventfd_pal_destroy,
    .attrquerybyhdl = &eventfd_pal_attrquerybyhdl,
    .attrsetbyhdl   = &eventfd_pal_attrsetbyhdl,
};
