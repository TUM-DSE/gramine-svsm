/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Pipes inside a vault.
 *
 * On other hosts a pipe is a kernel object and the two ends may be in
 * different processes. A vault is exactly one process with no host to ask, so
 * a pipe here is a pair of rings in its own memory: `pipe.srv:<name>` records
 * a name, `pipe:<name>` connects to it, and PalStreamWaitForClient hands back
 * the other end.
 *
 * This existed as a stub - open succeeded and read and write returned
 * NOTIMPLEMENTED - which was invisible for as long as nothing could start a
 * second thread. It stops being invisible the moment one can: LibOS builds
 * its pollable events out of a non-blocking pipe pair (libos_pollable_event.c
 * writes a byte to set one and drains it to clear), and the async worker -
 * which reaps exited threads and runs timers - waits on one. With the pipe
 * faked, the worker took a NOTIMPLEMENTED from PalStreamsWaitEvents on its
 * first pass and killed the process.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_svsm.h"

#define PIPE_RING_SIZE   4096
/* create_pollable_event connects and accepts back to back, so one is really
 * enough; the rest are slack for LibOS's own IPC pipes at startup. */
#define PIPE_PENDING_MAX 8

struct pal_svsm_pipe_ring {
    size_t head;                    /* next byte to read */
    size_t used;                    /* bytes in the ring */
    char   data[PIPE_RING_SIZE];
};

struct pal_svsm_pipe_pair {
    /* dir[s] is what side s wrote and side !s reads. */
    struct pal_svsm_pipe_ring dir[2];
    bool   open[2];                 /* is that end still attached */
    int    refs;
};

struct pipe_pending {
    char* name;
    struct pal_svsm_pipe_pair* pair;
};
static struct pipe_pending g_pending[PIPE_PENDING_MAX];

static struct pal_svsm_pipe_pair* pair_new(void) {
    struct pal_svsm_pipe_pair* p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    p->refs = 1;
    p->open[0] = true;
    /* Side 1 does not exist until somebody accepts; until then side 0 must
     * not see EOF, only "nothing yet". */
    p->open[1] = true;
    return p;
}

static void pair_put(struct pal_svsm_pipe_pair* p) {
    if (!p)
        return;
    if (--p->refs == 0)
        free(p);
}

static size_t ring_write(struct pal_svsm_pipe_ring* r, const char* buf, size_t len) {
    size_t space = PIPE_RING_SIZE - r->used;
    if (len > space)
        len = space;
    for (size_t i = 0; i < len; i++)
        r->data[(r->head + r->used + i) % PIPE_RING_SIZE] = buf[i];
    r->used += len;
    return len;
}

static size_t ring_read(struct pal_svsm_pipe_ring* r, char* buf, size_t len) {
    if (len > r->used)
        len = r->used;
    for (size_t i = 0; i < len; i++)
        buf[i] = r->data[(r->head + i) % PIPE_RING_SIZE];
    r->head = (r->head + len) % PIPE_RING_SIZE;
    r->used -= len;
    return len;
}

/* The ring this handle reads from, and the one it writes to. */
static struct pal_svsm_pipe_ring* in_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[1 - h->pipe.side];
}
static struct pal_svsm_pipe_ring* out_ring(PAL_HANDLE h) {
    return &h->pipe.pair->dir[h->pipe.side];
}

size_t pal_svsm_pipe_readable(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return 0;
    return in_ring(handle)->used;
}

bool pal_svsm_pipe_writable(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return false;
    return out_ring(handle)->used < PIPE_RING_SIZE;
}

bool pal_svsm_pipe_peer_gone(PAL_HANDLE handle) {
    if (!handle->pipe.pair)
        return true;
    return !handle->pipe.pair->open[1 - handle->pipe.side];
}

bool pal_svsm_pipesrv_pending(PAL_HANDLE handle) {
    if (!handle->pipe.name)
        return false;
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++)
        if (g_pending[i].name && !strcmp(g_pending[i].name, handle->pipe.name))
            return true;
    return false;
}

static int pipe_listen(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(hdl, PAL_TYPE_PIPESRV);
    hdl->pipe.name = strdup(name);
    if (!hdl->pipe.name) {
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    *handle = hdl;
    return 0;
}

static int pipe_connect(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    size_t slot = PIPE_PENDING_MAX;
    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        if (!g_pending[i].name) {
            slot = i;
            break;
        }
    }
    if (slot == PIPE_PENDING_MAX)
        return -PAL_ERROR_NOMEM;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    struct pal_svsm_pipe_pair* pair = pair_new();
    char* copy = strdup(name);
    if (!pair || !copy) {
        free(copy);
        pair_put(pair);
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_PIPE);
    hdl->pipe.pair        = pair;
    hdl->pipe.side        = 0;
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

    g_pending[slot].name = copy;
    g_pending[slot].pair = pair;
    pair->refs++;   /* the pending entry holds one until it is accepted */

    *handle = hdl;
    return 0;
}

static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                     pal_share_flags_t share, enum pal_create_mode create,
                     pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(share);
    __UNUSED(create);

    if (!strcmp(type, URI_TYPE_PIPE_SRV))
        return pipe_listen(handle, uri, options);

    if (!strcmp(type, URI_TYPE_PIPE))
        return pipe_connect(handle, uri, options);

    return -PAL_ERROR_INVAL;
}

static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client,
                              pal_stream_options_t options) {
    if (handle->hdr.type != PAL_TYPE_PIPESRV || !handle->pipe.name)
        return -PAL_ERROR_BADHANDLE;

    for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
        if (!g_pending[i].name || strcmp(g_pending[i].name, handle->pipe.name))
            continue;

        PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
        if (!hdl)
            return -PAL_ERROR_NOMEM;
        init_handle_hdr(hdl, PAL_TYPE_PIPE);
        hdl->pipe.pair        = g_pending[i].pair;   /* takes the pending ref */
        hdl->pipe.side        = 1;
        hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

        free(g_pending[i].name);
        g_pending[i].name = NULL;
        g_pending[i].pair = NULL;

        *client = hdl;
        return 0;
    }

    /* Nobody has connected. There is no other thread of execution that could
     * connect while we sit here unless it is one of ours, and blocking for a
     * connection that never comes would be a deadlock, so say so instead. */
    return -PAL_ERROR_TRYAGAIN;
}

static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE || !handle->pipe.pair)
        return -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    while (in_ring(handle)->used == 0) {
        if (pal_svsm_pipe_peer_gone(handle))
            return 0;   /* end of stream */
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        enum pal_svsm_wait_result wr = pal_svsm_poll_block(NULL);
        if (wr == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
    }

    size_t n = ring_read(in_ring(handle), buffer, len);
    /* Space freed: a writer that filled the ring may now proceed. */
    pal_svsm_poll_wake();
    return (int64_t)n;
}

static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, uint64_t len, const void* buffer) {
    __UNUSED(offset);
    if (handle->hdr.type != PAL_TYPE_PIPE || !handle->pipe.pair)
        return -PAL_ERROR_BADHANDLE;
    if (!len)
        return 0;

    while (out_ring(handle)->used == PIPE_RING_SIZE) {
        if (pal_svsm_pipe_peer_gone(handle))
            return -PAL_ERROR_CONNFAILED;
        if (handle->pipe.nonblocking)
            return -PAL_ERROR_TRYAGAIN;
        enum pal_svsm_wait_result wr = pal_svsm_poll_block(NULL);
        if (wr == PAL_SVSM_WAIT_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
    }

    size_t n = ring_write(out_ring(handle), buffer, len);
    /* This is what makes a pollable event pollable: whoever is parked in
     * _PalStreamsWaitEvents has to be told there is something to see. */
    pal_svsm_poll_wake();
    return (int64_t)n;
}

static int pipe_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    memset(attr, 0, sizeof(*attr));
    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->pipe.nonblocking;
    attr->pending_size = handle->hdr.type == PAL_TYPE_PIPE ? pal_svsm_pipe_readable(handle) : 0;
    return 0;
}

static int pipe_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    handle->pipe.nonblocking = attr->nonblocking;
    return 0;
}

static void pipe_destroy(PAL_HANDLE handle) {
    if (handle->hdr.type == PAL_TYPE_PIPESRV) {
        free(handle->pipe.name);
        handle->pipe.name = NULL;
        return;
    }
    if (handle->pipe.pair) {
        handle->pipe.pair->open[handle->pipe.side] = false;
        /* A reader parked on this end's peer has to see the close. */
        pal_svsm_poll_wake();
        pair_put(handle->pipe.pair);
        handle->pipe.pair = NULL;
    }
}

static int pipe_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    __UNUSED(delete_mode);
    /* Closing the listener drops any connection nobody accepted; the
     * connecting end is still a valid handle, it just has no peer. */
    if (handle->hdr.type == PAL_TYPE_PIPESRV && handle->pipe.name) {
        for (size_t i = 0; i < PIPE_PENDING_MAX; i++) {
            if (g_pending[i].name && !strcmp(g_pending[i].name, handle->pipe.name)) {
                g_pending[i].pair->open[1] = false;
                pair_put(g_pending[i].pair);
                free(g_pending[i].name);
                g_pending[i].name = NULL;
                g_pending[i].pair = NULL;
            }
        }
        return 0;
    }
    if (handle->pipe.pair)
        handle->pipe.pair->open[handle->pipe.side] = false;
    pal_svsm_poll_wake();
    return 0;
}

struct handle_ops g_pipe_ops = {
    .open           = &pipe_open,
    .waitforclient  = &pipe_waitforclient,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .destroy        = &pipe_destroy,
    .delete         = &pipe_delete,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};
