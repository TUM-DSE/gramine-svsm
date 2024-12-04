/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Operations to handle the console device.
 *
 * Note that some operations (like stat and truncate) are resolved in LibOS and don't have a
 * counterpart in PAL.
 */

#include "api.h"
#include "pal.h"
#include "pal_host.h"
#include "pal_error.h"
#include "pal_internal.h"

#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2

static int console_open(PAL_HANDLE* handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options) {
    log_debug("[PAL] console_open: type=%s, uri=%s, access=%d, share=%d, create=%d, options=%d",
              type, uri, access, share, create, options);

    if (strcmp(type, URI_TYPE_CONSOLE))
        return -PAL_ERROR_INVAL;

    if (strcmp(type, URI_TYPE_CONSOLE))
        return -PAL_ERROR_INVAL;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(console));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    hdl->hdr.type = PAL_TYPE_CONSOLE;
    hdl->flags = access == PAL_ACCESS_RDONLY ? PAL_HANDLE_FD_READABLE : PAL_HANDLE_FD_WRITABLE;
    hdl->console.fd = access == PAL_ACCESS_RDONLY ? /*host stdin*/0 : /*host stdout*/1;

    *handle = hdl;
    return 0;
}

static int64_t console_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    log_debug("[PAL] console_read: handle=%p, offset=%lu, size=%lu, buffer=%p", handle, offset, size,
              buffer);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t console_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    log_debug("[PAL] console_write: handle=%p, offset=%lu, size=%lu, buffer=%p", handle, offset,
              size, buffer);
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    if (offset)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    log_debug("[PAL] [Console Output]: %.*s", (int)size, (const char*)buffer);
    int ret = size; // fixme: assume all bytes are written
    return ret;
}

static void console_destroy(PAL_HANDLE handle) {
    /* noop */
}

static int console_flush(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_console_ops = {
    .open           = &console_open,
    .read           = &console_read,
    .write          = &console_write,
    .destroy        = &console_destroy,
    .flush          = &console_flush,
};
