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
#include "pal_svsm.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "perm.h"
#include "spinlock.h"

static int console_open(PAL_HANDLE* handle, const char* type, const char* uri,
                        enum pal_access access, pal_share_flags_t share,
                        enum pal_create_mode create, pal_stream_options_t options) {
    __UNUSED(uri);
    __UNUSED(share);
    __UNUSED(create);
    __UNUSED(options);

    if (strcmp(type, URI_TYPE_CONSOLE))
        return -PAL_ERROR_INVAL;

    if (access != PAL_ACCESS_RDONLY && access != PAL_ACCESS_WRONLY)
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
    log_error("attempting console_read");
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t console_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);
    if (offset)
        return -PAL_ERROR_INVAL;
    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    // NOTE: we need to set log level to debug to see the output
    log_debug("[PAL] [Console Output]: %.*s", (int)size, (const char*)buffer);
    int ret = size; // fixme: assume all bytes are written
    return ret;
}

static void console_destroy(PAL_HANDLE handle) {
    /* noop */
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);
    free(handle);
}

static int console_flush(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_CONSOLE);

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    return 0; /* no-op */
}

struct handle_ops g_console_ops = {
    .open           = &console_open,
    .read           = &console_read,
    .write          = &console_write,
    .destroy        = &console_destroy,
    .flush          = &console_flush,
};
