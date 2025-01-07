/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains operands to handle streams with URIs that start with "file:" or "dir:".
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"

#include <string.h>

static int file_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                     pal_share_flags_t share, enum pal_create_mode create,
                     pal_stream_options_t options) {
    log_debug("[PAL] file_open: type=%s, uri=%s, access=%d, share=%d, create=%d, options=%d\n", type,
              uri, access, share, create, options);

    // TODO: Initilize the handle with required information
    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(file));
    init_handle_hdr(hdl, PAL_TYPE_FILE);
    *handle = hdl;

    return 0;
    //return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    // TODO: Use handle to identify file, currently only the LibOS is loaded
    static uint8_t* libos_start = (void*)0x18000000000;
    uint8_t* buf = buffer;
    for(int i = 0; i < 0; i++){
        buf[i] = libos_start[offset+i];
    }
    return count;
    //return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void file_destroy(PAL_HANDLE handle) {
    /* noop */
}

static int file_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_map(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                    uint64_t size) {

    // TODO: Use handle to identify file

    void* ret = pal_svsm_mmap(addr, size, prot, prot, 0, offset);
    if(!ret)
        return -1;
    return 0;

}

static int file_setlength(PAL_HANDLE handle, uint64_t length) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_flush(PAL_HANDLE handle) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    log_debug("[PAL] file_attrquery: type=%s, uri=%s\n", type, uri);

    if (strcmp(type, URI_TYPE_FILE) && strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    struct pal_svsm_guest_request_arg arg = {};

    unsigned len = strlen(uri);
    if (len >= sizeof(arg.fileattr.path))
        return -PAL_ERROR_INVAL;
    memcpy(arg.fileattr.path, uri, len + 1);
    log_debug("[PAL] file_attrquery: path=%s\n", arg.fileattr.path);

    pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_FILEATTR, (void *)&arg.fileattr, sizeof(arg.fileattr));

    attr->nonblocking = false;
    attr->share_flags = arg.fileattr.mode & PAL_SHARE_MASK;
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_IFMT  0170000
#define S_ISREG( m ) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR( m ) (((m) & S_IFMT) == S_IFDIR)
    if (S_ISREG(arg.fileattr.mode))
        attr->handle_type = PAL_TYPE_FILE;
    else if (S_ISDIR(arg.fileattr.mode))
        attr->handle_type = PAL_TYPE_DIR;
    else
        return -PAL_ERROR_INVAL;
    attr->pending_size = arg.fileattr.size;

    log_debug("[PAL] file_attrquery: handle_type=%d, nonblocking=%d, share_flags=%d, pending_size=%lu\n",
              attr->handle_type, attr->nonblocking, attr->share_flags, attr->pending_size);

    return 0;
}

static int file_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    log_debug("[PAL] file_attrquerybyhdl: handle=%p\n", handle);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int file_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dir_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    log_debug("[PAL] dir_open: type=%s, uri=%s, access=%d, share=%d, create=%d, options=%d\n", type,
              uri, access, share, create, options);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buf) {
    log_debug("[PAL] dir_read: offset=%lu, count=%lu\n", offset, count);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void dir_destroy(PAL_HANDLE handle) {
    log_debug("[PAL] dir_destroy: handle=%p\n", handle);
    /* noop */
}

static int dir_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dir_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    log_debug("[PAL] dir_attrquerybyhdl: handle=%p\n", handle);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int dir_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

struct handle_ops g_file_ops = {
    .open           = &file_open,
    .read           = &file_read,
    .write          = &file_write,
    .destroy        = &file_destroy,
    .delete         = &file_delete,
    .map            = &file_map,
    .setlength      = &file_setlength,
    .flush          = &file_flush,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .rename         = &file_rename,
};

struct handle_ops g_dir_ops = {
    .open           = &dir_open,
    .read           = &dir_read,
    .destroy        = &dir_destroy,
    .delete         = &dir_delete,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &dir_attrquerybyhdl,
    .rename         = &dir_rename,
};
