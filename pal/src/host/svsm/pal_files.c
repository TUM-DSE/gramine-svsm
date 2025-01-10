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
#include "pal_rtld.h"
#include "toml.h"
#include "toml_utils.h"

#include <string.h>

#define FD_ERROR ((PAL_IDX)-1)
#define FD_LIBOS ((PAL_IDX)-2)

static int file_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                     pal_share_flags_t share, enum pal_create_mode create,
                     pal_stream_options_t options) {
    log_debug("[PAL] file_open: type=%s, uri=%s, access=%d, share=%d, create=%d, options=%d\n", type,
              uri, access, share, create, options);

    if (access != PAL_ACCESS_RDONLY) {
        log_error("[PAL] file_open: access=%d is not supported\n", access);
        return -PAL_ERROR_NOTIMPLEMENTED;
    }
    if (create) {
        log_error("[PAL] file_open: create=%d is not supported\n", create);
        return -PAL_ERROR_NOTIMPLEMENTED;
    }

    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(file));
    init_handle_hdr(hdl, PAL_TYPE_FILE);

    // Check if the requested file is the entrypoint of the loader
    toml_table_t* manifest_loader = toml_table_in(g_pal_public_state.manifest_root, "loader");
    assert(manifest_loader);
    char* entrypoint_name = NULL;
    int ret = toml_string_in(manifest_loader, "entrypoint", &entrypoint_name);
    assert(ret == 0);
    if (strstartswith(entrypoint_name, URI_PREFIX_FILE)){
        entrypoint_name += URI_PREFIX_FILE_LEN;
    }
    log_debug("[PAL] file_open: entrypoint_name=%s\n", entrypoint_name);
    if(!strcmp(uri, entrypoint_name)) {
        log_debug("[PAL] open etnrypoint of the loader\n");
        // XXX: pal/src/pal_rtld.c:load_entrypoint() open the libos file to
        // read. The file is already loaded into the pre-defined address at
        // the boot time, so we return a handle with a special fd
        hdl->file.fd = FD_LIBOS;
        hdl->flags |= PAL_HANDLE_FD_READABLE;
        *handle = hdl;
        return 0;
    }

    struct pal_svsm_guest_request_arg arg = {};

    unsigned len = strlen(uri);
    if (len >= sizeof(arg.open.path))
        return -PAL_ERROR_INVAL;
    memcpy(arg.open.path, uri, len + 1);
    log_debug("[PAL] file_open: path=%s\n", arg.fileattr.path);

    pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_OPEN, (void *)&arg.open, sizeof(arg.open));

    if (arg.open.fd == FD_ERROR) {
        log_error("[PAL] file_open: failed to open file\n");
        return -PAL_ERROR_INVAL;
    }

    hdl->file.fd = arg.open.fd;
    hdl->file.seekable = 1; // XXX: for now only consider regular file
    hdl->file.realpath = strdup(uri);
    hdl->flags |= PAL_HANDLE_FD_READABLE;
    *handle = hdl;

    log_debug("[PAL] file_open: fd=%d, seekable=%d, realpath=%s\n", hdl->file.fd, hdl->file.seekable,
              hdl->file.realpath);

    return 0;
}

static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    log_debug("[PAL] file_read: offset=%lu, count=%lu\n", offset, count);
    if (handle->file.fd == FD_LIBOS) {
        // XXX: libos file
        static uint8_t* libos_start = (void*)0x18000000000;
        uint8_t* buf = buffer;
        for(int i = 0; i < 0; i++){
            buf[i] = libos_start[offset+i];
        }
        return count;
    }

    struct pal_svsm_guest_request_arg arg = {};
    arg.read.fd = handle->file.fd;
    arg.read.offset = offset;
    arg.read.count = count;

    // FIXME: currently we use arg.read.buf as a read buffer but this is small
    pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_READ, (void *)&arg.read, sizeof(arg.read));

    if (arg.read.count == 0) {
        log_error("[PAL] file_read: failed to read file\n");
        return -PAL_ERROR_INVAL;
    }

    assert(arg.read.count <= count);

    memcpy(buffer, arg.read.buf, arg.read.count);

    log_debug("[PAL] file_read: read %lu bytes\n", arg.read.count);
#if 0
    int i = 0;
    for (i = 0; i < 64; i++) {
        log_debug("%02x ", ((char*)arg.read.buf)[i]);
    }
    log_debug("\n");
#endif

    return arg.read.count;
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

    log_debug("[PAL] file_map: fd=%d, addr=%p, prot=%d, offset=%lu, size=%lu\n", handle->file.fd, addr, prot, offset, size);

    void* ret = pal_svsm_mmap(addr, size, prot, prot, handle->file.fd, offset);
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

    if (arg.fileattr.ret != 0) {
        return -PAL_ERROR_INVAL;
    }

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
