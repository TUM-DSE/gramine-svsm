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
#include "pal_tf.h"
#include "list.h"
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
    (void)ret;
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

    // Check if the file is allowed or trusted
    struct trusted_file* tf = NULL;

    if (!(options & PAL_OPTION_PASSTHROUGH)) {
        tf = get_trusted_or_allowed_file(hdl->file.realpath);
        if (!tf) {
            if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
                log_warning("Disallowing access to file '%s'; file is not trusted or allowed.",
                            hdl->file.realpath);
                ret = -PAL_ERROR_DENIED;
                goto out;
            }
            log_warning("Allowing access to unknown file '%s' due to file_check_policy settings.",
                        hdl->file.realpath);
        }
    }

    if (tf && !tf->allowed && ((access == PAL_ACCESS_RDWR)
                || (access == PAL_ACCESS_WRONLY))) {
        log_error("Disallowing create/write/append to a trusted file '%s'", hdl->file.realpath);
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    if (tf) {
        /* now we can learn the size of the trusted file */
        struct pal_svsm_guest_request_arg arg = {};

        unsigned len = strlen(uri);
        if (len >= sizeof(arg.fileattr.path)) {
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
        memcpy(arg.fileattr.path, uri, len + 1);

        pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_FILEATTR, (void *)&arg.fileattr, sizeof(arg.fileattr));

        if (arg.fileattr.ret < 0) {
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
        tf->size = arg.fileattr.size;

        void* chunk_hashes = NULL;
        ret = load_trusted_or_allowed_file(tf, hdl, /*create=*/ 0, &chunk_hashes);
        if (ret < 0)
            goto out;

        hdl->file.chunk_hashes = chunk_hashes;
        hdl->file.size = tf->size;
    }

    log_debug("[PAL] file_open: fd=%d, seekable=%d, realpath=%s\n", hdl->file.fd, hdl->file.seekable,
              hdl->file.realpath);

    *handle = hdl;
    ret = 0;
out:
    if (ret < 0) {
        free(hdl->file.realpath);
        free(hdl);
    }
    return ret;
}

static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    log_debug("[PAL] file_read: offset=%lu, count=%lu\n", offset, count);

    if (handle->file.fd == FD_LIBOS) {
        // XXX: libos file
        static uint8_t* libos_start = (void*)0x18000000000;
        uint8_t* buf = buffer;
        for(unsigned long i = 0; i < count; i++){
            buf[i] = libos_start[offset+i];
        }
        return count;
    }

    if (!handle->file.chunk_hashes) {
        // Allowed or passthrough file

        struct pal_svsm_guest_request_arg arg = {};
        arg.read.fd = handle->file.fd;
        arg.read.offset = offset;
        arg.read.count = count;

        // TODO: use more bigger buffer to read
        pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_READ, (void *)&arg.read, sizeof(arg.read));

        if (arg.read.count == (uint64_t)(-1)) {
            log_error("[PAL] file_read: failed to read file\n");
            return -PAL_ERROR_INVAL;
        }

        assert(arg.read.count <= count);
        memcpy(buffer, arg.read.buf, arg.read.count);

        return arg.read.count;
    }

    // Trusted file
    uint64_t file_size = handle->file.size;
    if (offset >= file_size)
        return 0;

    int64_t end = MIN(offset + count, file_size);
    int64_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
    int64_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);

    int ret = copy_and_verify_trusted_file(handle, buffer, aligned_offset, aligned_end, offset, end,
                                       handle->file.chunk_hashes, file_size);
    if (ret < 0)
        return ret;

    return end - offset;
}

static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void file_destroy(PAL_HANDLE handle) {
    assert(handle);
    assert(handle->hdr.type == PAL_TYPE_FILE);

    // TODO: close fd on the host side

    free(handle->file.realpath);
    free(handle);
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

    __UNUSED(access);
    assert(create != PAL_CREATE_IGNORED);

    if (create == PAL_CREATE_TRY || create == PAL_CREATE_ALWAYS) {
        log_debug("[PAL] dir_open: create=%d is not supported\n", create);
        return -PAL_ERROR_NOTIMPLEMENTED;
    }

    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    struct pal_svsm_guest_request_arg arg = {};

    unsigned len = strlen(uri);
    if (len >= sizeof(arg.open.path))
        return -PAL_ERROR_INVAL;
    memcpy(arg.open.path, uri, len + 1);

    // TODO: On the host side, open the path with O_DIRECTORY flag
    pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_OPEN, (void *)&arg.open, sizeof(arg.open));

    if (arg.open.fd == FD_ERROR) {
        log_error("[PAL] file_open: failed to open file\n");
        return -PAL_ERROR_INVAL;
    }

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dir));
    if (!hdl) {
        // TODO: close the fd
        // DO_SYSCALL(close, fd);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_DIR);

    hdl->dir.fd = arg.open.fd;
    hdl->dir.realpath = strdup(uri);
    hdl->dir.buf = NULL;
    hdl->dir.endofstream = 0;
    hdl->flags |= PAL_HANDLE_FD_READABLE;
    *handle = hdl;

    return 0;
}

// The buffer will be filled with null-terminated names of the directory
// entries
static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buf) {
    log_debug("[PAL] dir_read: offset=%lu, count=%lu\n", offset, count);

    if (offset) {
        return -PAL_ERROR_INVAL;
    }

    if (handle->dir.endofstream) {
        return 0;
    }

    struct pal_svsm_guest_request_arg arg = {};
    arg.read.fd = handle->file.fd;
    arg.read.offset = (uint64_t)-1; // indicating dir read
    arg.read.count = count;

    pal_svsm_guest_request(PAL_SVSM_GUEST_REQUEST_READ, (void *)&arg.read, sizeof(arg.read));

    assert(arg.read.count <= count);
    memcpy(buf, arg.read.buf, arg.read.count);

    if (arg.read.count == 0) {
        handle->dir.endofstream = 1;
    }

    return arg.read.count;
}

static void dir_destroy(PAL_HANDLE handle) {
    assert(handle);
    assert(handle->hdr.type == PAL_TYPE_DIR);

    log_debug("[PAL] dir_destroy: handle=%p\n", handle);

    // TODO: close fd on the host side

    free(handle->dir.buf);
    free(handle->dir.realpath);
    free(handle);
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
