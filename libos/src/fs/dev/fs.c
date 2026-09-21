/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*!
 * \file
 *
 * This file contains the implementation of `/dev` pseudo-filesystem.
 */

#include "libos_flags_conv.h"
#include "libos_fs_pseudo.h"
#include "pal.h"

static ssize_t dev_null_read(struct libos_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return 0;
}

static ssize_t dev_null_write(struct libos_handle* hdl, const void* buf, size_t count) {
    __UNUSED(hdl);
    __UNUSED(buf);
    __UNUSED(count);
    return count;
}

static int64_t dev_null_seek(struct libos_handle* hdl, int64_t offset, int whence) {
    __UNUSED(hdl);
    __UNUSED(offset);
    __UNUSED(whence);
    return 0;
}

/* TODO: ftruncate() on /dev/null should fail, but open() with O_TRUNC should succeed */
static int dev_null_truncate(struct libos_handle* hdl, uint64_t size) {
    __UNUSED(hdl);
    __UNUSED(size);
    return 0;
}

static ssize_t dev_zero_read(struct libos_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    memset(buf, 0, count);
    return count;
}

static ssize_t dev_random_read(struct libos_handle* hdl, void* buf, size_t count) {
    __UNUSED(hdl);
    int ret = PalRandomBitsRead(buf, count);

    if (ret < 0)
        return pal_to_unix_errno(ret);
    return count;
}

static int dev_tty_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags) {
    __UNUSED(dent);

    char* uri = strdup(URI_PREFIX_CONSOLE);
    if (!uri)
        return -ENOMEM;

    PAL_HANDLE palhdl;
    int ret = PalStreamOpen(uri, LINUX_OPEN_FLAGS_TO_PAL_ACCESS(flags), PSEUDO_PERM_FILE_RW,
                            PAL_CREATE_NEVER, /*options=*/0, &palhdl);
    if (ret < 0) {
        free(uri);
        return pal_to_unix_errno(ret);
    }

    assert(hdl);
    hdl->uri = uri;
    hdl->pal_handle = palhdl;
    return 0;
}

static ssize_t dev_tty_read(struct libos_handle* hdl, void* buf, size_t count) {
    size_t actual_count = count;
    int ret = PalStreamRead(hdl->pal_handle, /*offset=*/0, &actual_count, buf);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    assert(actual_count <= count);
    return actual_count;
}

static ssize_t dev_tty_write(struct libos_handle* hdl, const void* buf, size_t count) {
    size_t actual_count = count;
    int ret = PalStreamWrite(hdl->pal_handle, /*offset=*/0, &actual_count, (void*)buf);
    if (ret < 0)
        return pal_to_unix_errno(ret);

    assert(actual_count <= count);
    return actual_count;
}

static int dev_tty_flush(struct libos_handle* hdl) {
    int ret = PalStreamFlush(hdl->pal_handle);
    return pal_to_unix_errno(ret);
}

/* this dummy function is required only to override the default behavior of pseudo_poll() -- this is
 * because we actually want to poll on the host tty/console; see also libos_poll.c */
static int dev_tty_poll(struct libos_handle* hdl, int in_events, int* out_events) {
    __UNUSED(hdl);
    __UNUSED(in_events);
    __UNUSED(out_events);
    return -ENOSYS;
}

/*
 * /dev/mvwindow - the vault's device window (see PLAN.md "A device driver in
 * a vault"). Memory this process and the HOST can both see: the monitor
 * carved it from its pool, converted it to host-shared and mapped it here
 * without the encryption bit, and the PAL asked for it at startup because
 * the manifest said `svsm.device_window_pages`.
 *
 * It exists as a file rather than only as a pointer so that ordinary code -
 * a driver, or a test written in Python - can reach it without a special
 * API. Reads and writes go straight to the memory; there is nothing
 * underneath and no copy in between.
 *
 * The first 32 bytes are the monitor's header {magic, guest-physical
 * address, size, base}. They are readable, and writable like the rest: this
 * is the vault's own memory and the monitor does not read it back. A vault
 * that overwrites its own header only loses the physical address it needs
 * for descriptors.
 */
static bool dev_mvwindow_present(void) {
    return g_pal_public_state->device_window.size != 0;
}

static ssize_t dev_mvwindow_rw(struct libos_handle* hdl, void* buf, size_t count, bool write) {
    if (!dev_mvwindow_present())
        return -ENODEV;

    char* base = g_pal_public_state->device_window.base;
    size_t size = g_pal_public_state->device_window.size;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    if (pos < 0 || (size_t)pos >= size) {
        unlock(&hdl->lock);
        return write ? -ENOSPC : 0;   /* reading past the end is EOF */
    }
    size_t avail = size - (size_t)pos;
    if (count > avail)
        count = avail;
    if (write)
        memcpy(base + pos, buf, count);
    else
        memcpy(buf, base + pos, count);
    hdl->pos = pos + count;
    unlock(&hdl->lock);
    return count;
}

static ssize_t dev_mvwindow_read(struct libos_handle* hdl, void* buf, size_t count) {
    return dev_mvwindow_rw(hdl, buf, count, /*write=*/false);
}

static ssize_t dev_mvwindow_write(struct libos_handle* hdl, const void* buf, size_t count) {
    return dev_mvwindow_rw(hdl, (void*)buf, count, /*write=*/true);
}

static int64_t dev_mvwindow_seek(struct libos_handle* hdl, int64_t offset, int whence) {
    if (!dev_mvwindow_present())
        return -ENODEV;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    int ret = generic_seek(pos, g_pal_public_state->device_window.size, offset, whence, &pos);
    if (ret == 0) {
        hdl->pos = pos;
        ret = pos;
    }
    unlock(&hdl->lock);
    return ret;
}

/*
 * /dev/mvmmio - a device's registers, when the manifest named one.
 *
 * Every access is a monitor call, not a memory access, and that is not a
 * design preference: under SEV-SNP an MMIO access from a guest is
 * intercepted and has to be completed through a GHCB by a #VC handler. A
 * vault has neither, so mapping the BAR here produces an RMP violation at
 * the first touch - measured, not assumed. The monitor does the access at
 * VMPL0 where both exist.
 *
 * Accesses are 4 bytes when the offset and length allow it, 1 byte
 * otherwise, which is what a driver expects of a register file exposed as
 * a file. A register file read with memcpy is read in whatever widths the
 * compiler felt like, and a device that latches on a 4-byte read sees four
 * 1-byte reads of the wrong thing.
 */
static bool dev_mvmmio_present(void) {
    return g_pal_public_state->device_mmio.size != 0
           && g_pal_public_state->device_mmio.io != NULL;
}

static ssize_t dev_mvmmio_rw(struct libos_handle* hdl, void* buf, size_t count, bool write) {
    if (!dev_mvmmio_present())
        return -ENODEV;

    size_t size = g_pal_public_state->device_mmio.size;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    if (pos < 0 || (size_t)pos >= size) {
        unlock(&hdl->lock);
        return write ? -ENXIO : 0;
    }
    size_t avail = size - (size_t)pos;
    if (count > avail)
        count = avail;

    /* Widest access the offset and length allow. NVMe's CAP, ASQ and ACQ
     * are 64-bit registers; splitting them into halves works on some
     * controllers and is not something to rely on. Neither is splitting a
     * 16-bit one: virtio's common configuration puts queue_select at
     * offset 0x16 and queue_size at 0x18, and a device decodes a register
     * at its own width - two byte writes reach the first byte and are
     * dropped on the floor for the second. */
    uint32_t width = 1;
    if ((pos % 8) == 0 && (count % 8) == 0)
        width = 8;
    else if ((pos % 4) == 0 && (count % 4) == 0)
        width = 4;
    else if ((pos % 2) == 0 && (count % 2) == 0)
        width = 2;
    unsigned char* bytes = buf;
    for (size_t done = 0; done < count; done += width) {
        uint64_t offset = (uint64_t)pos + done;
        if (write) {
            uint64_t value = 0;
            memcpy(&value, bytes + done, width);
            if (g_pal_public_state->device_mmio.io(offset, width, /*write=*/1, value) == ~0ULL) {
                unlock(&hdl->lock);
                return done ? (ssize_t)done : -EIO;
            }
        } else {
            /* All ones is also how a refusal comes back, and a register
             * really holding all ones is indistinguishable from one. That
             * is why the monitor bounds-checks the access rather than
             * signalling through the value: by the time a value is
             * returned it is data. */
            uint64_t value = g_pal_public_state->device_mmio.io(offset, width, /*write=*/0, 0);
            memcpy(bytes + done, &value, width);
        }
    }

    hdl->pos = pos + count;
    unlock(&hdl->lock);
    return count;
}

/*
 * /dev/mvcfg - this device's PCI configuration space, read-only.
 *
 * Where a modern device says where its registers actually are. virtio-net
 * keeps the location of its common configuration, notification and ISR
 * structures in a capability chain here, so a driver that cannot read
 * capabilities cannot find its registers at all.
 *
 * Read-only, and that is the whole of the policy: a driver that could
 * write configuration space could move the BAR that every /dev/mvmmio
 * access is bounds-checked against, or turn on bus mastering for a device
 * it was never given.
 *
 * 4 KiB because a capability chain may run past the first 256 bytes into
 * PCIe extended space.
 */
#define MVCFG_SIZE 4096

static bool dev_mvcfg_present(void) {
    return g_pal_public_state->device_mmio.size != 0
           && g_pal_public_state->device_mmio.cfg != NULL;
}

static ssize_t dev_mvcfg_read(struct libos_handle* hdl, void* buf, size_t count) {
    if (!dev_mvcfg_present())
        return -ENODEV;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    if (pos < 0 || (size_t)pos >= MVCFG_SIZE) {
        unlock(&hdl->lock);
        return 0;
    }
    size_t avail = MVCFG_SIZE - (size_t)pos;
    if (count > avail)
        count = avail;

    /* Configuration space is a dword file: capability records are laid out
     * on byte boundaries but the bus reads 32 bits at a time, so read the
     * widest the offset allows and let the caller slice. */
    uint32_t width = 1;
    if ((pos % 4) == 0 && (count % 4) == 0)
        width = 4;
    else if ((pos % 2) == 0 && (count % 2) == 0)
        width = 2;

    unsigned char* bytes = buf;
    for (size_t done = 0; done < count; done += width) {
        uint64_t value = g_pal_public_state->device_mmio.cfg((uint32_t)pos + done, width);
        memcpy(bytes + done, &value, width);
    }

    hdl->pos = pos + count;
    unlock(&hdl->lock);
    return count;
}

static int64_t dev_mvcfg_seek(struct libos_handle* hdl, int64_t offset, int whence) {
    if (!dev_mvcfg_present())
        return -ENODEV;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    int ret = generic_seek(pos, MVCFG_SIZE, offset, whence, &pos);
    if (ret == 0) {
        hdl->pos = pos;
        ret = pos;
    }
    unlock(&hdl->lock);
    return ret;
}

static ssize_t dev_mvmmio_read(struct libos_handle* hdl, void* buf, size_t count) {
    return dev_mvmmio_rw(hdl, buf, count, /*write=*/false);
}

static ssize_t dev_mvmmio_write(struct libos_handle* hdl, const void* buf, size_t count) {
    return dev_mvmmio_rw(hdl, (void*)buf, count, /*write=*/true);
}

static int64_t dev_mvmmio_seek(struct libos_handle* hdl, int64_t offset, int whence) {
    if (!dev_mvmmio_present())
        return -ENODEV;

    lock(&hdl->lock);
    file_off_t pos = hdl->pos;
    int ret = generic_seek(pos, g_pal_public_state->device_mmio.size, offset, whence, &pos);
    if (ret == 0) {
        hdl->pos = pos;
        ret = pos;
    }
    unlock(&hdl->lock);
    return ret;
}

int init_devfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("dev");

    /* Device minor numbers for pseudo-devices:
     * https://elixir.bootlin.com/linux/v5.9/source/drivers/char/mem.c#L950 */

    struct pseudo_node* null = pseudo_add_dev(root, "null");
    null->perm = PSEUDO_PERM_FILE_RW;
    null->dev.major = 1;
    null->dev.minor = 3;
    null->dev.dev_ops.read = &dev_null_read;
    null->dev.dev_ops.write = &dev_null_write;
    null->dev.dev_ops.seek = &dev_null_seek;
    null->dev.dev_ops.truncate = &dev_null_truncate;

    struct pseudo_node* zero = pseudo_add_dev(root, "zero");
    zero->perm = PSEUDO_PERM_FILE_RW;
    zero->dev.major = 1;
    zero->dev.minor = 5;
    zero->dev.dev_ops.read = &dev_zero_read;
    zero->dev.dev_ops.write = &dev_null_write;
    zero->dev.dev_ops.seek = &dev_null_seek;
    zero->dev.dev_ops.truncate = &dev_null_truncate;

    struct pseudo_node* random = pseudo_add_dev(root, "random");
    random->perm = PSEUDO_PERM_FILE_RW;
    random->dev.major = 1;
    random->dev.minor = 8;
    random->dev.dev_ops.read = &dev_random_read;
    /* writes in /dev/random add entropy in normal Linux, but not implemented in Gramine */
    random->dev.dev_ops.write = &dev_null_write;
    random->dev.dev_ops.seek = &dev_null_seek;

    struct pseudo_node* urandom = pseudo_add_dev(root, "urandom");
    urandom->perm = PSEUDO_PERM_FILE_RW;
    urandom->dev.major = 1;
    urandom->dev.minor = 9;
    /* /dev/urandom is implemented the same as /dev/random, so it has the same operations */
    urandom->dev.dev_ops = random->dev.dev_ops;

    /* The device window, when the manifest asked for one. The node always
     * exists - a vault without a window gets ENODEV on use, which is a
     * clearer answer than a missing path. */
    struct pseudo_node* mvwindow = pseudo_add_dev(root, "mvwindow");
    mvwindow->perm = PSEUDO_PERM_FILE_RW;
    mvwindow->dev.major = 10;   /* misc */
    mvwindow->dev.minor = 200;
    mvwindow->dev.dev_ops.read = &dev_mvwindow_read;
    mvwindow->dev.dev_ops.write = &dev_mvwindow_write;
    mvwindow->dev.dev_ops.seek = &dev_mvwindow_seek;

    struct pseudo_node* mvmmio = pseudo_add_dev(root, "mvmmio");
    mvmmio->perm = PSEUDO_PERM_FILE_RW;
    mvmmio->dev.major = 10;
    mvmmio->dev.minor = 201;
    mvmmio->dev.dev_ops.read = &dev_mvmmio_read;
    mvmmio->dev.dev_ops.write = &dev_mvmmio_write;
    mvmmio->dev.dev_ops.seek = &dev_mvmmio_seek;

    struct pseudo_node* mvcfg = pseudo_add_dev(root, "mvcfg");
    mvcfg->perm = PSEUDO_PERM_FILE_R;
    mvcfg->dev.major = 10;
    mvcfg->dev.minor = 202;
    mvcfg->dev.dev_ops.read = &dev_mvcfg_read;
    mvcfg->dev.dev_ops.seek = &dev_mvcfg_seek;

    /* see `man 4 tty` for more info, including major/minor numbers */
    struct pseudo_node* tty = pseudo_add_dev(root, "tty");
    tty->perm = PSEUDO_PERM_FILE_RW;
    tty->dev.major = 5;
    tty->dev.minor = 0;
    tty->dev.dev_ops.open = &dev_tty_open;
    tty->dev.dev_ops.read = &dev_tty_read;
    tty->dev.dev_ops.write = &dev_tty_write;
    tty->dev.dev_ops.flush = &dev_tty_flush;
    tty->dev.dev_ops.poll = &dev_tty_poll;

    struct pseudo_node* fd_link = pseudo_add_link(root, "fd", NULL);
    fd_link->link.target = "/proc/self/fd";

    struct pseudo_node* stdin = pseudo_add_link(root, "stdin", NULL);
    stdin->link.target = "/proc/self/fd/0";
    struct pseudo_node* stdout = pseudo_add_link(root, "stdout", NULL);
    stdout->link.target = "/proc/self/fd/1";
    struct pseudo_node* stderr = pseudo_add_link(root, "stderr", NULL);
    stderr->link.target = "/proc/self/fd/2";

    int ret = init_attestation(root);
    if (ret < 0)
        return ret;

    return 0;
}
