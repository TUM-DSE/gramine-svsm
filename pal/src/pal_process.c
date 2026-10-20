/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "pal.h"
#include "pal_internal.h"

int PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                     size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    *out_handle = NULL;
    return _PalProcessCreate(args, reserved_mem_ranges, reserved_mem_ranges_len, out_handle);
}

int PalProcessFork(uint64_t flags, struct pal_fork_ids* out) {
    if (!out)
        return -PAL_ERROR_INVAL;
    memset(out, 0, sizeof(*out));
    return _PalProcessFork(flags, out);
}

int PalProcessWait(uint64_t child, uint64_t child_serial, int64_t* out_reason,
                   uint64_t* out_value) {
    if (!out_reason)
        return -PAL_ERROR_INVAL;
    *out_reason = 0;
    if (out_value)
        *out_value = 0;
    return _PalProcessWait(child, child_serial, out_reason, out_value);
}

noreturn void PalProcessExit(int exitcode) {
    _PalProcessExit(exitcode);
}
