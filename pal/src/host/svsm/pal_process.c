/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"

int _PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                      size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    /* Still not implemented, and deliberately: this is gramine's "start a
     * fresh process and ship it a checkpoint", which exists because a normal
     * PAL cannot copy an address space. This monitor can, so fork goes
     * through _PalProcessFork below and nothing needs a checkpoint stream. */
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalProcessFork(uint64_t flags, uint64_t* out_child, uint64_t* out_self) {
    uint64_t self = 0;
    /* No other context may hold a LibOS lock at the instant the address
     * space is copied (pal_events.c). Nothing between the last look at the
     * count and the monitor call can yield, so nothing can take one in
     * between. 100 ms is far beyond any critical section; a fork that waits
     * that long is waiting on itself (another context blocked on a lock the
     * forker holds), so it goes ahead and says so. */
    int64_t foreign = pal_svsm_fork_quiesce(100 * 1000);
    if (foreign > 0)
        log_warning("fork: %ld lock hold(s) of other threads did not drain in 100 ms - forking "
                    "anyway; the child may block on them", foreign);
    uint64_t fflags = (flags & PAL_PROCESS_FORK_RESIDENT ? PAL_SVSM_FORK_RESIDENT : 0)
                      | (foreign > 0 ? PAL_SVSM_FORK_FOREIGN_HOLDS : 0);
    /* The child's holds on every shared pipe, counted BEFORE the copy: the
     * parent may close its own ends long before the child first runs (see
     * pal_svsm_pipes_fork_hold). Nothing from here to the monitor call can
     * yield. */
    pal_svsm_pipes_fork_hold(+1);
    uint64_t rc = pal_svsm_fork(fflags, &self);
    pal_svsm_fork_done();
    /* UINT64_MAX is the one answer that is neither a parent nor a child.
     * It has to be checked here: a failed fork returns ONCE, and a caller
     * that only looks for zero would carry on as the parent of a child that
     * does not exist. */
    if (rc == ~0ULL) {
        pal_svsm_pipes_fork_hold(-1);   /* there is no child to hold them */
        return -PAL_ERROR_DENIED;
    }
    *out_child = rc;
    if (rc == 0) {
        *out_self = self;               /* we are the child; this is us */
        /* First, before anything here can switch: the parent's other
         * threads are copies on this process's ring and must not run. */
        pal_svsm_threads_child_after_fork();
        /* This process's holds on the shared pipes were counted by the
         * parent before the copy, so there is nothing to add here - only the
         * pending connections of threads that did not come along to drop. */
        pal_svsm_pipes_child_after_fork();
        pal_svsm_net_ctr_reset();
    }
    return 0;
}

int _PalProcessWait(uint64_t child, int64_t* out_reason, uint64_t* out_value) {
    uint64_t value = 0;
    int64_t reason = pal_svsm_wait(child, &value);
    /* Negative is a refusal - not this vault's child, or its slot has been
     * reissued - and must never be reported as a reason, because every real
     * reason is >= 0 and "still running" is 0. Reading a refusal as "not
     * yet" turns a wrong id into a wait that never ends. */
    if (reason < 0)
        return -PAL_ERROR_INVAL;
    *out_reason = reason;
    if (out_value)
        *out_value = value;
    return 0;
}

noreturn void _PalProcessExit(int exitcode) {
    /* Forward the real exit code: for binary-entrypoint trustlets it
       is the result the guest receives (monitor pal_svsm_exit ->
       rdx -> guest generic.values[1]). Was hardcoded -1. */
    pal_svsm_net_ctr_report();
    pal_svsm_exit(exitcode);
    die_or_inf_loop();
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

static void proc_destroy(PAL_HANDLE handle) {
    /* noop */
}

struct handle_ops g_proc_ops = {
    .read  = &proc_read,
    .write = &proc_write,
    .destroy = &proc_destroy,
};
