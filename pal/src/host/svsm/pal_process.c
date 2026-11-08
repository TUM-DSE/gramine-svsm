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
#include "pal_host.h"
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

/*
 * What a refused fork tells the caller.
 *
 * TRYAGAIN (EAGAIN, which a shell reports as "fork: Resource temporarily
 * unavailable" and Python raises as BlockingIOError) for a LIMIT: the
 * process store, a parent's children, a lineage's region holders, the
 * scheduler's service slots. Each is freed by a reap or an exit, so a later
 * fork may get in - which is what POSIX's EAGAIN for fork means. A RESIDENT
 * fork with no service slot left used to SUCCEED into a child the scheduler
 * never ran, and its parent's waitpid polled for ever; the monitor now says
 * SERVICE_FULL instead, and the hang is this error.
 *
 * DENIED (EACCES) for everything else, as for every refusal before the
 * monitor gave a reason: UNSUPPORTED and BAD_STATE are about this process
 * (it holds a device, it is being deleted) and a retry will not change them,
 * and 0 is a monitor that did not say.
 */
static int fork_refused(int64_t status) {
    switch (status) {
        case PAL_SVSM_STATUS_NO_RESOURCES:
        case PAL_SVSM_STATUS_SERVICE_FULL:
            return -PAL_ERROR_TRYAGAIN;
        default:
            return -PAL_ERROR_DENIED;
    }
}

/* This process is in a lineage run set: it forked LINEAGE, or it is a
 * LINEAGE child (fork fix 3). Its waits for children are then LineageWaits
 * (below), which the drive answers at once when a child ends. Inherited by
 * a fork's child, which is right: a LINEAGE child is a member, and a
 * RESIDENT child of a member is refused by the monitor (its mode is the
 * run set's). */
uint8_t g_svsm_in_run_set = 0;

int _PalProcessFork(uint64_t flags, struct pal_fork_ids* out) {
    uint64_t self = 0;
    /* No other context may hold a LibOS lock at the instant the address
     * space is copied (pal_events.c). Nothing between the last look at the
     * count and the monitor call can yield, so nothing can take one in
     * between. 100 ms is far beyond any critical section; a fork that waits
     * that long is waiting on itself (another context blocked on a lock the
     * forker holds), so it goes ahead and says so.
     *
     * The child may then block on those holds, and for good: the contexts
     * that held them do not run in it (pal_svsm_threads_child_after_fork).
     * That is POSIX's own caveat for a fork from a threaded program, and
     * refusing instead was worse: a hold that does not drain is a lock held
     * across a blocking operation, so a retry never helped and every fork
     * from such a process failed. The ones the LibOS has - a socket's locks
     * across a recv or a connect - stop counting for the length of the wait
     * (libos_lock.h lock_holds_pause) and are made anew in the child, so
     * this is for a counted hold that did not drain. */
    int64_t foreign = pal_svsm_fork_quiesce(100 * 1000);
    if (g_pal_svsm_fork_report)
        pal_svsm_threads_report_holds(foreign);
    if (foreign > 0)
        log_warning("fork: %ld lock hold(s) of other threads did not drain in 100 ms - forking "
                    "anyway; the child may block on them", foreign);
    /* The mode (fork fix 3, owner 2026-11-07): LINEAGE when the caller asks
     * for it and the monitor offered it; RESIDENT when the caller asks for
     * that (the opt-out: a child that must run between its parent's
     * invokes) or LINEAGE is not on offer. Never both. */
    bool lineage = (flags & PAL_PROCESS_FORK_LINEAGE) && !(flags & PAL_PROCESS_FORK_RESIDENT)
                   && g_pal_svsm_cap_lineage;
    bool resident = !lineage && (flags & (PAL_PROCESS_FORK_RESIDENT | PAL_PROCESS_FORK_LINEAGE));
    uint64_t fflags = (lineage ? PAL_SVSM_FORK_LINEAGE : 0)
                      | (resident ? PAL_SVSM_FORK_RESIDENT : 0)
                      | (foreign > 0 ? PAL_SVSM_FORK_FOREIGN_HOLDS : 0);
    /* The child's holds on every shared pipe, counted - and written down in
     * a ledger row for it - BEFORE the copy: the parent may close its own
     * ends long before the child first runs (see pal_svsm_pipes_fork_prepare).
     * Nothing from here to the monitor call can yield. */
    pal_svsm_pipes_fork_prepare();
    uint64_t serial = 0;
    uint32_t name = 0;
    int64_t status = 0;
    uint64_t rc = pal_svsm_fork(fflags, &self, &serial, &name, &status);
    if (rc == ~0ULL && lineage && status == PAL_SVSM_STATUS_UNSUPPORTED) {
        /* Nothing can drive a run set from here (a service's dispatch, a
         * domain processor): the RESIDENT fallback, as before fix 3. The
         * holds are counted again for the second try; nothing between the
         * two calls can yield. */
        pal_svsm_pipes_fork_failed();
        pal_svsm_pipes_fork_prepare();
        lineage = false;
        fflags = (fflags & ~PAL_SVSM_FORK_LINEAGE) | PAL_SVSM_FORK_RESIDENT;
        status = 0;
        rc = pal_svsm_fork(fflags, &self, &serial, &name, &status);
        log_debug("fork: no run set here - RESIDENT instead");
    }
    pal_svsm_fork_done();
    if (rc != ~0ULL && lineage)
        g_svsm_in_run_set = 1;          /* both sides: parent and member */
    /* UINT64_MAX is the one answer that is neither a parent nor a child.
     * It has to be checked here: a failed fork returns ONCE, and a caller
     * that only looks for zero would carry on as the parent of a child that
     * does not exist. */
    if (rc == ~0ULL) {
        pal_svsm_pipes_fork_failed();   /* there is no child to hold them */
        log_debug("fork: refused by the monitor (status %ld)", status);
        return fork_refused(status);
    }
    out->child  = rc;
    out->serial = serial;
    out->name   = name;
    if (rc != 0)
        pal_svsm_pipes_fork_parent(serial);
    if (rc == 0) {
        out->self = self;               /* we are the child; this is us */
        /* First, before anything here can switch: the parent's other
         * threads are copies on this process's ring and must not run. */
        pal_svsm_threads_child_after_fork();
        pal_svsm_lock_holds_after_fork();
        /* This process's holds on the shared pipes were counted by the
         * parent before the copy, so there is nothing to add here - only the
         * pending connections of threads that did not come along to drop. */
        pal_svsm_pipes_child_after_fork(serial);
        pal_svsm_net_ctr_reset();
    }
    return 0;
}

/* The longest one held Wait lasts (the monitor caps it there too,
 * fork.rs WAIT_HOLD_MAX_US): between two, this looks again at the vault's
 * other contexts, so one whose deadline comes or whose handles get ready
 * waits at most this long for the processor. */
#define SVSM_WAIT_HOLD_US 1000

/*
 * Wait for a child to change, in the monitor (fork.rs wait_held): it holds
 * this call until the child generation moves - the child's death moves it -
 * so the parent hears of the death at once instead of at the end of the
 * LibOS's 10 ms bounded wait, which inside a host invoke (no Park, no Sleep)
 * this PAL could only spin out. Held in slices of SVSM_WAIT_HOLD_US, and only
 * while nothing else of this vault could run: else -DENIED, and the LibOS
 * waits the ordinary way (briefly) so the scheduler runs it.
 */
int _PalProcessWaitChange(uint64_t* gen, uint64_t timeout_us) {
    uint64_t g = 0, why = 0;
    if (*gen == UINT64_MAX) {
        if (pal_svsm_wait_gen(false, 0, 0, &g, &why) < 0)
            return -PAL_ERROR_NOTIMPLEMENTED;   /* a monitor before the generation */
        *gen = g;
        return 0;
    }
    uint64_t now = pal_svsm_now_usec();
    uint64_t deadline = now + timeout_us;
    /* In a run set (fork fix 3): block in the lineage on a CHILD arm, as the
     * held Wait does outside one - which the monitor refuses under a drive.
     * The drive runs the lineage meanwhile, the child included, on this
     * processor, and answers at the child's end. The same rule as below:
     * only while nothing else of this vault could run. UNSUPPORTED (nobody
     * runs the lineage here: no drive) falls through to the held Wait. */
    while (g_svsm_in_run_set) {
        if (pal_svsm_current_interrupted())
            return -PAL_ERROR_INTERRUPTED;
        if (now >= deadline)
            return -PAL_ERROR_TRYAGAIN;
        uint64_t next = deadline;
        if (pal_svsm_others_runnable(now, &next) || next <= now)
            return -PAL_ERROR_DENIED;
        /* The child arm, and the words the vault's other contexts wait on
         * (its IPC and pipes): a child whose exit needs this process - an
         * IPC answer, a pipe drained - must not wait out the slice. Sliced
         * as the held Wait is, so a context whose deadline comes waits at
         * most SVSM_WAIT_HOLD_US for the processor. */
        uint64_t arms[1 + PAL_SVSM_PARK_ARMS];
        bool partial = false;
        arms[0] = PAL_SVSM_LW_ARM(*gen, PAL_SVSM_LW_ARM_CHILD, 0);
        size_t n = 1 + pal_svsm_gather_arms(arms + 1, PAL_SVSM_PARK_ARMS, &partial);
        uint64_t slice = next - now;
        if (slice > SVSM_WAIT_HOLD_US)
            slice = SVSM_WAIT_HOLD_US;
        int64_t c = pal_svsm_lineage_wait(arms, n, PAL_SVSM_LW_WAIT_CHILD, slice, &g);
        if (c == PAL_SVSM_STATUS_UNSUPPORTED)
            break;
        if (c < 0)
            return -PAL_ERROR_DENIED;           /* wait in the vault */
        if ((uint32_t)g != (uint32_t)*gen) {
            *gen = g;
            return 0;
        }
        if ((uint64_t)c & ~(PAL_SVSM_LW_CAUSE_CHILD | PAL_SVSM_LW_CAUSE_TIMEOUT)) {
            /* A watched word moved: the context waiting on it runs first. */
            pal_svsm_poll_wake();
            return -PAL_ERROR_DENIED;
        }
        now = pal_svsm_now_usec();
    }
    while (1) {
        /* A _PalThreadResume (the LibOS has a signal for this thread): left
         * set, for the LibOS's own look - thread_block consumes it. */
        if (pal_svsm_current_interrupted())
            return -PAL_ERROR_INTERRUPTED;
        if (now >= deadline)
            return -PAL_ERROR_TRYAGAIN;
        uint64_t next = deadline;
        if (pal_svsm_others_runnable(now, &next) || next <= now)
            return -PAL_ERROR_DENIED;
        uint64_t slice = next - now;
        if (slice > SVSM_WAIT_HOLD_US)
            slice = SVSM_WAIT_HOLD_US;
        if (pal_svsm_wait_gen(true, *gen, slice, &g, &why) != 1)
            return -PAL_ERROR_DENIED;           /* not held: wait in the vault */
        if ((uint32_t)g != (uint32_t)*gen) {
            *gen = g;
            return 0;
        }
        if (why == PAL_SVSM_WAIT_HOLD_INTERRUPTED)
            return -PAL_ERROR_INTERRUPTED;
        now = pal_svsm_now_usec();
    }
}

int _PalProcessWait(uint64_t child, uint64_t child_serial, int64_t* out_reason,
                    uint64_t* out_value) {
    uint64_t value = 0;
    int64_t reason = pal_svsm_wait(child, child_serial, &value);
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
    pal_svsm_pipes_exit();
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

int _PalProcessKill(uint64_t child, uint64_t child_serial) {
    /* A refusal - not this process's child by id and serial - is negative,
     * and is reported as such rather than as a kill that happened. */
    return pal_svsm_kill_child(child, child_serial) < 0 ? -PAL_ERROR_INVAL : 0;
}
