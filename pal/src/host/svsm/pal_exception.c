/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Faults, and turning them into the signals an application expects.
 *
 * A vault could not take a signal before this. The file was thirteen lines
 * and never called a handler, so the five the LibOS registers could not
 * fire: a SIGSEGV retired the vault from the monitor, with the application
 * given no say and no way to see what happened.
 *
 * The monitor does the half that needs privilege. A fault at CPL3 lands on
 * the process's own stub at CPL0, which calls the monitor; if the monitor
 * cannot explain the fault (it is not copy-on-write, not a stale
 * translation) it builds a PAL_CONTEXT on this process's stack below the
 * red zone and rewrites the stub's return frame to enter the function
 * registered below - so the `iretq` the stub already performs does the
 * transition, and nothing new runs at CPL0.
 *
 * Going back is a monitor call too. Restoring rip, rsp and rflags together
 * is precisely what an `iretq` is for, and this side runs at CPL3 and has
 * none, so the PAL hands the context back and the monitor resumes from it.
 * That is the same division of labour as a Linux sigreturn, for the same
 * reason.
 *
 * What is NOT saved is the FPU and SSE state. Everything between the fault
 * and the return is the handler's own code, and `is_fpregs_used` is left
 * clear so nothing is told otherwise. A handler that wants to look at or
 * change the floating-point state of the interrupted code cannot yet.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"

/* Set by setup_pal_binary(); used to answer "did this fault happen inside
 * the PAL itself", which the LibOS asks before deciding whether the
 * application may hear about it. */
static uintptr_t g_pal_text_start;
static uintptr_t g_pal_text_end;

void pal_svsm_set_text_range(uintptr_t start, uintptr_t end) {
    g_pal_text_start = start;
    g_pal_text_end = end;
}

static bool rip_is_in_pal(uintptr_t rip) {
    /* Unknown range: say no. Claiming a fault was the PAL's own turns a
     * recoverable application fault into a fatal one, which is the worse
     * way to be wrong. */
    if (!g_pal_text_end)
        return false;
    return rip >= g_pal_text_start && rip < g_pal_text_end;
}

/*
 * Where the monitor enters this PAL with a fault.
 *
 * Entered at CPL3 on the interrupted thread's own stack, below its red
 * zone, with the interrupted context written out by the monitor.
 */
noreturn void pal_svsm_exception_entry(uint64_t event, uintptr_t addr, PAL_CONTEXT* context);

noreturn void pal_svsm_exception_entry(uint64_t event, uintptr_t addr, PAL_CONTEXT* context) {
    pal_event_handler_t upcall = _PalGetExceptionHandler((enum pal_event)event);

    if (!upcall) {
        /* Nobody registered one. Before this file did anything at all that
         * was every fault; now it is only the ones the LibOS has not
         * claimed, and it is still fatal - but it says what it was. */
        log_error("unhandled %s at %#lx (rip %#lx) and no handler is registered",
                  pal_event_name((enum pal_event)event), addr, context->rip);
        _PalProcessExit(1);
    }

    upcall(rip_is_in_pal(context->rip), addr, context);

    /* The handler returned, so it wants the context resumed - possibly a
     * different one than arrived, since a handler may set rip to unwind
     * somewhere else. Only the monitor can put it back. */
    pal_svsm_exception_return(context);
}

void pal_svsm_exception_init(void) {
    int ret = pal_svsm_set_exception_entry(&pal_svsm_exception_entry,
                                           offsetof(PAL_SVSM_TCB, alt_stack_top));
    if (ret < 0) {
        /* Not fatal: without it a fault retires the vault exactly as it
         * did before, which is the behaviour every vault has had so far. */
        log_error("the monitor refused an exception entry - faults stay fatal");
    }
}
