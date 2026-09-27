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

/*
 * How often this vault wants preempting, and whether there is currently
 * anything to preempt it for.
 *
 * A green thread cannot be taken off the CPU by anything inside the vault:
 * interrupts are off and the IDT has three vectors, so a compute-bound
 * thread runs until it calls something that yields. The monitor can take
 * the vCPU back - the hypervisor puts VMPL0 on it - and this is how it
 * knows whether doing so is worth anything.
 *
 * 4 ms is a scheduling quantum, not a timer tick: it is the longest a
 * runnable sibling should wait behind a thread that never blocks.
 */
struct pal_svsm_preempt_ctl g_pal_svsm_preempt = {
    .wanted = 0,
    .min_interval_us = 4000,
    .count = 0,
    .text_start = 0,
    .text_end = 0,
};

/* Whether the fault-return gate exists; see PAL_SVSM_CAP_RET_GATE. */
uint8_t g_pal_svsm_ret_gate = 0;

void pal_svsm_preempt_update(bool others_runnable) {
    __atomic_store_n(&g_pal_svsm_preempt.wanted, others_runnable ? 1 : 0,
                     __ATOMIC_RELEASE);
}

/* This PAL's own code, from the linker script. Used for two things: to
 * answer "did this fault happen inside the PAL itself", which the LibOS
 * asks before deciding whether the application may hear about it, and to
 * tell the monitor where it must not preempt. */
extern char __text_start;
extern char __text_end;

static uintptr_t g_pal_text_start;
static uintptr_t g_pal_text_end;

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
noreturn void pal_svsm_exception_deliver(uint64_t event, uintptr_t addr, PAL_CONTEXT* context,
                                         void* xsave_area);
noreturn void pal_svsm_exception_trampoline(uint64_t event, uintptr_t addr,
                                            PAL_CONTEXT* context);
noreturn void pal_svsm_exception_resume(PAL_CONTEXT* context, void* xsave_area);

noreturn void pal_svsm_exception_deliver(uint64_t event, uintptr_t addr, PAL_CONTEXT* context,
                                         void* xsave_area) {
    if (event == PAL_EVENT_INTERRUPTED) {
        /*
         * A preemption. The vCPU was taken off this thread between two
         * instructions and handed to the monitor, which built this frame
         * and brought us here on the alternate stack.
         *
         * Yielding is the whole of it. The scheduler picks another
         * runnable context and switches to it; this one is left parked in
         * the middle of this function, on its own alternate stack, and
         * resumes here when its turn comes round again. The interrupted
         * context is untouched in `context` throughout, and goes back
         * below.
         *
         * This is what makes a compute-bound thread yield without its
         * cooperation - the thing the cooperative scheduler could not do.
         */
        _PalThreadYieldExecution();
        pal_svsm_exception_resume(context, xsave_area);
    }

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
    pal_svsm_exception_resume(context, xsave_area);
}

void pal_svsm_exception_init(void) {
    g_pal_text_start = (uintptr_t)&__text_start;
    g_pal_text_end   = (uintptr_t)&__text_end;
    g_pal_svsm_preempt.text_start = g_pal_text_start;
    g_pal_svsm_preempt.text_end   = g_pal_text_end;

    uint64_t caps = pal_svsm_set_exception_entry(&pal_svsm_exception_trampoline,
                                                offsetof(PAL_SVSM_TCB, alt_stack_top),
                                                &g_pal_svsm_preempt);
    /* The answer used to be a bare 0 and there is no failure to report: the
     * monitor either has an entry for this vault or the vault is hosted and
     * gets none of the capabilities. What WOULD be fatal is assuming one it
     * was not given - `int $0x81` in a hosted vault is a #GP on the first
     * fault return - so the flag is set from the answer and nowhere else. */
    g_pal_svsm_ret_gate = (caps & PAL_SVSM_CAP_RET_GATE) ? 1 : 0;
}
