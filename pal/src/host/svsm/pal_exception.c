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
 * What is NOT saved for a FAULT is the FPU and SSE state. Everything
 * between the fault and the return is the handler's own code, and
 * `is_fpregs_used` is left clear so nothing is told otherwise. A handler
 * that wants to look at or change the floating-point state of the
 * interrupted code cannot yet.
 *
 * A PREEMPTION that delivers a signal is different, and does hand the LibOS
 * the state (deliver_on_tick below): its handler typically RETURNS into the
 * code it interrupted, and the frame the LibOS builds for that return is
 * the only copy of the interrupted vector registers that survives the
 * handler.
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

/*
 * The extended-state area the trampoline fills, described the way Linux
 * describes a signal frame's, so the LibOS will take it as a full XSAVE
 * image rather than a legacy FXSAVE one.
 *
 * The LibOS decides that in is_xstate_extended
 * (libos/src/arch/x86_64/libos_context.c:112-145): the software bytes at
 * 464..511 of the legacy region must carry
 * FP_XSTATE_MAGIC1, an xstate_size no larger than the CPUID 0xD.0 ECX it
 * read itself, xfeatures inside CPUID 0xD.0 EDX:EAX, and FP_XSTATE_MAGIC2
 * right after xstate_size bytes. Anything else and libos_xstate_copy
 * (:170-189) copies 512 bytes and zeroes the software bytes - the upper
 * halves of the YMM registers are then simply gone when the handler
 * returns, and the interrupted code computes on whatever is in them.
 *
 * Both numbers come from the same CPUID leaves the LibOS reads (through
 * the same instruction, so through the same monitor answer), once at init.
 * xstate_size is the leaf's MAXIMUM (ECX), not the size for XCR0 (EBX):
 * that is what the LibOS sized its frames with, and the bytes between what
 * XSAVE wrote and ECX are never loaded - XRSTOR initialises any component
 * whose XSTATE_BV bit is clear, and the trampoline zeroes the header before
 * the save, so a component outside XCR0 has its bit clear.
 *
 * Zero means "do not describe it": no XSAVE, a size that does not fit the
 * area with MAGIC2 behind it, or only FP/SSE (where the LibOS uses FXSAVE
 * frames and would reject the magic anyway). Delivery then still happens,
 * with fpregs NULL, which loses the vector state a returning handler would
 * need - the behaviour before this existed, and still correct for a handler
 * that exits.
 */
/* Must equal XSAVE_AREA_SIZE in arch/x86_64/pal_switch.S:77. */
#define PAL_SVSM_XSAVE_AREA_SIZE 4096

static uint32_t g_tick_xstate_size;
static uint64_t g_tick_xstate_features;

static void tick_xstate_init(void) {
    unsigned int w[4];
    cpuid(1, 0, w);
    /* XSAVE (bit 26) and OSXSAVE (bit 27) of ECX, as libos_xstate_init. */
    if (!(w[CPUID_WORD_ECX] & (1u << 26)) || !(w[CPUID_WORD_ECX] & (1u << 27)))
        return;
    cpuid(0xd, 0, w);
    uint64_t features = w[CPUID_WORD_EAX] | ((uint64_t)w[CPUID_WORD_EDX] << 32);
    uint32_t size = w[CPUID_WORD_ECX];
    if (!(features & ~PAL_XFEATURE_MASK_FPSSE))
        return;
    if (size < sizeof(PAL_XREGS_STATE)
            || size + PAL_FP_XSTATE_MAGIC2_SIZE > PAL_SVSM_XSAVE_AREA_SIZE) {
        log_warning("xsave size %u does not fit the %u-byte delivery area; a signal "
                    "delivered on a preemption will not carry the vector state",
                    size, PAL_SVSM_XSAVE_AREA_SIZE);
        return;
    }
    g_tick_xstate_size     = size;
    g_tick_xstate_features = features;
}

void pal_svsm_xstate_refresh(void) {
    g_tick_xstate_size     = 0;
    g_tick_xstate_features = 0;
    tick_xstate_init();
}

/* Make the trampoline's save look like a Linux xsave frame, and point the
 * context at it. The software bytes are not part of the XSAVE image (XSAVE
 * neither reads nor writes 464..511) and MAGIC2 sits past every component
 * this CPU has, so neither write changes what XRSTOR puts back. */
static void describe_xstate(PAL_CONTEXT* context, void* xsave_area) {
    if (!g_tick_xstate_size)
        return;
    PAL_XREGS_STATE* x = xsave_area;
    x->fpstate.sw_reserved.magic1        = PAL_FP_XSTATE_MAGIC1;
    x->fpstate.sw_reserved.extended_size = g_tick_xstate_size + PAL_FP_XSTATE_MAGIC2_SIZE;
    x->fpstate.sw_reserved.xfeatures     = g_tick_xstate_features;
    x->fpstate.sw_reserved.xstate_size   = g_tick_xstate_size;
    memset(&x->fpstate.sw_reserved.padding, 0, sizeof(x->fpstate.sw_reserved.padding));
    *(uint32_t*)((char*)xsave_area + g_tick_xstate_size) = PAL_FP_XSTATE_MAGIC2;
    context->fpregs         = x;
    context->is_fpregs_used = 1;
}

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

        /*
         * And then deliver what the yield made pending (next.md 170.4).
         *
         * While this thread was parked, the LibOS's async worker ran - it is
         * a thread blocked on a deadline, which is exactly what keeps the
         * tick armed (refresh_preempt_wanted, pal_threading.c) - saw an
         * alarm() or setitimer() expire and queued SIGALRM, which reaches
         * this thread as _PalThreadResume: the sticky `interrupted` flag.
         * Before this, nothing looked at it except a blocking call, so a
         * thread that waits for SIGALRM by COMPUTING - dhry2reg, hanoi,
         * arith, `while (!done) ;` - spun until the invoke watchdog.
         *
         * The LibOS's interrupted upcall is the same one Gramine's Linux PAL
         * calls on a host signal (libos_signal.c:519-529): it delivers only
         * if the interrupted rip is application code, never inside the LibOS
         * or the PAL, and otherwise returns having done nothing - then the
         * syscall return or the next tick owes the delivery, so the flag is
         * cleared only when the context was actually redirected. A signal
         * whose default action kills does not return here at all.
         *
         * The vector state goes with it (describe_xstate): the handler may
         * return, and then rt_sigreturn restores the interrupted code's
         * registers from the frame built from this area.
         */
        if (pal_svsm_current_interrupted()) {
            pal_event_handler_t upcall = _PalGetExceptionHandler(PAL_EVENT_INTERRUPTED);
            if (upcall) {
                uint64_t rip_before = context->rip;
                describe_xstate(context, xsave_area);
                upcall(rip_is_in_pal(context->rip), /*addr=*/0, context);
                if (context->rip != rip_before)
                    pal_svsm_current_clear_interrupted();
                /* Not delivered: leave the context as the monitor built it,
                 * so the fault path's "is_fpregs_used is clear" still holds
                 * for anything that reads it later. */
                else {
                    context->fpregs         = NULL;
                    context->is_fpregs_used = 0;
                }
            }
        }
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

    tick_xstate_init();
}
