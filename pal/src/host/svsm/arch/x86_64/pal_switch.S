/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Switching between cooperative contexts inside one vault.
 *
 * Callee-saved registers go on the outgoing context's own stack, so the only
 * thing that has to be remembered about a parked thread is its stack
 * pointer. Everything else - caller-saved registers, the FPU state - belongs
 * to the compiler's view of a function call, and this is a function call:
 * the caller has already spilled whatever it cared about.
 *
 * The GS base moves here too, because GS is the thread pointer (PAL_TCB) and
 * also where GCC's stack protector reads its canary from. Swapping it in C
 * would mean a function whose prologue read one thread's canary checking it
 * against another's on the way out; doing it between the two stacks, in code
 * with no prologue of its own, there is no window where they disagree.
 *
 * WRGSBASE is a CPL3 instruction only because CR4.FSGSBASE is set for a
 * vault (process_cow.rs sets cr4 = 0x3506f0), which is also what lets the
 * existing _PalSegmentBaseSet use WRFSBASE. It is spelled in bytes for the
 * same reason cpu.h spells WRFSBASE in bytes.
 */

    .text

/* void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base) */
    .globl pal_svsm_ctx_switch
    .type pal_svsm_ctx_switch, @function
    .align 16
pal_svsm_ctx_switch:
    .cfi_startproc
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    movq  %rsp, (%rdi)          /* park the outgoing context */
    movq  %rsi, %rsp            /* stand on the incoming one */

    movq  %rdx, %rdi
    .byte 0xf3, 0x48, 0x0f, 0xae, 0xdf   /* wrgsbase %rdi */

    popq  %r15
    popq  %r14
    popq  %r13
    popq  %r12
    popq  %rbx
    popq  %rbp
    ret
    .cfi_endproc
    .size pal_svsm_ctx_switch, .-pal_svsm_ctx_switch


/*
 * Delivery trampoline: save the extended state before any of the PAL runs.
 *
 * A fault delivery can get away without this, because the handler usually
 * ends the process. A preemption cannot: the interrupted code carries on
 * afterwards, and everything between here and the return - the PAL, the
 * LibOS, whatever memcpy they call - uses the vector registers. Resuming
 * with those clobbered does not crash, it computes the wrong thing, and
 * what it computed wrong turns up later as glibc reporting a corrupted
 * double-linked list from a memcpy that moved the wrong bytes.
 *
 * The hardware has already saved the process's register state into its
 * VMSA, FPU included, and will restore it - but the process is still
 * running on that VMSA, so the saved copy is the live one and the PAL is
 * about to overwrite it. The save has to happen here, in the first
 * instructions the process executes after being redirected, before the
 * compiler has had a chance to touch anything.
 *
 * Entered exactly as the C function was: rdi = event, rsi = address,
 * rdx = the interrupted context, on the alternate stack.
 */
#define XSAVE_AREA_SIZE 4096

    .text

    .globl pal_svsm_exception_trampoline
    .type pal_svsm_exception_trampoline, @function
    .align 16
pal_svsm_exception_trampoline:
    .cfi_startproc
    /* XSAVE takes its mask in edx:eax, and rdx is the third argument -
     * the interrupted context. Park the arguments somewhere the save
     * cannot reach before setting the mask, or the context pointer
     * becomes 0xffffffff and the resume has nothing to go back to. */
    movq  %rdi, %r8
    movq  %rsi, %r9
    movq  %rdx, %r10

    subq  $(XSAVE_AREA_SIZE + 64), %rsp
    andq  $-64, %rsp                 /* XSAVE wants 64-byte alignment */

    /* XSAVE reads the header it is about to write, so it has to be clear;
     * a stale XSTATE_BV or a non-zero XCOMP_BV makes XRSTOR refuse it. */
    xorl  %eax, %eax
    movq  %rax, 512(%rsp)
    movq  %rax, 520(%rsp)
    movq  %rax, 528(%rsp)
    movq  %rax, 536(%rsp)
    movq  %rax, 544(%rsp)
    movq  %rax, 552(%rsp)
    movq  %rax, 560(%rsp)
    movq  %rax, 568(%rsp)

    movl  $-1, %eax                  /* every component XCR0 enables */
    movl  $-1, %edx
    xsave64 (%rsp)

    movq  %r8,  %rdi                 /* the arguments, as they arrived */
    movq  %r9,  %rsi
    movq  %r10, %rdx
    movq  %rsp, %rcx                 /* 4th argument: where the state went */
    call  pal_svsm_exception_deliver
    ud2                              /* deliver never returns */
    .cfi_endproc
    .size pal_svsm_exception_trampoline, .-pal_svsm_exception_trampoline

/*
 * void pal_svsm_exception_resume(PAL_CONTEXT* ctx, void* xsave_area)
 *
 * Put the extended state back and resume from `ctx`. Nothing between the
 * XRSTOR and the resume may touch vector state, which is why this is written
 * out rather than left to a compiler.
 *
 * Two ways out, and rbx carries the context for both.
 *
 * `int $0x81` is a gate in the trustlet IDT - a stub at CPL0 in this vault's
 * own address space rebuilds the iretq frame from the context and returns,
 * which costs an interrupt and no more. The monitor call below does the same
 * work from VMPL0 and pays a VMPL round trip and a walk of this vault's page
 * table for it: 4.7 us of `excret` plus about 23,000 cycles, on every fault,
 * every trapped syscall and every preemption.
 *
 * The gate is used only when the monitor said it exists
 * (PAL_SVSM_CAP_RET_GATE). A hosted vault traps into the SVSM's own IDT and
 * has no such gate, so assuming it would be a #GP on the first fault return.
 */
    .globl pal_svsm_exception_resume
    .type pal_svsm_exception_resume, @function
    .align 16
pal_svsm_exception_resume:
    .cfi_startproc
    movq  %rdi, %rbx                 /* the context, for either route */
    movl  $-1, %eax
    movl  $-1, %edx
    xrstor64 (%rsi)

    cmpb  $0, g_pal_svsm_ret_gate(%rip)
    je    .Lresume_by_call
    int   $0x81                      /* does not return */
    ud2
.Lresume_by_call:
    movl  $0x4FFFFFE8, %eax          /* ExceptionReturn */
    cpuid                            /* does not return */
    ud2
    .cfi_endproc
    .size pal_svsm_exception_resume, .-pal_svsm_exception_resume

/* Mark the stack non-executable, as the rest of the PAL is. */
.section .note.GNU-stack,"",@progbits
