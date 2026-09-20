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

/* Mark the stack non-executable, as the rest of the PAL is. */
.section .note.GNU-stack,"",@progbits
