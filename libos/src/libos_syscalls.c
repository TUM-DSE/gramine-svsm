/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "asan.h"
#include "libos_defs.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_tcb.h"
#include "libos_thread.h"
#include "linux_abi/errors.h"

typedef arch_syscall_arg_t (*six_args_syscall_t)(arch_syscall_arg_t, arch_syscall_arg_t,
                                                 arch_syscall_arg_t, arch_syscall_arg_t,
                                                 arch_syscall_arg_t, arch_syscall_arg_t);

/*
 * `context` is expected to be placed at the bottom of Gramine-internal stack.
 * If you change this function please also look at `libos_syscall_rt_sigsuspend`!
 */
/* The syscall profile (MicroVault notes/sched/LIBOS-SYSCALL-PROFILE.md): the
 * PAL's table, 512 rows of {count, wall, monitor, park} TSC ticks, or NULL
 * (the default: one predicted branch per syscall). Set once at init. */
static uint64_t* g_libos_sysprof = NULL;

void libos_sysprof_init(void) {
    g_libos_sysprof = PalProfileSyscallTable();
}

static inline uint64_t sysprof_tsc(void) {
    return __builtin_ia32_rdtsc();
}

/* The body, specialised twice by `prof` (a constant at both call sites): the
 * profile-off copy is exactly the dispatcher without the profile - no extra
 * live values across the syscall, no spill - and the profiled one is out of
 * line. Step 25 put the profile's work in the one body, guarded by a branch:
 * UnixBench's syscall test lost 3.4% with the profile OFF (ledger end
 * benchmark 18 -> 29, bisected to step 25's PAL pair, 2026-11-20). */
static inline __attribute__((always_inline)) noreturn void emulate_syscall(PAL_CONTEXT* context,
                                                                           const bool prof) {
    LIBOS_TCB_SET(context.regs, context);

    unsigned long sysnr = pal_context_get_syscall(context);
    arch_syscall_arg_t ret = 0;
    uint64_t prof_t0 = 0, prof_m0 = 0, prof_p0 = 0;
    if (prof) {
        prof_t0 = sysprof_tsc();
        PalProfileThreadCycles(&prof_m0, &prof_p0);
    }

    if (sysnr == GRAMINE_CUSTOM_SYSCALL_NR) {
        unsigned long args[] = { ALL_SYSCALL_ARGS(context) };
        ret = handle_libos_call(args[0], args[1], args[2]);
    } else {
        if (sysnr >= LIBOS_SYSCALL_BOUND || !libos_syscall_table[sysnr]) {
            warn_unsupported_syscall(sysnr);
            ret = -ENOSYS;
            goto out;
        }

        LIBOS_TCB_SET(context.syscall_nr, sysnr);
        six_args_syscall_t syscall_func = (six_args_syscall_t)libos_syscall_table[sysnr];

        debug_print_syscall_before(sysnr, ALL_SYSCALL_ARGS(context));
        ret = syscall_func(ALL_SYSCALL_ARGS(context));
        debug_print_syscall_after(sysnr, ret, ALL_SYSCALL_ARGS(context));
    }
out:
    pal_context_set_retval(context, ret);

    /* Some syscalls e.g. `sigreturn` could have changed context and in reality we might be not
     * returning from a syscall. */
    if (!handle_signal(context) && LIBOS_TCB_GET(context.syscall_nr) >= 0) {
        switch (ret) {
            case -ERESTARTNOHAND:
            case -ERESTARTSYS:
            case -ERESTARTNOINTR:
                restart_syscall(context, sysnr);
                break;
            default:
                break;
        }
    }

    struct libos_thread* current = get_cur_thread();
    if (current->has_saved_sigmask) {
        lock(&current->lock);
        set_sig_mask(current, &current->saved_sigmask);
        unlock(&current->lock);
        current->has_saved_sigmask = false;
    }

    LIBOS_TCB_SET(context.syscall_nr, -1);
    LIBOS_TCB_SET(context.regs, NULL);

    if (prof && prof_t0 && sysnr < 512) {
        uint64_t m1, p1;
        PalProfileThreadCycles(&m1, &p1);
        uint64_t* row = &g_libos_sysprof[sysnr * 4];
        __atomic_fetch_add(&row[0], 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&row[1], sysprof_tsc() - prof_t0, __ATOMIC_RELAXED);
        __atomic_fetch_add(&row[2], m1 - prof_m0, __ATOMIC_RELAXED);
        __atomic_fetch_add(&row[3], p1 - prof_p0, __ATOMIC_RELAXED);
    }

    return_from_syscall(context);
}

static noreturn __attribute__((noinline, cold)) void libos_emulate_syscall_prof(PAL_CONTEXT* context) {
    emulate_syscall(context, true);
}

noreturn void libos_emulate_syscall(PAL_CONTEXT* context) {
    /* One load and a predicted-not-taken branch: the profile is off in every
     * vault but a [svsm] debug one that asked for it. */
    if (__builtin_expect(g_libos_sysprof != NULL, 0))
        libos_emulate_syscall_prof(context);
    emulate_syscall(context, false);
}

__attribute_no_sanitize_address
noreturn void return_from_syscall(PAL_CONTEXT* context) {
#ifdef ASAN
    uintptr_t libos_stack_bottom = (uintptr_t)LIBOS_TCB_GET(libos_stack_bottom);
    asan_unpoison_region(libos_stack_bottom - LIBOS_THREAD_LIBOS_STACK_SIZE,
                         LIBOS_THREAD_LIBOS_STACK_SIZE);
#endif
    _return_from_syscall(context);
}
