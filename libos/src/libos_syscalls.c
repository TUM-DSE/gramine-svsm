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

/* Own CPU (the DSB breakdown's Q2, owner 2026-11-27; the diagnostic gramine only): for the
 * calls that can block or switch threads, a SHADOW row at 480 + k whose count is the calls
 * and whose wall word is this thread's own running time in them (PalProfileThreadRan less
 * its parks) - their wall row counts the siblings that ran meanwhile. Rows 480..511 are no
 * x86-64 syscall (the last is 469, file_setattr), so the monitor prints them as any row
 * (VAULT_PROF "nr:count:wall:mon:park"); breakdown.py maps them back. 0 = no shadow. */
#define SYSPROF_SHADOW_BASE 480
static const uint16_t g_sysprof_shadow[] = {
    0 /* read */, 1 /* write */, 7 /* poll */, 19 /* readv */, 20 /* writev */,
    23 /* select */, 24 /* sched_yield */, 35 /* nanosleep */, 42 /* connect */,
    43 /* accept */, 44 /* sendto */, 45 /* recvfrom */, 46 /* sendmsg */, 47 /* recvmsg */,
    56 /* clone */, 61 /* wait4 */, 202 /* futex */, 230 /* clock_nanosleep */,
    232 /* epoll_wait */, 270 /* pselect6 */, 271 /* ppoll */, 281 /* epoll_pwait */,
    288 /* accept4 */, 435 /* clone3 */, 441 /* epoll_pwait2 */,
};
static inline int sysprof_shadow_row(unsigned long sysnr) {
    for (size_t k = 0; k < ARRAY_SIZE(g_sysprof_shadow); k++)
        if (g_sysprof_shadow[k] == sysnr)
            return SYSPROF_SHADOW_BASE + (int)k;
    return -1;
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
    int prof_sh = -1;
    if (prof) {
        prof_t0 = sysprof_tsc();
        PalProfileThreadCycles(&prof_m0, &prof_p0);
        /* own CPU, charged incrementally by the PAL from here to PalProfileOwnEnd */
        prof_sh = sysnr < 512 ? sysprof_shadow_row(sysnr) : -1;
        if (prof_sh >= 0)
            PalProfileOwnBegin(&g_libos_sysprof[prof_sh * 4 + 1]);
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
        if (prof_sh >= 0) {
            PalProfileOwnEnd();
            __atomic_fetch_add(&g_libos_sysprof[prof_sh * 4], 1, __ATOMIC_RELAXED);
        }
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
