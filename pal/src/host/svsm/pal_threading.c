/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Threads inside a vault.
 *
 * A vault is one CPL3 process with one VMSA. The monitor runs that VMSA on
 * one vCPU and refuses a second entrant to it - "two vCPUs inside one VMSA is
 * undefined behavior" (process_runtime/invoke.rs) - so there is exactly one
 * thread of execution here and no amount of PAL code can make a second one.
 * Before this file, that meant `pthread_create` failed: _PalThreadCreate
 * returned NOTIMPLEMENTED, so anything that wanted a thread did not run at
 * all, including LibOS's own async and IPC workers.
 *
 * What this gives instead is several contexts sharing that one thread of
 * execution, switched at the points where a thread would otherwise have
 * blocked or spun. That is enough for everything whose threads are *waiting*
 * rather than computing: a futex under contention, a worker parked on a
 * queue, time.sleep, and CPython in general, whose GIL means its threads
 * never run at once anyway. It is not parallelism, and it will not become
 * parallelism: two threads never execute simultaneously, so a compute-bound
 * thread starves its siblings until it calls something that yields. A vault
 * has interrupts disabled and an IDT with three vectors, so there is no timer
 * to preempt it with. Real parallelism is a monitor project - a VMSA per
 * thread, a scheduler in place of the invoke loop, a second vCPU - and is
 * deliberately not attempted here.
 *
 * Mechanically this is the classic arrangement: a ring of contexts, a saved
 * stack pointer per parked context, and a switch stub (arch/x86_64/pal_switch.S)
 * that moves callee-saved registers and the GS base between two stacks. No
 * locking, because with one thread of execution there is nothing to race
 * with - a spinlock here can only ever be uncontended, and a lock held across
 * a yield would be a deadlock no lock could fix.
 */

#include "api.h"
#include "assert.h"
#include "cpu.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"

/* Same shape as the Linux PAL's: 64 KiB is enough for LibOS and PAL frames,
 * and an application thread runs on the stack its clone() named, not this
 * one. */
#define SVSM_THREAD_STACK_SIZE (64 * 1024)

/* How long the idle loop spins between monitor calls. Interrupts are off in a
 * vault, so a spin produces no exits at all: without these the monitor could
 * not take the core back on its 10 ms slice, its invoke watchdog could not
 * fire and the host ring would not be served for the whole of a sleep. Often
 * enough to keep all three alive, rare enough not to turn a one-second sleep
 * into a million monitor calls. */
#define SVSM_IDLE_SLICE_US 100

/* void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base) */
void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base);

static PAL_HANDLE g_current = NULL;  /* the running context; NULL until init */
static size_t g_thread_cnt = 0;

/* A thread cannot free the stack it is standing on, so it leaves it here and
 * whoever runs next does it. Only ever one deep: the handover happens inside
 * the switch that follows. */
static void* g_stack_to_reap = NULL;

/* Somewhere for the switch stub to write the outgoing stack pointer of a
 * context that is never coming back. Its handle may be destroyed by LibOS the
 * moment we are off it, so we do not write into that. */
static void* g_dead_rsp = NULL;

static inline PAL_HANDLE current_thread(void) {
    return pal_get_svsm_tcb()->handle;
}

static void reap_stack(void) {
    void* stack = g_stack_to_reap;
    if (!stack)
        return;
    g_stack_to_reap = NULL;
    free(stack);
}

/* Give the vCPU back until `deadline_us`, in slices, so that the monitor and
 * the host both still get a turn while this vault has nothing to run. */
static void idle_until(uint64_t deadline_us) {
    while (1) {
        uint64_t now = pal_svsm_now_usec();
        if (now >= deadline_us)
            return;
        uint64_t left = deadline_us - now;
        uint64_t until = now + (left < SVSM_IDLE_SLICE_US ? left : SVSM_IDLE_SLICE_US);
        /* Bare pause, not CPU_RELAX: yielding from the idle loop would come
         * straight back here. */
        while (pal_svsm_now_usec() < until)
            __asm__ volatile("pause");
        pal_svsm_nop();
    }
}

/*
 * The next context to run, or NULL when nothing will ever be runnable again.
 * Expires deadlines on the way past, and waits for the nearest one if that is
 * the only thing that can change the answer.
 */
static PAL_HANDLE pick_next(void) {
    assert(g_current);

    while (1) {
        uint64_t now = pal_svsm_now_usec();
        uint64_t earliest = 0;
        bool have_deadline = false;

        PAL_HANDLE t = g_current;
        do {
            if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.has_deadline) {
                if (now >= t->thread.deadline_us) {
                    t->thread.timed_out  = true;
                    t->thread.waiting_on = NULL;
                    t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                } else if (!have_deadline || t->thread.deadline_us < earliest) {
                    earliest      = t->thread.deadline_us;
                    have_deadline = true;
                }
            }
            t = t->thread.next;
        } while (t != g_current);

        /* Round robin: start after whoever ran last, so a thread that yields
         * goes to the back. */
        PAL_HANDLE start = g_current->thread.next;
        t = start;
        do {
            if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE)
                return t;
            t = t->thread.next;
        } while (t != start);

        /* Nobody else wants it and we are still able to run: carry on. */
        if (g_current->thread.state == PAL_SVSM_THREAD_RUNNING)
            return g_current;

        if (!have_deadline)
            return NULL;

        idle_until(earliest);
    }
}

/* Nothing runnable and nothing that can become runnable. */
static noreturn void die_deadlocked(void) {
    /* Loud, because the alternative is a vault that sits there doing nothing
     * until the monitor's invoke watchdog kills it 600 seconds later with no
     * explanation of what it was waiting for. */
    pal_svsm_fail("deadlock: every thread is blocked and nothing can wake them",
                  (int)g_thread_cnt);
    die_or_inf_loop();
}

/* Hand the CPU to whoever should have it, and return once this context runs
 * again. Not for a context that is exiting - that has its own path, because
 * it must leave the ring before it lets go. */
static void schedule(void) {
    PAL_HANDLE prev = g_current;
    assert(prev->thread.state != PAL_SVSM_THREAD_ZOMBIE);

    PAL_HANDLE next = pick_next();
    if (!next)
        die_deadlocked();

    if (next == prev) {
        assert(prev->thread.state == PAL_SVSM_THREAD_RUNNING);
        reap_stack();
        return;
    }

    if (prev->thread.state == PAL_SVSM_THREAD_RUNNING)
        prev->thread.state = PAL_SVSM_THREAD_RUNNABLE;
    next->thread.state = PAL_SVSM_THREAD_RUNNING;
    g_current = next;

    /*
     * FS is the *application's* thread pointer - glibc's TLS block, which is
     * where pthread_self() and therefore Python's threading.get_ident() read
     * from - and it is per thread just as GS is. The switch stub moves GS
     * because the stack canary is read through it and there must be no
     * instruction where the two disagree; FS has no such constraint, so each
     * context saves its own here and puts it back when it is next run.
     *
     * Leaving it out is not a subtle bug. Every thread then sees whichever
     * thread ran last as itself: Thread.join() answers "cannot join current
     * thread", and anything else keyed on thread identity is silently wrong.
     */
    prev->thread.fsbase = rdfsbase();

    pal_svsm_ctx_switch(&prev->thread.rsp, next->thread.rsp, (uint64_t)next->thread.tcb);

    /* Back on prev's stack, however long later. */
    wrfsbase(prev->thread.fsbase);
    reap_stack();
}

/* Where a new context starts. Reached by the switch stub's `ret`, so GS -
 * and therefore the TCB, the canary and current_thread() - is already this
 * thread's. */
__attribute_no_stack_protector
static noreturn void thread_trampoline(void) {
    /* Zero until LibOS gives this thread its TLS; see the note in
     * schedule() about why FS travels with the context. */
    wrfsbase(current_thread()->thread.fsbase);
    reap_stack();

    PAL_SVSM_TCB* tcb = pal_get_svsm_tcb();
    int (*callback)(void*) = tcb->callback;
    void* param = tcb->param;

    callback(param);

    _PalThreadExit(/*clear_child_tid=*/NULL);
}

static void ring_insert_after(PAL_HANDLE at, PAL_HANDLE node) {
    node->thread.next = at->thread.next;
    at->thread.next   = node;
    g_thread_cnt++;
}

/* Caller must not leave g_current pointing at `node`: every walk starts
 * there and an unlinked node is no longer on any ring. */
static void ring_remove(PAL_HANDLE node) {
    assert(g_thread_cnt > 1);
    PAL_HANDLE prev = node->thread.next;
    while (prev->thread.next != node)
        prev = prev->thread.next;
    prev->thread.next = node->thread.next;
    node->thread.next = NULL;
    g_thread_cnt--;
}

/* Installed as g_cpu_relax_yield: see the comment on CPU_RELAX in cpu.h. */
static void cpu_relax_yield(void) {
    _PalThreadYieldExecution();
}

int pal_svsm_threading_init(PAL_HANDLE* out_first_thread) {
    assert(!g_current);

    PAL_HANDLE handle = calloc(1, HANDLE_SIZE(thread));
    if (!handle)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(handle, PAL_TYPE_THREAD);

    /* The first thread runs on the stack the monitor gave the vault and on
     * the TCB already in GS, so it owns neither: stack stays NULL so nothing
     * ever frees it. */
    handle->thread.stack = NULL;
    handle->thread.tcb   = pal_get_tcb();
    handle->thread.state = PAL_SVSM_THREAD_RUNNING;
    handle->thread.next  = handle;

    pal_get_svsm_tcb()->handle = handle;

    g_current    = handle;
    g_thread_cnt = 1;

    /* From here on a spin that waits on another thread has to give that
     * thread a turn. LibOS installs its own copy of this once it has read
     * pal_public_state::cooperative_threading. */
    g_cpu_relax_yield = cpu_relax_yield;

    *out_first_thread = handle;
    return 0;
}

int _PalThreadCreate(PAL_HANDLE* handle, int (*callback)(void*), void* param) {
    if (!g_current)
        return -PAL_ERROR_DENIED;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(thread));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    /*
     * One block: the stack, with the TCB sitting at the top of it.
     *
     *   stack +--> +-------------------+  low
     *              |                   |
     *              |   thread stack    |  SVSM_THREAD_STACK_SIZE, grows down
     *              |                   |
     *       tcb +--> +-----------------+
     *              |   PAL_SVSM_TCB    |
     *              +-------------------+  high
     */
    char* stack = malloc(SVSM_THREAD_STACK_SIZE + sizeof(PAL_SVSM_TCB));
    if (!stack) {
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }
    memset(stack, 0, SVSM_THREAD_STACK_SIZE + sizeof(PAL_SVSM_TCB));

    PAL_SVSM_TCB* tcb = (PAL_SVSM_TCB*)(stack + SVSM_THREAD_STACK_SIZE);
    tcb->common.self  = &tcb->common;
    /* The same canary the creating thread uses, as glibc does for its own
     * threads. A per-thread random one is a hardening nicety, but it has to
     * be installed by the new context itself, and every frame that straddles
     * the change would then check the wrong value. */
    pal_tcb_arch_set_stack_canary(&tcb->common, pal_get_tcb()->stack_protector_canary);
    tcb->handle    = hdl;
    tcb->alt_stack = NULL;   /* no signals reach a vault: pal_exception.c is a stub */
    tcb->callback  = callback;
    tcb->param     = param;

    /*
     * The frame pal_svsm_ctx_switch will unwind into. It pops six registers
     * and returns, so the top of the new stack has to look like the middle of
     * that stub: six saved registers below a return address.
     *
     * The alignment is the SysV rule read backwards - a function is entered
     * with rsp % 16 == 8, because the call that reached it pushed 8 bytes
     * onto a 16-aligned stack - so the null word below pins the trampoline's
     * entry to exactly that. The null doubles as a return address that
     * terminates a backtrace.
     */
    uint64_t* sp = (uint64_t*)ALIGN_DOWN_PTR(tcb, 16);
    *--sp = 0;                                 /* backstop return address */
    *--sp = (uint64_t)thread_trampoline;       /* what the stub returns into */
    for (int i = 0; i < 6; i++)
        *--sp = 0;                             /* rbp, rbx, r12, r13, r14, r15 */

    init_handle_hdr(hdl, PAL_TYPE_THREAD);
    hdl->thread.stack = stack;
    hdl->thread.tcb   = tcb;
    hdl->thread.rsp   = sp;
    hdl->thread.state = PAL_SVSM_THREAD_RUNNABLE;

    ring_insert_after(g_current, hdl);

    *handle = hdl;
    return 0;
}

void _PalThreadYieldExecution(void) {
    /* Before threading is up - and it is up before anything can block - there
     * is nothing to yield to. CPU_RELAX lands here from very early code. */
    if (!g_current)
        return;
    schedule();
}

noreturn void _PalThreadExit(int* clear_child_tid) {
    PAL_HANDLE self = g_current;
    assert(self && self == current_thread());

    /*
     * Tell LibOS the thread is gone before giving up the CPU. LibOS waits for
     * exactly this by spinning (bookkeep/libos_thread.c:483,
     * ipc/libos_ipc_worker.c:419), and those spins only end because CPU_RELAX
     * yields back into this scheduler - which is also why the store has to
     * happen before the switch rather than after it.
     */
    if (clear_child_tid)
        __atomic_store_n(clear_child_tid, 0, __ATOMIC_RELEASE);

    self->thread.state = PAL_SVSM_THREAD_ZOMBIE;

    if (g_thread_cnt == 1) {
        /* Nothing else was ever started, or everything else has gone. A
         * process with no threads left is a process that has ended. */
        _PalProcessExit(0);
    }

    /*
     * Leave the ring before letting go of the CPU. The handle is LibOS's to
     * destroy the moment this thread has exited, so it must not still be
     * linked when that happens - and pick_next() walks the ring starting at
     * g_current, so g_current has to name a thread that is still in it.
     *
     * The stack outlives us by exactly one switch: it is still underfoot
     * until pal_svsm_ctx_switch has moved to another one, so whoever runs
     * next frees it (reap_stack).
     */
    PAL_HANDLE succ = self->thread.next;
    assert(succ != self);
    ring_remove(self);
    assert(!g_stack_to_reap);
    g_stack_to_reap = self->thread.stack;
    g_current = succ;

    PAL_HANDLE next = pick_next();
    if (!next)
        die_deadlocked();

    next->thread.state = PAL_SVSM_THREAD_RUNNING;
    g_current = next;

    /* Nowhere to come back to, so the outgoing stack pointer goes to a
     * scratch word rather than into a handle that may already be freed, and
     * this context's FS is not worth saving. The thread we switch to puts
     * its own back on the far side of its own switch. */
    pal_svsm_ctx_switch(&g_dead_rsp, next->thread.rsp, (uint64_t)next->thread.tcb);

    die_or_inf_loop();
}

int _PalThreadResume(PAL_HANDLE thread_handle) {
    if (!thread_handle || thread_handle->hdr.type != PAL_TYPE_THREAD)
        return -PAL_ERROR_INVAL;

    /* What this means on other hosts is "interrupt whatever it is blocked in,
     * there is a signal for it". Sticky, because the signal may arrive just
     * before the thread blocks. */
    thread_handle->thread.interrupted = true;
    if (thread_handle->thread.state == PAL_SVSM_THREAD_BLOCKED) {
        thread_handle->thread.waiting_on = NULL;
        thread_handle->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
    }
    return 0;
}

enum pal_svsm_wait_result pal_svsm_thread_block(PAL_HANDLE waiting_on,
                                                const uint64_t* deadline_us) {
    PAL_HANDLE self = g_current;
    assert(self);

    if (self->thread.interrupted) {
        self->thread.interrupted = false;
        return PAL_SVSM_WAIT_INTERRUPTED;
    }

    self->thread.waiting_on   = waiting_on;
    self->thread.has_deadline = deadline_us != NULL;
    self->thread.deadline_us  = deadline_us ? *deadline_us : 0;
    self->thread.timed_out    = false;
    self->thread.state        = PAL_SVSM_THREAD_BLOCKED;

    schedule();

    self->thread.waiting_on   = NULL;
    self->thread.has_deadline = false;

    if (self->thread.interrupted) {
        self->thread.interrupted = false;
        return PAL_SVSM_WAIT_INTERRUPTED;
    }
    if (self->thread.timed_out) {
        self->thread.timed_out = false;
        return PAL_SVSM_WAIT_TIMEOUT;
    }
    return PAL_SVSM_WAIT_WOKEN;
}

/*
 * Waiting on something pollable.
 *
 * A poll watches a set of handles, so it cannot park against one of them.
 * The sentinel below stands for "anything pollable moved"; a woken poller
 * re-tests its whole set, which it has to do anyway because another thread
 * may have consumed what it was woken for. It is never dereferenced - only
 * compared - and never handed to anything that would.
 */
static const char g_poll_token_storage;
#define POLL_TOKEN ((PAL_HANDLE)(void*)&g_poll_token_storage)

enum pal_svsm_wait_result pal_svsm_poll_block(const uint64_t* deadline_us) {
    return pal_svsm_thread_block(POLL_TOKEN, deadline_us);
}

void pal_svsm_poll_wake(void) {
    pal_svsm_thread_wake_all(POLL_TOKEN);
}

void pal_svsm_thread_wake_all(PAL_HANDLE waiting_on) {
    if (!g_current || !waiting_on)
        return;

    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.waiting_on == waiting_on) {
            t->thread.waiting_on = NULL;
            t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
        }
        t = t->thread.next;
    } while (t != g_current);
}

/* One CPU, and it is not ours to hand out: the monitor decides which vCPU
 * runs this vault. Reporting the single online CPU keeps callers that read an
 * affinity mask working rather than failing. */
int _PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    __UNUSED(thread);
    if (!cpu_mask_len)
        return -PAL_ERROR_INVAL;
    /* Refuse a mask that excludes the only CPU there is, rather than pretend. */
    if (!(cpu_mask[0] & 1))
        return -PAL_ERROR_INVAL;
    return 0;
}

int _PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len) {
    __UNUSED(thread);
    if (!cpu_mask_len)
        return -PAL_ERROR_INVAL;
    memset(cpu_mask, 0, cpu_mask_len * sizeof(*cpu_mask));
    cpu_mask[0] = 1;
    return 0;
}

struct handle_ops g_thread_ops = {
    /* nothing */
};
