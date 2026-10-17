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

/* The stack a fault is delivered on, per thread. It cannot be the stack the
 * fault interrupted: the LibOS answers a memory-fault upcall by writing the
 * application's signal frame below the interrupted rsp, over anything the
 * PAL had put there. See the note in pal_svsm.h. 32 KiB carries the PAL
 * entry, the LibOS upcall and the signal delivery under it. */
#define SVSM_ALT_STACK_SIZE (32 * 1024)

/* How long the idle loop spins between monitor calls. Interrupts are off in a
 * vault, so a spin produces no exits at all: without these the monitor could
 * not take the core back on its 10 ms slice, its invoke watchdog could not
 * fire and the host ring would not be served for the whole of a sleep. Often
 * enough to keep all three alive, rare enough not to turn a one-second sleep
 * into a million monitor calls. */
#define SVSM_IDLE_SLICE_US 100

/* void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base) */
void pal_svsm_ctx_switch(void** save_rsp, void* new_rsp, uint64_t new_gs_base);

static void refresh_preempt_wanted(void);

static PAL_HANDLE g_current = NULL;  /* the running context; NULL until init */
static size_t g_thread_cnt = 0;

/* A thread cannot free the stack it is standing on, so it leaves it here and
 * whoever runs next does it. Only ever one deep: the handover happens inside
 * the switch that follows. */
static void* g_stack_to_reap = NULL;

/*
 * The exiting thread's `clear_child_tid`, cleared by whoever runs NEXT.
 *
 * LibOS's `cleanup_thread` spins on this word and then calls `put_thread`,
 * which destroys the PAL handle. So the store IS the handover, and it used to
 * happen at the top of `_PalThreadExit` - before `state = ZOMBIE`, before
 * `ring_remove(self)`, before reading `self->thread.stack`, and before
 * `pick_next()` walks the ring. Every one of those touches the handle after
 * LibOS has been told it may free it.
 *
 * That was harmless for as long as PalObjectDestroy was `return; // ignore`,
 * because then nothing freed anything. It is not harmless now: a preemption
 * in that window lets the async worker run, free the handle, and leave the
 * exiting context walking its own freed memory - an intermittent hang in a
 * second threads run on a warm vault, which is how it showed up.
 *
 * `g_dead_rsp` above exists for exactly this reason one step later ("Its
 * handle may be destroyed by LibOS the moment we are off it, so we do not
 * write into that"). This is the same rule applied to the handover itself:
 * the thread has exited when the PAL has stopped touching it, not when it has
 * decided to.
 */
static int* g_tid_to_clear = NULL;

/* Somewhere for the switch stub to write the outgoing stack pointer of a
 * context that is never coming back. Its handle may be destroyed by LibOS the
 * moment we are off it, so we do not write into that. */
static void* g_dead_rsp = NULL;

static inline PAL_HANDLE current_thread(void) {
    return pal_get_svsm_tcb()->handle;
}

static void reap_stack(void) {
    /* The handover first, and unconditionally: a thread with no stack of its
     * own to free still has a LibOS waiter to release. */
    int* tid = g_tid_to_clear;
    if (tid) {
        g_tid_to_clear = NULL;
        __atomic_store_n(tid, 0, __ATOMIC_RELEASE);
    }
    void* stack = g_stack_to_reap;
    if (!stack)
        return;
    g_stack_to_reap = NULL;
    free(stack);
}

/* How long a park waits when nobody asked for a deadline: insurance, not
 * a wait anybody requested. A missed wake then costs a late dispatch
 * instead of a vault that never runs again - the same trade the
 * scheduler's own device watch makes. The shorter one is for a park that
 * could not arm everything it wanted to. */
#define SVSM_PARK_FALLBACK_US  1000000UL
#define SVSM_PARK_PARTIAL_US     20000UL

/*
 * The words that would make any blocked thread runnable, gathered for a
 * Park.
 *
 * The PAL's scheduler is the thing that actually gives the processor
 * back, but the thread that knows WHY it is waiting is the one that
 * blocked. So a blocking thread leaves its arms on its own handle and
 * this collects them. A thread that had more waitable channels than it
 * could arm sets `arms_partial`, and so does an overflow here, because
 * both mean the same thing downstream: a wake may be missed, so the
 * park needs a bounded fallback.
 */
static size_t gather_arms(uint64_t* arms, size_t max, bool* partial) {
    size_t n = 0;
    *partial = false;
    PAL_HANDLE t = g_current;
    do {
        if (t->thread.state == PAL_SVSM_THREAD_BLOCKED) {
            if (t->thread.arms_partial)
                *partial = true;
            for (unsigned i = 0; i < t->thread.n_arms; i++) {
                if (n == max) {
                    *partial = true;
                    break;
                }
                arms[n++] = t->thread.arms[i];
            }
        }
        t = t->thread.next;
    } while (t != g_current);
    return n;
}

/*
 * Give the processor back until one of `arms` moves or `usec` passes.
 *
 * Park (0x4FFFFFE1), not Sleep (0x4FFFFFDE), and the difference is the
 * whole of why a LibOS application can be a resident service at all. A
 * Park issued inside a host invoke RETURNS GETRESULT to the host: the
 * invoke ends, the vault becomes parked and resident, and the scheduler
 * dispatches it again when one of these words changes, when a peer
 * notifies it, when a peer goes, or when the timeout expires. Sleep is
 * refused in that position on purpose (channel_calls.rs:148), which is
 * why everything here used to spin instead.
 *
 * Refused for a vault that never declared a service name, because the
 * scheduler has no slot to park it in. That is not an error: it is an
 * ordinary vault doing an ordinary invoke, and the caller falls back to
 * what it did before.
 */
static bool park_on(const uint64_t* arms, size_t n, uint64_t usec) {
    /* Only a vault whose MEASURED manifest declared a service. For
     * anything else a Park would end the host invoke it is sitting in
     * and hand the host a GETRESULT for a result nobody has written -
     * which is exactly why Sleep refuses in that position. The manifest
     * is the only signal available here that says "this vault means to
     * be resident", and being measured is what makes it a safe one. */
    if (!g_pal_svsm_is_service)
        return false;
    return pal_svsm_park(n ? arms : NULL, n, usec) >= 0;
}

/* Give the vCPU back until `deadline_us`, in slices, so that the monitor and
 * the host both still get a turn while this vault has nothing to run. */
static void idle_until(uint64_t deadline_us) {
    while (1) {
        uint64_t now = pal_svsm_now_usec();
        if (now >= deadline_us)
            return;
        uint64_t left = deadline_us - now;

        /* Every context is blocked, so there is nothing for this vault
         * to do with a processor. Ask the monitor for it back, WATCHING
         * whatever words would make a blocked thread runnable - without
         * them this waits out the whole deadline even though the peer
         * may have sent in the first microsecond, which is what a
         * poll-based service spent its life doing.
         *
         * Park rather than Sleep, because a Park in this position is
         * what makes the vault resident (see park_on). If the vault has
         * no service slot the monitor refuses, and then the Sleep and
         * the spin that were here before are still what happens. */
        uint64_t arms[PAL_SVSM_THREAD_ARMS];
        bool partial = false;
        size_t n = gather_arms(arms, PAL_SVSM_THREAD_ARMS, &partial);
        if (park_on(arms, n, left)) {
            /* RETURN, do not loop. A park can end because a watched word
             * moved, and that is a state change the waiter has to see -
             * looping here would re-park until the deadline passed and
             * throw away the very wake this was armed for. Every poller
             * becomes runnable and re-tests its handles; the ones that
             * are still not ready block again, which is one more park
             * and is correct. */
            pal_svsm_poll_wake();
            return;
        }
        /* The Park was refused: no service slot, so this vault has
         * nothing the scheduler could park it in. Sleep instead - but
         * sleep the SAME WAY, watching the same words and bounded, so a
         * missed wake costs a slice rather than the whole wait.
         *
         * `pal_svsm_sleep(left)` was here: no arms, and the entire
         * remaining deadline. Sleep takes arms in exactly the format Park
         * does, so there was never a reason for that; nothing could end
         * it early, and a poller underneath it waited out its own
         * timeout. */
        uint64_t slice = left;
        if (n || partial) {
            uint64_t cap = partial ? SVSM_PARK_PARTIAL_US : SVSM_PARK_FALLBACK_US;
            if (slice > cap)
                slice = cap;
        }
        if (pal_svsm_sleep_arms(n ? arms : NULL, n, slice) >= 0) {
            /* As in the Park branch: a watched word may have moved, and
             * that is a state change every poller has to see. Return
             * rather than loop, so `pick_next` runs them. */
            pal_svsm_poll_wake();
            return;
        }

        /* The monitor refused the Sleep as well, which is what happens
         * to a vault inside a HOST INVOKE: a park in that position would
         * end the invoke and hand the host a GETRESULT for a result
         * nobody wrote, so `park_common` refuses anything the scheduler
         * did not dispatch. An ordinary client vault - which is what
         * every socket application is - therefore spins its wait out.
         *
         * Spin a SLICE and hand control back, rather than spinning the
         * whole deadline here. The loop was internal to this function,
         * so nothing re-tested a thread blocked in poll() until the
         * deadline passed: a client with `settimeout(5)` burned five
         * seconds of its own vCPU and then found the reply that had been
         * in the ring since the first millisecond. `pick_next` re-tests
         * blocked pollers on every pass, so returning here is what turns
         * this into a 100 us poll interval instead of a 5 s one. */
        uint64_t until = now + (left < SVSM_IDLE_SLICE_US ? left : SVSM_IDLE_SLICE_US);
        /* Bare pause, not CPU_RELAX: yielding from the idle loop would come
         * straight back here. */
        while (pal_svsm_now_usec() < until)
            __asm__ volatile("pause");
        pal_svsm_nop();
        /* One round per slice spun here. A slice is at most
         * SVSM_IDLE_SLICE_US, so the count bounds how long a client sat
         * waiting for its peer with nowhere to give the processor back to. */
        PAL_SVSM_NET_CTR_INC(idle_rounds);
        return;
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
            /* A poller whose handles have become ready is runnable NOW,
             * whatever its deadline says. Nothing else re-tests it: a
             * peer's send runs no code in this vault, and the only other
             * place that looks is `idle_until`, which a vault with an
             * async worker never reaches. Plain loads from the ring's
             * control words - no monitor call - so this costs two loads
             * per watched socket per scheduler pass, and only while
             * something is actually blocked in poll(). */
            if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.n_watch
                    && pal_svsm_poller_ready(t)) {
                PAL_SVSM_NET_CTR_INC(pollers_ready);
                t->thread.waiting_on = NULL;
                t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                pal_svsm_preempt_update(true);
            }
            if (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.has_deadline) {
                if (now >= t->thread.deadline_us) {
                    t->thread.timed_out  = true;
                    t->thread.waiting_on = NULL;
                    t->thread.state      = PAL_SVSM_THREAD_RUNNABLE;
                    pal_svsm_preempt_update(true);
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

        if (!have_deadline) {
            /* No deadline. Before this that was a deadlock by
             * definition, and for a vault with no channels it still is -
             * but a thread waiting on a ring has something that can wake
             * it, and `epoll_wait(-1)` on a channel socket is the
             * ordinary shape of a server rather than a bug. */
            uint64_t arms[PAL_SVSM_THREAD_ARMS];
            bool partial = false;
            size_t n = gather_arms(arms, PAL_SVSM_THREAD_ARMS, &partial);
            if (!n && !partial)
                return NULL;
            if (park_on(arms, n, partial ? SVSM_PARK_PARTIAL_US
                                         : SVSM_PARK_FALLBACK_US)) {
                pal_svsm_poll_wake();
                continue;
            }
            /* No service slot, so this vault cannot be parked and a wait
             * with no deadline really is one that nothing can end. */
            return NULL;
        }

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
        refresh_preempt_wanted();
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
    refresh_preempt_wanted();
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

/*
 * Whether anything other than the running context has any prospect of
 * running.
 *
 * The monitor reads this to decide whether preempting is worth a frame and
 * a round trip: a vault with one context has nothing to switch to, and
 * interrupting it to find that out is pure cost.
 *
 * A thread waiting on a deadline counts, and that is not a detail. The
 * only thing that ever notices a deadline has passed is the scheduler, and
 * the scheduler only runs when somebody yields - so during a computation
 * that never yields, a sleeping sibling would stay asleep for ever, its
 * timer would never fire, and counting only RUNNABLE contexts would say
 * there was nothing to preempt for and make that permanent. Being
 * preempted is precisely how the deadline comes to be noticed.
 *
 * Recomputed whenever the ring's population or a context's state changes,
 * which is cheap: a vault has a handful of contexts, not thousands.
 */
static void refresh_preempt_wanted(void) {
    if (!g_current) {
        pal_svsm_preempt_update(false);
        return;
    }
    PAL_HANDLE t = g_current->thread.next;
    while (t != g_current) {
        if (t->thread.state == PAL_SVSM_THREAD_RUNNABLE
                || (t->thread.state == PAL_SVSM_THREAD_BLOCKED && t->thread.has_deadline)) {
            pal_svsm_preempt_update(true);
            return;
        }
        t = t->thread.next;
    }
    pal_svsm_preempt_update(false);
}

static void ring_insert_after(PAL_HANDLE at, PAL_HANDLE node) {
    node->thread.next = at->thread.next;
    at->thread.next   = node;
    g_thread_cnt++;
    refresh_preempt_wanted();
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
    /* Deliberately NOT refreshing here. This runs with g_current still
     * pointing at the node being unlinked, whose `next` has just been
     * cleared, and every walk of the ring starts at g_current - so a walk
     * from here leaves the ring immediately and reads whatever it lands
     * on. The caller refreshes once it has re-pointed g_current. */
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

    /* The first thread's stack is the monitor's, so its alternate stack has
     * to be found somewhere; every other thread carves one out of its own
     * block. Without it this thread cannot be delivered a fault at all. */
    void* alt = malloc(SVSM_ALT_STACK_SIZE);
    if (!alt) {
        free(handle);
        return -PAL_ERROR_NOMEM;
    }
    memset(alt, 0, SVSM_ALT_STACK_SIZE);

    PAL_SVSM_TCB* tcb = pal_get_svsm_tcb();
    tcb->handle         = handle;
    tcb->alt_stack_top  = (char*)alt + SVSM_ALT_STACK_SIZE;
    tcb->alt_stack_size = SVSM_ALT_STACK_SIZE;
    /* lock_holds is NOT reset here: this is the TCB pal_main installed,
       zeroed, and any hold already counted on it is still owed. */

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
     *              |  alternate stack  |  SVSM_ALT_STACK_SIZE, grows down
     *              +-------------------+
     *              |                   |
     *              |   thread stack    |  SVSM_THREAD_STACK_SIZE, grows down
     *              |                   |
     *       tcb +--> +-----------------+
     *              |   PAL_SVSM_TCB    |
     *              +-------------------+  high
     *
     * The alternate stack sits below the thread stack so that running off
     * the bottom of the latter lands in a region of this block rather than
     * in whatever malloc handed out next.
     */
    size_t block = SVSM_ALT_STACK_SIZE + SVSM_THREAD_STACK_SIZE + sizeof(PAL_SVSM_TCB);
    char* stack = malloc(block);
    if (!stack) {
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }
    memset(stack, 0, block);

    PAL_SVSM_TCB* tcb = (PAL_SVSM_TCB*)(stack + SVSM_ALT_STACK_SIZE + SVSM_THREAD_STACK_SIZE);
    tcb->common.self  = &tcb->common;
    /* The same canary the creating thread uses, as glibc does for its own
     * threads. A per-thread random one is a hardening nicety, but it has to
     * be installed by the new context itself, and every frame that straddles
     * the change would then check the wrong value. */
    pal_tcb_arch_set_stack_canary(&tcb->common, pal_get_tcb()->stack_protector_canary);
    tcb->handle         = hdl;
    tcb->alt_stack_top  = stack + SVSM_ALT_STACK_SIZE;
    tcb->alt_stack_size = SVSM_ALT_STACK_SIZE;
    tcb->callback       = callback;
    tcb->param          = param;
    tcb->lock_holds     = 0;

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

/*
 * In a copy-on-write fork's child, right after the fork: the forker is the
 * only thread.
 *
 * Every other context on the ring is a copy of one of the PARENT's threads -
 * its stack, its registers, its place in whatever it was doing - and the ring
 * is this process's own memory, so the copy was runnable here. It ran: a
 * parent thread blocked in a read went on reading in the child too, a worker
 * went on working, and the LibOS's exit and exec waited on them as its own
 * (kill_other_threads). POSIX's fork gives the child the calling thread and
 * nothing else, and so does this, before the child can pick anything else
 * to run - it is called on the forker's way out of the fork.
 *
 * Unlinked, not freed: the stacks are copies nobody will run on again, and a
 * leak of them is cheaper than being wrong about who still points into one.
 * A copy cannot be holding a PAL lock either: PAL text is never preempted,
 * and the one PAL lock a thread waits under (an event's) is let go before it
 * blocks. Nor a LibOS lock: _PalProcessFork refuses a fork while any other
 * context holds one (pal_svsm_fork_quiesce), since the copy could never let
 * go of it here.
 */
void pal_svsm_threads_child_after_fork(void) {
    PAL_HANDLE self = g_current;
    if (!self)
        return;
    PAL_HANDLE t = self->thread.next;
    while (t && t != self) {
        PAL_HANDLE next = t->thread.next;
        t->thread.next  = NULL;
        /* Anything that still finds this handle - nothing should - finds a
         * thread that has ended, which _PalThreadResume leaves alone. */
        t->thread.state = PAL_SVSM_THREAD_ZOMBIE;
        t = next;
    }
    self->thread.next = self;
    g_thread_cnt = 1;
    refresh_preempt_wanted();
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
     * Telling LibOS the thread is gone is DEFERRED to whoever runs next, with
     * the stack (see g_tid_to_clear): the store hands LibOS permission to free
     * this handle, and the code below is still using it.
     *
     * LibOS waits for exactly this by spinning (bookkeep/libos_thread.c:483,
     * ipc/libos_ipc_worker.c:419), and those spins end because CPU_RELAX
     * yields back into this scheduler - which still works when the store comes
     * one switch later: this context is runnable until it switches away, so it
     * always gets to finish, and the context it switches to does the store.
     */
    self->thread.state = PAL_SVSM_THREAD_ZOMBIE;

    if (g_thread_cnt == 1) {
        /* Nothing else was ever started, or everything else has gone. A
         * process with no threads left is a process that has ended. Nobody
         * will run next, so the handover happens here or not at all - and it
         * is safe here precisely because no other context can act on it. */
        if (clear_child_tid)
            __atomic_store_n(clear_child_tid, 0, __ATOMIC_RELEASE);
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
    assert(!g_tid_to_clear);
    g_stack_to_reap = self->thread.stack;
    g_tid_to_clear  = clear_child_tid;
    g_current = succ;
    /* Now that g_current is a node that is still in the ring. */
    refresh_preempt_wanted();

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
        refresh_preempt_wanted();
    }
    return 0;
}

/*
 * The sticky flag above, read and cleared for the thread that is running.
 *
 * A thread that blocks finds a pending signal through its wait returning
 * PAL_SVSM_WAIT_INTERRUPTED, and the LibOS delivers it on the way out of the
 * syscall. A thread that never blocks - dhry2reg's loop, UnixBench's hanoi
 * and arith, anything that waits for SIGALRM by computing - never gets
 * there, so the preemption path asks instead (next.md 170.4). Clearing is a
 * separate call because the flag must survive a tick on which the signal
 * could NOT be delivered (the thread was inside the LibOS): the blocking
 * path or the next tick still owes it.
 */
bool pal_svsm_current_interrupted(void) {
    return g_current && g_current->thread.interrupted;
}

void pal_svsm_current_clear_interrupted(void) {
    if (g_current)
        g_current->thread.interrupted = false;
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
    refresh_preempt_wanted();

    schedule();

    self->thread.waiting_on   = NULL;
    self->thread.has_deadline = false;
    /* The arms belonged to this wait. Anything that runs now re-tests
     * what it is waiting for, so a stale word would only make the next
     * park end early - but it would also make it end early for a
     * DIFFERENT thread's wait, which is a bug that would look like a
     * spurious wake and be very hard to see. */
    self->thread.n_arms       = 0;
    self->thread.arms_partial = false;
    /* Points into this call's own frame, which is about to go. */
    self->thread.n_watch       = 0;
    self->thread.watch_handles = NULL;
    self->thread.watch_events  = NULL;

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

/*
 * What this thread is about to wait on, in words the monitor can watch.
 *
 * Called just before blocking, by whoever knows what the wait is for.
 * `partial` says the caller had more it wanted watched than it could
 * fit, which the scheduler turns into a bounded fallback rather than an
 * indefinite park.
 */
void pal_svsm_thread_arm(const uint64_t* arms, size_t count, bool partial) {
    if (!g_current)
        return;
    if (count > PAL_SVSM_THREAD_ARMS) {
        count   = PAL_SVSM_THREAD_ARMS;
        partial = true;
    }
    for (size_t i = 0; i < count; i++)
        g_current->thread.arms[i] = arms[i];
    g_current->thread.n_arms       = (uint8_t)count;
    g_current->thread.arms_partial = partial;
}

/*
 * The handles a thread about to block in poll() is waiting on.
 *
 * Stored rather than copied: these point into the caller's frame, which
 * is alive for exactly as long as the thread is blocked in it, and
 * `pal_svsm_thread_block` clears them on the way out.
 */
void pal_svsm_thread_watch(size_t count, PAL_HANDLE* handles, pal_wait_flags_t* events) {
    if (!g_current)
        return;
    g_current->thread.watch_handles = handles;
    g_current->thread.watch_events  = events;
    g_current->thread.n_watch       = handles && events ? count : 0;
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
    refresh_preempt_wanted();
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
