#pragma once

/* PAL main function */
noreturn void pal_svsm_main(void);

typedef struct pal_svsm_tcb {
    PAL_TCB common;
    struct {
        PAL_HANDLE handle;
        /*
         * Where a fault is delivered: the top of this thread's alternate
         * stack, and its size.
         *
         * A fault cannot be delivered onto the stack it interrupted. The
         * LibOS answers a memory-fault upcall by building the
         * *application's* signal frame below the interrupted rsp - the
         * same place the interrupted context and the PAL's own frames
         * would be - and then returns expecting to be resumed from a
         * context it has just written over. Gramine on Linux keeps the
         * two apart with sigaltstack; this is that, by hand.
         *
         * The monitor reads these two words out of this thread's TCB via
         * the GS base it already has, so the right stack is picked per
         * thread without anything being told which thread is running.
         * They must stay adjacent and in this order; the offset of the
         * pair is registered once by pal_svsm_exception_init.
         */
        void*      alt_stack_top;
        uint64_t   alt_stack_size;
        int        (*callback)(void*);
        void*      param;
    };
} PAL_SVSM_TCB;

static inline PAL_SVSM_TCB* pal_get_svsm_tcb(void) {
    return (PAL_SVSM_TCB*)pal_get_tcb();
}

/*
 * Time (pal_misc.c). A vault has no clock: no RTC, no kvm-clock, no timer
 * interrupt. rdtsc is the only tick source and the monitor is the only place
 * that knows what a tick is worth, so ask it once and convert here.
 */
void     pal_svsm_time_init(void);
uint64_t pal_svsm_tsc_hz(void);
uint64_t pal_svsm_tsc_to_usec(uint64_t tsc);
uint64_t pal_svsm_now_usec(void);

/*
 * Faults and signals (pal_exception.c). The monitor enters
 * pal_svsm_exception_entry with a fault it will not handle itself; see the
 * comment at the top of that file.
 */
void pal_svsm_exception_init(void);
void pal_svsm_set_text_range(uintptr_t start, uintptr_t end);

/*
 * What the monitor needs to know to preempt this vault, and what it tells
 * the vault back. Read by the monitor out of this process's own memory, so
 * the three words must keep this order.
 *
 * `wanted` is the whole of the policy: the scheduler sets it when there is
 * more than one context to run and clears it when there is not, so a vault
 * with nothing to switch to is never interrupted to be told so.
 */
struct pal_svsm_preempt_ctl {
    uint64_t wanted;          /* nonzero: something else could run */
    uint64_t min_interval_us; /* the quantum this vault wants */
    uint64_t count;           /* preemptions taken; the monitor bumps it */
    /*
     * This PAL's own code, which must never be preempted.
     *
     * An application or the LibOS can be interrupted anywhere - both are
     * written for real preemptive threads and take real locks. The PAL is
     * not: it IS the scheduler, and stopping it in the middle of picking
     * the next context to run, to go and pick the next context to run,
     * does not end anywhere good. Measured before this range existed:
     * preemptions landed inside the PAL and the vault aborted.
     *
     * A range rather than a flag because it needs no instrumenting - every
     * PAL critical section is inside it by construction, and the monitor
     * pays one comparison.
     */
    uint64_t text_start;
    uint64_t text_end;
};

extern struct pal_svsm_preempt_ctl g_pal_svsm_preempt;

/*
 * The quantum a vault asks for when nothing is waiting on a sooner
 * deadline: a scheduling quantum, not a timer tick - the longest a runnable
 * sibling should wait behind a thread that never blocks.
 */
#define PAL_SVSM_PREEMPT_DEFAULT_US 4000

/*
 * What the monitor told this vault it can do (SetExceptionEntry's answer).
 *
 * RET_GATE: the trustlet IDT has a DPL-3 gate at 0x81 that resumes a
 * PAL_CONTEXT, so finishing a fault costs an `int` rather than a monitor
 * call - no VMPL round trip and no walk of this vault's page table by the
 * monitor. A HOSTED vault (VMPL0, CPL3 inside the monitor) is told 0,
 * because it traps into the SVSM's own IDT where that gate does not exist.
 */
#define PAL_SVSM_CAP_RET_GATE 1

/* Set once at startup from the capability word. A byte rather than the whole
 * word because the only reader is three instructions of assembly on the
 * fault-return path (arch/x86_64/pal_switch.S). */
extern uint8_t g_pal_svsm_ret_gate;
/* Keep `wanted` in step with the ready queue. Called by the scheduler. */
void pal_svsm_preempt_update(bool others_runnable);


/*
 * Threads (pal_threading.c). Cooperative contexts inside the one CPL3
 * process a vault is - not vCPUs. See the comment at the top of that file
 * for why, and for what this does and does not buy.
 */
enum pal_svsm_thread_state {
    PAL_SVSM_THREAD_RUNNING = 0,
    PAL_SVSM_THREAD_RUNNABLE,
    PAL_SVSM_THREAD_BLOCKED,
    PAL_SVSM_THREAD_ZOMBIE,
};

/* Why a blocked thread came back. */
enum pal_svsm_wait_result {
    PAL_SVSM_WAIT_WOKEN = 0,   /* somebody signalled what we waited on */
    PAL_SVSM_WAIT_TIMEOUT,     /* the deadline passed */
    PAL_SVSM_WAIT_INTERRUPTED, /* _PalThreadResume, i.e. a signal is pending */
};

/* Build the first thread's handle and make it current. Must run after the
 * slab allocator is up and before anything can block. */
int pal_svsm_threading_init(PAL_HANDLE* out_first_thread);

/* Park the caller until woken, until `deadline_us` (absolute, as
 * pal_svsm_now_usec reports; NULL = forever), or until resumed. `waiting_on`
 * is the handle being waited for, so a wake can find just its waiters; NULL
 * parks against nothing in particular. */
enum pal_svsm_wait_result pal_svsm_thread_block(PAL_HANDLE waiting_on,
                                                const uint64_t* deadline_us);

/* Make every thread parked on `waiting_on` runnable. Safe to call with no
 * waiters. */
void pal_svsm_thread_wake_all(PAL_HANDLE waiting_on);

/* The same, for threads waiting on something pollable rather than on one
 * handle: a poll may be watching several handles at once, so it parks
 * against the whole class and re-tests when woken. pal_svsm_poll_wake is
 * what a pipe write (or close) calls. */
enum pal_svsm_wait_result pal_svsm_poll_block(const uint64_t* deadline_us);
/* What the calling thread is about to wait on, so that the PAL's
 * scheduler can ask the monitor to watch those words rather than giving
 * the processor back blind. See pal_threading.c. */
void pal_svsm_thread_arm(const uint64_t* arms, size_t count, bool partial);
/* The manifest declared [svsm.service]: this vault means to be resident,
 * so the PAL may Park it and let a host invoke end with GETRESULT. */
extern bool g_pal_svsm_is_service;

/* Socket readiness, from the ring's own indices (pal_sockets.c). */
/* The ring word that would make this socket ready for `want`. Returns
 * the number of arms written (0 or 1). */
int pal_svsm_sock_arm(PAL_HANDLE handle, pal_wait_flags_t want, uint64_t* out_arm);
bool pal_svsm_sock_readable(PAL_HANDLE handle);
bool pal_svsm_sock_writable(PAL_HANDLE handle);

/* Who this vault may connect to, from [svsm.net] in its measured manifest. */
extern char     g_pal_svsm_net_name[32];
/* 1 when that peer is a network service and `connect` must say where it
 * is going first (svsm.net.protocol = "mvnet"). */
extern int      g_pal_svsm_net_protocol;
extern uint64_t g_pal_svsm_net_endpoint;
void pal_svsm_poll_wake(void);

/*
 * Pipes (pal_pipes.c). Both ends are in this address space, so what a poll
 * wants to know is answerable here; pal_object.c asks.
 */
size_t pal_svsm_pipe_readable(PAL_HANDLE handle);
bool   pal_svsm_pipe_writable(PAL_HANDLE handle);
bool   pal_svsm_pipe_peer_gone(PAL_HANDLE handle);
bool   pal_svsm_pipesrv_pending(PAL_HANDLE handle);
