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
        /* LibOS lock holds this context has counted (_PalLockHold). */
        int64_t    lock_holds;
        /* Holds it has PAUSED for a blocking wait (_PalLockHoldPause): not
         * counted for a fork, but still held - so this context never waits at
         * the fork's gate while it has any. */
        int64_t    paused_holds;
    };
} PAL_SVSM_TCB;

extern bool g_pal_svsm_fork_report;
extern bool g_pal_svsm_console_monitor;   /* [svsm] console = "monitor" */
void pal_svsm_console_write(const void* buf, size_t size);   /* pal_monitor_call.c */
void pal_svsm_threads_report_holds(int64_t foreign);

static inline PAL_SVSM_TCB* pal_get_svsm_tcb(void) {
    return (PAL_SVSM_TCB*)pal_get_tcb();
}

/* The fork's wait for other contexts' LibOS lock holds (pal_events.c). */
int64_t pal_svsm_fork_quiesce(uint64_t max_us);
void pal_svsm_fork_done(void);
/* In the child: the lock-hold count is the forker's alone (pal_events.c). */
void pal_svsm_lock_holds_after_fork(void);

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
/* Read leaf 0xD again for the preemption save area, after Avx512Declare
 * changed this vault's XCR0. */
void pal_svsm_xstate_refresh(void);
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

/* Whether a _PalThreadResume has landed on the RUNNING thread since it last
 * blocked - i.e. the LibOS may have a signal for it - and the matching
 * clear. Used by the preemption path (pal_exception.c), which is the only
 * place a thread that never blocks can find out; a blocking call consumes
 * the flag itself, in pal_svsm_thread_block. */
bool pal_svsm_current_interrupted(void);
void pal_svsm_current_clear_interrupted(void);

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

/* What a thread about to block in poll() is watching, and the test the
 * scheduler makes on it. Together these are what wakes a poller when its
 * peer sends rather than when its timeout runs out. */
void pal_svsm_thread_watch(size_t count, PAL_HANDLE* handles, pal_wait_flags_t* events);
bool pal_svsm_poller_ready(PAL_HANDLE thread);
/* The manifest declared [svsm.service]: this vault means to be resident,
 * so the PAL may Park it and let a host invoke end with GETRESULT. */
extern bool g_pal_svsm_is_service;

/* Socket readiness, from the ring's own indices (pal_sockets.c). */
/* The ring word that would make this socket ready for `want`. Returns
 * the number of arms written (0 or 1). */
int pal_svsm_sock_arm(PAL_HANDLE handle, pal_wait_flags_t want, uint64_t* out_arm);
bool pal_svsm_sock_readable(PAL_HANDLE handle);
bool pal_svsm_sock_writable(PAL_HANDLE handle);
/* A blocking socket call's own wait (sock_block), watched by the scheduler:
 * PAL_SVSM_WAIT_SOCK marks the watch as one, and the test is then exactly the
 * call's - pal_svsm_sock_wait_ready - rather than poll(2)'s, which reports a
 * hang-up whatever was asked and would wake a writer for ever on a socket
 * whose peer has half-closed. PAL_SVSM_WAIT_CREDIT is a send waiting for the
 * service's window. Both are PAL-internal and above every PAL_WAIT_* bit. */
#define PAL_SVSM_WAIT_SOCK   ((pal_wait_flags_t)1 << 30)
#define PAL_SVSM_WAIT_CREDIT ((pal_wait_flags_t)1 << 29)
pal_wait_flags_t pal_svsm_sock_wait_ready(PAL_HANDLE handle, pal_wait_flags_t want);

/* Who this vault may connect to, from [svsm.net] in its measured manifest. */
extern char     g_pal_svsm_net_name[32];
/* 1 when that peer is a network service and `connect` must say where it
 * is going first (svsm.net.protocol = "mvnet"). */
extern int      g_pal_svsm_net_protocol;
extern uint64_t g_pal_svsm_net_endpoint;
void pal_svsm_poll_wake(void);

/* What a socket client spent its sends on (NET-0c): whether a send went in,
 * or came back EAGAIN at the service's credit window or at a full ring, and
 * how often the scheduler idled or found a poller ready. Counts only - no
 * timing - so they cost one locked add where they sit. Relaxed atomics
 * because nothing orders on them and they are read once, at exit.
 * Reported by pal_svsm_net_ctr_report() from _PalProcessExit. */
struct pal_svsm_net_ctr {
    uint64_t sends;
    uint64_t eagain_credit;
    uint64_t eagain_ring;
    uint64_t idle_rounds;
    uint64_t pollers_ready;
    uint64_t credit_lost;          /* a CREDIT frame found the ring full */
    uint64_t credits_owed_retried; /* ... and a later attempt got it through */
    uint64_t fin_lost;             /* a close's FIN found the ring full */
    uint64_t fin_resent;           /* ... and was sent later */
    uint64_t dgrams;               /* datagrams a recv returned (UDP, shared channel) */
    uint64_t dgram_frames;         /* ... and the channel frames they came in */
    uint64_t udp_q_drop;           /* a datagram frame for a socket whose queue was full */
#line 234
};
extern struct pal_svsm_net_ctr g_pal_svsm_net_ctr;
#define PAL_SVSM_NET_CTR_INC(field) \
    ((void)__atomic_fetch_add(&g_pal_svsm_net_ctr.field, 1, __ATOMIC_RELAXED))
void pal_svsm_net_ctr_report(void);
void pal_svsm_net_ctr_reset(void);

/* How long a wait that involves a SHARED pipe may sleep before looking
 * again, and whether a handle is one. Both the blocking read/write
 * (pal_pipes.c) and poll (pal_object.c) need the same answer: a shared
 * pair's writer can be another process, and this process's wake never
 * reaches it. */
#define PAL_SVSM_SHARED_PIPE_POLL_US 200
bool pal_svsm_pipe_is_shared(PAL_HANDLE handle);

/*
 * Pipes (pal_pipes.c). Both ends are in this address space, so what a poll
 * wants to know is answerable here; pal_object.c asks.
 */
size_t pal_svsm_pipe_readable(PAL_HANDLE handle);

/* Does this image's MEASURED manifest declare pipes that survive a fork?
 *
 * [svsm.pipes] shared = true. Declared rather than assumed for two reasons
 * that are both properties of the vault and not of the implementation: it
 * puts a region of memory in reach of every descendant this vault ever
 * forks, and it spends one of the monitor's VM-wide regions. A verifier
 * reading the manifest digest can see both. */
extern bool g_pal_svsm_pipes_shared;
/* A fork is about to give the child a copy of every pipe handle; the pairs
 * are shared, so each gains a holder, recorded in a ledger row filled for the
 * child. Called in the PARENT right before the fork; then exactly one of
 * _fork_failed (no child) or _fork_parent (the child's serial). */
void pal_svsm_pipes_fork_prepare(void);
void pal_svsm_pipes_fork_failed(void);
void pal_svsm_pipes_fork_parent(uint64_t child_serial);
/* In the child: take the row filled for it, and forget the copied pending
 * connections, unreleased. */
void pal_svsm_pipes_child_after_fork(uint64_t self_serial);
/* On a clean exit: this process's empty ledger row goes back free. */
void pal_svsm_pipes_exit(void);
/* The forker is the child's only thread (pal_threading.c). */
void pal_svsm_threads_child_after_fork(void);
bool   pal_svsm_pipe_writable(PAL_HANDLE handle);
bool   pal_svsm_pipe_peer_gone(PAL_HANDLE handle);
bool   pal_svsm_pipe_hung_up(PAL_HANDLE handle);
bool   pal_svsm_sock_peer_gone(PAL_HANDLE handle);
bool   pal_svsm_pipesrv_pending(PAL_HANDLE handle);

/* The monitor's grant status codes, mirrored from
 * monitor/kernel/src/process_manager/mod.rs. Both ends are measured
 * separately, so neither can negotiate this with the other: change one and
 * change the other.
 *
 * Only the ones this PAL acts on are named. The two post-admission refusals
 * matter because they are the ones an application can do something about;
 * every other failure it can only report. A fork's refusal is told apart the
 * same way (pal_process.c): a limit a later fork may find room under is
 * EAGAIN, anything else EACCES. */
#define PAL_SVSM_STATUS_BAD_ID        (-2)
#define PAL_SVSM_STATUS_BAD_STATE     (-3)
#define PAL_SVSM_STATUS_BAD_ARGS      (-4)
#define PAL_SVSM_STATUS_NO_RESOURCES  (-5)
#define PAL_SVSM_STATUS_UNSUPPORTED   (-6)
#define PAL_SVSM_STATUS_PEER_QUOTA    (-7)
#define PAL_SVSM_STATUS_SERVICE_FULL  (-8)

/* --- many connections on one channel (pal_svsm_mux.c) ------------------
 *
 * A connection stops being a monitor-accounted object: the monitor grants ONE
 * channel per vault instance and never learns a connection exists. An id is a
 * slot in the low 16 bits and a GENERATION in the high 16, so a frame still in
 * flight for a closed connection cannot be demultiplexed into whoever reused
 * the slot. See the file's header for what this costs (head-of-line blocking
 * moves from one socket to the whole vault) and what is not here yet (credit).
 */
extern unsigned long g_pal_svsm_mux_win;
extern unsigned long g_pal_svsm_mux_widx;
extern int           g_pal_svsm_mux_side;
extern bool          g_pal_svsm_mux_open;

PAL_HANDLE pal_svsm_mux_conn_of(uint32_t id);
int        pal_svsm_mux_claim(PAL_HANDLE handle, uint32_t* out_id);
void       pal_svsm_mux_release(uint32_t id);
int        pal_svsm_mux_count(void);
PAL_HANDLE pal_svsm_mux_conn_at(int i);
/* Non-zero while the scheduler re-tests a blocked thread's handles
 * (pal_svsm_poller_ready): code reached from there must not use the heap. */
extern int g_pal_svsm_sched_ctx;
/* Set by such code when it needed the heap and did without: the thread being
 * re-tested is then woken to look again itself. */
extern bool g_pal_svsm_sched_deferred;
#define PAL_SVSM_MUX_MAX_CONNS 256
bool       pal_svsm_mux_id_sane(uint32_t id);
