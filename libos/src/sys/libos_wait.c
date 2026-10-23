/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stdbool.h>

#include "api.h"
#include "assert.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "linux_abi/errors.h"
#include "linux_abi/process.h"
#include "linux_abi/signals.h"

/* For wait4() return value */
#define WCOREFLAG 0x80

static bool child_matches_flags(struct libos_child_process* child, int flags) {
    if (flags & __WALL) {
        return true;
    }

    return (!!(flags & __WCLONE)) ^ (child->child_termination_signal == SIGCHLD);
}

static bool child_matches(struct libos_child_process* child, int which, IDTYPE id, int flags) {
    if (!child_matches_flags(child, flags)) {
        return false;
    }

    bool ret = false;
    switch (which) {
        case P_PID:
            if (child->pid == id) {
                ret = true;
            }
            break;
        case P_PGID:
            /* TODO: this makes no sense, until we implement IPC pgid change. */
            break;
        case P_ALL:
            ret = true;
            break;
        default:
            /* Impossible. */
            BUG();
            break;
    }

    return ret;
}

static void remove_qnode_from_wait_queue(struct libos_thread_queue* qnode) {
    lock(&g_process.children_lock);

    bool seen = false;
    if (g_process.wait_queue == qnode) {
        g_process.wait_queue = qnode->next;
        seen = true;
    } else if (g_process.wait_queue) {
        struct libos_thread_queue* tmp = g_process.wait_queue;
        while (tmp->next) {
            if (tmp->next == qnode) {
                tmp->next = qnode->next;
                seen = true;
                break;
            }
            tmp = tmp->next;
        }
    }

    unlock(&g_process.children_lock);

    if (!seen) {
        while (1) {
            thread_prepare_wait();
            /* Check `mark_child_exited` for explanation why we might need this compiler barrier. */
            COMPILER_BARRIER();
            /* Check if `qnode` is no longer used. */
            if (!__atomic_load_n(&qnode->in_use, __ATOMIC_ACQUIRE)) {
                break;
            }
            int ret = thread_wait(/*timeout_us=*/NULL, /*ignore_pending_signals=*/true);
            if (ret < 0 && ret != -EINTR) {
                /* We cannot handle any errors here. */
                log_error("remove_qnode_from_wait_queue: thread_wait failed with: %s",
                          unix_strerror(ret));
            }
        }
    } else {
        put_thread(qnode->thread);
    }
}

/*
 * Ask the host how this process's children ended.
 *
 * A child made by the copy-on-write fork has no IPC worker to report its own
 * death - it was never a separate gramine process in the sense the IPC
 * layer means, it is a copy of this one - so the usual path, where a dying
 * child tells its parent over a stream, never fires. The host knows,
 * because it is what ended the child, and PalProcessWait is how it says so.
 *
 * Polled rather than pushed, and that is the host's rule rather than a
 * shortcut: its wait is deliberately non-blocking, because a blocking one
 * would be a second answer to "who runs next" alongside the scheduler it
 * already has.
 *
 * Feeds `mark_child_exited_by_pid`, the same function the IPC path calls,
 * so everything downstream - zombies, the wait queue, SIGCHLD - is the
 * ordinary machinery and not a second copy of it.
 */
static void reap_host_children_locked(void);

/* Set while a thread reaps (reap_host_children). */
static int g_reaping;

/* In a copy-on-write fork's child: nobody is reaping. The flag is not a
 * counted lock hold - a reaper holds it across monitor calls and can be
 * preempted - so a fork while another thread sat in a blocking waitpid
 * copied it SET, nothing in the child ever cleared it, and every wait there
 * looped for ever (an exec keeps it: the exec'd shell's first wait hung). */
void wait_after_cow_fork(void) {
    g_reaping = 0;
}

/* Every reap held off, for a fork that records its new child: the flag
 * reap_host_children takes, waited for rather than tried. Yields; holds no
 * lock while it waits. */
void host_reap_hold(void) {
    while (__atomic_exchange_n(&g_reaping, 1, __ATOMIC_ACQ_REL))
        PalThreadYieldExecution();
}

void host_reap_release(void) {
    __atomic_store_n(&g_reaping, 0, __ATOMIC_RELEASE);
}

static void reap_host_children(void) {
    /* One reaper at a time. Two threads waiting at once each took a snapshot
     * of the list and asked the monitor; with pids reused, one thread's
     * answer for a child could be applied after the other had reaped it and
     * a new child had the pid. A thread that finds a reap in progress lets
     * it do the work - its wait loop looks again within 10 ms. */
    if (__atomic_exchange_n(&g_reaping, 1, __ATOMIC_ACQ_REL))
        return;
    reap_host_children_locked();
    __atomic_store_n(&g_reaping, 0, __ATOMIC_RELEASE);
}

static void reap_host_children_locked(void) {
    IDTYPE pids[32];
    uint64_t mids[32];
    uint64_t serials[32];
    IDTYPE uids[32];
    bool by_host[32];
    size_t n = 0;

    lock(&g_process.children_lock);
    struct libos_child_process* child;
    LISTP_FOR_EACH_ENTRY(child, &g_process.children, list) {
        if (n >= ARRAY_SIZE(pids))
            break;
        pids[n]  = child->pid;
        /* The host's names for it: id and serial (lineage-vmid). A child
         * recorded before monitor ids were kept apart has its pid there. */
        mids[n]    = child->monitor_id ? child->monitor_id : child->vmid;
        serials[n] = child->monitor_serial;
        uids[n]  = child->uid;
        by_host[n] = child->by_host;
        n++;
    }
    unlock(&g_process.children_lock);

    /* The PAL call is made with the lock DROPPED: it is a monitor call, and
     * holding a lock across one blocks every other thread in this vault for
     * the length of a VMGEXIT. */
    for (size_t i = 0; i < n; i++) {
        int64_t reason = 0;
        uint64_t value = 0;
        if (PalProcessWait(mids[i], serials[i], &reason, &value) < 0) {
            /* Refused: the monitor no longer links this child to us. For a
             * child the copy-on-write fork made, that happens one way - the
             * HOST deleted it, and its teardown dropped the link along with
             * any status - so it is reaped as killed, the nearest POSIX truth
             * (as below). Skipped, it was never reaped: a parent waiting for
             * it waited for ever, and it stayed on the list. */
            if (by_host[i]) {
                /* Said: this is one of the ways a child that exited cleanly
                 * could be reported as SIGKILLed (fork_parallel "rc -9 out
                 * '1'", 2026-10-20). */
                log_warning("reap: pid %u (host id %lu serial %lu): the host refused the wait - "
                            "reaped as SIGKILL", pids[i], (unsigned long)mids[i],
                            (unsigned long)serials[i]);
                (void)mark_child_exited_by_pid_host(pids[i], uids[i], 0, SIGKILL);
            }
            continue;
        }
        if (reason == 0)
            continue;                       /* still running */

        /* reason 1 is an ordinary exit and `value` is its code. Anything
         * else ended the child without its consent - a PAL error, a fault,
         * the watchdog - and the nearest POSIX truth is a signal, not an
         * exit code, because an exit code would claim the program chose it.
         * SIGKILL: the process was ended from outside and could not refuse,
         * which is exactly what the host did. */
        int exit_code = (reason == 1) ? (int)value : 0;
        int term_signal = (reason == 1) ? 0 : SIGKILL;
        if (reason != 1)
            log_warning("reap: pid %u (host id %lu serial %lu) ended with reason %ld value %lu - "
                        "reaped as SIGKILL", pids[i], (unsigned long)mids[i],
                        (unsigned long)serials[i], (long)reason, (unsigned long)value);
        (void)mark_child_exited_by_pid_host(pids[i], uids[i], exit_code, term_signal);
    }
}

static long do_waitid(int which, pid_t id, siginfo_t* infop, int options) {
    if (options & __WALL) {
        options &= ~__WCLONE;
    }

    if (options & WSTOPPED) {
        log_warning("Ignoring unsupported WSTOPPED flag to waitid/wait4");
        options &= ~WSTOPPED;
    }
    if (options & WCONTINUED) {
        log_warning("Ignoring unsupported WCONTINUED flag to waitid/wait4");
        options &= ~WCONTINUED;
    }
    if (!(options & WEXITED)) {
        log_error("Unsupported combination of flags passed to waitid/wait4");
        return -EINVAL;
    }

    if (options & __WNOTHREAD) {
        log_warning("Ignoring unsupported __WNOTHREAD flag to waitid/wait4");
        options &= ~__WNOTHREAD;
    }

    if (!(which == P_PGID || which == P_ALL || which == P_PID))
        return -EINVAL;

    long ret = 0;

    do {
        /* Before looking, ask the host: a child it ended has no other way
         * of telling us. */
        reap_host_children();

        lock(&g_process.children_lock);

        struct libos_child_process* child;
        /* First search already exited children. */
        LISTP_FOR_EACH_ENTRY(child, &g_process.zombies, list) {
            if (child_matches(child, which, id, options)) {
                /* We have a match! */
                if (infop) {
                    infop->si_pid = child->pid;
                    infop->si_uid = child->uid;
                    infop->si_signo = SIGCHLD;

                    fill_siginfo_code_and_status(infop, child->term_signal, child->exit_code);
                }

                if (!(options & WNOWAIT)) {
                    LISTP_DEL_INIT(child, &g_process.zombies, list);
                    destroy_child_process(child);
                }
                ret = 0;
                goto out;
            }
        }

        /* Do we have any non-exited child to wait for? */
        bool have_waitable_child = false;
        LISTP_FOR_EACH_ENTRY(child, &g_process.children, list) {
            if (child_matches(child, which, id, options)) {
                have_waitable_child = true;
                break;
            }
        }

        if (!have_waitable_child) {
            ret = -ECHILD;
            goto out;
        }
        /* There are some children we can wait for. */

        if (options & WNOHANG) {
            if (infop) {
                infop->si_pid = 0;
                infop->si_signo = 0;
            }
            ret = 0;
            goto out;
        }

        /* Ok, let's wait. */
        struct libos_thread* self = get_cur_thread();
        struct libos_thread_queue qnode = {
            .thread = self,
            .next = g_process.wait_queue,
        };
        get_thread(qnode.thread);
        __atomic_store_n(&qnode.in_use, true, __ATOMIC_RELEASE);
        g_process.wait_queue = &qnode;

        unlock(&g_process.children_lock);

        thread_prepare_wait();
        /* Check `mark_child_exited` for explanation why we might need this compiler barrier. */
        COMPILER_BARRIER();
        /* Check that we are still supposed to sleep. */
        if (!__atomic_load_n(&qnode.in_use, __ATOMIC_ACQUIRE)) {
            /* Something woke us up and took of the list in the meantime. */
            ret = -ERESTARTSYS;
            break;
        }
        /* BOUNDED, because nothing will wake this for a host-reaped child:
         * the wake comes from `mark_child_exited`, which for those children
         * only happens in `reap_host_children` at the top of this loop. An
         * untimed wait here is a parent that never returns from wait() even
         * though its child is long gone. 10 ms is below the cost of the
         * fork it is waiting on and far above the cost of one monitor call.
         */
        uint64_t wait_us = 10000;
        ret = thread_wait(&wait_us, /*ignore_pending_signals=*/false);
        if (ret == -ETIMEDOUT)
            ret = 0;                        /* go round and poll again */
        if (ret < 0 && ret != -EINTR) {
            log_warning("thread_wait failed in waitid");
            remove_qnode_from_wait_queue(&qnode);
            /* `ret` is already set. */
            goto out;
        }

        ret = -ERESTARTSYS;

        remove_qnode_from_wait_queue(&qnode);
    } while (!have_pending_signals());

out:
    unlock(&g_process.children_lock);
    return ret;
}

long libos_syscall_waitid(int which, pid_t id, siginfo_t* infop, int options,
                          struct __kernel_rusage* ru) {
    __UNUSED(ru);

    if (options & ~(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED |
                    __WNOTHREAD | __WCLONE | __WALL))
        return -EINVAL;

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;

    if (infop && !is_user_memory_writable(infop, sizeof(*infop)))
        return -EFAULT;

    return do_waitid(which, id, infop, options);
}

long libos_syscall_wait4(pid_t pid, int* status, int options, struct __kernel_rusage* ru) {
    __UNUSED(ru);

    int which;
    pid_t id;
    siginfo_t info;

    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL)) {
        return -EINVAL;
    }

    if (status && !is_user_memory_writable(status, sizeof(*status)))
        return -EFAULT;

    /* Prepare options for do_waitid(). */
    options |= WEXITED;
    if (options & WUNTRACED) {
        options &= ~WUNTRACED;
        options |= WSTOPPED;
    }

    if (pid < -1) {
        which = P_PGID;
        id = -pid;
    } else if (pid == -1) {
        which = P_ALL;
        id = 0;
    } else if (pid == 0) {
        which = P_PGID;
        id = 0;
    } else {
        which = P_PID;
        id = pid;
    }

    info.si_pid = 0;
    int ret = do_waitid(which, id, &info, options);
    if (ret < 0)
        return ret;

    if (info.si_pid == 0)
        return 0;

    if (status) {
        if (info.si_code == CLD_EXITED) {
            *status = (info.si_status & 0xff) << 8;
        } else if (info.si_code == CLD_DUMPED) {
            *status = info.si_status | WCOREFLAG;
        } else {
            *status = info.si_status;
        }
    }
    return info.si_pid;
}

/*
 * SIGCHLD for a host-reaped child, for a thread that waits for it as a
 * signal rather than in wait(): dash's `wait` with a live background job does
 * wait4(-1, WNOHANG) and then rt_sigsuspend, and pause() and sigwaitinfo()
 * are the same shape.
 *
 * Such a child's SIGCHLD is posted by `mark_child_exited`, which for a child
 * the host reaps runs only from `reap_host_children` - in do_waitid's loop and
 * in fork. Nothing reaps while a thread sits in sigsuspend, so the signal it
 * is waiting for is never posted; and the wait has no deadline, so with every
 * other thread blocked the PAL's scheduler has nothing to run and nothing to
 * wake for, and ends the vault as deadlocked - which its parent then reaps as
 * SIGKILL (UnixBench shell1, "Bad wait status: 0x9").
 *
 * So the same bounded wait as do_waitid: while this process has children the
 * host reaps, never more than 10 ms at a time, with a reap after each slice
 * that runs out. A caller's own deadline is kept - the slices are cut from
 * it, and what is left of it is written back as thread_wait does. With no
 * such child it is thread_wait, unchanged.
 *
 * A poll, not a wake, and an interim one: the host's wait is non-blocking by
 * design (see reap_host_children), so a reap is the only way to learn of the
 * exit. The reentrancy guard is reap_host_children's own: a thread that finds
 * another reaping lets it, and looks again on its next slice.
 *
 * Each slice is charged to the caller's deadline as the time it really took -
 * the wait and the reap after it, which is a host call per child - so a long
 * sigtimedwait ends when it would have, not later by the reaps.
 *
 * Known gap, left for the real wake (M3): mark_child_exited queues SIGCHLD
 * whatever its disposition, and have_pending_signals looks only at the mask.
 * So with SIGCHLD at SIG_DFL or SIG_IGN and unblocked, a reap here can end a
 * sigsuspend, or a sigtimedwait for other signals, with -EINTR where Linux
 * would have dropped the signal and kept waiting (pause restarts, so it is
 * unaffected). IPC children, and a reap in another thread's wait(), already
 * do this; the fix belongs where SIGCHLD is posted (cf. Linux sig_ignored).
 */
#define HOST_REAP_POLL_US 10000

/* Grepped for in libsysdb.so by the UnixBench harness: the prefix "signal: SIGCHLD on host reap"
 * says this build posts SIGCHLD for host-reaped children to a waiter in sigsuspend. */
static const char g_sigchld_host_reap_marker[] = "signal: SIGCHLD on host reap (10 ms poll)";

static bool have_host_children(void) {
    /* A process that has never forked (or whose children are all gone) has an empty list: say
     * so without the lock, so its waits are thread_wait and nothing more. A child added after
     * this load is seen on the next call - the same as one added after the unlock below. */
    if (!__atomic_load_n(&g_process.children.first, __ATOMIC_ACQUIRE))
        return false;

    bool any = false;
    lock(&g_process.children_lock);
    struct libos_child_process* child;
    LISTP_FOR_EACH_ENTRY(child, &g_process.children, list) {
        if (child->by_host) {
            any = true;
            break;
        }
    }
    unlock(&g_process.children_lock);
    return any;
}

int thread_wait_reaping(uint64_t* timeout_us, bool ignore_pending_signals) {
    if (!have_host_children())
        return thread_wait(timeout_us, ignore_pending_signals);

    static bool said = false;
    if (!__atomic_exchange_n(&said, true, __ATOMIC_RELAXED))
        log_debug("%s", g_sigchld_host_reap_marker);

    int ret;
    if (timeout_us && *timeout_us <= HOST_REAP_POLL_US) {
        /* The caller's deadline comes first: one wait to it, and a reap if it ran out, so a
         * SIGCHLD already due is there for the caller to find. */
        ret = thread_wait(timeout_us, ignore_pending_signals);
        if (ret == -ETIMEDOUT)
            reap_host_children();
        return ret;
    }

    uint64_t start_us = 0;
    bool timed = timeout_us && PalSystemTimeQuery(&start_us) == 0;

    uint64_t slice_us = HOST_REAP_POLL_US;
    ret = thread_wait(&slice_us, ignore_pending_signals);
    uint64_t spent_us = HOST_REAP_POLL_US - slice_us;   /* in the wait alone */
    if (ret == -ETIMEDOUT) {
        reap_host_children();
        ret = 0;                                        /* the caller looks, and comes back */
    }

    if (timeout_us) {
        uint64_t end_us;
        if (timed && PalSystemTimeQuery(&end_us) == 0 && end_us > start_us)
            spent_us = end_us - start_us;               /* the wait and the reap */
        /* What is left, never 0: a deadline that ran out here still ends in the short path
         * above, with its -ETIMEDOUT (and a last reap). */
        *timeout_us = spent_us < *timeout_us ? *timeout_us - spent_us : 1;
    }
    return ret;
}
