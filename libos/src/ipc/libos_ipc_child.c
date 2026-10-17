/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "libos_ipc.h"
#include "libos_process.h"

void ipc_child_disconnect_callback(IDTYPE vmid) {
    /*
     * NOTE: IPC port may be closed by the host OS because the child process exited on the host OS
     * (and so the host OS closed all its sockets). This may happen before arrival of the expected
     * IPC_MSG_CHILDEXIT message from child process. In such case report that the child process was
     * killed by SIGPWR (we've picked this signal hoping that nothing really uses it, as this case
     * is not distinguishable from a genuine signal).
     */
    if (mark_child_exited_by_vmid(vmid, /*uid=*/0, /*exit_code=*/0, SIGPWR)) {
        log_error("Child process (vmid: 0x%x) got disconnected", vmid);
    } else {
        log_debug("Unknown process (vmid: 0x%x) disconnected", vmid);
    }
}

/*
 * A copy-on-write fork's child tells its parent nothing when it ends: the
 * parent asks the HOST (reap_host_children, PalProcessWait), which ended it
 * and knows how, whether or not the child got to say anything.
 *
 * With the IPC worker on, the child used to say it as well, and two answers
 * were worse than one. The parent took whichever arrived first, the other
 * found the child gone, and a pid is a monitor id - a reused slot - so a late
 * notice from a child that had exec'd a subprocess and exited 0 could land on
 * the NEXT child with that pid, and a child that exited 7 was reaped as 0.
 * Set once, in the child, and kept across execve, which is the same process.
 */
static bool g_cld_exit_by_host = false;

void ipc_cld_exit_by_host(void) {
    g_cld_exit_by_host = true;
}

int ipc_cld_exit_send(unsigned int exitcode, unsigned int term_signal) {
    if (!g_process.ppid || g_cld_exit_by_host) {
        /* We have no parent inside Gramine, or one that asks the host. */
        return 0;
    }

    struct libos_thread* self = get_cur_thread();
    lock(&self->lock);
    IDTYPE uid = self->uid;
    unlock(&self->lock);

    struct libos_ipc_cld_exit msgin = {
        .ppid        = g_process.ppid,
        .pid         = g_process.pid,
        .exitcode    = exitcode,
        .term_signal = term_signal,
        .uid         = uid,
    };

    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin));
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_CHILDEXIT, total_msg_size);

    memcpy(msg->data, &msgin, sizeof(msgin));

    return ipc_send_message(g_process_ipc_ids.parent_vmid, msg);
}

int ipc_cld_exit_callback(IDTYPE src, void* data, uint64_t seq) {
    __UNUSED(seq);
    struct libos_ipc_cld_exit* msgin = (struct libos_ipc_cld_exit*)data;

    log_debug("IPC callback from %u: IPC_MSG_CHILDEXIT(%u, %u, %d, %u)", src, msgin->ppid,
              msgin->pid, msgin->exitcode, msgin->term_signal);

    if (mark_child_exited_by_pid_ipc(msgin->pid, msgin->uid, msgin->exitcode,
                                     msgin->term_signal)) {
        log_debug("Child process (pid: %u) died", msgin->pid);
    } else {
        /* Not fatal: this returned -EINVAL, which the IPC worker treats as
         * fatal (PalProcessExit(1)), and with the worker on a vault died a few
         * subprocess.run()s in, every time - a copy-on-write child's notice
         * arriving after its parent had already reaped it through the host.
         * Such a child sends none now (ipc_cld_exit_by_host); a notice about a
         * child this process does not track is still no reason to end it. */
        log_debug("child-death notification for a child no longer tracked: pid: %d, vmid: %u",
                  msgin->pid, src);
    }

    return 0;
}
