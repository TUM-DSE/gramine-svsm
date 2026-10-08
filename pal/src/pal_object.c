/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for closing or polling PAL handles.
 */

#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

void _PalObjectDestroy(PAL_HANDLE handle) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (ops && ops->destroy) {
        /* handle-specific callback is required to close + free all resources */
        ops->destroy(handle);
    } else {
        /* no handle-specific callback, just free this PAL handle */
        free(handle);
    }
}

void PalObjectDestroy(PAL_HANDLE handle) {
    /*
     * This was `return; // ignore` from 8dcb294d, "TMP: skip some
     * initialization (fix later)", alongside init_std_handles and
     * init_ipc_worker. It was the right shortcut at the time - the SVSM PAL
     * was new, most handle types did not exist yet - and it stopped being
     * one, because `put_handle` calls this on the LAST reference, so for two
     * years nothing in this PAL released anything a handle owned.
     *
     * Four bugs came out of that, each invisible while a vault was one
     * process with private memory and each a hard failure once state moved
     * into memory shared with descendants:
     *
     *   * a vault's UDP socket kept its channel, relay slot and lwIP pcb for
     *     the life of the network service; ten getaddrinfo calls exhausted it;
     *   * no close lowered a pipe pair's holder count, so a reader never saw
     *     end-of-file across a fork, which is how subprocess hangs;
     *   * the PAL's live-pipe list never shrank, so a shared pair was
     *     released while still held and the next pipe to claim that arena slot
     *     memset somebody's buffer under them;
     *   * one pollable event per thread, never released, filled the 32-pair
     *     lineage arena until pipe() returned ENOMEM.
     *
     * Each was fixed where it bit, by routing the cleanup through
     * PalStreamDelete, which IS reachable. That is a workaround for this line
     * and it only covers the types somebody has already been burned by.
     *
     * What had to be true before un-stubbing it, checked rather than assumed:
     *   - every destroy op either frees the handle or owns nothing (dev,
     *     eventfd and proc create no handles at all in this PAL);
     *   - no PAL global holds a handle POINTER past the free. Two do:
     *     the scheduler's thread ring, which `_PalThreadExit` leaves before
     *     the handle becomes the LibOS's ("The handle is LibOS's to destroy
     *     the moment this thread has exited"), and pal_pipes.c's live list,
     *     which `live_del` clears in both release paths;
     *   - delete and destroy cannot double-release: `sock_delete` clears
     *     `win` and `pipe_let_go` sets `released`.
     */
    assert(handle);
    _PalObjectDestroy(handle);
}

int PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                         pal_wait_flags_t* ret_events, uint64_t* timeout_us) {
    for (size_t i = 0; i < count; i++) {
        assert(!handle_array[i] || handle_array[i]->hdr.type < PAL_HANDLE_TYPE_BOUND);
    }

    return _PalStreamsWaitEvents(count, handle_array, events, ret_events, timeout_us);
}
