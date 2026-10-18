/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Many connections, one channel.
 *
 * WHY. A TCP connection through a network service is currently a
 * monitor-accounted object: one IPC channel, one row in the monitor's VM-wide
 * 64-entry region table (ipc/mod.rs, MAX_REGIONS = 64, shared with every
 * vaultfs lineage and pipe arena), 35 pages, and a 2 MiB window in each of two
 * vaults with page-table edits on both sides. That is why a service caps at 32
 * connections, and why running out made SeBS vaults die with
 * ConnectionRefusedError raised inside their own http/client.py.
 *
 * This file makes a connection an integer in a ring the two vaults already
 * share. The monitor grants ONE channel per vault instance, the first time
 * this vault connects anywhere, and never learns that a connection exists.
 *
 * WHAT A CONNECTION ID IS. Low 16 bits a slot in the table below, high 16 a
 * generation. A bare slot would not do: a frame still in flight for a closed
 * connection would be demultiplexed into whoever reused the slot, which is a
 * cross-talk bug between two of the vault's own sockets and would be
 * essentially impossible to find. The generation makes a stale frame
 * unmatchable, and `conn_of` drops it.
 *
 * HOW DEMULTIPLEXING WORKS, and what it costs. A reader cannot consume a
 * message before knowing whose it is, because if the destination has no room
 * there is nowhere else to hold it - buffering for every connection at once is
 * exactly the per-connection cost this file exists to remove. So the head is
 * PEEKED (pal_chan_peek), and consumed only when its connection can take it.
 *
 * The cost of that is stated rather than hidden: head-of-line blocking moves
 * from one socket to the whole vault. A connection whose application has
 * stopped reading holds the channel for the vault's other connections once its
 * own buffer is full. The plan's answer is per-connection credit with a shared
 * pool; this is the shape that works without it, and the limit is real.
 *
 * WHAT IS NOT HERE. Credit, and a second channel when one fills. Both are
 * additive. `MAX_MAPPERS_PER_SIDE = 8` bounds how many vaults may share a
 * region, which one-channel-per-instance is inside.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_host.h"
#include "pal_svsm.h"
#include "pal_svsm_chan.h"

/* How many connections one vault may hold on its channel at once.
 *
 * Not a monitor resource any more, so this is a table size and nothing else -
 * 256 entries of 16 bytes. The old limit was the service's `max_channels`, 32,
 * enforced by VMPL0 against a 64-entry VM-wide table. */
#define MUX_MAX_CONNS  PAL_SVSM_MUX_MAX_CONNS   /* pal_svsm.h, for the walkers */

struct mux_conn {
    PAL_HANDLE handle;      /* whose it is; NULL for a free slot */
    uint32_t   id;          /* slot | generation << 16, as it goes on the wire */
    bool       used;
};

static struct mux_conn g_conns[MUX_MAX_CONNS];
static uint16_t        g_gen = 1;       /* 0 is never a live generation */
static int             g_nconns;

/* The one channel. Granted on first use and kept for the life of the process:
 * a vault that connected once will connect again, and giving it back would
 * mean asking the monitor for a region per burst. */
unsigned long  g_pal_svsm_mux_win;
unsigned long  g_pal_svsm_mux_widx;
int            g_pal_svsm_mux_side;
bool           g_pal_svsm_mux_open;

static uint16_t id_slot(uint32_t id) { return (uint16_t)(id & 0xffff); }
static uint16_t id_gen(uint32_t id)  { return (uint16_t)(id >> 16); }

/* The handle a frame belongs to, or NULL if the id names nothing live.
 *
 * Both halves are checked. A slot that has been reused carries a different
 * generation, so a frame from the previous occupant finds the slot in use and
 * the generation wrong - and is dropped rather than delivered to a stranger. */
PAL_HANDLE pal_svsm_mux_conn_of(uint32_t id) {
    uint16_t slot = id_slot(id);
    if (slot >= MUX_MAX_CONNS)
        return NULL;
    struct mux_conn* c = &g_conns[slot];
    if (!c->used || c->id != id)
        return NULL;
    return c->handle;
}

/* Claim a connection id for `handle`.
 *
 * NOT lowest-free by slot alone: the generation is what makes the id unique
 * over time. The scan is linear over 256 entries, which is nothing against the
 * monitor call a connection used to cost.
 */
int pal_svsm_mux_claim(PAL_HANDLE handle, uint32_t* out_id) {
    for (uint16_t i = 0; i < MUX_MAX_CONNS; i++) {
        if (g_conns[i].used)
            continue;
        if (!++g_gen)
            g_gen = 1;                  /* never hand out generation 0 */
        g_conns[i].handle = handle;
        g_conns[i].id     = (uint32_t)i | ((uint32_t)g_gen << 16);
        g_conns[i].used   = true;
        g_nconns++;
        *out_id = g_conns[i].id;
        return 0;
    }
    return -PAL_ERROR_NOMEM;            /* the table, not the monitor, said no */
}

/* Give an id back. The slot is reusable at once; the generation is what keeps
 * a late frame for this connection from reaching the next occupant. */
void pal_svsm_mux_release(uint32_t id) {
    uint16_t slot = id_slot(id);
    if (slot >= MUX_MAX_CONNS)
        return;
    struct mux_conn* c = &g_conns[slot];
    if (!c->used || c->id != id)
        return;
    c->used   = false;
    c->handle = NULL;
    c->id     = 0;
    g_nconns--;
}

int pal_svsm_mux_count(void) { return g_nconns; }

/* The handle in table slot `i`, or NULL: for a walk over every live connection
 * (the credit grant, pal_sockets.c). */
PAL_HANDLE pal_svsm_mux_conn_at(int i) {
    if (i < 0 || i >= MUX_MAX_CONNS || !g_conns[i].used)
        return NULL;
    return g_conns[i].handle;
}

/* Unused, but kept honest: generation 0 and a slot out of range are the two
 * ids that can never be live, and a reader that builds one has a bug. */
bool pal_svsm_mux_id_sane(uint32_t id) {
    return id_gen(id) != 0 && id_slot(id) < MUX_MAX_CONNS;
}
