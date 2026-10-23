/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * Sockets in a vault.
 *
 * A socket here is a CHANNEL: a run of pages the monitor maps into this
 * vault and one other, with a ring each way (PLAN.md "Full socket support").
 * `send` is a store and `recv` is a load; the monitor is in the path only
 * when the ring runs dry and this vault would otherwise spin.
 *
 * What is on the far end is not this file's business. Today it is another
 * vault - the echo service the rows use. With lwIP in the network service
 * (N4) the same code reaches a TCP connection, because the service is just
 * the vault on the other side of the channel.
 *
 * Step 2 of the plan: create, connect, send, recv, close, and the poll
 * predicates. listen/accept are step 3 and still refuse.
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"
#include "pal_svsm_chan.h"
#include "socket_utils.h"

/* How long a blocking call parks before looking again. Not a timeout the
 * application can see - the loop goes round - but the interval at which a
 * vault whose wake was missed notices anyway. */
#define PAL_SOCK_PARK_US 200000UL

/* Spins before parking. A peer that is running answers in far less than the
 * monitor entry a park costs (PLAN.md's channel plan, D1). */
#define PAL_SOCK_SPINS 200
/* How many times a grant may be re-asked when the target is mid-dispatch.
 * Each try waits ~200 us, so this is about a tenth of a second - longer
 * than any dispatch and shorter than a client would notice. */
#define PAL_GRANT_TRIES 500

/* The grant request, exactly as monitor/kernel/src/ipc/mod.rs parses it. */
struct pal_sock_grant {
    uint32_t magic;             /* 'MVG1' */
    uint8_t  selector;          /* 1 name, 2 vault_id, 3 instance */
    uint8_t  dir;               /* 0 = whatever the endpoint offers */
    uint8_t  pad[2];
    uint64_t endpoint;
    uint8_t  name[32];
    uint8_t  vault_id[64];
    uint32_t inst_pid;
} __attribute__((packed));

/* Who this vault connects to, from its measured manifest ([svsm.net]).
 * Empty means it may not: `socket()` works, `connect()` does not. */
char     g_pal_svsm_net_name[32];
uint64_t g_pal_svsm_net_endpoint;
int      g_pal_svsm_net_protocol;

struct pal_svsm_net_ctr g_pal_svsm_net_ctr;
static int g_fin_owed_n;   /* see mux_fin_flush */
static bool g_mux_granting;  /* a connect is asking for the vault's channel (_PalSocketConnect) */

/* One line, at exit, through the debug channel. log_always and not
 * log_error: SeBS manifests set log_level = "error", and these are not
 * errors, but they have to come out there too - LOG_LEVEL_NONE is the one
 * level no manifest setting filters. A vault that never touched a socket
 * or idled prints nothing, so ordinary vaults' output is unchanged. A vault
 * the host deletes rather than one that exits never reaches here, and
 * prints nothing either. */
void pal_svsm_net_ctr_report(void) {
    struct pal_svsm_net_ctr c;
    c.sends         = __atomic_load_n(&g_pal_svsm_net_ctr.sends, __ATOMIC_RELAXED);
    c.eagain_credit = __atomic_load_n(&g_pal_svsm_net_ctr.eagain_credit, __ATOMIC_RELAXED);
    c.eagain_ring   = __atomic_load_n(&g_pal_svsm_net_ctr.eagain_ring, __ATOMIC_RELAXED);
    c.idle_rounds   = __atomic_load_n(&g_pal_svsm_net_ctr.idle_rounds, __ATOMIC_RELAXED);
    c.pollers_ready = __atomic_load_n(&g_pal_svsm_net_ctr.pollers_ready, __ATOMIC_RELAXED);
    c.credit_lost   = __atomic_load_n(&g_pal_svsm_net_ctr.credit_lost, __ATOMIC_RELAXED);
    c.credits_owed_retried = __atomic_load_n(&g_pal_svsm_net_ctr.credits_owed_retried,
                                             __ATOMIC_RELAXED);
    c.fin_lost      = __atomic_load_n(&g_pal_svsm_net_ctr.fin_lost, __ATOMIC_RELAXED);
    c.fin_resent    = __atomic_load_n(&g_pal_svsm_net_ctr.fin_resent, __ATOMIC_RELAXED);
    c.dgrams        = __atomic_load_n(&g_pal_svsm_net_ctr.dgrams, __ATOMIC_RELAXED);
    c.dgram_frames  = __atomic_load_n(&g_pal_svsm_net_ctr.dgram_frames, __ATOMIC_RELAXED);
    c.udp_q_drop    = __atomic_load_n(&g_pal_svsm_net_ctr.udp_q_drop, __ATOMIC_RELAXED);
#line 89
    if (!(c.sends | c.eagain_credit | c.eagain_ring | c.idle_rounds | c.pollers_ready
          | c.credit_lost | c.fin_lost | c.dgrams | c.udp_q_drop))
        return;
    log_always("pal_net: sends %lu eagain_credit %lu eagain_ring %lu idle_rounds %lu "
               "pollers_ready %lu credit_lost %lu credits_owed_retried %lu fin_lost %lu "
               "fin_resent %lu dgrams %lu dgram_frames %lu udp_q_drop %lu",
               c.sends, c.eagain_credit, c.eagain_ring, c.idle_rounds,
               c.pollers_ready, c.credit_lost, c.credits_owed_retried, c.fin_lost, c.fin_resent,
               c.dgrams, c.dgram_frames, c.udp_q_drop);
#line 96
}

/* A forked child has the parent's counts in its copy of this page; start
 * it from zero so that each process's line is its own and the lines of a
 * parent and its children add up. */
void pal_svsm_net_ctr_reset(void) {
    memset(&g_pal_svsm_net_ctr, 0, sizeof g_pal_svsm_net_ctr);
    /* And the parent's owed FINs: its connections, its to send. */
    g_fin_owed_n = 0;
    /* A grant in progress was another thread's, and that thread is not in
     * this process: left set, every connect here would wait for it. */
    g_mux_granting = false;
}

/* The frame header every message on a MUXED channel carries.
 *
 * Mirrored from tools/netsvc/src/mvmux.h - change one and change the other.
 *
 * A connection is currently a monitor-accounted object: one channel, one row
 * in the monitor's VM-wide 64-entry region table, 35 pages, a 2 MiB window in
 * each of two vaults. This header is what lets one channel carry many
 * connections instead, so the monitor never learns a connection exists.
 *
 * THE CONSTANT THAT GOES WITH IT: a body is clamped to slot - 4 - 8, and the
 * service's RELAY_CHUNK must equal that exactly. The tree has already paid
 * for a FOUR-byte mismatch here with half its downstream throughput. */
#define PAL_MVMUX_OP_DATA     0
#define PAL_MVMUX_OP_CONNECT  1
#define PAL_MVMUX_OP_FIN      2
#define PAL_MVMUX_OP_RST      3
#define PAL_MVMUX_OP_CREDIT   4
#define PAL_MVMUX_FIN_HALF    0x01  /* FIN's flags: shutdown(SHUT_WR), still reading */
/* DATA's flags on a datagram socket that asked for PAL_MVNET_REQ_DGRAM_BATCH:
 * the body is [pal_mvnet_dgram][payload] records back to back, none split.
 * The frame is ONE frame for credit; udp_recv returns one record per call and
 * counts the frame done after its last. */
#define PAL_MVMUX_DATA_DGRAMS 0x02
#line 128
#define PAL_MVMUX_HDR_BYTES   8

/* Does a second socket SHARE the vault's channel, or get one of its own?
 *
 * 0 is the framed-but-unshared shape: every socket still grants a channel, and
 * every message still carries a frame header naming connection 0. That is
 * complete and measured (116-123 MB/s for 1 MiB, unchanged from unframed), and
 * it is what makes the header's cost provable on its own.
 *
 * 1 is the mux: one channel per vault, an id per socket. It could not be
 * turned on before the service demultiplexed, because the service would have
 * read two sockets' frames as one stream and corrupted both - a vault's second
 * connection would silently interleave with its first. The gate exists so the
 * tree is green at every step of a change that has to land on both sides of a
 * measured boundary at once; the service now has its session table (relay.c,
 * `struct relay_link`) and this is on. */
#define PAL_MUX_SHARE_CHANNEL 1

struct pal_mvmux_hdr {
    uint32_t conn;      /* low 16 slot, high 16 generation; 0 while one per channel */
    uint8_t  op;
    uint8_t  flags;
    uint16_t pad;
} __attribute__((packed));

/* How many bytes of a slot a muxed body may use. */
static inline uint64_t mux_room(uint64_t slot, bool muxed) {
    uint64_t o = 4 + (muxed ? PAL_MVMUX_HDR_BYTES : 0);
    return slot > o ? slot - o : 0;
}

/* The record a vault sends a NETWORK service before anything else, and
 * the answer it waits for. Mirrored from tools/netsvc/src/mvnet.h - both
 * ends are measured separately, so neither can negotiate this with the
 * other; change one and change the other. */
#define PAL_MVNET_MAGIC      0x314E564DU   /* "MVN1" */
#define PAL_MVNET_OP_CONNECT 1
#define PAL_MVNET_PROTO_TCP  6
#define PAL_MVNET_PROTO_UDP  17
/* The request's flags. DGRAM_BATCH: this PAL reads PAL_MVMUX_DATA_DGRAMS
 * frames, so the service may pack several datagrams into one. A service that
 * predates it ignores it (it never checked flags) and sends one a frame. Why
 * it matters: each frame is a channel send and a Notify monitor call in the
 * service, and one datagram a frame held a host flood to ~61k datagrams/s. */
#define PAL_MVNET_REQ_DGRAM_BATCH 0x1u
#line 167

struct pal_mvnet_req {
    uint32_t magic;
    uint8_t  op;
    uint8_t  proto;             /* PAL_MVNET_PROTO_TCP or _UDP */
    /* TCP: the peer. UDP: the LOCAL port to bind, and addr is ignored -
     * a datagram socket has no peer until a datagram names one, and each
     * datagram then carries its own in a pal_mvnet_dgram. */
    uint16_t port;
    uint8_t  addr[4];
    uint32_t flags;
} __attribute__((packed));

struct pal_mvnet_rep {
    uint32_t magic;
    int32_t  status;
    uint16_t local_port;
    uint16_t pad;
    /* The service's own address: the source this vault's packets appear to
     * come from, and therefore what getsockname() must report. glibc's
     * getaddrinfo asserts on it - see mvnet.h. */
    uint8_t  local_addr[4];
} __attribute__((packed));

/* One datagram on a UDP channel, in either direction: outbound it says
 * where to send, inbound where it came from. The channel stays a byte pipe
 * and this is what gives a datagram its boundary and its address back -
 * neither of which a byte pipe can carry. MVNET_DGRAM_MAX in the service. */
#define PAL_MVNET_DGRAM_MAX 2048

struct pal_mvnet_dgram {
    uint16_t len;
    uint16_t port;
    uint8_t  addr[4];
} __attribute__((packed));

/* Windows already handed to a handle - by `connect`, which opened one, or by
 * `accept`, which found one. A bit per window, which is also how the monitor
 * publishes them in the directory. Without it `accept` would hand out this
 * vault's own outgoing connections, and hand the same arrival out twice. */
/* Defined at the bottom of this file. Declared here because the two places
 * a socket handle is made are above it, and `g_pal_handle_ops[]` carries no
 * entry for PAL_TYPE_SOCKET - so without attaching this per handle,
 * HANDLE_OPS() returns NULL and every attribute call on a socket answers
 * BADHANDLE. */
extern struct handle_ops g_sock_ops;

/* Which IPC windows this vault has already turned into a socket.
 *
 * EIGHT words, not one, because the monitor publishes eight: a vault has
 * IPC_WINDOWS = 512 windows and `write_directory` fills `0x040 + i*8` for
 * i in 0..8 (monitor ipc/mod.rs). A single u64 could only ever name windows
 * 0..63, so a channel granted into window 64 or above was invisible here -
 * `_PalSocketAccept` never saw it and the peer waited for an accept that
 * could not arrive. Harmless while a service held at most sixteen
 * connections; the first thing to break when that cap is raised, and silent
 * when it breaks. */
#define PAL_CHAN_LIVE_WORDS  8
#define PAL_CHAN_WINDOWS     (PAL_CHAN_LIVE_WORDS * 64)

static uint64_t g_sock_claimed[PAL_CHAN_LIVE_WORDS];

static inline bool sock_claimed(unsigned w) {
    return w < PAL_CHAN_WINDOWS && (g_sock_claimed[w / 64] & (1UL << (w % 64)));
}

static inline void sock_claim(unsigned w) {
    if (w < PAL_CHAN_WINDOWS)
        g_sock_claimed[w / 64] |= 1UL << (w % 64);
}

static inline void sock_unclaim(unsigned w) {
    if (w < PAL_CHAN_WINDOWS)
        g_sock_claimed[w / 64] &= ~(1UL << (w % 64));
}

/* A muxed handle does not own a channel - it owns a connection ID on the one
 * channel this vault holds. So its rings are the shared channel's, and every
 * socket to the service reads and writes the same two rings. */
/* Owning no channel is what says "I am on the shared one".
 *
 * NOT `muxed`: a framed socket still owns its own channel whenever sharing is
 * off, and keying on `muxed` pointed every socket after the first at the
 * FIRST one's rings - which reads as the whole path hanging, because the
 * service answers on a channel nobody is listening to. `win == 0` is the
 * precise question, and it is set exactly where a socket joins the shared
 * channel instead of being granted one. */
static bool sock_shares(PAL_HANDLE handle) {
    return handle->sock.muxed && handle->sock.win == 0;
}

/* The window and side this handle actually uses - its own channel, or the
 * vault's shared one.
 *
 * Everything that touches a ring goes through these, because a SHARING
 * handle's own `win` is deliberately 0 and must stay 0: `sock_destroy` closes
 * the channel of any handle whose `win` is set, so a socket that held the
 * shared window would take the whole vault's net channel with it when it
 * closed. (It did. The second connect faulted on the window's own address.) */
static unsigned long sock_win(PAL_HANDLE handle) {
    return sock_shares(handle) ? g_pal_svsm_mux_win : handle->sock.win;
}

static int sock_side(PAL_HANDLE handle) {
    return sock_shares(handle) ? g_pal_svsm_mux_side : handle->sock.side;
}

/* Is there a channel to read and write at all? `handle->sock.win` used to be
 * the whole test, which answers NO for every sharing socket - no recv, no
 * send, never readable - so the question has its own name now. */
static bool sock_has_chan(PAL_HANDLE handle) {
    return sock_win(handle) != 0;
}

/* Has the far end of the channel this handle uses gone? Note that on a SHARED
 * channel this is the whole SERVICE going, not one connection ending; a
 * connection ends with a FIN frame (`fin_seen`). */
static bool sock_chan_gone(PAL_HANDLE handle) {
    return pal_chan_peer_gone(sock_win(handle), sock_side(handle));
}

static void ring_for(PAL_HANDLE handle, struct pal_chan_ring* in,
                     struct pal_chan_ring* out) {
    unsigned long win = sock_win(handle);
    int side          = sock_side(handle);
    if (in)
        pal_chan_ring_init(in, win, side, /*producing=*/0);
    if (out)
        pal_chan_ring_init(out, win, side, /*producing=*/1);
}

/* The window index a muxed handle notifies and parks on. */
static unsigned long sock_widx(PAL_HANDLE handle) {
    return sock_shares(handle) ? g_pal_svsm_mux_widx : handle->sock.widx;
}

/*
 * A blocking call's wait: in the PAL scheduler, not in a Sleep of its own.
 *
 * Every blocking send, recv, accept and connect here used to wait with
 * pal_svsm_sleep_arms - which gives the whole VAULT's processor to the
 * monitor, so every other thread of the program stopped with it. A main
 * thread's 0.3 s sleep beside a reader blocked on an idle socket took 118 s,
 * as long as the socket stayed idle (vault_fork_recv_blocked), and a small
 * GET beside a bulk download waited out the download's parks. Inside a host
 * invoke the Sleep is refused and the wait was a spin of its own, which
 * starved them outright.
 *
 * So the call says what it waits for and blocks like any other waiter:
 * `arms`, the ring words the monitor watches when the whole vault has
 * nothing to run (idle_until makes the same Park or Sleep the call made by
 * itself, so a single-threaded program pays what it did); `want`, the test
 * the scheduler re-asks on every pass while other threads run
 * (pal_svsm_sock_wait_ready); and a bound, after which the caller looks
 * again whatever happened - the safety net for a missed wake that
 * PAL_SOCK_PARK_US always was. `handle` NULL or `want` 0 is a wait on the
 * bound alone, for what no ring word announces (a grant to retry, a window
 * to be published).
 *
 * Interruptible when `interruptible`: a signal for this thread ends the wait
 * with -PAL_ERROR_INTERRUPTED, which the LibOS restarts or answers EINTR as
 * the signal's SA_RESTART says. A wait that must not be abandoned halfway (a
 * handshake, a half-close's FIN) lets the signal be delivered when the call
 * returns, as it always was. Nothing the caller read before the wait is
 * true after it: other threads ran, and may have read, sent or closed.
 */
static int sock_block(PAL_HANDLE handle, pal_wait_flags_t want, const uint64_t* arms,
                      size_t n_arms, uint64_t max_us, bool interruptible) {
    PAL_HANDLE hs[1]       = { handle };
    pal_wait_flags_t ev[1] = { want | PAL_SVSM_WAIT_SOCK };
    pal_svsm_thread_arm(arms, n_arms, /*partial=*/false);
    if (handle && want)
        pal_svsm_thread_watch(1, hs, ev);
    uint64_t deadline = pal_svsm_now_usec() + max_us;
    if (pal_svsm_poll_block(&deadline) == PAL_SVSM_WAIT_INTERRUPTED && interruptible)
        return -PAL_ERROR_INTERRUPTED;
    return 0;
}

/* Has another thread ended this socket's reading - shutdown(SHUT_RD), a
 * close, or a channel closed under it (a socket that owns its channel lets
 * it go on any shutdown, sock_delete)? Asked after every wait, BEFORE the
 * rings are looked at again: with no channel there are none to look at. */
static bool sock_rd_over(PAL_HANDLE h) {
    return h->sock.rd_shut || h->sock.closed || !sock_has_chan(h);
}

/* The same for writing: shutdown(SHUT_WR)'s FIN out, or the same close. A
 * send parked across another thread's SHUT_WR must not put DATA behind its
 * FIN; one that gets in while the FIN still waits for room goes before it,
 * which is where Linux puts it too. */
static bool sock_wr_over(PAL_HANDLE h) {
    return h->sock.wr_shut || h->sock.closed || !sock_has_chan(h);
}

/* --------------------------------------------------- the frame pool, client
 *
 * The mirror of the service's (relay.c): one buffer per frame a peer may have
 * in flight, shared by every socket on the channel and allocated on first use.
 *
 * 32 floors, not MUX_MAX_CONNS of them: 256 would be 4 MiB of buffers for a
 * vault that will realistically hold tens of sockets, and 32 is the service's
 * session table, which is the real limit on how many connections one vault can
 * have open at once. The rest is headroom so a few can run at the cap.
 */
#define PAL_MUX_FLOORS 32
#define PAL_MUX_POOL   (PAL_MUX_FLOORS + 3 * (PAL_MUX_CREDIT_CAP - 1))

static void* g_mux_pool[PAL_MUX_POOL];
static bool  g_mux_pool_used[PAL_MUX_POOL];
static int   g_mux_pool_busy;

/* May this code use the heap? Not from the scheduler's re-test
 * (pal_svsm_poller_ready), and not on a thread inside a preemption upcall: a
 * large PAL allocation is the LibOS's VMA bookkeeping, which such a thread may
 * have been interrupted in. */
static inline bool pal_svsm_heap_unsafe(void) {
    return g_pal_svsm_sched_ctx || pal_get_svsm_tcb()->handle->thread.in_upcall;
}

static int mux_pool_take(uint32_t slot) {
    for (int i = 0; i < PAL_MUX_POOL; i++) {
        if (g_mux_pool_used[i])
            continue;
        if (!g_mux_pool[i]) {
            /* Allocated on first use - but never from the scheduler's
             * re-test, which can run from a preemption upcall with the
             * interrupted thread anywhere (pal_svsm_sched_ctx). The frame
             * then stays at the head (BLOCKED) until a thread routes it. */
            if (pal_svsm_heap_unsafe()) {
                g_pal_svsm_sched_deferred = true;
                continue;
            }
            /* Into a local, and the slot looked at again: the malloc can be
             * preempted (pal_memory.c bkeep upcalls), and another thread may
             * have filled this slot meanwhile - assigning straight over it
             * orphaned that buffer and over-counted busy (review by jamie). */
            void* n = malloc(slot);
            if (!n)
                return -2;                   /* NOMEM, not merely full */
            if (g_mux_pool[i]) {
                int j;
                for (j = 0; j < PAL_MUX_POOL && g_mux_pool[j]; j++)
                    ;
                if (j < PAL_MUX_POOL)
                    g_mux_pool[j] = n;       /* stocked for the next take */
                else
                    free(n);
                i = -1;                      /* scan again from the start */
                continue;
            }
            g_mux_pool[i] = n;
        }
        g_mux_pool_used[i] = true;
        g_mux_pool_busy++;
        return i;
    }
    return -1;
}

static void mux_pool_put_ptr(void* p) {
    if (!p)
        return;
    for (int i = 0; i < PAL_MUX_POOL; i++)
        if (g_mux_pool[i] == p && g_mux_pool_used[i]) {
            g_mux_pool_used[i] = false;
            g_mux_pool_busy--;
            return;
        }
}

/* Forward: the poll path's router is written beside the other poll helpers,
 * and the SEND path needs it too - a socket waiting on its window is waiting
 * for a credit frame, and routing the head is what collects one. */
static bool mux_poll_route(PAL_HANDLE handle, struct pal_chan_ring* in);

/* One buffer for a message being ROUTED rather than served. Grown once to the
 * channel's slot and kept: a vault that routed one frame will route more. */
static char* mux_scratch(uint32_t slot) {
    static char*    buf;
    static uint32_t have;
    if (!buf || have < slot) {
        if (pal_svsm_heap_unsafe()) {
            g_pal_svsm_sched_deferred = true;   /* wake the thread to do it */
            return NULL;
        }
        char* n = malloc(slot);
        if (!n)
            return NULL;
        free(buf);
        buf  = n;
        have = slot;
    }
    return buf;
}

/* Hand a handle a pool buffer that ALREADY HOLDS the frame.
 *
 * By pointer, never by copy. The frame was read out of the ring straight into
 * this buffer, so a socket's message costs exactly the one copy it has always
 * cost - the ring to the buffer it is read from. An earlier version copied into
 * scratch, then into a pool buffer, then into `rx`: three copies where there
 * had been one, and it took 1 MiB from 125 MB/s to 100.
 *
 * `off` is where the BODY starts, so the frame header travels with the buffer
 * and is skipped rather than moved. False means there was no room, and then the
 * caller must put the buffer back. */
/* Give a socket with no `rx` its own buffer, at a recv's entry.
 *
 * NOT `rx = malloc(...)` in one step. A slot-sized malloc goes to the LibOS's
 * VMA bookkeeping (pal_memory.c bkeep upcalls), which is LibOS text and can be
 * preempted - and the scheduler's re-test routes the shared channel meanwhile.
 * A frame for this socket installed into `rx` then (rx_pooled) was overwritten
 * by the assignment when the malloc returned: the frame lost, its pool buffer
 * orphaned, rx_done never advancing, the connection stalled for good (review by
 * jamie; the s2/s3 dumps on ryan). So: allocate into a local, and look again.
 */
static int mux_rx_own(PAL_HANDLE h, uint32_t slot) {
    char* own = h->sock.rx_spare;
    h->sock.rx_spare = NULL;
    if (!own)
        own = malloc(slot);
    if (!own)
        return -PAL_ERROR_NOMEM;
    if (!h->sock.rx) {
        h->sock.rx        = own;
        h->sock.rx_pooled = false;
        h->sock.rx_len = h->sock.rx_off = 0;
    } else if (!h->sock.rx_spare) {
        h->sock.rx_spare = own;          /* routed in meanwhile: keep it */
    } else {
        free(own);                       /* thread context: safe */
    }
    return 0;
}

static bool mux_rx_refill(PAL_HANDLE h);

static bool mux_sink_buf(PAL_HANDLE h, void* buf, uint32_t len, uint32_t off) {
    /* `rx` spent AND nothing queued behind it - not just `rx` spent.
     *
     * A read drains `rx` and returns, and only the NEXT read refills it from
     * the queue (mux_rx_refill). Anything that routes the head in between - a
     * poll, a peer-gone check, a send waiting for credit, an attribute query -
     * could find `rx` empty with older frames still queued, and this used to
     * make the NEW frame `rx`: the next read served it ahead of the queue, and
     * the older frame came out later. A stream delivered one frame early and
     * one frame late, at full length and with every byte from the right
     * file - so nothing failed loudly. Measured on jamie 2026-10-12: a 102 MB
     * download into a vault came back with the right size and the wrong
     * SHA-256 every time (10 of 10), the bad ranges holding the bytes from
     * exactly 0x3FF4 = 16,372 further on - one mux frame's payload - and
     * torch.load in SeBS 411 failed with KeyError 'storages'. */
    /* `rx` spent WITH frames queued behind it: the oldest of them becomes
     * `rx` first, so the queue has room for this one. The read that spent
     * `rx` counted its frame done (rx_done) and so promised the service a
     * slot - the window is CAP = `rx` + PAL_MUX_QUEUE - and without this the
     * slot was not there until the next read: a socket with 15 frames queued
     * behind a spent `rx` took the 16th as an overflow and was marked broken.
     * The client read ECONNRESET in the middle of a download. Measured with
     * 64 KiB frames, eight downloads at once from one vault: 7 of 8 reset
     * (net_client_share, ryan 2026-10-18), every one of them here with the
     * queue full and `rx` empty. Order is kept: the queue's head goes first,
     * and the new frame to the queue's tail. */
    if (h->sock.rx_off >= h->sock.rx_len && h->sock.q_count)
        mux_rx_refill(h);
    if (h->sock.rx_off >= h->sock.rx_len && !h->sock.q_count) {
        /* `rx` is spent: this buffer becomes it, and the old one goes back to
         * the pool if that is where it came from - or, if it was the socket's
         * own, is KEPT (rx_spare) for its next direct read. Freed here, it was
         * freed by whatever routed: the scheduler's re-test too, which runs
         * from a preemption upcall with the interrupted thread anywhere. The
         * heap is no place to be then (a free() of an unmapped allocation on
         * the alternate stack, ryan nd1 2026-10-18). */
        if (h->sock.rx_pooled)
            mux_pool_put_ptr(h->sock.rx);
        else if (h->sock.rx) {
            assert(!h->sock.rx_spare);   /* at most one own buffer per socket */
            h->sock.rx_spare = h->sock.rx;
        }
        h->sock.rx        = buf;
        h->sock.rx_pooled = true;
        h->sock.rx_len    = len;
        h->sock.rx_off    = off;
        return true;
    }
    if (h->sock.q_count >= PAL_MUX_QUEUE)
        return false;
    int t = (h->sock.q_head + h->sock.q_count) % PAL_MUX_QUEUE;
    h->sock.q[t]     = buf;
    h->sock.q_len[t] = len;
    h->sock.q_off[t] = off;
    h->sock.q_count++;
    return true;
}

/* `rx` is drained: move the next queued frame into it. */
static bool mux_rx_refill(PAL_HANDLE h) {
    if (h->sock.rx_off < h->sock.rx_len)
        return true;
    if (!h->sock.q_count)
        return false;
    int i = h->sock.q_head;
    /* A SWAP: the spent buffer goes back to the pool and the queue's head
     * becomes `rx`. No bytes move. */
    if (h->sock.rx_pooled)
        mux_pool_put_ptr(h->sock.rx);
    else if (h->sock.rx) {
        assert(!h->sock.rx_spare);          /* kept, as in mux_sink_buf */
        h->sock.rx_spare = h->sock.rx;
    }
    h->sock.rx        = h->sock.q[i];
    h->sock.rx_pooled = true;
    h->sock.rx_len    = h->sock.q_len[i];
    h->sock.rx_off    = h->sock.q_off[i];
    h->sock.q[i]      = NULL;
    h->sock.q_head    = (h->sock.q_head + 1) % PAL_MUX_QUEUE;
    h->sock.q_count--;
    return h->sock.rx_off < h->sock.rx_len;
}

static void mux_queue_release(PAL_HANDLE h) {
    if (h->sock.rx_pooled) {
        mux_pool_put_ptr(h->sock.rx);
        h->sock.rx        = NULL;
        h->sock.rx_pooled = false;
        h->sock.rx_len = h->sock.rx_off = 0;
    }
    while (h->sock.q_count) {
        int i = h->sock.q_head;
        mux_pool_put_ptr(h->sock.q[i]);
        h->sock.q[i]   = NULL;
        h->sock.q_head = (h->sock.q_head + 1) % PAL_MUX_QUEUE;
        h->sock.q_count--;
    }
}

/* How many frames the service may have in flight for this socket, now: the
 * floor always, plus what the pool can spare once every other live connection's
 * floor is covered, capped. The service's up_grant is the same rule from the
 * other end. */
/* What a socket can still have in the pool: every frame it was promised and
 * has not finished with (queued, in `rx`, or not yet arrived), at least the
 * floor - a new socket has advertised nothing and the service may still send
 * PAL_MVMUX_CREDIT_INIT. Plus one when it keeps a spent pool buffer as `rx`:
 * that buffer stays with the socket until its next frame replaces it. */
static int mux_claim(PAL_HANDLE s) {
    int owed  = (int32_t)(s->sock.rx_advert - s->sock.rx_done);
    int claim = owed > PAL_MUX_CREDIT_FLOOR ? owed : PAL_MUX_CREDIT_FLOOR;
    if (s->sock.rx_pooled && s->sock.rx_off >= s->sock.rx_len)
        claim++;
    return claim;
}

/* How many frames the service may have in flight for this socket: what the
 * pool has left after every OTHER socket's claim and the floors of the
 * PAL_MUX_FLOORS sockets that may still open, at least the floor, capped.
 *
 * Claims, not g_mux_pool_busy. Busy counts only frames that have arrived, and
 * the limit is cumulative - a socket keeps what it was promised - so each of
 * several sockets was granted the cap against the same free buffers: five
 * keep-alive sockets that had each finished a large reply held 80 frames of
 * promise against a pool of 77. When the pool ran dry the head frame had no
 * buffer (MUX_HEAD_BLOCKED) and every socket of the vault waited behind it,
 * for good if the application was reading a different socket. The service's
 * relay had the same flaw (up_grant, netsvc 59bef6f); this is its mirror. */
static uint32_t mux_grant(PAL_HANDLE h) {
    int taken = 0, live = 0;
    for (int i = 0; i < PAL_SVSM_MUX_MAX_CONNS; i++) {
        PAL_HANDLE s = pal_svsm_mux_conn_at(i);
        if (!s)
            continue;
        live++;
        if (s != h)
            taken += mux_claim(s);
    }
    if (live < PAL_MUX_FLOORS)
        taken += (PAL_MUX_FLOORS - live) * PAL_MUX_CREDIT_FLOOR;
    if (h->sock.rx_pooled && h->sock.rx_off >= h->sock.rx_len)
        taken++;                         /* its own kept buffer */
    int left = PAL_MUX_POOL - taken;
    uint32_t g = left > PAL_MUX_CREDIT_FLOOR ? (uint32_t)left : (uint32_t)PAL_MUX_CREDIT_FLOOR;
    if (g > PAL_MUX_CREDIT_CAP)
        g = PAL_MUX_CREDIT_CAP;
    return g;
}

/* Tell the service this socket's limit, when saying so is worth a message.
 *
 * At once when the socket has nothing left coming, because then a message is
 * the only thing that will restart it; otherwise only when the window has
 * opened by two, so a steady stream costs one credit frame per two data frames
 * rather than one per one.
 *
 * A credit that finds the ring full is NOT harmless, though the limit is
 * cumulative. It is harmless only if another attempt follows, and when the
 * socket is `blocked` the service is out of window and will send nothing more
 * for it - so nothing on this socket will ever call here again, and its reader
 * waits for a frame the service is waiting to be allowed to send. That was the
 * concurrent-upload stall: three keep-alive connections from one vault, the
 * other two filling the ring with 5 MiB bodies, and a connection's FIRST reply
 * (two frames: headers, body, against a floor window of one) stopped after its
 * headers until the client's timeout, in 12 of 15 calls on ryan. So a blocked
 * socket's credit stays OWED (`mux_credit_owed`), and whoever is about to wait
 * for that socket's input sends it first, or waits for ring room to send it
 * (`mux_credit_settle`). */
static bool mux_credit_due(PAL_HANDLE h, uint32_t* out_want) {
    if (!sock_shares(h) || !h->sock.conn_id)
        return false;
    /* GROWN WITH USE, as the relay's upload window is: FLOOR, doubled when
     * the socket has nearly consumed what it was promised and has consumed
     * since the last doubling. A promise cannot be taken back, so the cap
     * handed to a socket that reads one small reply and then idles on a
     * keep-alive is pool no other socket may use. */
    uint32_t win = h->sock.rx_win ? h->sock.rx_win : PAL_MUX_CREDIT_FLOOR;
    if ((int32_t)(h->sock.rx_advert - h->sock.rx_done) <= 2 && h->sock.rx_done != h->sock.rx_grew
        && (int32_t)(h->sock.rx_done - h->sock.rx_advert) >= -(int32_t)(win / 2)) {
        win = win * 2 > PAL_MUX_CREDIT_CAP ? PAL_MUX_CREDIT_CAP : win * 2;
        h->sock.rx_win  = win;
        h->sock.rx_grew = h->sock.rx_done;
    }
    uint32_t g = mux_grant(h);
    uint32_t want = h->sock.rx_done + (win < g ? win : g);
    if ((int32_t)(want - h->sock.rx_advert) <= 0)
        return false;                    /* only a greater limit means anything */
    bool blocked = (int32_t)(h->sock.rx_advert - h->sock.rx_done) <= 3;
    if (!blocked && (int32_t)(want - h->sock.rx_advert) < 4)
        return false;
    *out_want = want;
    return true;
}

static void mux_credit_maybe(PAL_HANDLE h) {
    uint32_t want;
    if (!mux_credit_due(h, &want))
        return;
    struct pal_chan_ring out;
    ring_for(h, NULL, &out);
    struct pal_mvmux_hdr mh;
    memset(&mh, 0, sizeof mh);
    mh.conn = h->sock.conn_id;
    mh.op   = PAL_MVMUX_OP_CREDIT;
    /* NO NOTIFY, deliberately.
     *
     * A notify is a monitor call, and it also WAKES the service - which for a
     * credit frame buys nothing: the frame carries no data, it only widens a
     * window, and the service is dispatched on its own clock every
     * MIN_PERIOD_US whether anybody rings or not. Seventeen of these per MiB
     * were seventeen monitor calls and seventeen service dispatches that had
     * nothing to do.
     *
     * Safe because nobody ever WAITS on a credit frame: the only party a window
     * stalls is the service, and a stalled service is a running one - it has
     * data to send and is being dispatched. The client waits on data, which is
     * still notified. */
    if (pal_chan_send2(&out, &mh, PAL_MVMUX_HDR_BYTES, &want, 4) == 0) {
        h->sock.rx_advert = want;
        if (h->sock.credit_owed) {
            h->sock.credit_owed = false;
            PAL_SVSM_NET_CTR_INC(credits_owed_retried);
        }
    } else if (!h->sock.credit_owed) {
        h->sock.credit_owed = true;
        PAL_SVSM_NET_CTR_INC(credit_lost);
    }
}

/* Owed: a credit this socket must get to the service before its reader can
 * expect anything (see mux_credit_maybe). */
static bool mux_credit_owed(PAL_HANDLE h) {
    uint32_t want;
    return h->sock.credit_owed && mux_credit_due(h, &want);
}

/* For a reader about to wait: send an owed credit, and if the ring is still
 * full, return true with `*out_arm` set to the outbound ring's head - room is
 * what the reader must wait for, because input cannot come before the credit
 * has gone. */
static bool mux_credit_settle(PAL_HANDLE h, uint64_t* out_arm) {
    if (!mux_credit_owed(h))
        return false;
    mux_credit_maybe(h);
    if (!mux_credit_owed(h))
        return false;
    struct pal_chan_ring out;
    ring_for(h, NULL, &out);
    *out_arm = pal_chan_arm(sock_widx(h), PAL_CHAN_ARM_HEAD, *out.peer_head);
    return true;
}

/* A close's FIN that found the shared ring full, kept to be sent later.
 *
 * The close itself must not wait for room (one busy peer would hold every
 * close), but a FIN that is simply dropped leaves the service holding the
 * connection - its lwIP side open, the far end never told, one of the
 * service's sessions used - until this vault exits. The same failure as a
 * dropped CREDIT, one frame over. So it is queued here and sent by the next
 * thing that uses the channel: a send, a read, a poll, another close.
 * Safe late: the service matches the WHOLE id, generation included
 * (relay.c conn_of), so a FIN for a connection it has already ended, or a
 * new connection in the same slot, touches nothing. One past the queue's
 * 32 is not resent - the vault's exit still ends it. fin_lost counts every
 * FIN that found the ring full, fin_resent the ones sent later. */
#define PAL_MUX_FIN_OWED 32
static uint32_t g_fin_owed[PAL_MUX_FIN_OWED];

static bool mux_fin_send(uint32_t id) {
    struct pal_chan_ring out;
    pal_chan_ring_init(&out, g_pal_svsm_mux_win, g_pal_svsm_mux_side, /*producing=*/1);
    struct pal_mvmux_hdr mh;
    memset(&mh, 0, sizeof mh);
    mh.conn = id;
    mh.op   = PAL_MVMUX_OP_FIN;
    if (pal_chan_send2(&out, &mh, PAL_MVMUX_HDR_BYTES, NULL, 0) != 0)
        return false;
    pal_svsm_channel_notify(g_pal_svsm_mux_widx);
    return true;
}

static void mux_fin_flush(void) {
    int sent = 0;
    while (sent < g_fin_owed_n && g_pal_svsm_mux_open && mux_fin_send(g_fin_owed[sent]))
        sent++;
    if (!sent)
        return;
    for (int i = sent; i < g_fin_owed_n; i++)
        g_fin_owed[i - sent] = g_fin_owed[i];
    g_fin_owed_n -= sent;
    for (int i = 0; i < sent; i++)
        PAL_SVSM_NET_CTR_INC(fin_resent);
}

/*
 * What to do with the message at the head of a SHARED channel, for a caller
 * that wants its OWN connection's next message.
 *
 * Factored out of _PalSocketRecv because the HANDSHAKE needs exactly the same
 * decision and did not make it: it read the head with pal_chan_recv and
 * checked only the length, so a connect() made while another socket on the
 * same channel was receiving consumed that socket's data as its reply - losing
 * the data and failing the connect. One socket at a time is the easy case and
 * the only one that was tested; an HTTP connection pool is the ordinary one.
 *
 *   MUX_HEAD_MINE     the head is this handle's. NOT consumed - read it.
 *   MUX_HEAD_MOVED    it was someone else's and has been dealt with: parked in
 *                     that handle's buffer, or dropped because its connection
 *                     is gone. Go round.
 *   MUX_HEAD_BLOCKED  it belongs to another socket whose buffer is still full.
 *                     Nothing can move until that socket reads - head-of-line
 *                     blocking at the vault, which is what sharing costs.
 *   MUX_HEAD_EMPTY    nothing there, or this handle owns its channel.
 *   MUX_HEAD_NOMEM
 */
enum mux_head {
    MUX_HEAD_EMPTY = 0,
    MUX_HEAD_MINE,
    MUX_HEAD_MOVED,
    MUX_HEAD_BLOCKED,
    MUX_HEAD_NOMEM,
};

static enum mux_head mux_head_step(PAL_HANDLE handle, struct pal_chan_ring* in,
                                   bool was_full);

/* Read the head message - but on a SHARED channel only what mux_head_step said
 * is ours (MINE). EMPTY means the ring was empty when it PEEKED, not that it
 * still is: the service fills it from another processor, so a message can land
 * between that peek and this read, and reading it here takes it without the
 * router ever seeing it - another socket's frame, or a CREDIT, handed to this
 * caller as its own. That is how a reader parked on a connection whose peer
 * never writes returned 01 00 00 00 (the body of a CREDIT with limit 1) on
 * ryan, once in about 25 vault_sock_park runs, in the phase where signals keep
 * its recv going round. -1, as for an empty ring: the caller looks again, and
 * routes what has arrived. A socket that owns its channel is never routed
 * (mux_head_step says EMPTY for it whatever is there) and reads directly. */
static int mux_recv_mine(PAL_HANDLE handle, struct pal_chan_ring* in, enum mux_head mh,
                         void* msg, uint32_t max, uint32_t* out_len) {
    if (mh == MUX_HEAD_EMPTY && sock_shares(handle))
        return -1;
    return pal_chan_recv(in, msg, max, out_len);
}

static enum mux_head mux_head_step(PAL_HANDLE handle, struct pal_chan_ring* in,
                                   bool was_full) {
    if (!sock_shares(handle))
        return MUX_HEAD_EMPTY;

    struct pal_mvmux_hdr ph;
    uint32_t mlen = 0;
    if (pal_chan_peek(in, &ph, PAL_MVMUX_HDR_BYTES, &mlen) != 0
        || mlen < PAL_MVMUX_HDR_BYTES)
        return MUX_HEAD_EMPTY;

    PAL_HANDLE target = pal_svsm_mux_conn_of(ph.conn);

    /* WHO OWNS THIS FRAME: the router, or a caller?
     *
     * FIN, RST and CREDIT are the router's - they change a handle's state and
     * carry nothing anybody reads, so they are consumed here whoever they are
     * for. Everything else belongs to a CALLER: DATA to whoever is reading the
     * socket, and a CONNECT reply to whoever is inside mvnet_handshake, which
     * reads the ring directly rather than through `rx`.
     *
     * Getting that second case wrong is how this was first written and it cost
     * every connection: a handshake reply is a CONNECT-op frame, the switch
     * below had no case for it, and "an op this build does not know" consumed
     * and dropped the one message the connecting socket was waiting for. */
    bool ctl = (ph.op == PAL_MVMUX_OP_FIN || ph.op == PAL_MVMUX_OP_RST
                || ph.op == PAL_MVMUX_OP_CREDIT);

    if (target == handle && !ctl) {
        /* Ours to read. Straight out of the ring into `rx` if there is room -
         * the one path that does not copy - and otherwise into our own queue,
         * because a frame of OURS left at the head because we are slow blocks
         * every other socket on this channel just as surely as somebody
         * else's would. A CONNECT reply is never queued: only the handshake
         * can read it, and it reads the ring. */
        if (ph.op != PAL_MVMUX_OP_DATA
            || (handle->sock.rx_off >= handle->sock.rx_len && !handle->sock.q_count))
            return MUX_HEAD_MINE;
    } else if (target && !ctl && ph.op != PAL_MVMUX_OP_DATA) {
        /* Another socket's handshake reply, which only that socket can read.
         * Left at the head for it - briefly, because the service answers a
         * CONNECT in the pass it arrives in. */
        return MUX_HEAD_BLOCKED;
    }

    /* A DATA frame is read straight into the buffer it will be READ FROM - the
     * pool's - so a message costs one copy, the same one it cost before any of
     * this existed. Control frames go into scratch: they are a handful of bytes
     * and they must never need a pool buffer, or a FIN could not be delivered
     * to a socket whose queue is full. */
    bool pooled = (ph.op == PAL_MVMUX_OP_DATA) && target;
    int pb = -1;
    char* into;
    if (pooled) {
        pb = mux_pool_take(in->slot);
        if (pb == -2)
            return MUX_HEAD_NOMEM;      /* the heap said no: not a full pool */
        if (pb < 0)
            return MUX_HEAD_BLOCKED;    /* no buffer: leave it, come back */
        into = g_mux_pool[pb];
    } else {
        into = mux_scratch(in->slot);
        if (!into)
            return MUX_HEAD_NOMEM;
    }
    uint32_t got = 0;
    if (pal_chan_recv(in, into, in->slot, &got) != 0) {
        if (pooled)
            mux_pool_put_ptr(into);
        return MUX_HEAD_EMPTY;
    }
    if (was_full)
        pal_svsm_channel_notify(sock_widx(handle));

    if (pooled && got > PAL_MVMUX_HDR_BYTES) {
        if (!mux_sink_buf(target, into, got, PAL_MVMUX_HDR_BYTES)) {
            /* Nowhere to put it, and it is already out of the ring. Dropping
             * would silently corrupt the stream, so the socket is marked rather
             * than lied to. Unreachable while the advertised window holds -
             * which it did not, until mux_sink_buf refilled a spent `rx`. */
            mux_pool_put_ptr(into);
            if (target->hdr.type == PAL_TYPE_SOCKET && target->sock.type == PAL_SOCKET_UDP) {
                /* A DATAGRAM socket loses the datagram, not the socket: that
                 * is what a full receive queue means for UDP. A service that
                 * does not pace datagram frames by credit (one older than
                 * DGRAM_BATCH) can reach this simply by sending to a socket
                 * the application is not reading while it reads another.
                 * Counted done, so the window it was sent against moves on. */
                target->sock.rx_done++;
                PAL_SVSM_NET_CTR_INC(udp_q_drop);
            } else {
                target->sock.broken = true;
            }
#line 931
        }
        return MUX_HEAD_MOVED;
    }
    if (pooled) {
        /* A DATA frame with no body. Counted done, as the read path counts
         * one (_PalSocketRecv), or the service's window would shrink by a
         * frame for good: it was sent against credit. */
        mux_pool_put_ptr(into);
        target->sock.rx_done++;
        return MUX_HEAD_MOVED;
    }

    char* scratch = into;
    if (!target || got < PAL_MVMUX_HDR_BYTES) {
        /* A frame for a connection that has closed, or one that cannot be a
         * frame at all. Consumed and DROPPED: the id carries a generation, so a
         * late frame cannot be mistaken for the next occupant of the slot. */
        return MUX_HEAD_MOVED;
    }

    if (ph.op == PAL_MVMUX_OP_FIN) {
        /* A FIN costs no queue room, so a stream can always be ended - even one
         * whose reader has stopped and whose queue is full. */
        target->sock.fin_seen = true;
    } else if (ph.op == PAL_MVMUX_OP_RST) {
        target->sock.broken = true;
    } else if (ph.op == PAL_MVMUX_OP_CREDIT) {
        if (got >= PAL_MVMUX_HDR_BYTES + 4) {
            uint32_t lim;
            memcpy(&lim, scratch + PAL_MVMUX_HDR_BYTES, 4);
            /* Cumulative, so an older frame arriving after a newer one cannot
             * shrink the window: only a strictly greater limit is taken. */
            if ((int32_t)(lim - target->sock.tx_limit) > 0)
                target->sock.tx_limit = lim;
        }
    }
    return MUX_HEAD_MOVED;
}

int _PalSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                     pal_stream_options_t options, PAL_HANDLE* out_handle) {
    if (domain != PAL_IPV4 && domain != PAL_IPV6)
        return -PAL_ERROR_NOTSUPPORT;
    if (type != PAL_SOCKET_TCP && type != PAL_SOCKET_UDP)
        return -PAL_ERROR_NOTSUPPORT;

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(sock));
    if (!hdl)
        return -PAL_ERROR_NOMEM;
    init_handle_hdr(hdl, PAL_TYPE_SOCKET);
    /* `g_pal_handle_ops[]` has no PAL_TYPE_SOCKET entry and HANDLE_OPS()
     * prefers a per-handle table, so this is what makes attributes work at
     * all. Without it every attribute call returned BADHANDLE, which the
     * LibOS turns into EBADF - so `socket.settimeout(5)` raised
     * `OSError: [Errno 9] Bad file descriptor` and an application could not
     * bound a wait. The ops table itself has been complete and unreachable
     * at the bottom of this file since sockets were written. */
    hdl->hdr.ops = &g_sock_ops;
    hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    hdl->sock.domain         = domain;
    hdl->sock.type           = type;
    hdl->sock.is_nonblocking = !!(options & PAL_OPTION_NONBLOCK);
    *out_handle = hdl;
    return 0;
}

/*
 * Bind records the address and nothing else.
 *
 * What this vault answers on is not chosen here: it is the endpoint its
 * MEASURED manifest declares ([svsm.endpoint]), which the PAL sealed with
 * the monitor before any application code ran. A port number in a bind is
 * therefore a label, not a decision - and with a network service on the far
 * end it becomes the port in the LISTEN message, which is the first point
 * at which it means anything to anybody.
 */
int _PalSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    /* For a STREAM socket the address is not kept: what this vault answers
     * on is the endpoint its measured manifest declares, and a port here
     * would only be a label for it.
     *
     * For a DATAGRAM socket it is kept, and means what it says. There is no
     * endpoint and no accept: an unsolicited datagram can only arrive if
     * the service bound a port for this socket on the tap, so the number
     * has to reach the service - and it can only do that at open time,
     * which is why it is remembered here rather than used here. A client
     * binds nothing and gets an ephemeral port, which is the usual case. */
    if (handle->sock.type == PAL_SOCKET_UDP && addr && addr->domain == PAL_IPV4)
        handle->sock.bind_port = ntohs(addr->ipv4.port);
    else
        __UNUSED(addr);
    handle->sock.bound = true;
    return 0;
}

/*
 * Listen makes this handle the one `accept` draws from.
 *
 * Nobody has to be told: a vault that declared an endpoint is already
 * reachable - peers open channels to it by name and the monitor admits them
 * by the sealed policy. The backlog is the monitor's to hold, in the sense
 * that a channel exists from the moment it is granted whether or not this
 * vault has accepted it yet.
 */
int _PalSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    handle->sock.listening = true;
    handle->sock.backlog   = backlog;
    return 0;
}

/*
 * A connection is a channel appearing in this vault's directory.
 *
 * The monitor publishes one bit per window there, and writes the region's
 * header - magic, geometry, both ends' identity - before it sets the bit. So
 * accept is: find a bit that is set, that this vault did not set itself by
 * connecting, and whose header is the shape a channel has. The peer is on
 * side 0 because it asked; we are side 1 because we were asked.
 *
 * Waiting for one is a sleep and a look, not a park: a new CHANNEL is not a
 * ring index moving, so there is no word to arm. Posting a cause to the
 * target at grant time is five lines in the monitor and is what turns this
 * 50 ms poll into a wake (PLAN.md's receive loop, M2). While other threads
 * run, the scheduler makes the look for it (pal_svsm_sock_wait_ready).
 */
/* The first window that is a channel nobody here has taken, or 0. Loads only:
 * the scheduler asks it for a blocked accept. */
static unsigned accept_find(void) {
    /* All eight published words, not just the first. Window 0 is the
       directory page itself, so the scan starts at 1. */
    for (unsigned w = 1; w < PAL_CHAN_WINDOWS; w++) {
        uint64_t live = pal_chan_u64(PAL_CHAN_DIR_VADDR,
                                     PAL_CHAN_DIR_LIVE + (w / 64) * 8);
        if (!(live & (1UL << (w % 64))) || sock_claimed(w))
            continue;
        if (pal_chan_u64(pal_chan_window_addr(w), 0) != PAL_CHAN_HDR_MAGIC)
            continue;
        return w;
    }
    return 0;
}

int _PalSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                     struct pal_socket_addr* out_client_addr,
                     struct pal_socket_addr* out_local_addr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    if (!handle->sock.listening || handle->sock.closed)
        return -PAL_ERROR_INVAL;

    bool nonblock = handle->sock.is_nonblocking || (options & PAL_OPTION_NONBLOCK);

    for (;;) {
        unsigned w = accept_find();
        if (w) {
            unsigned long win = pal_chan_window_addr(w);
            PAL_HANDLE cli = calloc(1, HANDLE_SIZE(sock));
            if (!cli)
                return -PAL_ERROR_NOMEM;
            init_handle_hdr(cli, PAL_TYPE_SOCKET);
            cli->hdr.ops = &g_sock_ops;      /* as in _PalSocketCreate */
            cli->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
            cli->sock.domain         = handle->sock.domain;
            cli->sock.type           = handle->sock.type;
            cli->sock.is_nonblocking = !!(options & PAL_OPTION_NONBLOCK);
            cli->sock.win            = win;
            cli->sock.widx           = w;
            cli->sock.side           = 1;   /* they asked, we were asked */
            sock_claim(w);

            if (out_client_addr)
                memset(out_client_addr, 0, sizeof(*out_client_addr));
            if (out_local_addr)
                memset(out_local_addr, 0, sizeof(*out_local_addr));
            *out_client = cli;
            return 0;
        }

        if (nonblock)
            return -PAL_ERROR_TRYAGAIN;
        /* The monitor posts a cause when it publishes a new window, so this
           is a wake rather than a poll interval; the bound is the backstop
           for a monitor that does not (and for the case where this vault is
           not the scheduler's to park). */
        int wr = sock_block(handle, PAL_WAIT_READ, NULL, 0, 50000, /*interruptible=*/true);
        if (wr < 0)
            return wr;
        if (handle->sock.closed)
            return -PAL_ERROR_INVAL;     /* shut down under it, as Linux has it */
    }
}

/*
 * Open the channel this vault's manifest says it may open, and call that the
 * connection.
 *
 * What the address means depends on what is on the far end, and the
 * manifest says which: to a peer vault the channel IS the connection and
 * the address is not used; to a network service (svsm.net.protocol =
 * "mvnet") the address goes across first as an MVN1 record and the same
 * handle then carries a TCP connection.
 */
/* How many times a connecting vault looks for its answer before giving
   up. The service is dispatched by the scheduler about every millisecond,
   so a few hundred rounds is a comfortable second or two. */
#define PAL_MVNET_ROUNDS 2000
/* How long a connect may wait for the service to answer, in microseconds.
 * Wall clock, because a "round" is a park for a client the scheduler
 * dispatches and a short spin for one inside an invoke - the same number
 * of rounds was seconds for one and milliseconds for another. Two seconds
 * is longer than a service with a full table takes to come round and
 * short enough that a service which is not there loses the client. */
#define PAL_MVNET_WAIT_US 2000000ULL

static inline uint64_t mvnet_now(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static uint64_t mvnet_deadline(uint64_t us) {
    uint64_t hz = pal_svsm_tsc_hz();
    if (!hz)
        hz = 1000000ULL;
    return mvnet_now() + (hz / 1000000ULL) * us;
}

/* One round of waiting: for room to send the request (`want` WRITE: the
   peer's head moving off `seen`) or for the reply (READ: its tail moving off
   `seen`), 2 ms at most. `seen` is what the caller read BEFORE it looked, so
   a move between its look and this park ends the park at once. Not
   interruptible: a connect abandoned between its request and the reply would
   leave the service holding a connection nobody asked for, and the whole
   handshake is bounded by PAL_MVNET_WAIT_US anyway. `in` and `out` are the
   caller's rings, set again afterwards. */
static bool mvnet_wait(PAL_HANDLE handle, pal_wait_flags_t want, uint32_t seen,
                       struct pal_chan_ring* in, struct pal_chan_ring* out) {
    uint64_t arm = pal_chan_arm(sock_widx(handle),
                                want & PAL_WAIT_WRITE ? PAL_CHAN_ARM_HEAD : PAL_CHAN_ARM_TAIL,
                                seen);
    (void)sock_block(handle, want, &arm, 1, 2000, /*interruptible=*/false);
    /* Closed by another thread, or a FIN or reset for this connection routed
     * while it waited (the service refused it, and no reply is coming).
     * False: give up now rather than wake at once for the rest of
     * PAL_MVNET_WAIT_US. */
    if (handle->sock.closed || !sock_has_chan(handle) || handle->sock.broken
        || handle->sock.fin_seen)
        return false;
    ring_for(handle, in, out);
    return true;
}

/* Tell a network service where this connection is going, and wait for it
 * to say whether it got there. Only for a peer the manifest declared to
 * be one: to any other peer these sixteen bytes would be the
 * application's data, arriving with a meaning nobody agreed to. */
static int mvnet_handshake(PAL_HANDLE handle, struct pal_socket_addr* addr,
                           uint8_t proto, uint16_t local_port,
                           struct pal_mvnet_rep* out_rep) {
    /* TCP must name a peer; UDP must not. For a datagram socket the peer
     * travels with each datagram, so an address here would be either
     * ignored or misleading - what it sends instead is the local port, so
     * the service knows whether to bind one or take an ephemeral. */
    if (proto == PAL_MVNET_PROTO_TCP && (!addr || addr->domain != PAL_IPV4))
        return -PAL_ERROR_INVAL;

    struct pal_mvnet_req req;
    memset(&req, 0, sizeof(req));
    req.magic = PAL_MVNET_MAGIC;
    req.op    = PAL_MVNET_OP_CONNECT;
    req.proto = proto;
    /* The port is carried in host order because both ends are the same
     * machine and neither puts it on a wire; the address is not, because
     * the service copies it straight into the header it builds. */
    if (proto == PAL_MVNET_PROTO_TCP) {
        req.port = ntohs(addr->ipv4.port);
        memcpy(req.addr, &addr->ipv4.addr, 4);
    } else {
        req.port = local_port;
        /* Only framed: a batch is read through the mux header's flags. */
        if (handle->sock.muxed)
            req.flags |= PAL_MVNET_REQ_DGRAM_BATCH;
#line 1214
    }

    struct pal_chan_ring in, out;
    ring_for(handle, &in, &out);
    if (!pal_chan_present(&in) || !pal_chan_present(&out))
        return -PAL_ERROR_NOTSUPPORT;

    /* A park is a request, not a right: a vault that is not the
       scheduler's to dispatch - a client running inside an invoke, which
       is most of them - is told no, and the answer to that is to spin,
       not to give up. Treating the refusal as a failed connection is how
       this first refused every connection it ever made, a millisecond
       before the service accepted it. The bound is rounds, so a service
       that never answers still loses the client rather than keeping it. */
    /* Bounded by the CLOCK, not by a number of rounds. A round is a park
     * when the monitor allows one and a spin of a few tens of
     * microseconds when it does not (a client inside an invoke is not
     * the scheduler's to dispatch), so "2000 rounds" was four seconds
     * for one client and forty milliseconds for another - and a service
     * with eight connections in its table does not always come back
     * within forty milliseconds. That is how a busy service looked like
     * a refused connection (PLAN.md phase 4). */
    /* FRAMED, with op = CONNECT.
     *
     * The service used to know this was a request because it was the FIRST
     * sizeof(mvnet_req) bytes on the channel - it recognised it by POSITION.
     * One channel carrying many connections has no first message, so the
     * frame has to say what this is. */
    struct pal_mvmux_hdr cmh;
    memset(&cmh, 0, sizeof cmh);
    cmh.conn = handle->sock.conn_id;
    cmh.op   = PAL_MVMUX_OP_CONNECT;
    const void* chf = handle->sock.muxed ? &cmh : NULL;
    uint32_t chfl = handle->sock.muxed ? PAL_MVMUX_HDR_BYTES : 0;

    uint64_t deadline = mvnet_deadline(PAL_MVNET_WAIT_US);
    for (;;) {
        uint32_t seen = *out.peer_head;
        if (pal_chan_send2(&out, chf, chfl, &req, sizeof(req)) == 0)
            break;
        if (sock_chan_gone(handle))
            return -PAL_ERROR_CONNFAILED;
        if (mvnet_now() > deadline)
            return -PAL_ERROR_CONNFAILED;
        if (!mvnet_wait(handle, PAL_WAIT_WRITE, seen, &in, &out))
            return -PAL_ERROR_CONNFAILED;
    }
    pal_svsm_channel_notify(sock_widx(handle));

    struct pal_mvnet_rep rep;
    deadline = mvnet_deadline(PAL_MVNET_WAIT_US);
    for (;;) {
        uint32_t got = 0;
        uint32_t seen = *in.peer_tail;      /* before looking: mvnet_wait */
        /* THE HEAD MAY NOT BE OURS. On a shared channel another socket's data
         * can be in front of this reply, and reading it as the reply loses the
         * data and fails the connect - so it goes through the same routing the
         * read path uses, and this loop only consumes a message it owns.
         *
         * `was_full` is passed false: a notify here would be about room this
         * handshake did not make, and mux_head_step makes its own when it
         * consumes something. */
        enum mux_head mh = mux_head_step(handle, &in, /*was_full=*/false);
        if (mh == MUX_HEAD_NOMEM)
            return -PAL_ERROR_NOMEM;
        if (mh == MUX_HEAD_MOVED)
            continue;                   /* dealt with; look again */
        if (mh == MUX_HEAD_BLOCKED) {
            /* Another socket is not reading. Wait it out rather than fail: the
             * deadline below still bounds this. */
            if (mvnet_now() > deadline)
                return -PAL_ERROR_CONNFAILED;
            if (!mvnet_wait(handle, PAL_WAIT_READ, seen, &in, &out))
                return -PAL_ERROR_CONNFAILED;
            continue;
        }
        /* Big enough for the frame as well as the record. */
        unsigned char rbuf[PAL_MVMUX_HDR_BYTES + sizeof(rep)];
        int rc = mux_recv_mine(handle, &in, mh, rbuf, sizeof(rbuf), &got);
        if (rc == 0) {
            uint32_t off = handle->sock.muxed ? PAL_MVMUX_HDR_BYTES : 0;
            if (got != off + sizeof(rep))
                return -PAL_ERROR_CONNFAILED;
            memcpy(&rep, rbuf + off, sizeof(rep));
            if (rep.magic != PAL_MVNET_MAGIC)
                return -PAL_ERROR_CONNFAILED;
            /* The service's own codes are negative; it has already said
               which kind of failure it was, and the application only gets
               to know that the connection did not happen. */
            if (rep.status != 0)
                return -PAL_ERROR_CONNFAILED;
            if (out_rep)
                *out_rep = rep;
            return 0;
        }
        if (rc == -2 || sock_chan_gone(handle))
            return -PAL_ERROR_CONNFAILED;
        if (mvnet_now() > deadline)
            return -PAL_ERROR_CONNFAILED;
        if (!mvnet_wait(handle, PAL_WAIT_READ, seen, &in, &out))
            return -PAL_ERROR_CONNFAILED;
    }
}

/*
 * What getsockname() reports: the service's own address and the port it
 * bound for us. The vault has no address of its own, so there is nothing
 * else it could be - and it must be a real AF_INET address rather than
 * zeros, because glibc's getaddrinfo asserts on the family while sorting
 * candidates (see pal_mvnet_rep.local_addr).
 */
static void sock_report_local(PAL_HANDLE handle, struct pal_socket_addr* out) {
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!g_pal_svsm_net_protocol)
        return;             /* a raw channel to a peer vault has no address */
    out->domain = PAL_IPV4;
    memcpy(&out->ipv4.addr, handle->sock.local.local_addr, 4);
    out->ipv4.port = htons(handle->sock.local.local_port);
}

/*
 * Connect, for both shapes.
 *
 * For UDP this is not a connection: it opens the channel to the service and
 * records a default destination. `addr` may be NULL, which is how a sendto
 * on a socket nobody connected gets its channel - see udp_send.
 */
int _PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                      struct pal_socket_addr* out_local_addr, bool* out_inprogress) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    if (handle->sock.type == PAL_SOCKET_UDP && handle->sock.win) {
        /* A second connect on a datagram socket only re-points it; the
         * channel it already has is the same channel. glibc's getaddrinfo
         * does this for EVERY candidate address it sorts, with a disconnect
         * between them - connect() to AF_UNSPEC, which is how a datagram
         * socket is unconnected - so both halves are ordinary traffic here
         * rather than edge cases. */
        if (addr && addr->domain == PAL_IPV4) {
            memcpy(handle->sock.peer_addr, &addr->ipv4.addr, 4);
            handle->sock.peer_port = ntohs(addr->ipv4.port);
            handle->sock.has_peer  = true;
        } else {
            handle->sock.has_peer = false;
        }
        /* And the local address AGAIN, which is the whole bug this path had.
         * Returning 0 without touching out_local_addr left the LibOS to
         * record whatever was in the buffer - family 0 - so getsockname on
         * a RE-connected socket reported AF_UNSPEC and glibc's
         * rfc3484_sort aborted the process on its assertion. The first
         * connect filled it and every later one did not, which is why a
         * single lookup worked and a name with several addresses did not. */
        sock_report_local(handle, out_local_addr);
        if (out_inprogress)
            *out_inprogress = false;
        return 0;
    }
    if (handle->sock.win)
        return -PAL_ERROR_INVAL;
    if (!g_pal_svsm_net_name[0])
        return -PAL_ERROR_DENIED;
    /* IPv4 only, and refused HERE rather than carried and dropped later.
     *
     * The network service's stack is a NO_SYS IPv4 lwIP with no IPv6 at all
     * (tools/fn/filesystem/svc/create.sh), so there is no address a v6
     * destination could be reached from. Reporting a v4 local address on a
     * v6 socket instead is not harmless: glibc's getaddrinfo for an
     * unspecified family connects a datagram socket to every candidate and
     * calls getsockname to sort them per RFC 3484, and a v6 socket that
     * answers with AF_INET makes it die on
     *
     *   getaddrinfo.c:1642 (rfc3484_sort): assertion failed:
     *   a1->source_addr.sin6_family == PF_INET
     *
     * A connect that FAILS is what glibc is written for - it marks that
     * candidate as having no source address and sorts without it - so a
     * name with both A and AAAA records resolves to its A records and an
     * application reaches it. Refusing is also the truthful answer: this
     * vault has no IPv6 route. */
    if (addr && addr->domain != PAL_IPV4)
        return -PAL_ERROR_AFNOSUPPORT;

    struct pal_sock_grant req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.magic, "MVG1", 4);
    req.selector = 1;                       /* by name */
    req.endpoint = g_pal_svsm_net_endpoint;
    memcpy(req.name, g_pal_svsm_net_name, sizeof(req.name));

    /* -3 (STATUS_BAD_STATE) from a grant is "the target is being entered
     * or deleted - retry", not a refusal: the monitor needs the target's
     * entry lock to map the region into it, and a RESIDENT service holds
     * that lock every time the scheduler dispatches it. A service busy
     * serving is exactly when a new client turns up, so one look was
     * enough to lose roughly one connection in eight (PLAN.md phase 4).
     *
     * Bounded, and it gives the processor back between tries rather than
     * spinning through the window: the target has to RUN and finish its
     * dispatch for this to succeed. */
    uint64_t addr_out = 0;
    int64_t win = -1;

    /* ONE CHANNEL PER VAULT, not per connection - and the test for "already
     * have one" belongs BEFORE the grant, not after it.
     *
     * After it, every socket from the second onwards asked the monitor for a
     * channel, got one, and then jumped past the code that records it: 35
     * pages, two 2 MiB windows and a row in the VM-wide 64-entry region table
     * leaked per connect, which is the precise cost this step exists to stop
     * paying. */
    /* ONE GRANT AT A TIME, for the same reason. The grant retry below gives
     * the processor away, so a second thread's first connect could start
     * while this one's was still asking: both were granted, the second
     * overwrote the mux's window, and the first's sockets went on through a
     * channel where the service had never heard of their ids - and its own
     * channel leaked. So a connect that finds a grant in progress waits for
     * it and then looks for the channel again. */
    bool granting = PAL_MUX_SHARE_CHANNEL && g_pal_svsm_net_protocol;
    while (granting && g_mux_granting && !g_pal_svsm_mux_open)
        (void)sock_block(NULL, 0, NULL, 0, 200, /*interruptible=*/false);
    if (PAL_MUX_SHARE_CHANNEL && g_pal_svsm_net_protocol && g_pal_svsm_mux_open) {
        handle->sock.muxed = true;
        handle->sock.win   = 0;          /* the MUX owns the channel, not this */
        handle->sock.side  = g_pal_svsm_mux_side;
        /* The window each side ASSUMES before being told one, so a brand-new
         * connection's first frame needs no round trip (mvmux.h). */
        handle->sock.tx_limit = PAL_MUX_CREDIT_FLOOR;
        int cl = pal_svsm_mux_claim(handle, &handle->sock.conn_id);
        if (cl < 0)
            return cl;                   /* the table said no, not the monitor */
        goto have_channel;
    }

    if (granting)
        g_mux_granting = true;
    for (int try = 0; try < PAL_GRANT_TRIES; try++) {
        win = pal_svsm_channel_grant(&req, sizeof(req), &addr_out);
        if (win >= 0 || win != PAL_SVSM_STATUS_BAD_STATE)
            break;
        /* Nothing here announces the target's dispatch ending: the bound
         * alone, and the vault's other threads run meanwhile. */
        (void)sock_block(NULL, 0, NULL, 0, 200, /*interruptible=*/false);
    }
    /* Cleared here, and nothing below yields before g_pal_svsm_mux_open is
     * set (or this returns): PAL text is not preempted, so a waiter next
     * runs with the channel recorded, or free to ask for its own. */
    if (granting)
        g_mux_granting = false;
    if (win < 0) {
        /*
         * A POLICY refusal is not a connection failure, and an application
         * that cannot tell them apart cannot do the right thing about either.
         * `[[svsm.accept]] max` spent means this vault may not open another
         * channel on that endpoint however healthy the service is - retrying
         * will never help, and closing a socket will. EACCES says that;
         * ECONNRESET, which every refusal used to become, says the opposite.
         *
         * Only this one changes. The service being at `max_channels` stays
         * CONNFAILED: it is transient, a client that retries does get in when
         * another disconnects, and no PAL error maps to ECONNREFUSED - so
         * rather than invent an errno for it, the distinction is left in the
         * monitor's log and its status code, where the two are now visibly
         * different.
         *
         * Safe to surface at all because this is reached only after the
         * endpoint ADMITTED us: "nothing admits you" and "no such endpoint"
         * both still answer -2, identically, so a vault still cannot learn
         * who exists by asking (the `chan_denied_uniform` row).
         */
        if (win == PAL_SVSM_STATUS_PEER_QUOTA)
            return -PAL_ERROR_DENIED;
        return -PAL_ERROR_CONNFAILED;
    }

    /* Ours, not an arrival: `accept` must not hand this back to us. */
    sock_claim((unsigned)win);

    /* EVERY socket through a service is framed and carries a connection id.
     *
     * Framing is not the gated part - channel SHARING is. With sharing off
     * each socket owns a channel and is the only connection on it, which is
     * the shape stage 1 measured; with it on they share. Getting this wrong
     * once already cost an hour: when `muxed` was set only for the socket
     * that happened to open the channel, every LATER socket sent unframed
     * bytes to a service that was parsing frames, and `cm8` opened exactly
     * one connection of eight. */
    if (g_pal_svsm_net_protocol) {
        if (PAL_MUX_SHARE_CHANNEL) {
            /* THE MUX OWNS IT, not this socket - including the very socket
             * whose connect granted it.
             *
             * The first socket used to keep it (`win = addr_out`), and that
             * made the vault's net channel die with that one socket:
             * `sock_destroy` closes the channel of any handle whose `win` is
             * set. So the first close unmapped the window every LATER socket
             * was still reading through, and the next connect faulted on the
             * window's own address. Granted once, kept for the life of the
             * vault - a vault that connected once will connect again, and
             * handing the region back would mean a grant per burst - and
             * nothing but the vault's exit releases it. */
            g_pal_svsm_mux_win  = addr_out;
            g_pal_svsm_mux_widx = (unsigned long)win;
            g_pal_svsm_mux_side = 0;
            g_pal_svsm_mux_open = true;
            handle->sock.win      = 0;
            handle->sock.side     = 0;
            handle->sock.tx_limit = PAL_MUX_CREDIT_FLOOR;
        } else {
            handle->sock.win  = addr_out;
            handle->sock.widx = (unsigned long)win;
            handle->sock.side = 0;          /* we asked, so we are side 0 */
        }
        handle->sock.muxed = true;
        int cl = pal_svsm_mux_claim(handle, &handle->sock.conn_id);
        if (cl < 0)
            return cl;
    } else {
        handle->sock.win  = addr_out;
        handle->sock.widx = (unsigned long)win;
        handle->sock.side = 0;              /* we asked, so we are side 0 */
    }

have_channel:

    if (handle->sock.type == PAL_SOCKET_UDP && addr && addr->domain == PAL_IPV4) {
        memcpy(handle->sock.peer_addr, &addr->ipv4.addr, 4);
        handle->sock.peer_port = ntohs(addr->ipv4.port);
        handle->sock.has_peer  = true;
    }

    if (g_pal_svsm_net_protocol) {
        /* `muxed` and the connection id are set above, by whichever branch
         * granted or reused the channel. */
        uint8_t proto = handle->sock.type == PAL_SOCKET_UDP
                      ? PAL_MVNET_PROTO_UDP : PAL_MVNET_PROTO_TCP;
        struct pal_mvnet_rep rep;
        memset(&rep, 0, sizeof(rep));
        int rc = mvnet_handshake(handle, addr, proto, handle->sock.bind_port, &rep);
        if (rc == 0) {
            handle->sock.local.local_port = rep.local_port;
            memcpy(handle->sock.local.local_addr, rep.local_addr, 4);
        }
        if (rc < 0) {
            if (handle->sock.closed)
                return rc;               /* another thread's close let it all go */
            if (sock_shares(handle)) {
                /* The CONNECTION failed, not the channel: it is the vault's,
                 * other sockets may be on it already, and closing it would
                 * close window 0 (this handle's widx) and hand the shared
                 * window back to accept_find. Only the id goes. */
                pal_svsm_mux_release(handle->sock.conn_id);
                handle->sock.conn_id = 0;
                return rc;
            }
            pal_svsm_channel_close(handle->sock.widx);
            sock_unclaim((unsigned)handle->sock.widx);
            handle->sock.win = 0;
            return rc;
        }
    }

    /* The local address, which was all zeros and is load-bearing.
     *
     * An application learns its own address only from getsockname(), and the
     * LibOS answers that from what is reported here - so zeros meant family
     * AF_UNSPEC, and glibc's getaddrinfo for an UNSPECIFIED family dies on
     * `rfc3484_sort: assertion failed: a1->source_addr.sin6_family ==
     * PF_INET` while sorting candidate addresses. That is SIGABRT inside a
     * plain socket.create_connection(), which is what urllib does.
     *
     * The address is the SERVICE's, because the service is what puts the
     * packets on the wire; the vault has none of its own. A raw channel to
     * a peer vault still reports nothing, because for that there is no
     * address to report and nothing asks. */
    sock_report_local(handle, out_local_addr);
    if (out_inprogress)
        *out_inprogress = false;
    return 0;
}

static uint64_t iov_total(struct iovec* iov, size_t iov_len) {
    uint64_t total = 0;
    for (size_t i = 0; i < iov_len; i++)
        total += iov[i].iov_len;
    return total;
}

/* --- datagrams ---------------------------------------------------------
 *
 * A datagram socket shares the channel machinery and almost nothing else.
 * Its own send and recv are here rather than as branches inside the stream
 * ones because the stream code's whole subject is the thing a datagram does
 * not have: a residue worth keeping. A short read of a stream is ordinary
 * and the rest waits for the next call; a short read of a datagram
 * DISCARDS the rest, which is what recvfrom(2) means and the opposite of
 * what the stream path does with it.
 */

/* One datagram out, framed. The caller's iov is the payload; the header in
 * front of it says where it goes. */
static int udp_send(PAL_HANDLE handle, struct iovec* iov, size_t iov_len,
                    size_t* out_size, struct pal_socket_addr* addr,
                    bool force_nonblocking) {
    /* A sendto on a socket nobody connected still needs a channel. Opened
     * here, lazily, because there is nowhere earlier to do it: bind does
     * not reach the service and socket() does not know whether this will
     * ever be used. */
    if (!sock_has_chan(handle)) {
        int rc = _PalSocketConnect(handle, NULL, NULL, NULL);
        if (rc < 0)
            return rc;
    }

    struct pal_mvnet_dgram hdr;
    memset(&hdr, 0, sizeof(hdr));
    if (addr && addr->domain == PAL_IPV4) {
        memcpy(hdr.addr, &addr->ipv4.addr, 4);
        hdr.port = ntohs(addr->ipv4.port);
    } else if (handle->sock.has_peer) {
        memcpy(hdr.addr, handle->sock.peer_addr, 4);
        hdr.port = handle->sock.peer_port;
    } else {
        /* No address in the call and none from a connect: there is nowhere
         * to send it. send(2) answers EDESTADDRREQ for exactly this. */
        return -PAL_ERROR_INVAL;
    }

    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    if (!pal_chan_present(&out))
        return -PAL_ERROR_NOTSUPPORT;

    uint64_t payload = iov_total(iov, iov_len);
    /* The frame must fit ONE channel message, because a datagram that
     * arrived in two pieces would not be a datagram. Refused rather than
     * truncated: a silently shortened datagram is a corrupt one, and the
     * caller can only find out by not being answered. */
    /* The datagram header sits UNDER the frame header on a muxed channel, so
     * both come off the usable room. */
    uint64_t slotroom = mux_room(out.slot, handle->sock.muxed);
    uint64_t room = (slotroom > sizeof(hdr)) ? slotroom - sizeof(hdr) : 0;
    if (payload > PAL_MVNET_DGRAM_MAX || payload > room)
        return -PAL_ERROR_TOOLONG;

    char* buf = malloc(sizeof(hdr) + (payload ? payload : 1));
    if (!buf)
        return -PAL_ERROR_NOMEM;
    hdr.len = (uint16_t)payload;
    memcpy(buf, &hdr, sizeof(hdr));
    uint64_t off = 0;
    for (size_t i = 0; i < iov_len && off < payload; i++) {
        uint64_t take = iov[i].iov_len;
        if (take > payload - off)
            take = payload - off;
        memcpy(buf + sizeof(hdr) + off, iov[i].iov_base, take);
        off += take;
    }

    /* FRAMED on a muxed channel, exactly as a stream send is.
     *
     * This was written when a UDP socket owned its channel, and the mux
     * (which put an [mvmux_hdr] in front of every message on the shared
     * channel) framed the handshake and the stream path but not this one:
     * `mux_room` above was taught that the header exists and nothing ever
     * wrote it. So the relay read the first eight bytes of the DATAGRAM
     * header as a frame header - an op and a connection id that mean
     * nothing - and no datagram from a client vault reached lwIP at all.
     * Measured 2026-10-12 on jamie: with the vault's /etc/resolv.conf right
     * and off-subnet TCP through the same service working, a UDP sendto,
     * connected or not, put NOTHING on the tap, and getaddrinfo answered
     * EAI_AGAIN after 30 s. No lane row covered it: service_net_udp sends
     * from inside the service, which owns the NIC and has no mux. */
    struct pal_mvmux_hdr mh;
    memset(&mh, 0, sizeof mh);
    mh.conn = handle->sock.conn_id;
    mh.op   = PAL_MVMUX_OP_DATA;
    const void* fh = handle->sock.muxed ? &mh : NULL;
    uint32_t fhl = handle->sock.muxed ? PAL_MVMUX_HDR_BYTES : 0;

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    int ret = -PAL_ERROR_TRYAGAIN;
    for (;;) {
        /* Ended while this waited: another thread's read routed a reset, or
         * shut this socket's writing or closed it. */
        if (handle->sock.broken) {
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (sock_wr_over(handle)) {
            ret = -PAL_ERROR_CONNFAILED_PIPE;
            break;
        }
        /* The service's window, as in _PalSocketSend: a frame sent past it
         * has nowhere to go at the far end and blocks this vault's whole
         * link. The relay advertises credit for datagram sessions too
         * (udp_step), so a socket at its limit is waiting for a frame that
         * comes. */
        if (sock_shares(handle)
            && (int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) <= 0) {
            if (sock_chan_gone(handle)) {
                ret = -PAL_ERROR_CONNFAILED;
                break;
            }
            struct pal_chan_ring in;
            ring_for(handle, &in, NULL);
            /* COLLECT CREDIT THAT HAS ALREADY ARRIVED before answering
             * EAGAIN. The floor is ONE frame (PAL_MUX_CREDIT_FLOOR), and the
             * service's first CREDIT goes out right behind its CONNECT reply -
             * but a frame in the ring is only seen when somebody routes the
             * head, and a resolver sends A and then AAAA without reading in
             * between. So the second send found the window spent with the
             * credit sitting unread, a non-blocking socket said EAGAIN, and
             * glibc abandoned the socket and every retry the same way:
             * getaddrinfo(AF_UNSPEC) failed in 12 ms with both answers on the
             * tap. Measured on jamie 2026-10-12. */
            mux_poll_route(handle, &in);
            if ((int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) > 0)
                continue;
            if (nonblock)
                break;
            uint32_t seen = *in.peer_tail;
            uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
            int wr = sock_block(handle, PAL_SVSM_WAIT_CREDIT, &arm, 1, PAL_SOCK_PARK_US,
                                /*interruptible=*/true);
            if (wr < 0) {
                ret = wr;
                break;
            }
            if (sock_wr_over(handle))
                continue;                    /* the loop's top says EPIPE */
            ring_for(handle, &in, &out);
            mux_poll_route(handle, &in);     /* which is what collects it */
            continue;
        }
        if (pal_chan_send2(&out, fh, fhl, buf, (uint32_t)(sizeof(hdr) + payload)) == 0) {
            pal_svsm_channel_notify(sock_widx(handle));
            if (sock_shares(handle))
                handle->sock.tx_sent++;
            /* The PAYLOAD, not the frame: the caller sent a datagram, not
             * a header. */
            *out_size = payload;
            ret = 0;
            break;
        }
        if (sock_chan_gone(handle)) {
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (nonblock)
            break;
        for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_writable(&out); i++)
            __asm__ volatile("pause");
        if (pal_chan_writable(&out))
            continue;
        uint32_t seen = *out.peer_head;
        uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_HEAD, seen);
        int wr = sock_block(handle, PAL_WAIT_WRITE, &arm, 1, PAL_SOCK_PARK_US,
                            /*interruptible=*/true);
        if (wr < 0) {
            ret = wr;
            break;
        }
        if (sock_wr_over(handle))
            continue;                        /* the loop's top says EPIPE */
        ring_for(handle, NULL, &out);
    }
    free(buf);
    return ret;
}

/* One datagram in, with the address it came from. */
static int udp_recv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len,
                    size_t* out_total_size, struct pal_socket_addr* addr,
                    bool force_nonblocking) {
    if (!sock_has_chan(handle))
        return -PAL_ERROR_NOTCONNECTION;

    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    if (!pal_chan_present(&in))
        return -PAL_ERROR_NOTSUPPORT;

    if (!handle->sock.rx) {
        int arc = mux_rx_own(handle, in.slot);
        if (arc < 0)
            return arc;
    }

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t room = iov_total(iov, iov_len);

    for (;;) {
        bool was_full = pal_chan_present(&in)
                        && (uint32_t)(*in.peer_tail - *in.head) >= in.depth;
        uint32_t got = 0;
        int rc = -1;
        bool head_blocked = false;
        /* DEMULTIPLEXED on a shared channel, for the reason udp_send frames:
         * the head may be any of this vault's sockets' traffic, and a frame
         * for THIS socket may already have been parked in `rx` or its queue
         * by another socket's read. So the same three steps _PalSocketRecv
         * takes - serve what is parked, route the head, read only what is
         * ours - and then the body starts after the frame header rather than
         * at 0. Reading the shared ring directly, as this did, would also
         * have taken other sockets' frames as datagrams. */
        if (handle->sock.muxed) {
            if (handle->sock.rx_off >= handle->sock.rx_len)
                mux_rx_refill(handle);
            if (handle->sock.rx_off < handle->sock.rx_len) {
                rc = 0;                     /* parked: body at rx + rx_off */
            } else {
                enum mux_head mh = mux_head_step(handle, &in, was_full);
                if (mh == MUX_HEAD_NOMEM)
                    return -PAL_ERROR_NOMEM;
                if (mh == MUX_HEAD_MOVED) {
                    /* Possibly our own FIN: the service reaped this datagram
                     * session (RELAY_UDP_IDLE_US) or is gone. A datagram
                     * socket has no end of stream to report, so it fails. */
                    if (handle->sock.broken || handle->sock.fin_seen)
                        return -PAL_ERROR_CONNFAILED;
                    continue;
                }
                head_blocked = mh == MUX_HEAD_BLOCKED;
                if (mh != MUX_HEAD_BLOCKED) {
                    rc = mux_recv_mine(handle, &in, mh, handle->sock.rx, in.slot, &got);
                    if (rc == 0) {
                        if (was_full)
                            pal_svsm_channel_notify(sock_widx(handle));
                        if (got < PAL_MVMUX_HDR_BYTES) {
                            handle->sock.broken = true;
                            return -PAL_ERROR_CONNFAILED;
                        }
                        struct pal_mvmux_hdr oh;
                        memcpy(&oh, handle->sock.rx, PAL_MVMUX_HDR_BYTES);
                        if (oh.op == PAL_MVMUX_OP_FIN || oh.op == PAL_MVMUX_OP_RST) {
                            handle->sock.rx_len = handle->sock.rx_off = 0;
                            if (oh.op == PAL_MVMUX_OP_FIN)
                                handle->sock.fin_seen = true;
                            else
                                handle->sock.broken = true;
                            return -PAL_ERROR_CONNFAILED;
                        }
                        handle->sock.rx_len = got;
                        handle->sock.rx_off = PAL_MVMUX_HDR_BYTES;
                    }
                }
            }
        } else {
            rc = pal_chan_recv(&in, handle->sock.rx, in.slot, &got);
            if (rc == 0) {
                if (was_full)
                    pal_svsm_channel_notify(sock_widx(handle));
                handle->sock.rx_len = got;
                handle->sock.rx_off = 0;
            }
        }
        if (rc == 0) {
            const char* body = handle->sock.rx + handle->sock.rx_off;
            uint64_t blen = handle->sock.rx_len - handle->sock.rx_off;
            struct pal_mvnet_dgram hdr;
            if (blen < sizeof(hdr)) {
                handle->sock.broken = true;
                return -PAL_ERROR_CONNFAILED;
            }
            memcpy(&hdr, body, sizeof(hdr));
            if (hdr.len > blen - sizeof(hdr)) {
                /* The frame claims more than arrived. Not recoverable: the
                 * next message would be read as a header. */
                handle->sock.broken = true;
                return -PAL_ERROR_CONNFAILED;
            }
            if (addr) {
                memset(addr, 0, sizeof(*addr));
                addr->domain = PAL_IPV4;
                memcpy(&addr->ipv4.addr, hdr.addr, 4);
                addr->ipv4.port = htons(hdr.port);
            }
            uint64_t have = hdr.len;
            uint64_t off = 0;
            for (size_t i = 0; i < iov_len && off < have && off < room; i++) {
                uint64_t take = iov[i].iov_len;
                if (take > have - off)
                    take = have - off;
                memcpy(iov[i].iov_base, body + sizeof(hdr) + off, take);
                off += take;
            }
            /* What did not fit is GONE, and that is not a bug: a datagram
             * read into too small a buffer is truncated, and the remainder
             * is not the next datagram's business. The stream path keeps a
             * residue here; this must not.
             *
             * Except the rest of a BATCH: the next datagram in the same frame
             * is a datagram of its own, so `rx_off` moves to it and the frame
             * stays parked in `rx` - readable, and FIONREAD sees the next
             * record's length - until its last record is read. */
            uint64_t next = handle->sock.rx_off + sizeof(hdr) + hdr.len;
            bool batch = handle->sock.muxed && handle->sock.rx_len >= PAL_MVMUX_HDR_BYTES
                         && (((const struct pal_mvmux_hdr*)handle->sock.rx)->flags
                             & PAL_MVMUX_DATA_DGRAMS);
            if (handle->sock.muxed)
                PAL_SVSM_NET_CTR_INC(dgrams);
            if (batch && next + sizeof(hdr) <= handle->sock.rx_len) {
                handle->sock.rx_off = next;
            } else {
                handle->sock.rx_len = handle->sock.rx_off = 0;
                if (handle->sock.muxed) {
                    /* One frame finished, which is what earns the service more
                     * window - the same accounting as _PalSocketRecv. */
                    PAL_SVSM_NET_CTR_INC(dgram_frames);
                    handle->sock.rx_done++;
                    mux_credit_maybe(handle);
                }
#line 1912
            }
            *out_total_size = off;
            return 0;
        }
        if (rc == -2) {
            handle->sock.broken = true;
            return -PAL_ERROR_CONNFAILED;
        }
        if (sock_chan_gone(handle)) {
            /* The service is gone. For a datagram socket there is no "end
             * of stream" to report, so this is an error rather than a 0. */
            return -PAL_ERROR_CONNFAILED;
        }
        /* AN OWED CREDIT GOES OUT before a non-blocking reader is told
         * there is nothing: nothing will come until it does. A credit is
         * owed when the outbound ring was full as it fell due; the blocking
         * waits below send it (mux_credit_settle) and so does poll's
         * readable test, but a reader that spins on MSG_DONTWAIT without
         * poll (nbench's udp_down/udp_rr/tcp_rr loops) never got there, and
         * the service - which sends only within the window - stopped for
         * good. */
        if (nonblock) {
            if (mux_credit_owed(handle))
                mux_credit_maybe(handle);
            return -PAL_ERROR_TRYAGAIN;
        }
#line 1927

        /* Somebody else's frame at the head: wait at once, as the stream
         * path does (_PalSocketRecv) - the ring is readable and will stay so
         * until its owner runs. */
        if (!head_blocked) {
            for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_readable(&in); i++)
                __asm__ volatile("pause");
            if (pal_chan_readable(&in))
                continue;
        }
        uint32_t seen = *in.peer_tail;
        if (!head_blocked && seen != *in.head)
            continue;
        uint64_t arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
        int wr = sock_block(handle, PAL_WAIT_READ, &arm, 1, PAL_SOCK_PARK_US,
                            /*interruptible=*/true);
        if (wr < 0)
            return wr;
        if (sock_rd_over(handle)) {
            /* Shut or closed under it. No datagram, so no sender either:
             * the address must still say so (PAL_DISCONNECT, AF_UNSPEC to
             * the LibOS), or ip.c converts whatever the stack held. */
            if (addr)
                memset(addr, 0, sizeof(*addr));
            *out_total_size = 0;
            return 0;
        }
        ring_for(handle, &in, NULL);
        /* Our FIN or reset, routed by the scheduler's look at this socket
         * while it waited (mux_poll_route): the session is over, as above,
         * once nothing parked for it is left. */
        if ((handle->sock.broken || handle->sock.fin_seen)
            && handle->sock.rx_off >= handle->sock.rx_len && !handle->sock.q_count)
            return -PAL_ERROR_CONNFAILED;
    }
}

int _PalSocketSend(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.type == PAL_SOCKET_UDP)
        return udp_send(handle, iov, iov_len, out_size, addr, force_nonblocking);
    __UNUSED(addr);
    if (!sock_has_chan(handle))
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.broken)
        return -PAL_ERROR_CONNFAILED;
    if (g_fin_owed_n && sock_shares(handle))
        mux_fin_flush();

    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    if (!pal_chan_present(&out))
        return -PAL_ERROR_NOTSUPPORT;

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t total = iov_total(iov, iov_len);
    /* The body's room, which is 8 bytes smaller on a muxed channel. The
     * service's RELAY_CHUNK tracks this number; if the two ever disagree a
     * full-slot load goes as a full chunk plus a tiny tail - two messages,
     * two dispatches - which is how four bytes once halved this path. */
    uint64_t room = mux_room(out.slot, handle->sock.muxed);
    if (total > room)
        total = room;                       /* one message per call, like a datagram */

    /*
     * ONE iovec needs no gather buffer, and that is the whole of this path.
     *
     * The gather was unconditional: malloc(total), memcpy into it,
     * pal_chan_send from it, free. For a stream socket `total` is clamped to
     * `out.slot - 4` just above, which for this service's geometry was 16,380
     * (65,532 since the 64 KiB slots, further still from the slab) -
     * and the PAL slab's top level is 8288 - SLAB_HDR_SIZE = 8,272 B
     * (common/include/slabmgr.h:86-98). So every full-slot send missed the
     * slab, fell to LARGE_MEM_OBJ -> system_malloc (slabmgr.h:306-322), and
     * cost a page-granular MMAP on the way in and a MUNMAP on the way out -
     * two MONITOR CALLS per send that nothing in the tree accounted for. At
     * the 11.2 us anchor and 65 sends per MiB (then) that is ~1,456 us per MiB spent
     * on allocating a buffer whose only job was to be copied out of again.
     *
     * send(2), sendto(2) and write(2) all arrive here with iov_len == 1
     * (libos_socket.c:771-776 builds a one-element iovec and net/ip.c:750
     * passes it through), so the fast path covers the ordinary case and the
     * gather stays for writev(2), sendmsg(2) and sendmmsg(2), which pass the
     * application's own iovlen. UDP never reaches here - udp_send returned
     * above - so there is no datagram header to prepend.
     *
     * Passing the caller's buffer to pal_chan_send is not a new exposure: the
     * gather copied from the same application memory a moment earlier, and
     * pal_chan_send copies out of it into the ring either way. What goes away
     * is one copy and one mmap/munmap pair.
     */
    char* buf = NULL;
    const void* msg;
    if (iov_len == 1 && total) {
        msg = iov[0].iov_base;
    } else {
        /* A stream socket may send less than it was given, and the LibOS
         * handles the short write. */
        buf = malloc(total ? total : 1);
        if (!buf)
            return -PAL_ERROR_NOMEM;
        uint64_t off = 0;
        for (size_t i = 0; i < iov_len && off < total; i++) {
            uint64_t take = iov[i].iov_len;
            if (take > total - off)
                take = total - off;
            memcpy(buf + off, iov[i].iov_base, take);
            off += take;
        }
        msg = buf;
    }

    struct pal_mvmux_hdr mh;
    memset(&mh, 0, sizeof mh);
    mh.conn = handle->sock.conn_id;
    mh.op   = PAL_MVMUX_OP_DATA;
    const void* fh = handle->sock.muxed ? &mh : NULL;
    uint32_t fhl = handle->sock.muxed ? PAL_MVMUX_HDR_BYTES : 0;

    int ret = -PAL_ERROR_TRYAGAIN;
    for (;;) {
        /* Ended while this waited: another thread's read routed a reset, or
         * shut this socket's writing or closed it. */
        if (handle->sock.broken) {
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (sock_wr_over(handle)) {
            ret = -PAL_ERROR_CONNFAILED_PIPE;
            break;
        }
        /* THE SERVICE'S WINDOW, before the ring's.
         *
         * A ring that is not full says only that the CHANNEL has room; it says
         * nothing about whether the service has anywhere to put another frame
         * for THIS connection. Sending past the window is what would leave a
         * frame stuck at the head with nowhere to go, which is the head-of-line
         * blocking the window exists to prevent - so a socket at its limit
         * waits here, and every other socket on the channel keeps running.
         *
         * Only for a sharing socket: one that owns its channel is the only
         * connection on it, so the ring's own fullness is the whole truth. */
        if (sock_shares(handle)
            && (int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) <= 0) {
            if (sock_chan_gone(handle)) {
                ret = -PAL_ERROR_CONNFAILED;
                break;
            }
            /* COLLECT CREDIT THAT HAS ALREADY ARRIVED before answering
             * EAGAIN, as udp_send does. The floor is ONE frame and the
             * service's CREDIT comes back as a message on the inbound ring,
             * counted only once somebody routes it - and a non-blocking
             * writer that sends twice before it reads (a client's header,
             * then its request) never does: its second send said EAGAIN for
             * ever with the credit sitting unread. nbench's tcp_rr and
             * tcp_up from a vault (jamie, 2026-10-23: 0 transactions, ~48M
             * EAGAIN, 0 bytes acked). A blocking send routes after its wait
             * below, and poll's writability test (sock_no_credit) routes
             * first, so neither was affected. */
            if (nonblock) {
                struct pal_chan_ring cin;
                ring_for(handle, &cin, NULL);
                mux_poll_route(handle, &cin);
                if ((int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) > 0)
                    continue;                /* it had arrived: send */
                PAL_SVSM_NET_CTR_INC(eagain_credit);
                break;
            }
#line 2081
            /* Room is a CREDIT frame arriving, which arrives as a message like
             * any other - so wait on the peer's tail, and let the read path
             * route it. */
            struct pal_chan_ring in;
            ring_for(handle, &in, NULL);
            uint32_t seen = *in.peer_tail;
            uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
            int wr = sock_block(handle, PAL_SVSM_WAIT_CREDIT, &arm, 1, PAL_SOCK_PARK_US,
                                /*interruptible=*/true);
            if (wr < 0) {
                ret = wr;
                break;
            }
            if (sock_wr_over(handle))
                continue;                    /* the loop's top says EPIPE */
            ring_for(handle, &in, &out);
            mux_poll_route(handle, &in);     /* which is what collects it */
            continue;
        }

        /* Header and body in one message, without building a combined buffer:
         * that buffer was a slot-sized malloc (16,380 bytes then) that missed the PAL slab and
         * cost an mmap and a munmap through the monitor on every send. */
        if (pal_chan_send2(&out, fh, fhl, msg, (uint32_t)total) == 0) {
            /* The peer may be parked on this index; the monitor turns that
             * into one dispatch however many messages went in. */
            pal_svsm_channel_notify(sock_widx(handle));
            if (sock_shares(handle))
                handle->sock.tx_sent++;
            PAL_SVSM_NET_CTR_INC(sends);
            /* The ring took a frame, so it may take this socket's owed
             * credit too - the reader would otherwise send it only when
             * it next waits. */
            if (handle->sock.credit_owed)
                mux_credit_maybe(handle);
            *out_size = total;
            ret = 0;
            break;
        }
        if (sock_chan_gone(handle)) {
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (nonblock) {
            PAL_SVSM_NET_CTR_INC(eagain_ring);
            break;
        }

        for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_writable(&out); i++)
            __asm__ volatile("pause");
        if (pal_chan_writable(&out))
            continue;
        /* Room is the peer's HEAD moving. */
        uint32_t seen = *out.peer_head;
        uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_HEAD, seen);
        int wr = sock_block(handle, PAL_WAIT_WRITE, &arm, 1, PAL_SOCK_PARK_US,
                            /*interruptible=*/true);
        if (wr < 0) {
            ret = wr;
            break;
        }
        if (sock_wr_over(handle))
            continue;                        /* the loop's top says EPIPE */
        ring_for(handle, NULL, &out);
    }
    free(buf);
    return ret;
}

int _PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.broken)
        return -PAL_ERROR_CONNFAILED;
    if (handle->sock.type == PAL_SOCKET_UDP)
        return udp_recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
    /* A FIN already seen, and nothing left in the residue, is end of stream -
     * on EVERY later call, not just the one that saw it. Checked before the
     * ring, because the ring may well have another connection's traffic in it
     * and a blocking read here would otherwise wait on data that is not
     * coming. */
    if (handle->sock.fin_seen && handle->sock.rx_off >= handle->sock.rx_len
        && !handle->sock.q_count) {
        /* A FIN costs no queue room, so it can arrive while frames are still
         * queued behind `rx`. Those are data the caller has not had yet and
         * reporting end of stream over them would lose them. */
        *out_total_size = 0;
        return 0;
    }
    if (!sock_has_chan(handle))
        return -PAL_ERROR_NOTCONNECTION;
    if (addr)
        memset(addr, 0, sizeof(*addr));

    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    if (!pal_chan_present(&in))
        return -PAL_ERROR_NOTSUPPORT;
    if (g_fin_owed_n && sock_shares(handle))
        mux_fin_flush();

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t room = iov_total(iov, iov_len);

    /* The residue buffer. A channel carries MESSAGES; a stream socket is
     * read in whatever pieces the program chose, and those are not the
     * same size. The whole message comes out of the ring in one go - so
     * the ring stays safe for the several holders a fork makes, and the
     * head advances immediately - and what the caller could not take
     * waits in the handle for its next read.
     *
     * Before this, a read smaller than a message was answered with the
     * SAME -2 as a malformed length, and `broken` then made every later
     * call on the handle fail with EACCES. Any ordinary program that
     * reads in 512-byte pieces, or peeks a byte, was dead on its first
     * read. */
    if (!handle->sock.rx) {
        int arc = mux_rx_own(handle, in.slot);
        if (arc < 0)
            return arc;
    }

    int ret;
    for (;;) {
        bool head_blocked = false;
        /* Serve what is already here first - `rx`, then the queue behind it. */
        if (handle->sock.rx_off >= handle->sock.rx_len)
            mux_rx_refill(handle);
        if (handle->sock.rx_off < handle->sock.rx_len) {
            uint64_t have = handle->sock.rx_len - handle->sock.rx_off;
            uint64_t off = 0;
            for (size_t i = 0; i < iov_len && off < have && off < room; i++) {
                uint64_t take = iov[i].iov_len;
                if (take > have - off)
                    take = have - off;
                memcpy(iov[i].iov_base, handle->sock.rx + handle->sock.rx_off + off, take);
                off += take;
            }
            handle->sock.rx_off += (uint32_t)off;
            if (handle->sock.rx_off >= handle->sock.rx_len) {
                handle->sock.rx_len = handle->sock.rx_off = 0;
                /* One frame FINISHED, which is what earns the service more
                 * window - not one frame received, or the limit would promise
                 * room that is still occupied. */
                handle->sock.rx_done++;
                mux_credit_maybe(handle);
            }
            *out_total_size = off;
            return 0;
        }

        uint32_t got = 0;
        /* Was the ring FULL before this read? If it was, a writer may be
         * unable to write, and freeing this slot is the only thing that
         * will ever change that - so it has to be announced.
         *
         * _PalSocketSend notifies the peer on every successful send, and
         * its blocking branch arms on PAL_CHAN_ARM_HEAD ("Room is the
         * peer's HEAD moving"), so a writer waiting for room is MEANT to
         * be woken when the head moves. Nothing fired that notify: recv
         * advanced the head and told nobody. A BLOCKING writer survived
         * anyway, because it armed on the word itself and the monitor ends
         * a park when the armed word changes. A NON-BLOCKING writer never
         * arms, so it got no wake at all and had to wait for its next
         * ordinary dispatch.
         *
         * That is the whole cost of a relay that sends with MSG_DONTWAIT:
         * measured on a 1 MiB download, the channel (4 slots, ~8 KB) was
         * refilled about every 95 ms, for ~70 KB/s, while the same path
         * with a blocking send ran at ~6 MB/s. Not chunking, not the
         * window, not the ACK timer - the reader simply never said that
         * it had made room.
         *
         * Only on the full -> not-full edge. A notify is a monitor call,
         * and one per message would put a VMGEXIT on every 2044 bytes;
         * one per ring-full episode is what a blocked writer needs and
         * nothing more. */
        bool was_full = pal_chan_present(&in)
                        && (uint32_t)(*in.peer_tail - *in.head) >= in.depth;

        /* DEMULTIPLEX, when the channel is shared: the head may belong to any
         * of this vault's sockets, so it is PEEKED before it is consumed. See
         * mux_head_step, which the handshake shares. */
        enum mux_head mh = mux_head_step(handle, &in, was_full);
        if (mh == MUX_HEAD_NOMEM)
            return -PAL_ERROR_NOMEM;
        if (mh == MUX_HEAD_MOVED) {
            /* It may have been OUR end of stream, which the step consumes so a
             * poller can see it (see there). Nothing is buffered at this point
             * by construction - the loop only reaches here with the residue
             * empty - so this is the end. */
            if (handle->sock.broken)
                return -PAL_ERROR_CONNFAILED;
            if (handle->sock.fin_seen) {
                *out_total_size = 0;
                return 0;
            }
            continue;                   /* look at the next message */
        }
        if (mh == MUX_HEAD_BLOCKED)
            goto mux_blocked;

        int rc = mux_recv_mine(handle, &in, mh, handle->sock.rx, in.slot, &got);
        if (rc == 0) {
            if (was_full)
                pal_svsm_channel_notify(sock_widx(handle));
            handle->sock.rx_len = got;
            handle->sock.rx_off = 0;
            if (handle->sock.muxed) {
                /* Strip the frame. A short message cannot be one, and the
                 * stream has no way to resynchronise inside a ring of whole
                 * messages, so it is the same "the stream is over" the
                 * malformed-length arm below reports rather than a skip. */
                if (got < PAL_MVMUX_HDR_BYTES) {
                    handle->sock.broken = true;
                    return -PAL_ERROR_CONNFAILED;
                }
                /* WHICH control frame, because dropping them all made a
                 * FIN for THIS socket indistinguishable from an empty
                 * message: a blocking reader then waited for data the
                 * service had already said would never come. (The demux
                 * arm above always read the op; this path never did,
                 * because before sharing the service announced an end by
                 * closing the channel and `pal_chan_peer_gone` answered
                 * it. A shared channel outlives the connection.) */
                struct pal_mvmux_hdr oh;
                memcpy(&oh, handle->sock.rx, PAL_MVMUX_HDR_BYTES);
                if (oh.op == PAL_MVMUX_OP_FIN || oh.op == PAL_MVMUX_OP_RST) {
                    handle->sock.rx_len = handle->sock.rx_off = 0;
                    if (oh.op == PAL_MVMUX_OP_FIN) {
                        handle->sock.fin_seen = true;
                        *out_total_size = 0;
                        return 0;
                    }
                    handle->sock.broken = true;
                    return -PAL_ERROR_CONNFAILED;
                }
                handle->sock.rx_off = PAL_MVMUX_HDR_BYTES;
                if (handle->sock.rx_off >= handle->sock.rx_len) {
                    /* A DATA frame with no body. Nothing for this caller;
                     * go round for the next message. */
                    handle->sock.rx_len = handle->sock.rx_off = 0;
                    handle->sock.rx_done++;
                    mux_credit_maybe(handle);
                    continue;
                }
            }
            continue;                   /* serve it from the buffer above */
        }
        if (0) {
mux_blocked:
            /* The head is another socket's and that socket is not reading.
             * Nothing can move until it does, so this behaves exactly as an
             * empty ring does: a non-blocking caller is told to try again, a
             * blocking one waits. */
            rc = -1;
            head_blocked = true;
        }
        if (rc == -2) {
            /* A length that cannot be right - not "your buffer is small",
             * which is now impossible here because the whole slot is
             * always offered. The head is not advanced, so nothing is
             * silently skipped; the stream is over. */
            handle->sock.broken = true;
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (sock_chan_gone(handle)) {
            *out_total_size = 0;            /* end of stream, as recv(2) has it */
            ret = 0;
            break;
        }
        /* AN OWED CREDIT GOES OUT before a non-blocking reader is told
         * there is nothing: nothing will come until it does. A credit is
         * owed when the outbound ring was full as it fell due; the blocking
         * waits below send it (mux_credit_settle) and so does poll's
         * readable test, but a reader that spins on MSG_DONTWAIT without
         * poll (nbench's udp_down/udp_rr/tcp_rr loops) never got there, and
         * the service - which sends only within the window - stopped for
         * good. */
        if (nonblock) {
            if (mux_credit_owed(handle))
                mux_credit_maybe(handle);
            ret = -PAL_ERROR_TRYAGAIN;
            break;
        }
#line 2358

        /* A head that is somebody else's - their handshake reply, or a frame
         * with no pool buffer to go to - is a ring that IS readable and has
         * nothing for this socket: looking again at once, as for an empty
         * ring that has just filled, would spin here for ever without
         * letting the thread that owns the head run. So it waits at once,
         * on the tail as it is now, and the predicate (false until the head
         * moves) is what lets it go. */
        if (!head_blocked) {
            for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_readable(&in); i++)
                __asm__ volatile("pause");
            if (pal_chan_readable(&in))
                continue;
        }
        uint32_t seen = *in.peer_tail;
        if (!head_blocked && seen != *in.head)
            continue;                        /* it moved while we looked */
        uint64_t arms[2];
        arms[0] = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
        /* An owed credit first: until it is out nothing will arrive. */
        uint64_t n_arms = 1 + mux_credit_settle(handle, &arms[1]);
        int wr = sock_block(handle, PAL_WAIT_READ, arms, n_arms, PAL_SOCK_PARK_US,
                            /*interruptible=*/true);
        if (wr < 0) {
            ret = wr;
            break;
        }
        /* Shut down or closed by another thread: end of stream, which is
         * what a reader parked across shutdown(SHUT_RD or SHUT_RDWR) gets on
         * Linux - and the usual way to stop one. */
        if (sock_rd_over(handle)) {
            *out_total_size = 0;
            ret = 0;
            break;
        }
        ring_for(handle, &in, NULL);
        /* What the wait may have brought without this thread reading: the
         * scheduler's look at this socket routes the shared head, and a FIN
         * or reset it finds is consumed there (mux_poll_route) - the ring
         * may now be empty with the end of the stream already recorded. */
        if (handle->sock.broken) {
            ret = -PAL_ERROR_CONNFAILED;
            break;
        }
        if (handle->sock.fin_seen && handle->sock.rx_off >= handle->sock.rx_len
            && !handle->sock.q_count) {
            *out_total_size = 0;
            ret = 0;
            break;
        }
    }
    return ret;
}

/* The ring word that would make this socket ready for `want`, for a
 * thread that is about to give the processor back.
 *
 * This is the difference between a vault that wakes when its peer sends
 * and one that wakes when its poll timeout expires. The baseline is what
 * THIS side last saw, not what the word says now: if the peer wrote
 * between the poll and the park, the word already differs and the
 * monitor ends the park before it begins, rather than waiting for a
 * write that has already happened.
 *
 * Returns the number of arms written (0 or 1). A socket with residue
 * already buffered writes none and reports itself ready instead.
 */
int pal_svsm_sock_arm(PAL_HANDLE handle, pal_wait_flags_t want, uint64_t* out_arm) {
    if (handle->hdr.type != PAL_TYPE_SOCKET || !sock_has_chan(handle))
        return 0;   /* nothing to arm: a channel-less socket has no rings */
    struct pal_chan_ring in, out;
    ring_for(handle, &in, &out);
    if ((want & PAL_WAIT_READ) && !pal_svsm_sock_readable(handle)) {
        /* An owed credit that still cannot be sent: wait for ROOM, then the
         * poll looks again and this sends it (mux_credit_settle). */
        if (mux_credit_settle(handle, out_arm))
            return 1;
        *out_arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, *in.peer_tail);
        return 1;
    }
    if ((want & PAL_WAIT_WRITE) && !pal_svsm_sock_writable(handle)) {
        /* A shared socket waiting for WINDOW waits for a CREDIT frame,
         * which arrives on the inbound ring - arming on the outbound head
         * would sleep through it. (writable has just routed, so the count
         * is current.) */
        if (sock_shares(handle)
            && (int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) <= 0) {
            *out_arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, *in.peer_tail);
            return 1;
        }
        *out_arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_HEAD, *out.peer_head);
        return 1;
    }
    return 0;
}

/* Has the other end of this socket's channel gone?
 *
 * Exported for the poll path, which is in another translation unit and has no
 * business knowing about rings - the pipe case next to it reaches its peer
 * through pal_svsm_pipe_peer_gone for the same reason. */
/* How many messages a QUESTION about a socket may push along. The ring's depth
 * is 4, so this cannot bind in practice; it is here because a loop that
 * consumes from shared memory must terminate on its own terms. */
#define PAL_MUX_POLL_STEPS 16

/* Push the shared channel's head along so a question about THIS socket sees
 * what has actually arrived for it.
 *
 * Nothing a reader wants is consumed: `mux_head_step` leaves a data frame
 * addressed to this handle exactly where it is. What it does take is another
 * socket's message - parked in that socket's own buffer - and this socket's
 * control frames. Both are necessary for a poll to mean anything on a shared
 * channel: without the first, a socket's data sitting behind an idle peer's
 * frame is invisible to every question anyone can ask; without the second, the
 * end of a stream is a fact that only comes into existence when someone reads
 * it, which is no use to the caller asking whether to read at all.
 *
 * True means this socket has something now. False means it does not, and says
 * nothing about why. */
static bool mux_poll_route(PAL_HANDLE handle, struct pal_chan_ring* in) {
    if (!sock_shares(handle))
        return false;
    for (int i = 0; i < PAL_MUX_POLL_STEPS; i++) {
        enum mux_head mh = mux_head_step(handle, in, /*was_full=*/false);
        if (mh == MUX_HEAD_MINE)
            return true;                 /* its own data is at the head */
        if (mh != MUX_HEAD_MOVED)
            return false;                /* EMPTY, BLOCKED or NOMEM */
        if (handle->sock.fin_seen || handle->sock.broken
            || handle->sock.rx_off < handle->sock.rx_len)
            return true;
    }
    return false;
}

bool pal_svsm_sock_peer_gone(PAL_HANDLE handle) {
    if (handle->hdr.type != PAL_TYPE_SOCKET || !sock_has_chan(handle))
        return false;
    /* A FIN frame is this connection's hang-up. Without this a server that
     * speaks and closes left poll() reporting nothing at all on a SHARED
     * channel - the channel is still very much alive - which is the same
     * five-second stall the unshared case had before STACK_PEER_CLOSED was
     * handled in the relay, arriving by a different route.
     *
     * And the frame has to be LOOKED FOR, not just remembered: it arrives in
     * the ring, and asking "have I seen one" of a poller that has never read
     * answers no for ever. `sock_poll_hup` measured exactly that - POLLIN for
     * five seconds with the FIN at the head of the ring. */
    if (handle->sock.fin_seen)
        return true;
    if (sock_shares(handle)) {
        struct pal_chan_ring in;
        ring_for(handle, &in, NULL);
        mux_poll_route(handle, &in);
        if (handle->sock.fin_seen)
            return true;
    }
    return sock_chan_gone(handle);
}

bool pal_svsm_sock_readable(PAL_HANDLE handle) {
    if (!sock_has_chan(handle))
        return false;
    /* What a previous read could not take is readable too, or a poll
     * after a short read says "nothing here" with bytes in hand. */
    if (handle->sock.rx_off < handle->sock.rx_len || handle->sock.q_count)
        return true;
    if (handle->sock.fin_seen)
        return true;                /* readable, and the read returns 0 */
    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    if (sock_shares(handle)) {
        if (mux_poll_route(handle, &in))
            return true;
        /* Not readable, and perhaps only because a credit is owed: every
         * re-test of a waiting poller is a chance to send it - and any FIN
         * a close could not send. */
        if (mux_credit_owed(handle))
            mux_credit_maybe(handle);
        if (g_fin_owed_n)
            mux_fin_flush();
        /* The head is not this socket's, so there is nothing here it could
         * read - `pal_chan_readable` would say yes about somebody else's
         * message and the read that followed would answer EAGAIN. */
        return sock_chan_gone(handle);
    }
    return pal_chan_readable(&in) || sock_chan_gone(handle);
}

/* Has a sharing socket used up the service's window (MVMUX_OP_CREDIT)? A
 * CREDIT frame is a message on the inbound ring, so the shared head is routed
 * first - as a send does after its own wait - or a credit that has arrived
 * would be counted as one that has not. */
static bool sock_no_credit(PAL_HANDLE handle) {
    if (!sock_shares(handle) || (int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) > 0)
        return false;
    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    mux_poll_route(handle, &in);
    return (int32_t)(handle->sock.tx_limit - handle->sock.tx_sent) <= 0;
}

/* Room in the outbound ring for one more message, credit or not. What a
 * blocked send waits for once it has its credit, and all a FIN or a connect
 * request needs: neither spends any. */
static bool sock_ring_room(PAL_HANDLE handle) {
    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    return pal_chan_writable(&out);
}

bool pal_svsm_sock_writable(PAL_HANDLE handle) {
    if (!sock_has_chan(handle)) {
        /* A datagram socket with no channel yet IS writable: the first
         * send opens one (udp_send). Saying otherwise is not a cautious
         * answer, it is a wrong one, and it deadlocks the ordinary case -
         * CPython polls for writability BEFORE calling send, so a plain
         *
         *     s = socket(AF_INET, SOCK_DGRAM); s.sendto(q, (ns, 53))
         *
         * waited for a channel that only the send it was gating would
         * have created, and raised `TimeoutError: timed out` from sendto
         * with nothing having gone wrong. A STREAM socket with no channel
         * is a different thing - it has not been connected, and there is
         * no address for a write to use - so it stays false. */
        return handle->sock.type == PAL_SOCKET_UDP;
    }
    /* A SHARED socket is writable only with credit in hand: past the
     * service's window its send cannot go, however much room the ring has.
     * A POLLOUT that the send then answers with EAGAIN is a promise broken,
     * and each kind of caller pays for it differently:
     *   - a datagram socket's: a resolver's sockets are non-blocking, and
     *     glibc gives the socket up on the EAGAIN;
     *   - a stream socket's: a socket with a timeout is non-blocking
     *     underneath (CPython polls, then sends), so poll said yes, send
     *     said EAGAIN, and poll said yes again - the caller can spin
     *     without ever waiting for the credit. Requiring credit here took
     *     447 ms off 504's 1.48 s PUT (native-gap pal-wait C, jamie
     *     2026-10-18).
     *
     * Before any of that: writing over - shut down, closed, reset, or the
     * channel gone - is POLLOUT, as Linux sets it once SEND_SHUTDOWN is
     * (tcp_poll) or with the error, because the send then answers at once and
     * says which. Asked after the credit test, a poll for writing after
     * shutdown(SHUT_WR) waited for a credit that need never come, and a reset
     * socket with a full ring was never writable at all. */
    if (sock_wr_over(handle) || handle->sock.broken || sock_chan_gone(handle))
        return true;
    if (sock_no_credit(handle))
        return false;
    return sock_ring_room(handle);
}

/* The test the scheduler makes for a thread blocked in sock_block: has what
 * it waits for happened, or has something happened that ends the wait - the
 * channel gone, a reset routed in? Only what was asked: a writer on a socket
 * whose peer has half-closed is not woken by the FIN, or it would be woken
 * on every pass for as long as its ring stays full. */
pal_wait_flags_t pal_svsm_sock_wait_ready(PAL_HANDLE handle, pal_wait_flags_t want) {
    if (handle->sock.listening)
        return (want & PAL_WAIT_READ) && (handle->sock.closed || accept_find())
               ? PAL_WAIT_READ : 0;
    /* Another thread's shutdown or close: the waits it ends are over before
     * anything is asked of the rings - which may be gone. */
    pal_wait_flags_t over = 0;
    if ((want & PAL_WAIT_READ) && sock_rd_over(handle))
        over |= PAL_WAIT_READ;
    if ((want & (PAL_WAIT_WRITE | PAL_SVSM_WAIT_CREDIT)) && sock_wr_over(handle))
        over |= want & (PAL_WAIT_WRITE | PAL_SVSM_WAIT_CREDIT);
    if (over)
        return over;
    if (!sock_has_chan(handle) || handle->sock.closed)
        return PAL_WAIT_ERROR;          /* closed under it: let it look */
    pal_wait_flags_t got = 0;
    bool ended = handle->sock.broken;
    if (want & PAL_WAIT_READ) {
        if (pal_svsm_sock_readable(handle) || handle->sock.broken)
            got |= PAL_WAIT_READ;
    }
    if (want & PAL_WAIT_WRITE) {
        /* RING room, not poll(2)'s writable: a send waits for its credit as
         * PAL_SVSM_WAIT_CREDIT, and the FIN and the connect request that wait
         * here spend no credit at all - asking for one would hold a
         * shutdown(SHUT_WR) behind data the service has not taken yet. */
        if (sock_ring_room(handle) || ended || sock_chan_gone(handle))
            got |= PAL_WAIT_WRITE;
    }
    if (want & PAL_SVSM_WAIT_CREDIT) {
        if (!sock_no_credit(handle) || handle->sock.broken || sock_chan_gone(handle))
            got |= PAL_SVSM_WAIT_CREDIT;
    }
    return got;
}

static int sock_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    memset(attr, 0, sizeof(*attr));
    attr->handle_type  = PAL_TYPE_SOCKET;
    attr->nonblocking  = handle->sock.is_nonblocking;
    if (sock_shares(handle)) {
        /* FIONREAD on a socket that SHARES the vault's channel, which is
         * every socket to the network service. The branch below keys on
         * `win`, and a sharing socket's `win` is 0 by design (sock_shares),
         * so this answered 0 pending bytes for every one of them - and glibc's
         * resolver sizes the buffer for its SECOND answer from FIONREAD:
         * told 0 it recvfrom()s into a NULL, zero-length buffer, gets 0 and
         * abandons the socket. getaddrinfo(AF_UNSPEC), i.e. every urllib
         * request, failed that way with both answers on the tap (traced on
         * jamie 2026-10-12: `ioctl(3, FIONREAD) = 0` then `recvfrom(3, 0, 0)`).
         *
         * What Linux reports: for a datagram socket the size of the NEXT
         * datagram, for a stream the bytes buffered. The next frame for this
         * socket is the parked `rx`, else its queue, else the ring's head once
         * routing says it is ours. */
        struct pal_chan_ring in;
        ring_for(handle, &in, NULL);
        const char* body = NULL;
        uint64_t blen = 0;
        unsigned char peek[PAL_MVMUX_HDR_BYTES + sizeof(struct pal_mvnet_dgram)];
        if (handle->sock.rx_off < handle->sock.rx_len) {
            body = handle->sock.rx + handle->sock.rx_off;
            blen = handle->sock.rx_len - handle->sock.rx_off;
        } else if (handle->sock.q_count) {
            int qi = handle->sock.q_head;
            body = (const char*)handle->sock.q[qi] + handle->sock.q_off[qi];
            blen = handle->sock.q_len[qi] - handle->sock.q_off[qi];
        } else if (pal_chan_present(&in) && mux_poll_route(handle, &in)
                   && handle->sock.rx_off >= handle->sock.rx_len) {
            /* Ours and still in the ring: peek it, nothing is consumed. */
            uint32_t mlen = 0;
            if (pal_chan_peek(&in, peek, sizeof(peek), &mlen) == 0
                && mlen >= PAL_MVMUX_HDR_BYTES) {
                body = (const char*)peek + PAL_MVMUX_HDR_BYTES;
                blen = mlen - PAL_MVMUX_HDR_BYTES;
            }
        } else if (handle->sock.rx_off < handle->sock.rx_len) {
            /* Routing parked it in `rx` just now. */
            body = handle->sock.rx + handle->sock.rx_off;
            blen = handle->sock.rx_len - handle->sock.rx_off;
        }
        if (body) {
            if (handle->sock.type == PAL_SOCKET_UDP) {
                struct pal_mvnet_dgram dh;
                if (blen >= sizeof(dh)) {
                    memcpy(&dh, body, sizeof(dh));
                    attr->pending_size = dh.len;
                }
            } else {
                attr->pending_size = blen;
            }
        }
        if (pal_chan_present(&in))
            attr->socket.recv_buf_size = (size_t)in.slot * in.depth;
        struct pal_chan_ring out;
        ring_for(handle, NULL, &out);
        if (pal_chan_present(&out))
            attr->socket.send_buf_size = (size_t)out.slot * out.depth;
    } else if (handle->sock.win) {
        struct pal_chan_ring in;
        ring_for(handle, &in, NULL);
        if (pal_chan_present(&in)) {
            /* Whole messages waiting times what one holds: a byte count is
             * what the caller asked for and this is the honest bound. */
            attr->pending_size = (uint64_t)(*in.peer_tail - *in.head) * in.slot;
            /* The ring IS the buffer, and its size is in the endpoint's
             * measured manifest - so this is an attested number, not a knob. */
            attr->socket.recv_buf_size = (size_t)in.slot * in.depth;
        }
        struct pal_chan_ring out;
        ring_for(handle, NULL, &out);
        if (pal_chan_present(&out))
            attr->socket.send_buf_size = (size_t)out.slot * out.depth;
    }
    attr->socket.receivetimeout_us = handle->sock.recvtimeout_us;
    attr->socket.sendtimeout_us    = handle->sock.sendtimeout_us;
    return 0;
}

static int sock_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    handle->sock.is_nonblocking = attr->nonblocking;
    handle->sock.recvtimeout_us = attr->socket.receivetimeout_us;
    handle->sock.sendtimeout_us = attr->socket.sendtimeout_us;
    /* Buffer sizes are not ours to change: the ring's geometry comes from
     * the endpoint's measured manifest. Accepting the call and ignoring the
     * value is what Linux does when it clamps, and the truth is readable
     * through attrquery. */
    return 0;
}

static void sock_destroy(PAL_HANDLE handle) {
    mux_queue_release(handle);      /* the pool is the vault's, not this socket's */
    if (handle->sock.win)
        sock_unclaim((unsigned)handle->sock.widx);
    if (handle->sock.win)
        pal_svsm_channel_close(handle->sock.widx);
    if (!handle->sock.rx_pooled)
        free(handle->sock.rx);      /* the residue buffer, if it was ever needed */
    free(handle->sock.rx_spare);
    free(handle);
}

/* shutdown(SHUT_WR) on a sharing socket: FIN|HALF, and keep the id.
 *
 * Unlike close's FIN this one is NOT best-effort. It is the only end-of-input
 * the far end will ever see while the connection stays up, so a FIN lost to a
 * full ring is a server waiting forever for the rest of a request and a client
 * waiting forever for the answer. It waits for ring room the way a send does;
 * a FIN costs no credit (mvmux.h), so the ring is the only thing to wait for. */
static int sock_half_close(PAL_HANDLE handle) {
    if (handle->sock.wr_shut || !handle->sock.conn_id || !g_pal_svsm_mux_open)
        return 0;
    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    struct pal_mvmux_hdr mh;
    memset(&mh, 0, sizeof mh);
    mh.conn  = handle->sock.conn_id;
    mh.op    = PAL_MVMUX_OP_FIN;
    mh.flags = PAL_MVMUX_FIN_HALF;
    for (;;) {
        if (pal_chan_send2(&out, &mh, PAL_MVMUX_HDR_BYTES, NULL, 0) == 0) {
            pal_svsm_channel_notify(g_pal_svsm_mux_widx);
            handle->sock.wr_shut = true;
            return 0;
        }
        if (sock_chan_gone(handle) || handle->sock.broken)
            return -PAL_ERROR_CONNFAILED;
        for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_writable(&out); i++)
            __asm__ volatile("pause");
        if (pal_chan_writable(&out))
            continue;
        uint32_t seen = *out.peer_head;
        uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_HEAD, seen);
        /* Not interruptible: shutdown(2) does not fail EINTR, and this FIN
         * is the only end-of-input the far end will get. */
        (void)sock_block(handle, PAL_WAIT_WRITE, &arm, 1, PAL_SOCK_PARK_US,
                         /*interruptible=*/false);
        if (handle->sock.closed || !sock_has_chan(handle))
            return -PAL_ERROR_CONNFAILED;  /* closed while the FIN waited */
        ring_for(handle, NULL, &out);
    }
}

static int sock_delete(PAL_HANDLE handle, enum pal_delete_mode mode) {
    if (sock_shares(handle)) {
        /* The mode matters here and was ignored: shutdown(SHUT_WR) sent the
         * same FIN as close(2) and released the id, so the service dropped
         * the connection and the answer to an upload that half-closed and
         * then read never arrived (net_client_upload, 2026-10-14).
         * SHUT_RD has nothing to tell the service - the LibOS stops reading
         * on its own - and SHUT_WR is a half-close. Only ALL is a close. */
        if (mode == PAL_DELETE_READ) {
            handle->sock.rd_shut = true;     /* ends a parked recv: 0 */
            return 0;
        }
        if (mode == PAL_DELETE_WRITE)
            return sock_half_close(handle);
        handle->sock.closed = true;          /* ends every parked call */
        /* A SHARING socket owns a CONNECTION, not a channel. Closing it must
         * tell the service - the service holds an lwIP connection for it and
         * nothing else would ever end it - and must release the id, but must
         * NOT close the channel: the vault's other sockets are on it.
         *
         * The FIN is best-effort. If the ring is full the service finds out
         * when the vault exits and its channel goes; dropping the socket here
         * and blocking to announce it would let one busy peer hold a close. */
        /* A credit still owed dies with the connection: the FIN below is
         * all the service needs to hear, and nobody will read again. */
        handle->sock.credit_owed = false;
        if (handle->sock.conn_id && g_pal_svsm_mux_open) {
            mux_fin_flush();             /* older FINs first */
            if (!mux_fin_send(handle->sock.conn_id)) {
                PAL_SVSM_NET_CTR_INC(fin_lost);
                if (g_fin_owed_n < PAL_MUX_FIN_OWED)
                    g_fin_owed[g_fin_owed_n++] = handle->sock.conn_id;
            }
        }
        pal_svsm_mux_release(handle->sock.conn_id);
        handle->sock.conn_id = 0;
        /* And its frames go back to the vault's pool now, not at close(2):
         * with the id released it is out of mux_grant's walk, so buffers it
         * kept would be pool nobody's claim covers (review by jamie). Every
         * parked call is over (`closed`) and no reader takes from it again. */
        mux_queue_release(handle);
        return 0;
    }
    /* Framed but not sharing: it owns a channel like any other socket, and
     * leaving it open here would leak one of the service's max_channels per
     * connection - the exact leak conn_drop's shutdown() was written to fix.
     * Whatever the mode (a channel has no half-close; its closing is the
     * peer's end of stream), and so every call of this socket parked in
     * sock_block is over: `closed`, which they test before they look at a
     * ring again. A listener lands here too, and its parked accept ends -
     * but not for SHUT_WR, which Linux ignores on a listening socket. */
    if (!(handle->sock.listening && mode == PAL_DELETE_WRITE))
        handle->sock.closed = true;
    if (handle->sock.conn_id) {
        pal_svsm_mux_release(handle->sock.conn_id);
        handle->sock.conn_id = 0;
    }
    if (handle->sock.win) {
        /* Release the claim BEFORE clearing `win`, because `sock_destroy`
         * guards its own release on `win` being set and would then never
         * run: the window index would stay claimed for the life of the
         * vault and `accept` would skip it for ever. Unreachable until the
         * ops table above was attached, and reachable now, so it is fixed
         * in the same change that reaches it. */
        sock_unclaim((unsigned)handle->sock.widx);
        pal_svsm_channel_close(handle->sock.widx);
        handle->sock.win = 0;
    }
    return 0;
}

struct handle_ops g_sock_ops = {
    .attrquerybyhdl = &sock_attrquerybyhdl,
    .attrsetbyhdl   = &sock_attrsetbyhdl,
    .delete         = &sock_delete,
    .destroy        = &sock_destroy,
};
