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
                                   bool was_full) {
    if (!sock_shares(handle))
        return MUX_HEAD_EMPTY;

    struct pal_mvmux_hdr ph;
    uint32_t mlen = 0;
    if (pal_chan_peek(in, &ph, PAL_MVMUX_HDR_BYTES, &mlen) != 0
        || mlen < PAL_MVMUX_HDR_BYTES)
        return MUX_HEAD_EMPTY;

    PAL_HANDLE target = pal_svsm_mux_conn_of(ph.conn);

    /* Scratch for a message that is not going to a caller. This handle's own
     * residue buffer is free by construction: a caller only looks at the head
     * when it has nothing left of its own. */
    if (!handle->sock.rx) {
        handle->sock.rx = malloc(in->slot);
        if (!handle->sock.rx)
            return MUX_HEAD_NOMEM;
        handle->sock.rx_len = handle->sock.rx_off = 0;
    }

    if (target == handle) {
        /* OUR OWN control frame is consumed HERE rather than left for the
         * reader, and that is not a tidy-up.
         *
         * The mux made end of stream IN-BAND: a FIN is a message in the ring,
         * where before it was the channel being closed and `pal_chan_peer_gone`
         * answered it out of band. A marker that only exists once somebody
         * READS it cannot tell a POLLER anything - measured as `sock_poll_hup`
         * reporting POLLIN for five seconds and never POLLHUP, with the FIN
         * sitting at the head of the ring the whole time. So it is consumed at
         * the one place both the read path and the poll path pass, and it
         * carries nothing a reader wanted anyway. */
        if (ph.op == PAL_MVMUX_OP_FIN || ph.op == PAL_MVMUX_OP_RST) {
            uint32_t cgot = 0;
            if (pal_chan_recv(in, handle->sock.rx, in->slot, &cgot) != 0)
                return MUX_HEAD_MINE;       /* could not take it: leave it */
            if (was_full)
                pal_svsm_channel_notify(sock_widx(handle));
            handle->sock.rx_len = handle->sock.rx_off = 0;
            if (ph.op == PAL_MVMUX_OP_FIN)
                handle->sock.fin_seen = true;
            else
                handle->sock.broken = true;
            return MUX_HEAD_MOVED;
        }
        return MUX_HEAD_MINE;
    }

    if (!target) {
        /* A frame for a connection that has closed. Consume and DROP: the id
         * carries a generation, so this cannot be mistaken for the next
         * occupant of the slot. */
        uint32_t drop = 0;
        if (pal_chan_recv(in, handle->sock.rx, in->slot, &drop) != 0)
            return MUX_HEAD_EMPTY;
        if (was_full)
            pal_svsm_channel_notify(sock_widx(handle));
        handle->sock.rx_len = handle->sock.rx_off = 0;
        return MUX_HEAD_MOVED;
    }

    if (target->sock.rx_off < target->sock.rx_len)
        return MUX_HEAD_BLOCKED;
    if (!target->sock.rx) {
        target->sock.rx = malloc(in->slot);
        if (!target->sock.rx)
            return MUX_HEAD_NOMEM;
    }
    uint32_t tgot = 0;
    if (pal_chan_recv(in, target->sock.rx, in->slot, &tgot) != 0)
        return MUX_HEAD_EMPTY;
    if (was_full)
        pal_svsm_channel_notify(sock_widx(handle));
    if (tgot < PAL_MVMUX_HDR_BYTES) {
        target->sock.broken = true;
        target->sock.rx_len = target->sock.rx_off = 0;
    } else if (ph.op == PAL_MVMUX_OP_FIN || ph.op == PAL_MVMUX_OP_RST) {
        /* Its stream is over. A FIN reads as EOF and an RST as a reset, which
         * is the difference between `fin_seen` and `broken` - and the frame is
         * consumed either way, so the head moves and the OTHER sockets on this
         * channel keep running. */
        if (ph.op == PAL_MVMUX_OP_FIN)
            target->sock.fin_seen = true;
        else
            target->sock.broken = true;
        target->sock.rx_len = target->sock.rx_off = 0;
    } else {
        target->sock.rx_len = tgot;
        target->sock.rx_off = PAL_MVMUX_HDR_BYTES;
        if (target->sock.rx_off >= target->sock.rx_len)
            target->sock.rx_len = target->sock.rx_off = 0;   /* header only */
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
 * 50 ms poll into a wake (PLAN.md's receive loop, M2).
 */
int _PalSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                     struct pal_socket_addr* out_client_addr,
                     struct pal_socket_addr* out_local_addr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    if (!handle->sock.listening)
        return -PAL_ERROR_INVAL;

    bool nonblock = handle->sock.is_nonblocking || (options & PAL_OPTION_NONBLOCK);

    for (;;) {
        /* All eight published words, not just the first. Window 0 is the
           directory page itself, so the scan starts at 1. */
        for (unsigned w = 1; w < PAL_CHAN_WINDOWS; w++) {
            uint64_t live = pal_chan_u64(PAL_CHAN_DIR_VADDR,
                                         PAL_CHAN_DIR_LIVE + (w / 64) * 8);
            if (!(live & (1UL << (w % 64))) || sock_claimed(w))
                continue;
            unsigned long win = pal_chan_window_addr(w);
            if (pal_chan_u64(win, 0) != PAL_CHAN_HDR_MAGIC)
                continue;

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
           is a wake rather than a poll interval; the timeout is the backstop
           for a monitor that does not (and for the case where this vault is
           not the scheduler's to park). */
        if (pal_svsm_sleep(50000) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS * 50; i++)
                __asm__ volatile("pause");
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

/* One round of waiting. A park if the monitor will grant one, a spin if
   it will not - which it will not for a vault running inside an invoke. */
static void mvnet_wait(void) {
    if (pal_svsm_sleep(2000) < 0)
        for (int i = 0; i < PAL_SOCK_SPINS * 50; i++)
            __asm__ volatile("pause");
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
    while (pal_chan_send2(&out, chf, chfl, &req, sizeof(req)) != 0) {
        if (sock_chan_gone(handle))
            return -PAL_ERROR_CONNFAILED;
        if (mvnet_now() > deadline)
            return -PAL_ERROR_CONNFAILED;
        mvnet_wait();
    }
    pal_svsm_channel_notify(sock_widx(handle));

    struct pal_mvnet_rep rep;
    deadline = mvnet_deadline(PAL_MVNET_WAIT_US);
    for (;;) {
        uint32_t got = 0;
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
            mvnet_wait();
            continue;
        }
        /* Big enough for the frame as well as the record. */
        unsigned char rbuf[PAL_MVMUX_HDR_BYTES + sizeof(rep)];
        int rc = pal_chan_recv(&in, rbuf, sizeof(rbuf), &got);
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
        mvnet_wait();
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
    if (PAL_MUX_SHARE_CHANNEL && g_pal_svsm_net_protocol && g_pal_svsm_mux_open) {
        handle->sock.muxed = true;
        handle->sock.win   = 0;          /* the MUX owns the channel, not this */
        handle->sock.side  = g_pal_svsm_mux_side;
        int cl = pal_svsm_mux_claim(handle, &handle->sock.conn_id);
        if (cl < 0)
            return cl;                   /* the table said no, not the monitor */
        goto have_channel;
    }

    for (int try = 0; try < PAL_GRANT_TRIES; try++) {
        win = pal_svsm_channel_grant(&req, sizeof(req), &addr_out);
        if (win >= 0 || win != PAL_SVSM_STATUS_BAD_STATE)
            break;
        if (pal_svsm_sleep(200) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS * 50; i++)
                __asm__ volatile("pause");
    }
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
            handle->sock.win    = 0;
            handle->sock.side   = 0;
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
            pal_svsm_channel_close(handle->sock.widx);
            sock_unclaim((unsigned)win);
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

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    int ret = -PAL_ERROR_TRYAGAIN;
    for (;;) {
        if (pal_chan_send(&out, buf, (uint32_t)(sizeof(hdr) + payload)) == 0) {
            pal_svsm_channel_notify(sock_widx(handle));
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
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
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
        handle->sock.rx = malloc(in.slot);
        if (!handle->sock.rx)
            return -PAL_ERROR_NOMEM;
        handle->sock.rx_len = handle->sock.rx_off = 0;
    }

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t room = iov_total(iov, iov_len);

    for (;;) {
        bool was_full = pal_chan_present(&in)
                        && (uint32_t)(*in.peer_tail - *in.head) >= in.depth;
        uint32_t got = 0;
        int rc = pal_chan_recv(&in, handle->sock.rx, in.slot, &got);
        if (rc == 0) {
            if (was_full)
                pal_svsm_channel_notify(sock_widx(handle));
            struct pal_mvnet_dgram hdr;
            if (got < sizeof(hdr)) {
                handle->sock.broken = true;
                return -PAL_ERROR_DENIED;
            }
            memcpy(&hdr, handle->sock.rx, sizeof(hdr));
            if (hdr.len > got - sizeof(hdr)) {
                /* The frame claims more than arrived. Not recoverable: the
                 * next message would be read as a header. */
                handle->sock.broken = true;
                return -PAL_ERROR_DENIED;
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
                memcpy(iov[i].iov_base, handle->sock.rx + sizeof(hdr) + off, take);
                off += take;
            }
            /* What did not fit is GONE, and that is not a bug: a datagram
             * read into too small a buffer is truncated, and the remainder
             * is not the next datagram's business. The stream path keeps a
             * residue here; this must not. */
            handle->sock.rx_len = handle->sock.rx_off = 0;
            *out_total_size = off;
            return 0;
        }
        if (rc == -2) {
            handle->sock.broken = true;
            return -PAL_ERROR_DENIED;
        }
        if (sock_chan_gone(handle)) {
            /* The service is gone. For a datagram socket there is no "end
             * of stream" to report, so this is an error rather than a 0. */
            return -PAL_ERROR_CONNFAILED;
        }
        if (nonblock)
            return -PAL_ERROR_TRYAGAIN;

        for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_readable(&in); i++)
            __asm__ volatile("pause");
        if (pal_chan_readable(&in))
            continue;
        uint32_t seen = *in.peer_tail;
        if (seen != *in.head)
            continue;
        uint64_t arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
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
        return -PAL_ERROR_DENIED;

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
     * `out.slot - 4` just above, which for this service's geometry is 16,380 -
     * and the PAL slab's top level is 8288 - SLAB_HDR_SIZE = 8,272 B
     * (common/include/slabmgr.h:86-98). So every full-slot send missed the
     * slab, fell to LARGE_MEM_OBJ -> system_malloc (slabmgr.h:306-322), and
     * cost a page-granular MMAP on the way in and a MUNMAP on the way out -
     * two MONITOR CALLS per send that nothing in the tree accounted for. At
     * the 11.2 us anchor and 65 sends per MiB that is ~1,456 us per MiB spent
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
        /* Header and body in one message, without building a combined buffer:
         * that buffer was a 16,380-byte malloc that missed the PAL slab and
         * cost an mmap and a munmap through the monitor on every send. */
        if (pal_chan_send2(&out, fh, fhl, msg, (uint32_t)total) == 0) {
            /* The peer may be parked on this index; the monitor turns that
             * into one dispatch however many messages went in. */
            pal_svsm_channel_notify(sock_widx(handle));
            *out_size = total;
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
        /* Room is the peer's HEAD moving. Refused inside a host invoke, and
         * then the spin above is all there is. */
        uint32_t seen = *out.peer_head;
        uint64_t arm  = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_HEAD, seen);
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
    }
    free(buf);
    return ret;
}

int _PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.broken)
        return -PAL_ERROR_DENIED;
    if (handle->sock.type == PAL_SOCKET_UDP)
        return udp_recv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
    /* A FIN already seen, and nothing left in the residue, is end of stream -
     * on EVERY later call, not just the one that saw it. Checked before the
     * ring, because the ring may well have another connection's traffic in it
     * and a blocking read here would otherwise wait on data that is not
     * coming. */
    if (handle->sock.fin_seen && handle->sock.rx_off >= handle->sock.rx_len) {
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
        handle->sock.rx = malloc(in.slot);
        if (!handle->sock.rx)
            return -PAL_ERROR_NOMEM;
        handle->sock.rx_len = handle->sock.rx_off = 0;
    }

    int ret;
    for (;;) {
        /* Serve what is already here first. */
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
            if (handle->sock.rx_off >= handle->sock.rx_len)
                handle->sock.rx_len = handle->sock.rx_off = 0;
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

        int rc = pal_chan_recv(&in, handle->sock.rx, in.slot, &got);
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
        }
        if (rc == -2) {
            /* A length that cannot be right - not "your buffer is small",
             * which is now impossible here because the whole slot is
             * always offered. The head is not advanced, so nothing is
             * silently skipped; the stream is over. */
            handle->sock.broken = true;
            ret = -PAL_ERROR_DENIED;
            break;
        }
        if (sock_chan_gone(handle)) {
            *out_total_size = 0;            /* end of stream, as recv(2) has it */
            ret = 0;
            break;
        }
        if (nonblock) {
            ret = -PAL_ERROR_TRYAGAIN;
            break;
        }

        for (int i = 0; i < PAL_SOCK_SPINS && !pal_chan_readable(&in); i++)
            __asm__ volatile("pause");
        if (pal_chan_readable(&in))
            continue;
        uint32_t seen = *in.peer_tail;
        if (seen != *in.head)
            continue;                        /* it moved while we looked */
        uint64_t arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, seen);
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
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
        *out_arm = pal_chan_arm(sock_widx(handle), PAL_CHAN_ARM_TAIL, *in.peer_tail);
        return 1;
    }
    if ((want & PAL_WAIT_WRITE) && !pal_svsm_sock_writable(handle)) {
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
    if (handle->sock.rx_off < handle->sock.rx_len)
        return true;
    if (handle->sock.fin_seen)
        return true;                /* readable, and the read returns 0 */
    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    if (sock_shares(handle)) {
        if (mux_poll_route(handle, &in))
            return true;
        /* The head is not this socket's, so there is nothing here it could
         * read - `pal_chan_readable` would say yes about somebody else's
         * message and the read that followed would answer EAGAIN. */
        return sock_chan_gone(handle);
    }
    return pal_chan_readable(&in) || sock_chan_gone(handle);
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
    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    return pal_chan_writable(&out);
}

static int sock_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    memset(attr, 0, sizeof(*attr));
    attr->handle_type  = PAL_TYPE_SOCKET;
    attr->nonblocking  = handle->sock.is_nonblocking;
    if (handle->sock.win) {
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
    if (handle->sock.win)
        sock_unclaim((unsigned)handle->sock.widx);
    if (handle->sock.win)
        pal_svsm_channel_close(handle->sock.widx);
    free(handle->sock.rx);          /* the residue buffer, if it was ever needed */
    free(handle);
}

static int sock_delete(PAL_HANDLE handle, enum pal_delete_mode mode) {
    __UNUSED(mode);
    if (sock_shares(handle)) {
        /* A SHARING socket owns a CONNECTION, not a channel. Closing it must
         * tell the service - the service holds an lwIP connection for it and
         * nothing else would ever end it - and must release the id, but must
         * NOT close the channel: the vault's other sockets are on it.
         *
         * The FIN is best-effort. If the ring is full the service finds out
         * when the vault exits and its channel goes; dropping the socket here
         * and blocking to announce it would let one busy peer hold a close. */
        if (handle->sock.conn_id && g_pal_svsm_mux_open) {
            struct pal_chan_ring out;
            ring_for(handle, NULL, &out);
            struct pal_mvmux_hdr mh;
            memset(&mh, 0, sizeof mh);
            mh.conn = handle->sock.conn_id;
            mh.op   = PAL_MVMUX_OP_FIN;
            if (pal_chan_send2(&out, &mh, PAL_MVMUX_HDR_BYTES, NULL, 0) == 0)
                pal_svsm_channel_notify(g_pal_svsm_mux_widx);
        }
        pal_svsm_mux_release(handle->sock.conn_id);
        handle->sock.conn_id = 0;
        return 0;
    }
    /* Framed but not sharing: it owns a channel like any other socket, and
     * leaving it open here would leak one of the service's max_channels per
     * connection - the exact leak conn_drop's shutdown() was written to fix. */
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
