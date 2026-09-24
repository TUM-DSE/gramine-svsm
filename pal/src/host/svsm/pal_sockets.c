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

/* How long a blocking call parks before looking again. Not a timeout the
 * application can see - the loop goes round - but the interval at which a
 * vault whose wake was missed notices anyway. */
#define PAL_SOCK_PARK_US 200000UL

/* Spins before parking. A peer that is running answers in far less than the
 * monitor entry a park costs (PLAN.md's channel plan, D1). */
#define PAL_SOCK_SPINS 200

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

/* Windows already handed to a handle - by `connect`, which opened one, or by
 * `accept`, which found one. A bit per window, which is also how the monitor
 * publishes them in the directory. Without it `accept` would hand out this
 * vault's own outgoing connections, and hand the same arrival out twice. */
static uint64_t g_sock_claimed;

static void ring_for(PAL_HANDLE handle, struct pal_chan_ring* in,
                     struct pal_chan_ring* out) {
    if (in)
        pal_chan_ring_init(in, handle->sock.win, handle->sock.side, /*producing=*/0);
    if (out)
        pal_chan_ring_init(out, handle->sock.win, handle->sock.side, /*producing=*/1);
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
    /* The address itself is not kept: what this vault answers on is the
     * endpoint its measured manifest declares, and a port here would only
     * be a label for it. */
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
        uint64_t live = pal_chan_u64(PAL_CHAN_DIR_VADDR, PAL_CHAN_DIR_LIVE);
        for (unsigned w = 1; w < 64; w++) {
            uint64_t bit = 1UL << w;
            if (!(live & bit) || (g_sock_claimed & bit))
                continue;
            unsigned long win = pal_chan_window_addr(w);
            if (pal_chan_u64(win, 0) != PAL_CHAN_HDR_MAGIC)
                continue;

            PAL_HANDLE cli = calloc(1, HANDLE_SIZE(sock));
            if (!cli)
                return -PAL_ERROR_NOMEM;
            init_handle_hdr(cli, PAL_TYPE_SOCKET);
            cli->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
            cli->sock.domain         = handle->sock.domain;
            cli->sock.type           = handle->sock.type;
            cli->sock.is_nonblocking = !!(options & PAL_OPTION_NONBLOCK);
            cli->sock.win            = win;
            cli->sock.widx           = w;
            cli->sock.side           = 1;   /* they asked, we were asked */
            g_sock_claimed |= bit;

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
 * The address is not used yet, and saying so is better than pretending: with
 * a network service on the far end it becomes a CONNECT message on the
 * control channel (step 4), and the same handle then carries a TCP
 * connection instead of an echo service's ring.
 */
int _PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                      struct pal_socket_addr* out_local_addr, bool* out_inprogress) {
    __UNUSED(addr);
    if (handle->hdr.type != PAL_TYPE_SOCKET)
        return -PAL_ERROR_INVAL;
    if (handle->sock.win)
        return -PAL_ERROR_INVAL;
    if (!g_pal_svsm_net_name[0])
        return -PAL_ERROR_DENIED;

    struct pal_sock_grant req;
    memset(&req, 0, sizeof(req));
    memcpy(&req.magic, "MVG1", 4);
    req.selector = 1;                       /* by name */
    req.endpoint = g_pal_svsm_net_endpoint;
    memcpy(req.name, g_pal_svsm_net_name, sizeof(req.name));

    uint64_t addr_out = 0;
    int64_t win = pal_svsm_channel_grant(&req, sizeof(req), &addr_out);
    if (win < 0)
        return -PAL_ERROR_CONNFAILED;

    handle->sock.win  = addr_out;
    handle->sock.widx = (unsigned long)win;
    handle->sock.side = 0;                  /* we asked, so we are side 0 */
    /* Ours, not an arrival: `accept` must not hand this back to us. */
    g_sock_claimed |= 1UL << (unsigned)win;

    if (out_local_addr)
        memset(out_local_addr, 0, sizeof(*out_local_addr));
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

int _PalSocketSend(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    __UNUSED(addr);
    if (handle->hdr.type != PAL_TYPE_SOCKET || !handle->sock.win)
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.broken)
        return -PAL_ERROR_DENIED;

    struct pal_chan_ring out;
    ring_for(handle, NULL, &out);
    if (!pal_chan_present(&out))
        return -PAL_ERROR_NOTSUPPORT;

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t total = iov_total(iov, iov_len);
    if (total > out.slot - 4)
        total = out.slot - 4;               /* one message per call, like a datagram */

    /* Gather into the slot's worth. A stream socket may send less than it
     * was given, and the LibOS handles the short write. */
    char* buf = malloc(total ? total : 1);
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

    int ret = -PAL_ERROR_TRYAGAIN;
    for (;;) {
        if (pal_chan_send(&out, buf, (uint32_t)total) == 0) {
            /* The peer may be parked on this index; the monitor turns that
             * into one dispatch however many messages went in. */
            pal_svsm_channel_notify(handle->sock.widx);
            *out_size = total;
            ret = 0;
            break;
        }
        if (pal_chan_peer_gone(handle->sock.win, handle->sock.side)) {
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
        uint64_t arm  = pal_chan_arm(handle->sock.widx, PAL_CHAN_ARM_HEAD, seen);
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
    }
    free(buf);
    return ret;
}

int _PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                   struct pal_socket_addr* addr, bool force_nonblocking) {
    if (handle->hdr.type != PAL_TYPE_SOCKET || !handle->sock.win)
        return -PAL_ERROR_NOTCONNECTION;
    if (handle->sock.broken)
        return -PAL_ERROR_DENIED;
    if (addr)
        memset(addr, 0, sizeof(*addr));

    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    if (!pal_chan_present(&in))
        return -PAL_ERROR_NOTSUPPORT;

    bool nonblock = force_nonblocking || handle->sock.is_nonblocking;
    uint64_t room = iov_total(iov, iov_len);
    char* buf = malloc(in.slot);
    if (!buf)
        return -PAL_ERROR_NOMEM;

    int ret;
    for (;;) {
        uint32_t got = 0;
        int rc = pal_chan_recv(&in, buf, (uint32_t)(room < in.slot ? room : in.slot), &got);
        if (rc == 0) {
            uint64_t off = 0;
            for (size_t i = 0; i < iov_len && off < got; i++) {
                uint64_t take = iov[i].iov_len;
                if (take > got - off)
                    take = got - off;
                memcpy(iov[i].iov_base, buf + off, take);
                off += take;
            }
            *out_total_size = off;
            ret = 0;
            break;
        }
        if (rc == -2) {
            /* A length that cannot be right. The head is not advanced, so
             * nothing is silently skipped; the stream is over. */
            handle->sock.broken = true;
            ret = -PAL_ERROR_DENIED;
            break;
        }
        if (pal_chan_peer_gone(handle->sock.win, handle->sock.side)) {
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
        uint64_t arm = pal_chan_arm(handle->sock.widx, PAL_CHAN_ARM_TAIL, seen);
        if (pal_svsm_sleep_arms(&arm, 1, PAL_SOCK_PARK_US) < 0)
            for (int i = 0; i < PAL_SOCK_SPINS; i++)
                __asm__ volatile("pause");
    }
    free(buf);
    return ret;
}

bool pal_svsm_sock_readable(PAL_HANDLE handle) {
    if (!handle->sock.win)
        return false;
    struct pal_chan_ring in;
    ring_for(handle, &in, NULL);
    return pal_chan_readable(&in) || pal_chan_peer_gone(handle->sock.win, handle->sock.side);
}

bool pal_svsm_sock_writable(PAL_HANDLE handle) {
    if (!handle->sock.win)
        return false;
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
        g_sock_claimed &= ~(1UL << handle->sock.widx);
    if (handle->sock.win)
        pal_svsm_channel_close(handle->sock.widx);
    free(handle);
}

static int sock_delete(PAL_HANDLE handle, enum pal_delete_mode mode) {
    __UNUSED(mode);
    if (handle->sock.win) {
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
