/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#pragma once

#include <stdint.h>
#include "spinlock.h"

struct pal_svsm_pipe_pair;
#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

/* How many ring words one blocked thread may ask the monitor to watch.
 * The monitor's budget is `queue::PARK_ARMS` (3 today); this is the
 * PAL-side array and the gather in pick_next() clamps to whatever the
 * Park call accepts, so raising one does not require raising the other
 * in the same commit. */
#define PAL_SVSM_THREAD_ARMS 4

/* How many DATA frames one socket on a SHARED channel may have in flight, and
 * so how deep its inbound queue is. Must equal MVMUX_CREDIT_CAP in the
 * service's mvmux.h: neither end can negotiate it, both are measured
 * separately, so CHANGE ONE AND CHANGE THE OTHER. `rx` holds the message being
 * read and the queue holds the rest, which is why this is CAP - 1. */
#define PAL_MUX_CREDIT_CAP   16
#define PAL_MUX_CREDIT_FLOOR 1
#define PAL_MUX_QUEUE        (PAL_MUX_CREDIT_CAP - 1)

/* Named, unlike the other hosts' anonymous version, because a thread handle
 * links to the next one in the scheduler's ring (see pal_threading.c). */
struct pal_handle_inner;
typedef struct pal_handle_inner* PAL_HANDLE;

struct pal_handle_inner {
    /* TSAI: Here we define the internal types of PAL_HANDLE in PAL design, user has not to access
     * the content inside the handle, also there is no need to allocate the internal handles, so we
     * hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;
    uint32_t flags;

    /*
     * PAL has different kinds of handles, so you probably want to add an union with data specific
     * for following types:
     * - file,
     * - pipe,
     * - eventfd,
     * - dev,
     * - dir,
     * - sock,
     * - process,
     * - thread,
     * - event.
     * Note that this is just a hint, not a requirement. You can check the Linux PAL for a sample
     * implementation.
     */
    union {
        struct {
            spinlock_t lock;
            uint32_t waiters_cnt;
            uint32_t signaled;
            bool auto_clear;
        } event;

        /* A cooperative context, not a vCPU: the monitor runs one VMSA per
         * vault and refuses a second entrant into it, so everything here is
         * scheduled by the PAL itself inside that one thread of execution.
         * See pal_threading.c. */
        struct {
            void*      stack;        /* the malloc'd block, NULL for the first
                                        thread (its stack is the monitor's) */
            void*      rsp;          /* where the context sits while not running */
            uint64_t   fsbase;       /* the application's thread pointer (glibc TLS) */
            void*      tcb;          /* PAL_SVSM_TCB, at the top of the block */
            PAL_HANDLE next;         /* round-robin ring, never NULL */
            PAL_HANDLE waiting_on;   /* what it is parked on, NULL if nothing */
            uint64_t   deadline_us;  /* absolute wake time, 0 = no deadline */
            uint32_t   state;        /* enum pal_svsm_thread_state */
            bool       has_deadline;
            bool       interrupted;  /* _PalThreadResume landed */
            bool       timed_out;
            /* The ring words that would make this thread runnable, as
             * `pal_chan_arm` encodes them. A blocked thread leaves them
             * here so that the PAL's scheduler, which is the thing that
             * actually gives the processor back, can tell the monitor
             * what to watch - without which a vault waiting in poll()
             * wakes on its timeout rather than on its peer's send.
             *
             * `arms_partial` means there were more waitable channels
             * than arms, so a wake may be missed and the park needs a
             * bounded fallback: late rather than invisible. */
            uint64_t   arms[PAL_SVSM_THREAD_ARMS];
            uint8_t    n_arms;
            bool       arms_partial;
            /* What a thread blocked in poll() is watching, so that the
             * scheduler can re-test it without a monitor call.
             *
             * The arms above are for the MONITOR, and they only reach it
             * when this vault parks. A vault with a LibOS async worker
             * never gets that far: the worker's deadline is a
             * millisecond or two away, so there is always something
             * runnable, `idle_until` is never reached, and a poller
             * stayed blocked until its own timeout expired even though
             * its peer had answered - `settimeout(5)` on an ordinary
             * socket meant a five-second wait for a reply that was
             * already in the ring (next.md 124).
             *
             * These point into the frame of the thread's own
             * `_PalStreamsWaitEvents`, which is alive for exactly as
             * long as it is blocked there. */
            PAL_HANDLE* watch_handles;
            uint32_t*   watch_events;   /* pal_wait_flags_t, not declared yet here */
            size_t      n_watch;
        } thread;

        struct {
            PAL_IDX fd;
        } console;

        /* Both ends of a pipe start in this address space - a vault is one
         * process - so a pipe is a pair of rings rather than anything the
         * host knows about. They do not STAY in one address space: a fork
         * gives the child a copy of every handle, and the pair they point at
         * lives in memory the monitor shares with descendants rather than
         * copies. See pal_pipes.c. */
        struct {
            struct pal_svsm_pipe_pair* pair;
            char*    name;       /* PIPESRV only: what a connect must match */
            unsigned side;       /* which end of the pair this handle is */
            bool     nonblocking;
            /* Has this handle already given up its hold on the pair? close()
             * reaches both `delete` and `destroy`, and a side counted down
             * twice closes a pipe end somebody else is still holding. */
            bool     released;
            /* This process got the handle by being forked, as a copy of its
             * parent's - the only way it can hold one that no fd of its own
             * names (_PalStreamsKeepOnly). */
            bool     inherited;
            /* PIPESRV only: this listener's slot in the arena's SHARED
             * rendezvous table, or -1 if it is a process-local listener.
             * A cross-process connect finds a listener by looking there,
             * because the local pending table is this process's memory and
             * a peer in another process cannot see it. */
            int      rdv;
        } pipe;

        /* A socket is a CHANNEL: the monitor maps a run of pages into this
         * vault and one other, and send/recv are a store and a load on the
         * rings in it. What the network service adds on top is where the
         * other end of that channel goes - see PLAN.md "Full socket
         * support". Nothing here is host-visible. */
        struct {
            unsigned long win;      /* the window's address, 0 until connected */
            unsigned long widx;     /* its index, for park arms and close */
            int      side;          /* 0 = we opened it, 1 = it was opened to us */
            enum pal_socket_domain domain;
            enum pal_socket_type   type;
            uint64_t recvtimeout_us;
            uint64_t sendtimeout_us;
            bool     is_nonblocking;
            bool     broken;        /* a malformed length: the stream is over */
            /* The service sent a FIN frame for this connection: the far end
             * is finished and there will be no more data.
             *
             * NOT `broken`, which is an error and makes every later call
             * return EACCES. A FIN is the ordinary end of a stream and recv(2)
             * answers it with 0, so it needs a flag of its own. It exists
             * because a shared channel cannot carry a close: the channel
             * outlives any one connection on it, so `pal_chan_peer_gone` -
             * which is how an unshared socket learns this - stays false. */
            bool     fin_seen;
            /* shutdown(SHUT_WR) has sent its FIN|HALF: the service
             * has been told this side sends nothing more, once. */
            bool     wr_shut;
            /* Does every message on this channel carry a mux frame header?
             *
             * True only for a socket this vault CONNECTED through a network
             * service (side 0, and only when [svsm.net] named one). An
             * accepted socket is the service's end and must see the frame
             * bytes, because the service is what demultiplexes them; and a
             * vault-to-vault channel socket that never went through a service
             * is not framed at all. So this is a property of the handle, not
             * of the build. */
            bool     muxed;
            /* Which connection this handle is on the shared channel: a slot in
             * the low 16 bits and a GENERATION in the high 16. Only meaningful
             * when `muxed`. 0 is never a live id. */
            uint32_t conn_id;
            /* What a message had left over when the caller's buffer was
             * smaller than it. A channel carries MESSAGES and a stream
             * socket is read in whatever pieces the program felt like,
             * so the two have to meet somewhere: the whole message is
             * taken from the ring (which keeps the ring safe for the
             * several holders a fork makes) and the rest waits here. */
            char*    rx;            /* one slot's worth, allocated on demand */
            uint32_t rx_len;        /* bytes in it */
            uint32_t rx_off;        /* how many the caller has had */
            /* AND A QUEUE BEHIND IT, on a shared channel.
             *
             * `rx` alone holds one message, which is all a socket with its own
             * channel ever needs. Sharing changes that: the channel's head may
             * be any socket's, so a socket that is not being read stops every
             * other socket on the channel - head-of-line blocking at the vault.
             * The receiver therefore has to be able to take the head ALWAYS,
             * which means somewhere to put it, which means a bounded queue and
             * credit (MVMUX_OP_CREDIT) to keep the sender inside it.
             *
             * Entries are [q_head, q_head + q_count) modulo the array, so a
             * zeroed handle is an empty queue. The buffers come from a pool
             * shared by every socket, so idle sockets cost nothing. */
            /* Is `rx` itself a pool buffer? When it is, a refill is a POINTER
             * SWAP rather than a copy, which is what keeps a frame's cost at
             * the one copy it always had: into the buffer it will be read
             * from, straight out of the ring. */
            bool     rx_pooled;
            void*    q[PAL_MUX_QUEUE];
            uint32_t q_len[PAL_MUX_QUEUE];
            uint32_t q_off[PAL_MUX_QUEUE];
            int      q_head, q_count;
            /* The window this socket ADVERTISES, for frames coming down. */
            uint32_t rx_done;       /* DATA frames fully consumed, cumulative */
            uint32_t rx_advert;     /* the limit last advertised to the service */
            /* And the window it RESPECTS, for frames going up. */
            uint32_t tx_sent;       /* DATA frames sent, cumulative */
            uint32_t tx_limit;      /* the limit the service advertised */
            bool     credit_owed;   /* a CREDIT frame found the ring full */
            bool     bound;
            bool     listening;
            unsigned int backlog;
            /* --- MVNET_PROTO_UDP only -------------------------------------
             * A datagram socket's addresses live here rather than in the
             * channel, because a channel has exactly one far end and a
             * datagram socket has as many peers as it has datagrams. The
             * local port is what bind() asked for, which the service needs
             * at open time; the peer is what connect() named, which send()
             * uses when the caller gives no address of its own. */
            /* What the network service said when it answered the MVN1
             * handshake: its own address and the local port it bound. This
             * is what getsockname() reports, and glibc's getaddrinfo
             * asserts if it is not a real AF_INET address. */
            struct {
                uint16_t local_port;
                uint8_t  local_addr[4];
            } local;
            uint16_t bind_port;
            uint16_t peer_port;
            uint8_t  peer_addr[4];
            bool     has_peer;
        } sock;

        struct {
            PAL_IDX fd;
            char* realpath;
            bool seekable; /* regular files are seekable, FIFO pipes are not */
        } file;

        struct {
            PAL_IDX fd;
            char* realpath;
            char* buf;
            bool endofstream;
        } dir;
    };

};

/* These two flags indicate whether the underlying host fd of `PAL_HANDLE` is readable and/or
 * writable respectively. If none of these is set, then the handle has no host-level fd. */
#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2
/* Set if an error was seen on this handle. */
#define PAL_HANDLE_FD_ERROR     4
/* Set if a hang-up was seen on this handle. */
#define PAL_HANDLE_FD_HANG_UP   8
