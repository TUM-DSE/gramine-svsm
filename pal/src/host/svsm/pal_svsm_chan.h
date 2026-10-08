/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * The shape of a vault-to-vault channel, for the PAL.
 *
 * A channel is a run of pages the monitor maps into two vaults at once: a
 * header the monitor writes and both sides read, one control page per side
 * carrying that side's ring indices, and the ring slots. After the grant
 * the monitor is out of the way - a message is a store by the sender and a
 * load by the receiver.
 *
 * This is the same layout tools/netsvc/src/mvchan.h describes for C vaults,
 * trimmed to what a socket needs. The two must agree; the monitor writes
 * the header (monitor/kernel/src/ipc/mod.rs) and is the one to follow.
 */
#ifndef PAL_SVSM_CHAN_H
#define PAL_SVSM_CHAN_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define PAL_CHAN_START_VADDR  0x80000000000UL   /* PML4 slot 16 */
#define PAL_CHAN_WINDOW_SHIFT 21
#define PAL_CHAN_WINDOW_SIZE  (1UL << PAL_CHAN_WINDOW_SHIFT)

/* The monitor's header, at the first page of a window. */
#define PAL_CHAN_HDR_MAGIC    0x31304e414843564dUL  /* "MVCHAN01" */
#define PAL_CHAN_HDR_RING(s)  (0x020 + (s) * 16)    /* slot, depth, off_pages, pages */
#define PAL_CHAN_HDR_STATE    0x040
#define PAL_CHAN_HDR_END(s)   (0x100 + (s) * 0x200)
#define PAL_CHAN_END_PID      0x004

/* The directory, window 0 of every vault that holds a channel. */
#define PAL_CHAN_DIR_VADDR    PAL_CHAN_START_VADDR
#define PAL_CHAN_DIR_SERIAL   0x018
#define PAL_CHAN_DIR_LIVE     0x040

/* WHO is in a lineage: sixteen serials in the region header, zero for an
 * empty slot (monitor ipc/mod.rs write_header, KIND_LINEAGE only). The PAL
 * reads it so that the LibOS never has to know the monitor's header format -
 * the same division as everywhere else here. */
#define PAL_CHAN_HDR_MEMBERS  0x500
#define PAL_CHAN_MAX_MEMBERS  16

/* Per-side control words. A producer owns TAIL on its own page, a consumer
 * HEAD; the LOCKs are how several holders of one side (a vault and the
 * workers it forked) take turns. */
#define PAL_CHAN_CTL_TAIL     0x000
#define PAL_CHAN_CTL_HEAD     0x040
#define PAL_CHAN_CTL_TX_LOCK  0x100
#define PAL_CHAN_CTL_RX_LOCK  0x140

/* Which of the peer's indices a park waits on. */
#define PAL_CHAN_ARM_TAIL 0u
#define PAL_CHAN_ARM_HEAD 1u

struct pal_chan_ring {
    volatile unsigned char* base;
    volatile uint64_t* lock;
    uint64_t serial;
    volatile uint32_t* tail;       /* mine, when producing */
    volatile uint32_t* head;       /* mine, when consuming */
    volatile uint32_t* peer_tail;
    volatile uint32_t* peer_head;
    unsigned char* slots;
    uint32_t slot, depth;
    unsigned long window;
};

/*
 * VOLATILE, both of them. Everything they read - the directory's live
 * bitmap, the region header, the geometry - is written by somebody else:
 * the monitor when it grants a channel, the peer when it goes. A plain
 * read is loop-invariant to a compiler that cannot see another agent, and
 * at -O3 it is hoisted: `accept` then woke on the monitor's notify, looked
 * at a copy of the bitmap taken before the channel existed, and went back
 * to sleep for another poll interval. One word, one iteration late, every
 * time.
 */
static inline uint64_t pal_chan_u64(unsigned long base, unsigned long off) {
    return *(const volatile uint64_t*)(base + off);
}

static inline uint32_t pal_chan_u32(unsigned long base, unsigned long off) {
    return *(const volatile uint32_t*)(base + off);
}

static inline unsigned long pal_chan_window_addr(unsigned long window) {
    return PAL_CHAN_START_VADDR + window * PAL_CHAN_WINDOW_SIZE;
}

/* expected:32 | which:4 | window:28 */
static inline uint64_t pal_chan_arm(unsigned long window, unsigned which, uint32_t expected) {
    return ((uint64_t)expected << 32) | ((uint64_t)(which & 0xF) << 28)
           | (uint64_t)(window & 0x0FFFFFFF);
}

/* Side 0 is the requester, side 1 the target. */
static inline void pal_chan_ring_init(struct pal_chan_ring* r, unsigned long win, int side,
                                      int producing) {
    unsigned char* base = (unsigned char*)win;
    int ring = producing ? (side == 0 ? 0 : 1) : (side == 0 ? 1 : 0);
    r->base   = base;
    r->window = (win - PAL_CHAN_START_VADDR) >> PAL_CHAN_WINDOW_SHIFT;
    r->slot   = pal_chan_u32(win, PAL_CHAN_HDR_RING(ring));
    r->depth  = pal_chan_u32(win, PAL_CHAN_HDR_RING(ring) + 4);
    r->slots  = base + (unsigned long)pal_chan_u32(win, PAL_CHAN_HDR_RING(ring) + 8) * 4096;
    unsigned char* mine = base + 4096 * (1 + side);
    unsigned char* peer = base + 4096 * (1 + !side);
    r->tail      = (volatile uint32_t*)(mine + PAL_CHAN_CTL_TAIL);
    r->head      = (volatile uint32_t*)(mine + PAL_CHAN_CTL_HEAD);
    r->lock      = (volatile uint64_t*)(mine + (producing ? PAL_CHAN_CTL_TX_LOCK
                                                          : PAL_CHAN_CTL_RX_LOCK));
    r->serial    = pal_chan_u64(PAL_CHAN_DIR_VADDR, PAL_CHAN_DIR_SERIAL);
    r->peer_tail = (volatile uint32_t*)(peer + PAL_CHAN_CTL_TAIL);
    r->peer_head = (volatile uint32_t*)(peer + PAL_CHAN_CTL_HEAD);
}

static inline bool pal_chan_present(const struct pal_chan_ring* r) {
    return r->slot != 0 && r->depth != 0;
}

static inline bool pal_chan_readable(const struct pal_chan_ring* r) {
    return pal_chan_present(r) && *r->head != *r->peer_tail;
}

static inline bool pal_chan_writable(const struct pal_chan_ring* r) {
    return pal_chan_present(r) && (*r->tail - *r->peer_head) < r->depth;
}

/* The peer's side is gone: the monitor rewrites the header when a side's
 * last holder drops, so this is readable long after the wake that carried
 * the news. */
static inline bool pal_chan_peer_gone(unsigned long win, int side) {
    return (pal_chan_u32(win, PAL_CHAN_HDR_STATE) & (1u << (1 - side))) != 0;
}

/* Take this side's lock for this direction, or give up. A holder that
 * cannot get in returns as it would for a full or empty ring. */
static inline int pal_chan_lock(struct pal_chan_ring* r) {
    uint64_t want = r->serial ? r->serial : 1;
    for (int spin = 0; spin < 200000; spin++) {
        uint64_t free_ = 0;
        if (__atomic_compare_exchange_n(r->lock, &free_, want, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return 0;
        __asm__ volatile("pause");
    }
    return -1;
}

static inline void pal_chan_unlock(struct pal_chan_ring* r) {
    __atomic_store_n(r->lock, 0, __ATOMIC_RELEASE);
}

/* One message: a 4-byte length then the bytes. Returns 0, or -1 when the
 * ring is full, empty, busy or malformed - the caller decides which of
 * those is EAGAIN and which is an error, because only it knows whether the
 * ring said "not yet" or "never". */
static inline int pal_chan_send(struct pal_chan_ring* r, const void* msg, uint32_t len) {
    if (!pal_chan_present(r) || r->slot < 4 || len > r->slot - 4)
        return -1;
    if (pal_chan_lock(r) != 0)
        return -1;
    uint32_t t = *r->tail, h = *r->peer_head;
    if (t - h >= r->depth) {
        pal_chan_unlock(r);
        return -1;
    }
    unsigned char* s = r->slots + (unsigned long)(t & (r->depth - 1)) * r->slot;
    memcpy(s + 4, msg, len);
    memcpy(s, &len, 4);
    __atomic_store_n(r->tail, t + 1, __ATOMIC_RELEASE);
    pal_chan_unlock(r);
    return 0;
}

static inline int pal_chan_recv(struct pal_chan_ring* r, void* msg, uint32_t max,
                                uint32_t* out_len) {
    if (!pal_chan_present(r) || r->slot < 4)
        return -1;
    if (pal_chan_lock(r) != 0)
        return -1;
    uint32_t h = *r->head, t = __atomic_load_n(r->peer_tail, __ATOMIC_ACQUIRE);
    if (h == t) {
        pal_chan_unlock(r);
        return -1;
    }
    const unsigned char* s = r->slots + (unsigned long)(h & (r->depth - 1)) * r->slot;
    uint32_t n;
    memcpy(&n, s, 4);
    if (n > max || n > r->slot - 4) {
        /* Does not advance the head: a malformed length is not something to
         * step over, and the caller is told the stream is broken. */
        pal_chan_unlock(r);
        return -2;
    }
    memcpy(msg, s + 4, n);
    if (out_len)
        *out_len = n;
    __atomic_store_n(r->head, h + 1, __ATOMIC_RELEASE);
    pal_chan_unlock(r);
    return 0;
}

#endif /* PAL_SVSM_CHAN_H */
