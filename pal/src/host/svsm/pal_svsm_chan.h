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
/* A word in this vault's own device window, the low 28 bits its offset (the
 * monitor's DEVICE_ARM, channel_calls.rs). */
#define PAL_CHAN_ARM_DEVICE 0xFu

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

/* May this arm go to a Park or a Sleep? Only the three kinds above: other
 * values of `which` are other words to the monitor (a lineage's own, a
 * child's), which a monitor that knows them refuses there with BAD_ARGS - and
 * one before them read any nonzero `which` as HEAD, watching a word nobody
 * meant. A thread may still hold another kind; the gather leaves it out and
 * calls the park partial. */
static inline bool pal_chan_arm_parkable(uint64_t arm) {
    unsigned which = (unsigned)(arm >> 28) & 0xF;
    return which == PAL_CHAN_ARM_TAIL || which == PAL_CHAN_ARM_HEAD
           || which == PAL_CHAN_ARM_DEVICE;
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
/* TWO PARTS, one message: a header and a body, concatenated into the slot.
 *
 * Exists so a caller that must prepend something - a mux frame header, a
 * datagram address - does not have to build a combined buffer first. That
 * buffer was the whole of the per-send malloc problem: a full-slot gather is
 * 16,380 bytes, the PAL slab's top level is 8,272 (slabmgr.h:86-98), so every
 * one fell to system_malloc and cost an mmap AND a munmap through the monitor.
 *
 * Both copies happen inside the ring lock, which is where the length check and
 * the tail publish already are, so there is no window in which a slot holds
 * half a message.
 *
 * `hdr` may be NULL with hdr_len 0, which makes this exactly pal_chan_send. */
static inline int pal_chan_send2(struct pal_chan_ring* r, const void* hdr, uint32_t hdr_len,
                                 const void* body, uint32_t body_len) {
    uint32_t len = hdr_len + body_len;
    if (!pal_chan_present(r) || r->slot < 4 || len > r->slot - 4 || len < hdr_len)
        return -1;                      /* the < hdr_len test catches overflow */
    if (pal_chan_lock(r) != 0)
        return -1;
    uint32_t t = *r->tail, h = *r->peer_head;
    if (t - h >= r->depth) {
        pal_chan_unlock(r);
        return -1;
    }
    unsigned char* s = r->slots + (unsigned long)(t & (r->depth - 1)) * r->slot;
    if (hdr_len)
        memcpy(s + 4, hdr, hdr_len);
    if (body_len)
        memcpy(s + 4 + hdr_len, body, body_len);
    memcpy(s, &len, 4);
    __atomic_store_n(r->tail, t + 1, __ATOMIC_RELEASE);
    pal_chan_unlock(r);
    return 0;
}

static inline int pal_chan_send(struct pal_chan_ring* r, const void* msg, uint32_t len) {
    return pal_chan_send2(r, NULL, 0, msg, len);
}

/* The head message's first `n` bytes, WITHOUT consuming it.
 *
 * This is what makes demultiplexing one channel among many connections
 * possible. A reader has to know which connection a message belongs to before
 * it can decide whether it has anywhere to put it - and if it does not, the
 * message must stay in the ring, because there is nowhere else to hold it. A
 * recv that consumed first would have to buffer for every connection at once.
 *
 * Returns 0 and fills `out_len` with the WHOLE message's length (not n), -1 if
 * the ring is empty or busy, -2 if the length at the head cannot be right. */
static inline int pal_chan_peek(struct pal_chan_ring* r, void* hdr, uint32_t n,
                                uint32_t* out_len) {
    if (!pal_chan_present(r) || r->slot < 4)
        return -1;
    if (pal_chan_lock(r) != 0)
        return -1;
    uint32_t h = *r->head, t = *r->peer_tail;
    if (h == t) {
        pal_chan_unlock(r);
        return -1;                      /* empty */
    }
    unsigned char* s = r->slots + (unsigned long)(h & (r->depth - 1)) * r->slot;
    uint32_t len;
    memcpy(&len, s, 4);
    if (len > r->slot - 4) {
        pal_chan_unlock(r);
        return -2;
    }
    if (n > len)
        n = len;
    if (n)
        memcpy(hdr, s + 4, n);
    *out_len = len;
    pal_chan_unlock(r);
    return 0;                           /* head NOT advanced */
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

/*
 * WHICH WINDOWS ARE A NEW CHANNEL (SHM-1, notes/shm/SHM-REVIEW.md).
 *
 * The directory's live bits say which windows are booked, one bit per
 * window, and a region of several windows sets them all. Only the region's
 * FIRST window starts with the monitor's header; window w+1 of a region
 * starts with region page 512, which for a netsvc-sized channel (65536 x 32
 * each way, 1027 pages, three windows) is in RING0 - bytes the requester
 * writes. Taking every live, unclaimed window that starts with "MVCHAN01"
 * therefore let a client, or an unlucky payload, plant a header with a
 * geometry of its choosing: the server then faulted on a "control page" that
 * was the client's ring, or wrote its replies at offsets the client chose.
 *
 * The directory does not mark region starts (SHM-4 would add a bitmap), so a
 * start is inferred the way tools/dpdksvc/rings/mvring_dir.h does it, never
 * from the bytes of a window alone:
 *   - a window this vault holds is held with its whole run (pal_chan_hold_run),
 *     so the later windows of a held channel are never candidates;
 *   - a live, unheld window whose predecessor is live and unheld is not a
 *     candidate either: in ascending order a region's first window is looked
 *     at before its middle, so such a window is the middle of a region not
 *     taken (or not takeable) yet;
 *   - a candidate's header must be the monitor's (magic, abi 1, KIND_CHANNEL)
 *     with a geometry inside the region and a window count that agrees with
 *     the page count and with the live bits.
 * The predecessor's bit is read AFTER the candidate's: a grant writes the
 * live words in ascending order, so a reader that sees the candidate's bit
 * set also sees its predecessor's.
 *
 * Loads only; nothing is consumed by looking. Takes the slot's base (window
 * 0, the directory) so that test/chan_accept_test.c runs the same code on an
 * imitation of the slot.
 */
#define PAL_CHAN_SLOT_WINDOWS    512u   /* IPC_WINDOWS */
#define PAL_CHAN_REGION_WINDOWS  256u   /* MAX_WINDOWS_PER_REGION (monitor ipc/mod.rs) */
#define PAL_CHAN_PAGE            4096u
#define PAL_CHAN_HDR_ABI         0x008
#define PAL_CHAN_HDR_REGION      0x010  /* region id u32, then epoch u32 */
#define PAL_CHAN_HDR_NPAGES      0x018
#define PAL_CHAN_HDR_WINDOWS     0x01C
#define PAL_CHAN_HDR_KIND        0x048
#define PAL_CHAN_KIND_CHANNEL    0u
#define PAL_CHAN_HDR_FIXED_PAGES 3u     /* HDR, CTL0, CTL1 */
/* The monitor's ok_ring (ipc/mod.rs, the endpoint policy check). */
#define PAL_CHAN_SLOT_MIN        64u
#define PAL_CHAN_SLOT_MAX        65536u
#define PAL_CHAN_DEPTH_MAX       4096u

/* Why a header was refused; 0 is a good one. */
enum {
    PAL_CHAN_HDR_OK = 0,
    PAL_CHAN_HDR_BAD_MAGIC,
    PAL_CHAN_HDR_BAD_ABI,
    PAL_CHAN_HDR_BAD_KIND,
    PAL_CHAN_HDR_BAD_WINDOWS,
    PAL_CHAN_HDR_BAD_NPAGES,
    PAL_CHAN_HDR_BAD_RING0,
    PAL_CHAN_HDR_BAD_RING1,
    PAL_CHAN_HDR_NO_RING,
    PAL_CHAN_HDR_OVERLAP,
};

static inline const char* pal_chan_hdr_why(int why) {
    switch (why) {
        case PAL_CHAN_HDR_OK:          return "ok";
        case PAL_CHAN_HDR_BAD_MAGIC:   return "no header";
        case PAL_CHAN_HDR_BAD_ABI:     return "abi";
        case PAL_CHAN_HDR_BAD_KIND:    return "kind";
        case PAL_CHAN_HDR_BAD_WINDOWS: return "window count";
        case PAL_CHAN_HDR_BAD_NPAGES:  return "page count";
        case PAL_CHAN_HDR_BAD_RING0:   return "ring 0 geometry";
        case PAL_CHAN_HDR_BAD_RING1:   return "ring 1 geometry";
        case PAL_CHAN_HDR_NO_RING:     return "no ring";
        case PAL_CHAN_HDR_OVERLAP:     return "rings overlap";
    }
    return "?";
}

static inline bool pal_chan_pow2(uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

/* One ring's geometry against the region's page count. An absent direction
 * is all zeros but its offset (the monitor still sets off_pages). */
static inline bool pal_chan_ring_geom_ok(uint32_t slot, uint32_t depth, uint32_t off,
                                         uint32_t pages, uint32_t npages, bool* present) {
    *present = false;
    if (slot == 0 && depth == 0)
        return pages == 0;
    if (slot < PAL_CHAN_SLOT_MIN || slot > PAL_CHAN_SLOT_MAX || !pal_chan_pow2(slot)
        || depth > PAL_CHAN_DEPTH_MAX || !pal_chan_pow2(depth))
        return false;
    uint64_t need = ((uint64_t)slot * depth + PAL_CHAN_PAGE - 1) / PAL_CHAN_PAGE;
    if ((uint64_t)pages < need)
        return false;
    if (off < PAL_CHAN_HDR_FIXED_PAGES || (uint64_t)off + pages > npages)
        return false;
    *present = true;
    return true;
}

/*
 * Is the page at `hdr`, the first page of window `w`, a channel header this
 * vault may build rings from? Reads that page only, each field once, and
 * forms no pointer: every offset pal_chan_ring_init will add to the window
 * is checked to stay inside the region. Returns PAL_CHAN_HDR_OK and the
 * region's window count, or the reason.
 *
 * Only meaningful at a region's first window, whose header page the monitor
 * maps read-only to both sides; at any other window these are a peer's
 * bytes, which is why pal_chan_accept_scan never asks about one.
 */
static inline int pal_chan_hdr_check(unsigned long hdr, unsigned w, uint32_t* out_windows) {
    if (pal_chan_u64(hdr, 0) != PAL_CHAN_HDR_MAGIC)
        return PAL_CHAN_HDR_BAD_MAGIC;
    if (pal_chan_u32(hdr, PAL_CHAN_HDR_ABI) != 1)
        return PAL_CHAN_HDR_BAD_ABI;
    if (pal_chan_u32(hdr, PAL_CHAN_HDR_KIND) != PAL_CHAN_KIND_CHANNEL)
        return PAL_CHAN_HDR_BAD_KIND;
    uint32_t n  = pal_chan_u32(hdr, PAL_CHAN_HDR_WINDOWS);
    uint32_t np = pal_chan_u32(hdr, PAL_CHAN_HDR_NPAGES);
    if (n == 0 || n > PAL_CHAN_REGION_WINDOWS || w == 0
        || (uint64_t)w + n > PAL_CHAN_SLOT_WINDOWS)
        return PAL_CHAN_HDR_BAD_WINDOWS;
    uint64_t bytes = (uint64_t)np * PAL_CHAN_PAGE;
    if (np < PAL_CHAN_HDR_FIXED_PAGES || bytes > ((uint64_t)n << PAL_CHAN_WINDOW_SHIFT)
        || bytes <= ((uint64_t)(n - 1) << PAL_CHAN_WINDOW_SHIFT))
        return PAL_CHAN_HDR_BAD_NPAGES;
    uint32_t g[2][4];
    for (int s = 0; s < 2; s++)
        for (int i = 0; i < 4; i++)
            g[s][i] = pal_chan_u32(hdr, PAL_CHAN_HDR_RING(s) + 4 * i);
    bool p0, p1;
    if (!pal_chan_ring_geom_ok(g[0][0], g[0][1], g[0][2], g[0][3], np, &p0))
        return PAL_CHAN_HDR_BAD_RING0;
    if (!pal_chan_ring_geom_ok(g[1][0], g[1][1], g[1][2], g[1][3], np, &p1))
        return PAL_CHAN_HDR_BAD_RING1;
    if (!p0 && !p1)
        return PAL_CHAN_HDR_NO_RING;
    if (p0 && p1 && g[0][2] < g[1][2] + g[1][3] && g[1][2] < g[0][2] + g[0][3])
        return PAL_CHAN_HDR_OVERLAP;
    if (out_windows)
        *out_windows = n;
    return PAL_CHAN_HDR_OK;
}

static inline bool pal_chan_bit(const uint64_t* bm, unsigned w) {
    return w < PAL_CHAN_SLOT_WINDOWS && ((bm[w / 64] >> (w % 64)) & 1);
}

static inline bool pal_chan_dir_live(unsigned long slot_base, unsigned w) {
    if (w == 0 || w >= PAL_CHAN_SLOT_WINDOWS)
        return false;
    return (pal_chan_u64(slot_base, PAL_CHAN_DIR_LIVE + (w / 64) * 8) >> (w % 64)) & 1;
}

/* Hold a channel's whole run of windows in `held` (one bit per window), and
 * remember the run's length at its first window so the release frees the
 * same run. */
static inline void pal_chan_hold_run(uint64_t* held, uint16_t* run_len, unsigned w, unsigned n) {
    if (w == 0 || w >= PAL_CHAN_SLOT_WINDOWS)
        return;
    if (n == 0)
        n = 1;
    if (w + n > PAL_CHAN_SLOT_WINDOWS)
        n = PAL_CHAN_SLOT_WINDOWS - w;
    for (unsigned i = 0; i < n; i++)
        held[(w + i) / 64] |= 1UL << ((w + i) % 64);
    run_len[w] = (uint16_t)n;
}

static inline void pal_chan_release_run(uint64_t* held, uint16_t* run_len, unsigned w) {
    if (w == 0 || w >= PAL_CHAN_SLOT_WINDOWS)
        return;
    unsigned n = run_len[w] ? run_len[w] : 1;
    if (w + n > PAL_CHAN_SLOT_WINDOWS)
        n = PAL_CHAN_SLOT_WINDOWS - w;
    for (unsigned i = 0; i < n; i++)
        held[(w + i) / 64] &= ~(1UL << ((w + i) % 64));
    run_len[w] = 0;
}

/* Told about a candidate whose header was refused: the window, the reason,
 * and the header's region-id/epoch word (to tell one refusal from the next). */
typedef void (*pal_chan_reject_fn)(unsigned w, int why, uint64_t tag);

/*
 * The first window of a channel granted to this vault that it does not hold
 * yet, or 0; its window count in *out_windows. `held` is this vault's own
 * record (PAL_CHAN_SLOT_WINDOWS bits) of the windows it holds, either side.
 * A run that is not yet wholly live is skipped silently (a grant publishes
 * the live words one at a time); a refused header goes to `reject`.
 */
static inline unsigned pal_chan_accept_scan(unsigned long slot_base, const uint64_t* held,
                                            uint32_t* out_windows, pal_chan_reject_fn reject) {
    for (unsigned w = 1; w < PAL_CHAN_SLOT_WINDOWS; w++) {
        if (pal_chan_bit(held, w) || !pal_chan_dir_live(slot_base, w))
            continue;
        if (w > 1 && pal_chan_dir_live(slot_base, w - 1) && !pal_chan_bit(held, w - 1))
            continue;                    /* the middle of a region not taken */
        unsigned long hdr = slot_base + ((unsigned long)w << PAL_CHAN_WINDOW_SHIFT);
        uint32_t n = 0;
        int why = pal_chan_hdr_check(hdr, w, &n);
        if (why != PAL_CHAN_HDR_OK) {
            if (reject)
                reject(w, why, pal_chan_u64(hdr, PAL_CHAN_HDR_REGION));
            continue;
        }
        bool whole = true;
        for (unsigned i = 1; i < n && whole; i++)
            whole = !pal_chan_bit(held, w + i) && pal_chan_dir_live(slot_base, w + i);
        if (!whole)
            continue;
        if (out_windows)
            *out_windows = n;
        return w;
    }
    return 0;
}

#endif /* PAL_SVSM_CHAN_H */
