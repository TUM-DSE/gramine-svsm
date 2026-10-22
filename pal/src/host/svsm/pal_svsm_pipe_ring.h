/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * One direction of a pipe, as several processes on several processors share it.
 *
 * A pipe pair in the lineage arena (pal_pipes.c) is shared memory: a forked
 * child holds the same ends as its parent, and the two run at the same time on
 * different processors - a RESIDENT child on the service core, its parent on
 * the processor of the invoke it is in. The ring was written for one process
 * on one processor and kept `head` and `used`, with the writer doing
 * `used += n` and the reader `used -= n`. Two processors doing that to one word
 * lose an update: a write that landed between the reader's load and its store
 * of `used` was forgotten (its bytes were later overwritten), or a read that
 * landed in the writer's was (its bytes read twice). Nothing locked either
 * end, either, so a parent and a child writing the same pipe - a shell and its
 * builtins, both on stdout - wrote over each other at the same `head + used`.
 *
 * So the ring is single-producer single-consumer in the classical way, and
 * each END has a lock so that many processes can be that single producer or
 * consumer by turns:
 *
 *  - `tail` counts bytes ever written and only the producer stores it; `head`
 *    counts bytes ever read and only the consumer stores it. Both run free and
 *    wrap at 2^32, which the ring size divides, so `tail - head` is what is in
 *    the ring and neither side ever writes the other's word. The producer
 *    publishes with a release store of `tail` after its copy, the consumer
 *    with one of `head` after its copy, and each acquires the other's word
 *    before touching the bytes it guards.
 *  - `wlock` is held by whoever is producing, `rlock` by whoever is consuming.
 *    Each holds the holder's SERIAL, not a bare 1: a holder the monitor
 *    deletes in the middle of a copy runs nothing more, ever, and a lock that
 *    said only "taken" would be taken for good. A waiter that has spun out its
 *    bound reads the serial and, if the monitor no longer lists it among the
 *    lineage's members, takes the lock over. Never from a member that is still
 *    listed, however long it holds it: a live holder may be in the middle of a
 *    copy, and a holder that is only slow costs a wait, while a steal from it
 *    costs the stream. Taking over a dead holder's lock is safe because the
 *    state it guards is only ever changed by one store: a copy the holder did
 *    not publish is bytes past `tail` (or before `head`) that nobody reads.
 *  - `rwait` and `wwait` count the readers waiting for `tail` to move and the
 *    writers waiting for `head` to. Counts, not flags: two readers in two
 *    processes, and one of them done waiting, must still leave the other's
 *    wake wanted. Nothing reads them to wake anybody yet - a wake across
 *    processes needs a monitor call that does not exist yet - but they are
 *    kept, with the fences that make them usable, so that the doorbell is an
 *    addition and not a change to this protocol.
 *
 * A lock is taken and dropped inside one call of PAL text, around one copy,
 * and nothing between the two can block or yield - which is what makes a
 * holder that is listed always a holder that will let go.
 *
 * Freestanding on purpose: no PAL type and no PAL call, so a host test can
 * build THIS file with pthreads and hammer the code the PAL runs (MicroVault
 * tools/fn/test/pipe_ring). What only the PAL knows - its own serial and who
 * is still a member - comes in as arguments.
 */
#ifndef PAL_SVSM_PIPE_RING_H
#define PAL_SVSM_PIPE_RING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* A power of two, so that free-running 32-bit indices wrap onto it. */
#define PAL_PIPE_RING_SIZE 4096u
_Static_assert((PAL_PIPE_RING_SIZE & (PAL_PIPE_RING_SIZE - 1)) == 0,
               "pipe ring size must divide 2^32");

/* How long a waiter spins on a held end before asking whether its holder still
 * exists: pal_chan_lock's bound, for the same kind of lock. A copy is at most
 * PAL_PIPE_RING_SIZE bytes, so a holder that is running lets go in a tiny
 * fraction of this; one that has not is not running. */
#define PAL_PIPE_LOCK_SPINS 200000u

/* The tag of a holder with no serial to give. Never taken over: nobody can say
 * whether it is still alive. A process holding an arena pair always has a
 * serial (the region and the directory come together), so this is a guard and
 * not a path. */
#define PAL_PIPE_LOCK_ANON UINT64_MAX

struct pal_svsm_pipe_ring {
    uint32_t head;      /* bytes ever read; stored by the consumer only */
    uint32_t tail;      /* bytes ever written; stored by the producer only */
    uint32_t rwait;     /* readers waiting for `tail` to move */
    uint32_t wwait;     /* writers waiting for `head` to move */
    uint64_t rlock;     /* 0, or the serial of the process consuming */
    uint64_t wlock;     /* 0, or the serial of the process producing */
    char     data[PAL_PIPE_RING_SIZE];
};

enum pal_pipe_lock_result {
    PAL_PIPE_LOCK_BUSY = 0,     /* a listed member holds it: look again later */
    PAL_PIPE_LOCK_TAKEN,
    PAL_PIPE_LOCK_STOLEN,       /* taken over from a holder the monitor no longer lists */
};

/* Is `serial` still a member of the lineage? The PAL answers from the roster
 * in the region header, which only the monitor writes. */
typedef bool (*pal_pipe_alive_fn)(uint64_t serial, void* arg);

static inline void pal_pipe_pause(void) {
    __asm__ volatile("pause" ::: "memory");
}

/*
 * Take one end's lock (`&r->wlock` or `&r->rlock`) for `self`.
 *
 * BUSY after the spin bound when the holder is still listed - including when
 * the holder is this process, which a single-processor process can only be
 * through a bug, and a bug is not a reason to break the stream. The caller
 * then treats the end as not ready and waits, bounded, as it does for an
 * empty or a full ring. STOLEN puts the dead holder's serial in `*out_from`.
 */
static inline enum pal_pipe_lock_result pal_pipe_lock(uint64_t* lock, uint64_t self,
                                                      pal_pipe_alive_fn alive, void* arg,
                                                      uint64_t* out_from) {
    uint64_t want = self ? self : PAL_PIPE_LOCK_ANON;
    for (uint32_t spin = 0; spin < PAL_PIPE_LOCK_SPINS; spin++) {
        uint64_t free_ = 0;
        /* Look before the CAS: a waiter that only CASes keeps the line in
         * its own cache, exclusively, and the holder's release has to take it
         * back for every round. */
        if (__atomic_load_n(lock, __ATOMIC_RELAXED) == 0
                && __atomic_compare_exchange_n(lock, &free_, want, false, __ATOMIC_ACQUIRE,
                                               __ATOMIC_RELAXED))
            return PAL_PIPE_LOCK_TAKEN;
        pal_pipe_pause();
    }
    uint64_t holder = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
    if (holder == 0) {
        uint64_t free_ = 0;
        return __atomic_compare_exchange_n(lock, &free_, want, false, __ATOMIC_ACQUIRE,
                                           __ATOMIC_RELAXED)
               ? PAL_PIPE_LOCK_TAKEN : PAL_PIPE_LOCK_BUSY;
    }
    if (holder == want || holder == PAL_PIPE_LOCK_ANON || !alive || alive(holder, arg))
        return PAL_PIPE_LOCK_BUSY;
    /* The roster was read AFTER the lock word. A serial is never issued twice
     * and a process the monitor has dropped never runs again, so a lock that
     * still says `holder` now is the dead holder's, and the CAS fails only if
     * another waiter took it over first. */
    if (!__atomic_compare_exchange_n(lock, &holder, want, false, __ATOMIC_ACQUIRE,
                                     __ATOMIC_RELAXED))
        return PAL_PIPE_LOCK_BUSY;
    if (out_from)
        *out_from = holder;
    return PAL_PIPE_LOCK_STOLEN;
}

/* Let go of a lock taken with the same `self`. False if it was not ours any
 * more - taken over, which happens only to a holder the monitor no longer
 * lists, so a false here is something to say out loud. */
static inline bool pal_pipe_unlock(uint64_t* lock, uint64_t self) {
    uint64_t mine = self ? self : PAL_PIPE_LOCK_ANON;
    return __atomic_compare_exchange_n(lock, &mine, 0, false, __ATOMIC_RELEASE,
                                       __ATOMIC_RELAXED);
}

/*
 * How many bytes are in the ring, without a lock: what poll asks.
 *
 * `tail` read between two equal reads of `head`, so the answer is exact for
 * the instant of that read. A single pair of loads is not: tail-then-head can
 * see a head that has passed the tail it read (another writer wrote and the
 * reader consumed in between), and head-then-tail more than a ring's worth -
 * both of which read as "full". Bounded, since a reader moving `head` on every
 * round is a reader that is making progress anyway.
 */
static inline uint32_t pal_pipe_ring_used(const struct pal_svsm_pipe_ring* r) {
    uint32_t h = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    uint32_t used = 0;
    for (int round = 0; round < 64; round++) {
        uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
        uint32_t h2 = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
        used = t - h;
        if (h2 == h)
            break;
        h = h2;
    }
    /* More than a ring's worth is a ring some member scribbled on. Clamped,
     * so that the masks below are all that stands between it and the bytes
     * next to the ring - which they are anyway. */
    return used > PAL_PIPE_RING_SIZE ? PAL_PIPE_RING_SIZE : used;
}

static inline uint32_t pal_pipe_ring_room(const struct pal_svsm_pipe_ring* r) {
    return PAL_PIPE_RING_SIZE - pal_pipe_ring_used(r);
}

/* Copy in at most `len` bytes and publish them. The caller holds `wlock`. */
static inline size_t pal_pipe_ring_write(struct pal_svsm_pipe_ring* r, const void* buf,
                                         size_t len) {
    uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    /* The consumer's release of `head` comes after its copy out: the bytes
     * below `head` are free to overwrite once this has seen it. */
    uint32_t h = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    uint32_t used = t - h;
    if (used >= PAL_PIPE_RING_SIZE)
        return 0;
    size_t room = PAL_PIPE_RING_SIZE - used;
    if (len > room)
        len = room;
    uint32_t at = t & (PAL_PIPE_RING_SIZE - 1);
    size_t first = PAL_PIPE_RING_SIZE - at;
    if (first > len)
        first = len;
    memcpy(r->data + at, buf, first);
    memcpy(r->data, (const char*)buf + first, len - first);
    __atomic_store_n(&r->tail, t + (uint32_t)len, __ATOMIC_RELEASE);
    return len;
}

/* Copy out at most `len` bytes and give their room back. The caller holds
 * `rlock`. */
static inline size_t pal_pipe_ring_read(struct pal_svsm_pipe_ring* r, void* buf, size_t len) {
    uint32_t h = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    /* The producer's release of `tail` comes after its copy in. */
    uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    uint32_t avail = t - h;
    if (avail > PAL_PIPE_RING_SIZE)
        avail = PAL_PIPE_RING_SIZE;     /* scribbled on: see pal_pipe_ring_used */
    if (len > avail)
        len = avail;
    uint32_t at = h & (PAL_PIPE_RING_SIZE - 1);
    size_t first = PAL_PIPE_RING_SIZE - at;
    if (first > len)
        first = len;
    memcpy(buf, r->data + at, first);
    memcpy((char*)buf + first, r->data, len - first);
    __atomic_store_n(&r->head, h + (uint32_t)len, __ATOMIC_RELEASE);
    return len;
}

/*
 * The waiter counts (`&r->rwait` for a reader, `&r->wwait` for a writer).
 *
 * The protocol is the eventcount's, with a full fence on both sides:
 *   waiter: pal_pipe_wait_begin; test the ring again; block only if it is
 *           still not ready; pal_pipe_wait_end.
 *   waker:  publish (the release store of `tail` or `head`);
 *           pal_pipe_wake_wanted; ring the doorbell if it says so.
 * Either the waiter's second test sees the publish, or the waker sees the
 * count - never neither, which a release/acquire pair alone does not give
 * (each side's load could be ordered before its own store).
 *
 * A waiter that dies counted leaves the count high for good. That costs a
 * doorbell nobody needed, never one somebody did; and the count never goes
 * below zero, so no waiter's increment is cancelled by somebody else's
 * decrement.
 */
static inline void pal_pipe_wait_begin(uint32_t* waiters) {
    __atomic_add_fetch(waiters, 1, __ATOMIC_SEQ_CST);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}

static inline void pal_pipe_wait_end(uint32_t* waiters) {
    uint32_t v = __atomic_load_n(waiters, __ATOMIC_RELAXED);
    while (v && !__atomic_compare_exchange_n(waiters, &v, v - 1, false, __ATOMIC_RELEASE,
                                             __ATOMIC_RELAXED))
        ;
}

static inline bool pal_pipe_wake_wanted(const uint32_t* waiters) {
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return __atomic_load_n(waiters, __ATOMIC_RELAXED) != 0;
}

#endif /* PAL_SVSM_PIPE_RING_H */
