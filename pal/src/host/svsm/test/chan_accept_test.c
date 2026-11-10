/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Host-side test of the PAL's accept scan and header check (SHM-1,
 * pal_svsm_chan.h pal_chan_accept_scan / pal_chan_hdr_check /
 * pal_chan_hold_run): the same inline code the PAL runs, on an imitation of
 * a vault's IPC slot.
 *
 * The slot is 512 windows of 2 MiB at the PAL's own address, reserved PROT_NONE. Only what the monitor
 * would have mapped AND what the test means the scan to read is made
 * readable: the directory page (window 0) and the first page of each window
 * that holds something - a region's header, or a planted fake at a later
 * window's start. Every other page stays PROT_NONE, so a scan or a check
 * that reads a byte it should not is a SIGSEGV, and the test dies rather
 * than passing.
 *
 * The monitor's side is played as monitor/kernel src/ipc/mod.rs does it:
 * geometry (Geom::of, off_pages 3 and 3 + pages0, windows = ceil(npages *
 * 4 KiB / 2 MiB)), write_header's fields, and write_directory's live bits
 * from the book - the lowest free run from window 1 (find_run).
 *
 *   make -C pal/src/host/svsm/test check
 */
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../pal_svsm_chan.h"

#define WIN       (1UL << PAL_CHAN_WINDOW_SHIFT)
#define SLOT_SIZE ((unsigned long)PAL_CHAN_SLOT_WINDOWS * WIN)

static unsigned char* g_slot;
static uint16_t g_book[PAL_CHAN_SLOT_WINDOWS];   /* region id + 1, monitor's */
static uint32_t g_epoch = 1;
static int g_fail, g_pass;

/* The PAL's own records, as pal_sockets.c keeps them. */
static uint64_t g_held[PAL_CHAN_SLOT_WINDOWS / 64];
static uint16_t g_run[PAL_CHAN_SLOT_WINDOWS];

static unsigned g_rej_n, g_rej_w;
static int g_rej_why;
static void on_reject(unsigned w, int why, uint64_t tag) {
    (void)tag;
    g_rej_n++;
    g_rej_w   = w;
    g_rej_why = why;
}

#define CHECK(cond, ...)                                            \
    do {                                                            \
        if (cond) {                                                 \
            g_pass++;                                               \
        } else {                                                    \
            g_fail++;                                               \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);    \
            fprintf(stderr, __VA_ARGS__);                           \
            fprintf(stderr, "\n");                                  \
        }                                                           \
    } while (0)

static unsigned char* win_addr(unsigned w) {
    return g_slot + (unsigned long)w * WIN;
}

static void page_rw(void* p) {
    if (mprotect(p, PAL_CHAN_PAGE, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
        exit(2);
    }
}

static void page_ro(void* p) {
    if (mprotect(p, PAL_CHAN_PAGE, PROT_READ) != 0) {
        perror("mprotect");
        exit(2);
    }
}

static void page_none(void* p) {
    if (mprotect(p, PAL_CHAN_PAGE, PROT_NONE) != 0) {
        perror("mprotect");
        exit(2);
    }
}

static void put32(unsigned char* p, unsigned off, uint32_t v) { memcpy(p + off, &v, 4); }
static void put64(unsigned char* p, unsigned off, uint64_t v) { memcpy(p + off, &v, 8); }

/* write_directory: the live bits from the book. One word at a time, in
 * ascending order, as the monitor stores them. */
static void write_directory(void) {
    uint64_t live[8] = {0};
    for (unsigned w = 0; w < PAL_CHAN_SLOT_WINDOWS; w++)
        if (g_book[w])
            live[w / 64] |= 1UL << (w % 64);
    for (unsigned i = 0; i < 8; i++)
        put64(g_slot, PAL_CHAN_DIR_LIVE + i * 8, live[i]);
}

struct geom { uint32_t slot, depth, off, pages; };

static struct geom geom_of(uint32_t slot, uint32_t depth) {
    struct geom g = {slot, depth, 0, 0};
    g.pages = (uint32_t)(((uint64_t)slot * depth + 4095) / 4096);
    return g;
}

/* find_run: the lowest run of k free windows from window 1. */
static unsigned find_run(unsigned k) {
    for (unsigned start = 1; start + k <= PAL_CHAN_SLOT_WINDOWS;) {
        unsigned w = start;
        while (w < start + k && !g_book[w])
            w++;
        if (w == start + k)
            return start;
        start = w + 1;
    }
    return 0;
}

/* A grant to this vault: header first, then the book and the directory.
 * Returns the region's first window; *nwin its window count. The header page
 * is left read-only (as the monitor maps it), the rest of the region
 * PROT_NONE except what a caller opens. */
static unsigned grant(uint32_t slot_in, uint32_t depth_in, uint32_t slot_out, uint32_t depth_out,
                      unsigned* nwin, bool publish) {
    struct geom g[2] = {geom_of(slot_in, depth_in), geom_of(slot_out, depth_out)};
    if (!slot_in)
        g[0] = (struct geom){0, 0, 0, 0};
    if (!slot_out)
        g[1] = (struct geom){0, 0, 0, 0};
    g[0].off = 3;
    g[1].off = 3 + g[0].pages;
    uint32_t npages = 3 + g[0].pages + g[1].pages;
    unsigned n = (unsigned)(((uint64_t)npages * 4096 + WIN - 1) / WIN);
    unsigned w = find_run(n);
    if (!w) {
        fprintf(stderr, "no run of %u windows\n", n);
        exit(2);
    }
    static uint16_t region = 0;
    region++;
    unsigned char* h = win_addr(w);
    page_rw(h);
    memset(h, 0, PAL_CHAN_PAGE);
    put64(h, 0x000, PAL_CHAN_HDR_MAGIC);
    put32(h, 0x008, 1);
    put32(h, 0x00C, (slot_in ? 1 : 0) | (slot_out ? 2 : 0));
    put32(h, 0x010, region);
    put32(h, 0x014, g_epoch++);
    put32(h, 0x018, npages);
    put32(h, 0x01C, n);
    for (int s = 0; s < 2; s++) {
        put32(h, 0x020 + s * 16, g[s].slot);
        put32(h, 0x024 + s * 16, g[s].depth);
        put32(h, 0x028 + s * 16, g[s].off);
        put32(h, 0x02C + s * 16, g[s].pages);
    }
    put32(h, 0x048, PAL_CHAN_KIND_CHANNEL);
    page_ro(h);
    for (unsigned i = 0; i < n; i++)
        g_book[w + i] = region;
    if (publish)
        write_directory();
    *nwin = n;
    return w;
}

/* drop_mapper on this vault's side: unbook, rewrite the directory. */
static void unbook(unsigned w, unsigned n) {
    for (unsigned i = 0; i < n; i++)
        g_book[w + i] = 0;
    write_directory();
    page_none(win_addr(w));
}

/* A peer's bytes at the start of window w (a later window of a region): a
 * header with the geometry the peer chooses. Window w's first page becomes
 * readable, as a ring page of the region is to the server. */
static void plant_fake(unsigned w, uint32_t windows, uint32_t off_pages) {
    unsigned char* p = win_addr(w);
    page_rw(p);
    memset(p, 0, PAL_CHAN_PAGE);
    put64(p, 0x000, PAL_CHAN_HDR_MAGIC);
    put32(p, 0x008, 1);
    put32(p, 0x018, 3 + 16);
    put32(p, 0x01C, windows);
    put32(p, 0x020, 64);         /* ring 0: slot 64, depth 64, at off_pages */
    put32(p, 0x024, 64);
    put32(p, 0x028, off_pages);
    put32(p, 0x02C, 1);
    put32(p, 0x048, 0);
}

static unsigned scan(uint32_t* n) {
    return pal_chan_accept_scan((unsigned long)g_slot, g_held, n, on_reject);
}

/* What accept_find was before SHM-1: any live, unclaimed window starting
 * with the magic, and only the first window claimed. Reads the window's
 * first page, which is why the planted-fake cases open it. */
static uint64_t g_old_claimed[8];
static unsigned old_accept_find(void) {
    for (unsigned w = 1; w < PAL_CHAN_SLOT_WINDOWS; w++) {
        uint64_t live = pal_chan_u64((unsigned long)g_slot, PAL_CHAN_DIR_LIVE + (w / 64) * 8);
        if (!(live & (1UL << (w % 64))) || (g_old_claimed[w / 64] & (1UL << (w % 64))))
            continue;
        if (pal_chan_u64((unsigned long)win_addr(w), 0) != PAL_CHAN_HDR_MAGIC)
            continue;
        return w;
    }
    return 0;
}

static void reset(void) {
    for (unsigned w = 1; w < PAL_CHAN_SLOT_WINDOWS; w++) {
        if (g_book[w] || pal_chan_bit(g_held, w))
            page_none(win_addr(w));
    }
    memset(g_book, 0, sizeof g_book);
    memset(g_held, 0, sizeof g_held);
    memset(g_run, 0, sizeof g_run);
    memset(g_old_claimed, 0, sizeof g_old_claimed);
    g_rej_n = 0;
    write_directory();
}

/* ---- cases ---- */

static void t_single_and_multi(void) {
    reset();
    unsigned n1, n3;
    unsigned w1 = grant(4096, 16, 4096, 16, &n1, true);       /* 3 + 16 + 16 pages: 1 window */
    unsigned w3 = grant(65536, 32, 65536, 32, &n3, true);     /* netsvc: 1027 pages, 3 windows */
    CHECK(n1 == 1 && n3 == 3, "geometry: %u %u windows", n1, n3);
    uint32_t n = 0;
    unsigned w = scan(&n);
    CHECK(w == w1 && n == 1, "single-window channel accepted (got %u/%u, want %u/1)", w, n, w1);
    pal_chan_hold_run(g_held, g_run, w, n);
    w = scan(&n);
    CHECK(w == w3 && n == 3, "multi-window channel accepted (got %u/%u, want %u/3)", w, n, w3);
    pal_chan_hold_run(g_held, g_run, w, n);
    w = scan(&n);
    CHECK(w == 0, "nothing after both are held (got %u)", w);
    CHECK(g_rej_n == 0, "no refusals for good channels (%u)", g_rej_n);
    /* All three windows of the multi-window one are held. */
    CHECK(pal_chan_bit(g_held, w3) && pal_chan_bit(g_held, w3 + 1) && pal_chan_bit(g_held, w3 + 2)
          && !pal_chan_bit(g_held, w3 + 3), "run held whole");
    pal_chan_release_run(g_held, g_run, w3);
    CHECK(!pal_chan_bit(g_held, w3) && !pal_chan_bit(g_held, w3 + 1)
          && !pal_chan_bit(g_held, w3 + 2) && pal_chan_bit(g_held, w1), "run released whole");
}

/* SHM-1 itself: a client writes a header at the start of its window w+1. */
static void t_planted_fake_later_window(void) {
    reset();
    unsigned n3;
    unsigned w3 = grant(65536, 32, 65536, 32, &n3, true);
    plant_fake(w3 + 1, 1, 0x7fff0000u);       /* geometry pointing far outside */
    plant_fake(w3 + 2, 1, 3);

    /* The old code took the first window, claimed only it, and then took the
     * fake: this is the bug the test is about. */
    unsigned o = old_accept_find();
    CHECK(o == w3, "old: first window first (%u)", o);
    g_old_claimed[o / 64] |= 1UL << (o % 64);
    o = old_accept_find();
    CHECK(o == w3 + 1, "old: the planted fake at w+1 was accepted (%u) - the test reproduces SHM-1",
          o);

    uint32_t n = 0;
    unsigned w = scan(&n);
    CHECK(w == w3 && n == 3, "new: the real channel (%u/%u)", w, n);
    pal_chan_hold_run(g_held, g_run, w, n);
    w = scan(&n);
    CHECK(w == 0, "new: the planted fake at w+1/w+2 is not accepted (got %u)", w);
    CHECK(g_rej_n == 0, "new: the fake is never even examined (%u refusals)", g_rej_n);

    /* Before the real one is held: still the real one, never the fake. */
    memset(g_held, 0, sizeof g_held);
    w = scan(&n);
    CHECK(w == w3, "new, unheld: the first window, not the fake (%u)", w);
}

/* The fake behind a first window whose header is bad: the region is not
 * taken, and its middle is not mistaken for a start. */
static void t_fake_behind_refused_first(void) {
    reset();
    unsigned n3;
    unsigned w3 = grant(65536, 32, 65536, 32, &n3, true);
    unsigned char* h = win_addr(w3);
    page_rw(h);
    put32(h, PAL_CHAN_HDR_ABI, 2);
    page_ro(h);
    plant_fake(w3 + 1, 1, 3);
    uint32_t n = 0;
    unsigned w = scan(&n);
    CHECK(w == 0, "nothing accepted (%u)", w);
    CHECK(g_rej_n == 1 && g_rej_w == w3 && g_rej_why == PAL_CHAN_HDR_BAD_ABI,
          "one refusal, at the first window, for abi (%u at %u why %d)", g_rej_n, g_rej_w,
          g_rej_why);
}

/* A held OUTBOUND channel (this vault connected): its later windows start
 * with the far end's ring - never an arrival. */
static void t_outbound_held_run(void) {
    reset();
    unsigned n3, n1;
    unsigned wo = grant(65536, 32, 65536, 32, &n3, true);
    uint32_t n = 0;
    CHECK(pal_chan_hdr_check((unsigned long)win_addr(wo), wo, &n) == PAL_CHAN_HDR_OK && n == 3,
          "connect side's check");
    pal_chan_hold_run(g_held, g_run, wo, n);
    plant_fake(wo + 1, 1, 3);
    plant_fake(wo + 2, 1, 3);
    unsigned wi = grant(4096, 16, 4096, 16, &n1, true);       /* an arrival behind it */
    unsigned w = scan(&n);
    CHECK(w == wi && n == 1, "the arrival, not the outbound's later windows (%u, want %u)", w, wi);
}

static void t_partial_publish(void) {
    reset();
    /* Fill windows so that the next 3-window region straddles the first and
     * second live words: 62, 63, 64. */
    unsigned n;
    for (int i = 0; i < 61; i++)
        grant(4096, 16, 4096, 16, &n, false);
    for (unsigned w = 1; w <= 61; w++)
        pal_chan_hold_run(g_held, g_run, w, 1);
    unsigned w3 = grant(65536, 32, 65536, 32, &n, false);
    CHECK(w3 == 62 && n == 3, "straddling region at %u/%u", w3, n);
    /* The monitor has stored live word 0 but not yet word 1. */
    uint64_t live0 = 0;
    for (unsigned w = 0; w < 64; w++)
        if (g_book[w])
            live0 |= 1UL << w;
    put64(g_slot, PAL_CHAN_DIR_LIVE, live0);
    uint32_t got = 0;
    unsigned w = scan(&got);
    CHECK(w == 0 && g_rej_n == 0, "half-published run: not yet, and not a refusal (%u, %u)", w,
          g_rej_n);
    write_directory();
    w = scan(&got);
    CHECK(w == 62 && got == 3, "published: taken (%u/%u)", w, got);
}

static void t_one_direction(void) {
    reset();
    unsigned n;
    unsigned w1 = grant(4096, 64, 0, 0, &n, true);
    uint32_t got = 0;
    unsigned w = scan(&got);
    CHECK(w == w1 && got == 1, "one-direction channel (%u)", w);
}

static void t_reuse_after_close(void) {
    reset();
    unsigned n1, n3;
    unsigned wa = grant(65536, 32, 65536, 32, &n3, true);
    uint32_t got;
    unsigned w = scan(&got);
    pal_chan_hold_run(g_held, g_run, w, got);
    pal_chan_release_run(g_held, g_run, wa);
    unbook(wa, n3);
    unsigned wb = grant(4096, 16, 4096, 16, &n1, true);       /* lands in the freed run */
    CHECK(wb == wa, "the freed window is reused (%u, %u)", wb, wa);
    w = scan(&got);
    CHECK(w == wb && got == 1, "the new channel there is taken (%u/%u)", w, got);
}

/* Each malformed header in turn: refused for the right reason, and no read
 * past the header page (everything else is PROT_NONE). */
static void t_malformed(void) {
    struct {
        const char* what;
        unsigned off;
        uint32_t val;
        int why;
    } cases[] = {
        {"magic",               0x000, 0x12345678, PAL_CHAN_HDR_BAD_MAGIC},
        {"abi 2",               0x008, 2,          PAL_CHAN_HDR_BAD_ABI},
        {"kind lineage",        0x048, 1,          PAL_CHAN_HDR_BAD_KIND},
        {"windows 0",           0x01C, 0,          PAL_CHAN_HDR_BAD_WINDOWS},
        {"windows 300",         0x01C, 300,        PAL_CHAN_HDR_BAD_WINDOWS},
        {"windows past slot",   0x01C, 255,        PAL_CHAN_HDR_BAD_WINDOWS},
        {"windows vs npages",   0x01C, 2,          PAL_CHAN_HDR_BAD_NPAGES},
        {"npages too big",      0x018, 513,        PAL_CHAN_HDR_BAD_NPAGES},
        {"npages 2",            0x018, 2,          PAL_CHAN_HDR_BAD_NPAGES},
        {"slot not pow2",       0x020, 4000,       PAL_CHAN_HDR_BAD_RING0},
        {"slot too big",        0x020, 131072,     PAL_CHAN_HDR_BAD_RING0},
        {"slot too small",      0x020, 32,         PAL_CHAN_HDR_BAD_RING0},
        {"depth 0, slot set",   0x024, 0,          PAL_CHAN_HDR_BAD_RING0},
        {"depth not pow2",      0x024, 12,         PAL_CHAN_HDR_BAD_RING0},
        {"off in ctl pages",    0x028, 1,          PAL_CHAN_HDR_BAD_RING0},
        {"off past region",     0x028, 0x7fffffff, PAL_CHAN_HDR_BAD_RING0},
        {"off + pages > np",    0x028, 30,         PAL_CHAN_HDR_BAD_RING0},
        {"pages short",         0x02C, 1,          PAL_CHAN_HDR_BAD_RING0},
        {"pages huge",          0x02C, 0xffffffff, PAL_CHAN_HDR_BAD_RING0},
        {"ring1 slot pow2",     0x030, 100,        PAL_CHAN_HDR_BAD_RING1},
        {"ring1 overlaps 0",    0x038, 10,         PAL_CHAN_HDR_OVERLAP},
        {"ring1 absent, pages", 0x030, 0,          PAL_CHAN_HDR_BAD_RING1},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        reset();
        unsigned n;
        unsigned w1 = grant(4096, 16, 4096, 16, &n, true);    /* off 3/19, pages 16/16, np 35 */
        if (i == 5) {
            /* windows past slot: place the region near the top. */
            unbook(w1, n);
            for (unsigned w = 1; w < 300; w++)
                g_book[w] = 999;
            w1 = grant(4096, 16, 4096, 16, &n, true);
            for (unsigned w = 1; w < 300; w++)
                pal_chan_hold_run(g_held, g_run, w, 1);
        }
        unsigned char* h = win_addr(w1);
        page_rw(h);
        put32(h, cases[i].off, cases[i].val);
        if (cases[i].off == 0x030 && cases[i].val == 0)
            put32(h, 0x034, 0);       /* absent ring 1 (slot 0, depth 0) that keeps pages 16 */
        page_ro(h);
        uint32_t got = 0;
        unsigned w = scan(&got);
        CHECK(w == 0, "%s: not accepted (%u)", cases[i].what, w);
        CHECK(g_rej_n == 1 && g_rej_w == w1 && g_rej_why == cases[i].why,
              "%s: refused for %s (got %u refusals, %s)", cases[i].what,
              pal_chan_hdr_why(cases[i].why), g_rej_n, pal_chan_hdr_why(g_rej_why));
    }

    /* Both rings absent. */
    reset();
    unsigned n;
    unsigned w1 = grant(4096, 16, 4096, 16, &n, true);
    unsigned char* h = win_addr(w1);
    page_rw(h);
    for (unsigned o = 0x020; o < 0x040; o += 4)
        if ((o & 0xF) != 0x8)
            put32(h, o, 0);
    page_ro(h);
    uint32_t got;
    CHECK(scan(&got) == 0 && g_rej_why == PAL_CHAN_HDR_NO_RING, "no ring: refused (%s)",
          pal_chan_hdr_why(g_rej_why));

    /* Garbage: every byte of the header page random, many times. Never
     * accepted at a window whose geometry does not fit, never a fault. */
    srand(12345);
    unsigned accepted = 0;
    for (int round = 0; round < 20000; round++) {
        page_rw(h);
        for (unsigned o = 0; o < 0x60; o += 4)
            put32(h, o, (uint32_t)rand() ^ ((uint32_t)rand() << 16));
        if (round & 1)
            put64(h, 0, PAL_CHAN_HDR_MAGIC);
        if (round & 2)
            put32(h, 0x008, 1);
        if (round & 4)
            put32(h, 0x048, 0);
        page_ro(h);
        if (pal_chan_hdr_check((unsigned long)h, w1, &got) == PAL_CHAN_HDR_OK)
            accepted++;
    }
    CHECK(accepted == 0, "random headers: none accepted (%u)", accepted);
}

/* A good header's rings, as pal_chan_ring_init forms them, are inside the
 * region and past the control pages. */
static void t_ring_init_inside(void) {
    reset();
    unsigned n;
    unsigned w = grant(65536, 32, 65536, 32, &n, true);
    unsigned long base = (unsigned long)win_addr(w);
    uint32_t got;
    CHECK(pal_chan_hdr_check(base, w, &got) == PAL_CHAN_HDR_OK, "good header");
    uint32_t np = pal_chan_u32(base, PAL_CHAN_HDR_NPAGES);
    for (int side = 0; side < 2; side++)
        for (int prod = 0; prod < 2; prod++) {
            struct pal_chan_ring r;
            pal_chan_ring_init(&r, base, side, prod);
            unsigned long lo = (unsigned long)r.slots, hi = lo + (unsigned long)r.slot * r.depth;
            CHECK(lo >= base + 3 * 4096 && hi <= base + (unsigned long)np * 4096,
                  "side %d %s ring inside the region", side, prod ? "out" : "in");
        }
}

int main(void) {
    /* At the PAL's own address (PML4 slot 16): pal_chan_ring_init reads the
     * directory at PAL_CHAN_DIR_VADDR, not at an address it is given. */
    void* p = mmap((void*)PAL_CHAN_START_VADDR, SLOT_SIZE, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED || p != (void*)PAL_CHAN_START_VADDR) {
        perror("mmap");
        return 2;
    }
    g_slot = p;
    page_rw(g_slot);                  /* the directory */
    put64(g_slot, 0, 0x3130524944564d00UL);

    t_single_and_multi();
    t_planted_fake_later_window();
    t_fake_behind_refused_first();
    t_outbound_held_run();
    t_partial_publish();
    t_one_direction();
    t_reuse_after_close();
    t_malformed();
    t_ring_init_inside();

    printf("chan_accept_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
