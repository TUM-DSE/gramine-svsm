/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Host test of libos_exec_free.h: the execve free loop (libos_exec.c) run against a model of the
 * LibOS VMA bookkeeping and of the PAL's memory.
 *
 * The model: an address space of NPAGES pages. Each page has a bookkeeping state (free, a user
 * VMA, a user VMA_UNMAPPED VMA, an internal VMA, a placeholder left by bkeep_munmap) and a PAL
 * state (allocated or not). A random layout is built (ELF-object-like runs of adjacent user VMAs,
 * internal VMAs interleaved, unmapped VMAs, the kept stack and red zone), dumped as
 * dump_all_vmas does (user VMAs only, in address order), and freed by
 *   - stock:     the loop as it was (bkeep, free, remove per VMA);
 *   - coalesced: the header's loop (EXEC_FREE_RUN_MAX as built, and 1);
 *   - early:     a deliberately wrong coalescing that removes each placeholder right after its
 *                bkeep, to show that the model catches the bug the header's ordering prevents.
 * Inside every bkeep the model may grow the "slab": an internal VMA is bookkept on free pages
 * (top-down, bottom-up or random fit) and allocated in the PAL, as alloc_vma -> _vma_malloc
 * does inside bkeep_munmap.
 *
 * Checked for every layout and loop:
 *   - the PAL free never covers a page that is not a placeholder of a mapped user VMA (a gap,
 *     internal or kept memory, an unmapped VMA's pages, a page freed already);
 *   - a placeholder of a mapped VMA is removed only after its pages were freed;
 *   - at the end, the freed page set equals the stock loop's (every mapped, not kept user VMA,
 *     each page once), kept and internal memory is still allocated, nothing is a placeholder;
 *   - the number of PAL frees equals the number of maximal runs computed independently, and the
 *     stock loop's equals the number of mapped VMAs.
 * And the early variant must be caught on some layouts.
 *
 *   make -C libos/test/host check
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libos_exec_free.h"

#define PAGE   4096ul
#define NPAGES 2048
#define BASE   0x10000000ul
#define MAXV   512

/* BK_RELEASED: a mapped VMA's range whose placeholder the wrong variant dropped before the free -
 * free in the bookkeeping (the slab may take it), not yet freed in the PAL. */
enum bk { BK_FREE, BK_USER, BK_USER_UNMAPPED, BK_INTERNAL, BK_TMP, BK_RELEASED };

struct vma {
    size_t first, pages; /* in pages */
    int kind;            /* enum exec_free_kind for user VMAs; -1 for internal */
};

static enum bk g_bk[NPAGES];
static bool g_pal[NPAGES];
static bool g_freed[NPAGES];      /* freed by the loop under test */
static bool g_tmp_mapped[NPAGES]; /* the placeholder on this page is a mapped VMA's */
static int g_fail;                /* first violation seen, 0 = none */
static const char* g_fail_why;
static unsigned long g_frees, g_bkeeps;
static unsigned g_rng;
static int g_policy;     /* slab fit: 0 top-down, 1 bottom-up, 2 random */
static int g_slab_prob;  /* percent of bkeeps that grow the slab */

struct tmp {
    size_t first, pages;
    bool mapped;
    bool live;
};
static struct tmp g_tmps[MAXV];
static size_t g_ntmps;

static unsigned rnd(void) {
    g_rng = g_rng * 1103515245u + 12345u;
    return (g_rng >> 8) & 0xffffff;
}

static size_t page_of(uintptr_t a) {
    return (a - BASE) / PAGE;
}

static const char WIPED[] = "free covers live internal (LibOS) memory";

static void violation(const char* why) {
    if (!g_fail) {
        g_fail = 1;
        g_fail_why = why;
    }
}

/* alloc_vma's slab growth: an internal VMA on free pages, allocated in the PAL. */
static bool fits(size_t p, size_t want) {
    if (p + want > NPAGES)
        return false;
    for (size_t i = 0; i < want; i++)
        if (g_bk[p + i] != BK_FREE && g_bk[p + i] != BK_RELEASED)
            return false;
    return true;
}

static void slab_grow(void) {
    size_t want = 1 + rnd() % 4;
    size_t start = g_policy == 0 ? NPAGES - want : g_policy == 1 ? 0 : rnd() % NPAGES;
    size_t at = NPAGES;
    for (size_t k = 0; k < NPAGES; k++) {
        /* top-down, bottom-up, or upward from a random page (wrapping) */
        size_t p = g_policy == 0 ? (start + NPAGES - k) % NPAGES : (start + k) % NPAGES;
        if (fits(p, want)) {
            at = p;
            break;
        }
    }
    if (at == NPAGES)
        return;
    for (size_t i = 0; i < want; i++) {
        g_bk[at + i]  = BK_INTERNAL;
        g_pal[at + i] = true;
    }
}

static int m_bkeep_unmap(void* addr, size_t length, void** tmp_vma) {
    size_t f = page_of((uintptr_t)addr), n = length / PAGE;
    if ((uintptr_t)addr % PAGE || length % PAGE || !n || f + n > NPAGES)
        return -1;
    enum bk was = g_bk[f];
    if (was != BK_USER && was != BK_USER_UNMAPPED) {
        violation("bkeep of a range that is not a user VMA");
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (g_bk[f + i] != was) {
            violation("bkeep across VMAs of different kinds");
            return -1;
        }
        g_bk[f + i]         = BK_TMP;
        g_tmp_mapped[f + i] = was == BK_USER;
    }
    assert(g_ntmps < MAXV);
    g_tmps[g_ntmps] = (struct tmp){ .first = f, .pages = n, .mapped = was == BK_USER, .live = true };
    *tmp_vma = &g_tmps[g_ntmps++];
    g_bkeeps++;
    if ((int)(rnd() % 100) < g_slab_prob)
        slab_grow();
    return 0;
}

static int m_pal_free(void* addr, size_t length) {
    size_t f = page_of((uintptr_t)addr), n = length / PAGE;
    g_frees++;
    if ((uintptr_t)addr % PAGE || length % PAGE || !n || f + n > NPAGES) {
        violation("free of a misaligned or out-of-range span");
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        size_t p = f + i;
        if (g_bk[p] == BK_INTERNAL) {
            violation(WIPED);
        } else if (g_bk[p] == BK_RELEASED) {
            g_bk[p] = BK_FREE;   /* the wrong variant's range, nothing else took it */
        } else if (g_bk[p] != BK_TMP)
            violation("free covers a page that is no placeholder (a gap or kept memory)");
        else if (!g_tmp_mapped[p])
            violation("free covers an unmapped VMA's page");
        else if (g_freed[p])
            violation("free covers a page twice");
        g_freed[p] = true;
        g_pal[p]   = false;
    }
    return 0;
}

static void m_remove_tmp(void* tmp_vma) {
    struct tmp* t = tmp_vma;
    if (!t->live) {
        violation("placeholder removed twice");
        return;
    }
    for (size_t i = 0; i < t->pages; i++) {
        size_t p = t->first + i;
        if (g_bk[p] != BK_TMP)
            violation("placeholder page changed under it");
        if (t->mapped && !g_freed[p])
            violation("placeholder removed before its pages were freed");
        g_bk[p] = BK_FREE;
    }
    t->live = false;
}

static int fail_free(void* addr, size_t length) {
    (void)addr;
    (void)length;
    g_frees++;
    return -1;
}

static const struct exec_free_ops g_ops = {
    .bkeep_unmap = m_bkeep_unmap,
    .pal_free    = m_pal_free,
    .remove_tmp  = m_remove_tmp,
};

/* ---- layouts */

static struct vma g_layout[MAXV];
static size_t g_nlayout;

static void put(size_t* p, size_t pages, int kind) {
    if (*p + pages > NPAGES || g_nlayout >= MAXV)
        return;
    g_layout[g_nlayout++] = (struct vma){ .first = *p, .pages = pages, .kind = kind };
    *p += pages;
}

/* ELF-object-like groups of adjacent user VMAs, with internal VMAs, gaps, unmapped VMAs and the
 * kept stack/red zone in between. */
static void make_layout(void) {
    g_nlayout = 0;
    size_t p = rnd() % 4;
    bool stack_done = false;
    while (p < NPAGES - 64 && g_nlayout < MAXV - 16) {
        unsigned what = rnd() % 100;
        if (what < 55) {
            size_t segs = 1 + rnd() % (rnd() % 8 == 0 ? 50 : 6);   /* sometimes > RUN_MAX */
            for (size_t s = 0; s < segs; s++)
                put(&p, 1 + rnd() % 8, rnd() % 12 == 0 ? EXEC_FREE_UNMAPPED : EXEC_FREE_MAPPED);
        } else if (what < 75) {
            put(&p, 1 + rnd() % 4, -1);
        } else if (what < 90) {
            p += 1 + rnd() % 6;                                     /* a real hole */
        } else if (!stack_done) {
            put(&p, 1, EXEC_FREE_KEEP);                             /* stack_red */
            put(&p, 2 + rnd() % 8, EXEC_FREE_KEEP);                 /* stack */
            stack_done = true;
        }
    }
}

/* The execl image as the gaps note describes it (exec, ld.so, libc, ub-cap.so, heap, vDSO,
 * stack), internal VMAs between objects: a fixed case whose call counts are printed. */
static void make_execl_layout(void) {
    g_nlayout = 0;
    size_t p = 8;
    const size_t objs[][6] = {
        { 1, 1, 1, 1, 0, 0 },     /* execl: r--, r-x, r--, rw- */
        { 1, 0, 0, 0, 0, 0 },     /* brk heap */
        { 1, 13, 4, 1, 1, 0 },    /* ld.so */
        { 40, 337, 86, 2, 3, 1 }, /* libc: r--, r-x, r--, rw-, bss, tail */
        { 1, 4, 2, 1, 1, 0 },     /* ub-cap.so */
        { 2, 0, 0, 0, 0, 0 },     /* static TLS / misc anon */
        { 2, 0, 0, 0, 0, 0 },     /* vDSO */
    };
    for (size_t o = 0; o < sizeof(objs) / sizeof(objs[0]); o++) {
        for (size_t s = 0; s < 6 && objs[o][s]; s++)
            put(&p, objs[o][s], EXEC_FREE_MAPPED);
        put(&p, 1, -1); /* an internal VMA between objects */
    }
    put(&p, 1, EXEC_FREE_KEEP);
    put(&p, 8, EXEC_FREE_KEEP);
}

static void apply_layout(void) {
    memset(g_bk, 0, sizeof(g_bk));
    memset(g_pal, 0, sizeof(g_pal));
    memset(g_freed, 0, sizeof(g_freed));
    memset(g_tmp_mapped, 0, sizeof(g_tmp_mapped));
    for (size_t i = 0; i < g_nlayout; i++) {
        struct vma* v = &g_layout[i];
        enum bk b = v->kind < 0 ? BK_INTERNAL
                    : v->kind == EXEC_FREE_UNMAPPED ? BK_USER_UNMAPPED : BK_USER;
        for (size_t k = 0; k < v->pages; k++) {
            g_bk[v->first + k]  = b;
            g_pal[v->first + k] = b != BK_USER_UNMAPPED;
        }
    }
    g_ntmps = 0;
    g_fail = 0;
    g_fail_why = NULL;
    g_frees = g_bkeeps = 0;
}

/* The dump: user VMAs in address order (dump_all_vmas leaves out VMA_INTERNAL). */
static size_t dump(struct vma* out) {
    size_t n = 0;
    for (size_t i = 0; i < g_nlayout; i++)
        if (g_layout[i].kind >= 0)
            out[n++] = g_layout[i];
    return n;
}

static void* va(size_t page) {
    return (void*)(BASE + page * PAGE);
}

/* Maximal runs, computed independently of the header. */
static unsigned long expected_runs(const struct vma* d, size_t n, size_t cap) {
    unsigned long runs = 0;
    size_t len = 0, end = 0;
    for (size_t i = 0; i < n; i++) {
        if (d[i].kind != EXEC_FREE_MAPPED) {
            len = 0;
            continue;
        }
        if (len && d[i].first == end && len < cap) {
            len++;
        } else {
            runs++;
            len = 1;
        }
        end = d[i].first + d[i].pages;
    }
    return runs;
}

/* ---- the loops */

static int loop_stock(const struct vma* d, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (d[i].kind == EXEC_FREE_KEEP)
            continue;
        void* tmp = NULL;
        if (m_bkeep_unmap(va(d[i].first), d[i].pages * PAGE, &tmp) < 0)
            return -1;
        if (d[i].kind == EXEC_FREE_MAPPED && m_pal_free(va(d[i].first), d[i].pages * PAGE) < 0)
            return -1;
        m_remove_tmp(tmp);
    }
    return 0;
}

/* The header's loop with its own placeholder cap: EXEC_FREE_RUN_MAX is compiled in, so the cap-1
 * case flushes by hand before each VMA - the same sequence the header gives at RUN_MAX 1. */
static int loop_header(const struct vma* d, size_t n, bool cap1) {
    struct exec_free_run run;
    exec_free_init(&run, &g_ops);
    for (size_t i = 0; i < n; i++) {
        if (cap1 && exec_free_flush(&run) < 0)
            return -1;
        if (exec_free_vma(&run, va(d[i].first), d[i].pages * PAGE, d[i].kind) < 0)
            return -1;
    }
    return exec_free_finish(&run);
}

/* WRONG on purpose: coalesces, but drops each placeholder right after its bkeep. */
static int loop_early(const struct vma* d, size_t n) {
    size_t begin = 0, end = 0;
    bool open = false;
    for (size_t i = 0; i <= n; i++) {
        bool join = i < n && d[i].kind == EXEC_FREE_MAPPED && open && d[i].first == end;
        if (open && !join) {
            if (m_pal_free(va(begin), (end - begin) * PAGE) < 0)
                return -1;
            open = false;
        }
        if (i == n || d[i].kind == EXEC_FREE_KEEP)
            continue;
        void* tmp = NULL;
        if (m_bkeep_unmap(va(d[i].first), d[i].pages * PAGE, &tmp) < 0)
            return -1;
        if (d[i].kind == EXEC_FREE_MAPPED) {
            /* pretend the free happened, so that the removal check passes: the model then sees
             * only what the real code would do - the range is free in the bookkeeping. */
            struct tmp* t = tmp;
            for (size_t k = 0; k < t->pages; k++) {
                g_bk[t->first + k] = BK_RELEASED;
                g_freed[t->first + k] = false;
            }
            t->live = false;
            if (!open) {
                begin = d[i].first;
                open  = true;
            }
            end = d[i].first + d[i].pages;
        } else {
            m_remove_tmp(tmp);
        }
    }
    return 0;
}

/* After a loop: kept and internal memory still there, the freed set as expected. */
static void check_end(const struct vma* d, size_t n) {
    static bool want[NPAGES];
    memset(want, 0, sizeof(want));
    for (size_t i = 0; i < n; i++)
        if (d[i].kind == EXEC_FREE_MAPPED)
            for (size_t k = 0; k < d[i].pages; k++)
                want[d[i].first + k] = true;
    for (size_t p = 0; p < NPAGES; p++) {
        if (g_freed[p] != want[p])
            violation(want[p] ? "a mapped VMA's page was not freed" : "freed set differs");
        if (g_bk[p] == BK_TMP)
            violation("a placeholder was left behind");
        if (g_bk[p] == BK_INTERNAL && !g_pal[p])
            violation("internal memory lost its PAL allocation");
    }
    for (size_t i = 0; i < n; i++)
        if (d[i].kind == EXEC_FREE_KEEP)
            for (size_t k = 0; k < d[i].pages; k++)
                if (g_bk[d[i].first + k] != BK_USER || !g_pal[d[i].first + k])
                    violation("kept memory was touched");
    for (size_t i = 0; i < g_ntmps; i++)
            if (g_tmps[i].live)
                violation("a placeholder was never removed");
}

static int failures;

static void expect(bool ok, const char* what, unsigned seed) {
    if (!ok) {
        failures++;
        if (failures < 20)
            printf("FAIL seed %u: %s%s%s\n", seed, what, g_fail_why ? ": " : "",
                   g_fail_why ? g_fail_why : "");
    }
}

int main(void) {
    static struct vma d[MAXV];
    unsigned long stock_calls = 0, coal_calls = 0, cap1_calls = 0, vmas = 0, layouts = 0;
    unsigned long early_caught = 0;

    for (unsigned seed = 1; seed <= 10000; seed++) {
        g_rng = seed;
        make_layout();
        size_t n = dump(d);
        unsigned layout_rng = g_rng;
        layouts++;
        vmas += n;

        for (int policy = 0; policy < 3; policy++) {
            g_policy    = policy;
            g_slab_prob = (int)(seed % 4) * 25 + 10;

            /* stock */
            g_rng = layout_rng;
            apply_layout();
            expect(loop_stock(d, n) == 0 && !g_fail, "stock loop", seed);
            check_end(d, n);
            expect(!g_fail, "stock end state", seed);
            unsigned long mapped = 0;
            for (size_t i = 0; i < n; i++)
                mapped += d[i].kind == EXEC_FREE_MAPPED;
            expect(g_frees == mapped, "stock: one free per mapped VMA", seed);
            stock_calls += g_frees;

            /* the header, EXEC_FREE_RUN_MAX */
            g_rng = layout_rng;
            apply_layout();
            expect(loop_header(d, n, false) == 0 && !g_fail, "coalesced loop", seed);
            check_end(d, n);
            expect(!g_fail, "coalesced end state", seed);
            expect(g_frees == expected_runs(d, n, EXEC_FREE_RUN_MAX), "coalesced: one free per run",
                   seed);
            coal_calls += g_frees;

            /* the header at cap 1: the stock sequence */
            g_rng = layout_rng;
            apply_layout();
            expect(loop_header(d, n, true) == 0 && !g_fail, "cap-1 loop", seed);
            check_end(d, n);
            expect(!g_fail, "cap-1 end state", seed);
            expect(g_frees == mapped, "cap 1: one free per mapped VMA", seed);
            cap1_calls += g_frees;

            /* the wrong variant: the model has to catch it somewhere */
            g_rng = layout_rng;
            apply_layout();
            loop_early(d, n);
            early_caught += g_fail_why == WIPED;
        }
    }

    /* A failing free keeps the run's placeholders (the range stays reserved). */
    {
        g_rng = 7;
        g_nlayout = 0;
        size_t p = 0;
        put(&p, 2, EXEC_FREE_MAPPED);
        put(&p, 3, EXEC_FREE_MAPPED);
        apply_layout();
        size_t n = dump(d);
        static const struct exec_free_ops failing = {
            .bkeep_unmap = m_bkeep_unmap,
            .pal_free    = fail_free,
            .remove_tmp  = m_remove_tmp,
        };
        struct exec_free_run run;
        exec_free_init(&run, &failing);
        g_slab_prob = 0;
        int r1 = exec_free_vma(&run, va(d[0].first), d[0].pages * PAGE, EXEC_FREE_MAPPED);
        int r2 = exec_free_vma(&run, va(d[1].first), d[1].pages * PAGE, EXEC_FREE_MAPPED);
        int r3 = r2 < 0 ? r2 : exec_free_finish(&run);
        /* RUN_MAX 1: the first VMA's free fails when the second one is added, and the second is
         * never bkept; otherwise both are bkept and the run's one free fails at the finish. */
        size_t held = EXEC_FREE_RUN_MAX == 1 ? 2 : 5;
        bool kept = n == 2 && g_tmps[0].live && (EXEC_FREE_RUN_MAX == 1 || g_tmps[1].live);
        for (size_t k = 0; k < 5; k++)
            kept = kept && g_bk[k] == (k < held ? BK_TMP : BK_USER);
        bool rets = EXEC_FREE_RUN_MAX == 1 ? r1 == 0 && r2 < 0 : r1 == 0 && r2 == 0 && r3 < 0;
        expect(rets && kept && g_frees == 1, "failed free keeps the placeholders", 7);
    }

    /* The execl-like image. */
    g_rng = 1;
    make_execl_layout();
    size_t n = dump(d);
    g_slab_prob = 50;
    g_policy    = 2;
    apply_layout();
    expect(loop_stock(d, n) == 0 && !g_fail, "execl stock", 0);
    unsigned long es = g_frees;
    g_rng = 1;
    apply_layout();
    expect(loop_header(d, n, false) == 0 && !g_fail, "execl coalesced", 0);
    check_end(d, n);
    expect(!g_fail, "execl coalesced end state", 0);
    unsigned long ec = g_frees;

    expect(early_caught > 0, "the early-removal variant was never caught", 0);

    printf("layouts %lu (x3 slab policies), dumped VMAs %lu\n", layouts, vmas);
    printf("PAL frees: stock %lu, coalesced (RUN_MAX %d) %lu (%.1f%%), cap 1 %lu\n", stock_calls,
           EXEC_FREE_RUN_MAX, coal_calls, 100.0 * coal_calls / stock_calls, cap1_calls);
    printf("execl-like image: %zu dumped VMAs, frees stock %lu -> coalesced %lu\n", n, es, ec);
    printf("early-removal variant caught on %lu of %lu runs\n", early_caught, layouts * 3);
    if (failures) {
        printf("FAILED (%d)\n", failures);
        return 1;
    }
    printf("ok\n");
    return 0;
}
