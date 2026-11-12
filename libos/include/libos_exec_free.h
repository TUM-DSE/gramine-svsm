/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Freeing the old image's memory at execve: one PAL free per run of exactly adjacent VMAs.
 *
 * execve drops every user VMA but the new stack (libos_exec.c). It used to issue one
 * PalVirtualMemoryFree per VMA, and on the svsm PAL every free is a monitor call
 * (pal_svsm_free). An exec image is a few ELF objects of 4-5 adjacent segments each, so most of
 * those calls are for ranges that touch the previous one. Here a run of VMAs that touch
 * end-to-start is freed with ONE call over the run's whole range.
 *
 * The page set freed is exactly the old one: a run is extended only by a VMA that begins where
 * the run ends, so its range is the union of its VMAs' ranges and covers no byte that was not
 * freed before. A run ends at
 *   - any gap: the dump excludes VMA_INTERNAL VMAs (vma_filter_all in libos_vma.c), so a gap
 *     between two dumped VMAs may be LibOS memory and must never be freed;
 *   - a kept VMA (the new stack and its red zone), which is not touched at all;
 *   - a VMA_UNMAPPED VMA, which is only bookkept and never freed;
 *   - EXEC_FREE_RUN_MAX VMAs, the size of the placeholder array.
 *
 * Ordering. bkeep_munmap leaves a placeholder (a VMA_INTERNAL | VMA_UNMAPPED "tmp" VMA) on the
 * range, and libos_vma.h requires it be removed only AFTER the memory itself is freed - until
 * then the range is not free in the bookkeeping, so nothing can be allocated there. With a
 * deferred free that rule covers the whole run: every placeholder of a run is kept until the
 * run's free has been issued. Removing one earlier would let a LibOS allocation made meanwhile
 * (alloc_vma growing its slab through bkeep_mmap_any, inside a later bkeep_munmap) land in the
 * released range, and the run's free would then unmap live LibOS memory.
 *
 * EXEC_FREE_RUN_MAX 1 reproduces the old call sequence exactly (bkeep, free, remove per VMA).
 *
 * Self-contained (no LibOS headers) so that the host test libos/test/host/exec_free_test.c runs
 * this same code against a model of the bookkeeping and the PAL.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef EXEC_FREE_RUN_MAX
#define EXEC_FREE_RUN_MAX 32
#endif

_Static_assert(EXEC_FREE_RUN_MAX >= 1, "EXEC_FREE_RUN_MAX must be at least 1");

enum exec_free_kind {
    EXEC_FREE_KEEP,     /* not touched (the new stack and its red zone); ends a run */
    EXEC_FREE_UNMAPPED, /* bookkeeping only (VMA_UNMAPPED), no PAL free; ends a run */
    EXEC_FREE_MAPPED,   /* bookkeeping and PAL free; joins the run when exactly adjacent */
};

struct exec_free_ops {
    /* Bookkeep the removal of one VMA; on success `*tmp_vma` is its placeholder. */
    int (*bkeep_unmap)(void* addr, size_t length, void** tmp_vma);
    /* Free the memory (PalVirtualMemoryFree). */
    int (*pal_free)(void* addr, size_t length);
    /* Drop a placeholder (bkeep_remove_tmp_vma). */
    void (*remove_tmp)(void* tmp_vma);
};

struct exec_free_run {
    const struct exec_free_ops* ops;
    uintptr_t begin;
    uintptr_t end;
    size_t n;
    void* tmp[EXEC_FREE_RUN_MAX];
};

static inline void exec_free_init(struct exec_free_run* r, const struct exec_free_ops* ops) {
    r->ops   = ops;
    r->begin = 0;
    r->end   = 0;
    r->n     = 0;
}

/* Frees the pending run, then drops its placeholders - in that order. On a failed free the
 * placeholders stay (the range stays reserved) and the error is returned. */
static inline int exec_free_flush(struct exec_free_run* r) {
    if (!r->n)
        return 0;
    int ret = r->ops->pal_free((void*)r->begin, r->end - r->begin);
    if (ret < 0)
        return ret;
    for (size_t i = 0; i < r->n; i++)
        r->ops->remove_tmp(r->tmp[i]);
    r->n     = 0;
    r->begin = 0;
    r->end   = 0;
    return 0;
}

/* One dumped VMA, in address order. Returns 0 or the first failure (bkeep or free). */
static inline int exec_free_vma(struct exec_free_run* r, void* addr, size_t length,
                                enum exec_free_kind kind) {
    uintptr_t a = (uintptr_t)addr;
    int ret;

    if (kind != EXEC_FREE_MAPPED || !r->n || a != r->end || r->n == EXEC_FREE_RUN_MAX) {
        ret = exec_free_flush(r);
        if (ret < 0)
            return ret;
    }
    if (kind == EXEC_FREE_KEEP)
        return 0;

    void* tmp = NULL;
    ret = r->ops->bkeep_unmap(addr, length, &tmp);
    if (ret < 0)
        return ret;
    if (kind == EXEC_FREE_UNMAPPED) {
        r->ops->remove_tmp(tmp);
        return 0;
    }
    if (!r->n)
        r->begin = a;
    r->end = a + length;
    r->tmp[r->n++] = tmp;
    return 0;
}

/* After the last VMA. */
static inline int exec_free_finish(struct exec_free_run* r) {
    return exec_free_flush(r);
}
