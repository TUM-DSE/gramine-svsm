/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * The table GRAMINE_CALL_CPUID answers from (libos_cpuid.c).
 *
 * Why it exists: a vault has no #VC handler of its own, so every CPUID it executes exits to the
 * monitor and back (pal/src/host/svsm/pal_misc.c, _PalCpuIdRetrieve) - about 9.2 us each, where a
 * LibOS call is about 0.05 us (mvperf, vmpl2-recheck-20261105). glibc's ld.so runs about 40 of
 * them at every start (init_cpu_features, update_active, dl_init_cacheinfo/handle_amd), and an
 * exec is an ld.so start. The patched glibc (subprojects/packagefiles/glibc-<v>/
 * gramine-cpuid.patch) asks the LibOS instead; the LibOS answers a (leaf, subleaf) it has seen
 * from here, and for one it has not it asks the PAL - the same CPUID glibc would have executed -
 * and keeps the answer.
 *
 * Why a kept answer is the answer: on the SVSM PAL the monitor answers CPUID from the SNP CPUID
 * page, keyed by the leaf, the subleaf for the subleaf-indexed leaves, and the vault's XCR0
 * (monitor process_runtime/process/misc.rs, pal_svsm_cpuid); nothing in it depends on the vCPU,
 * and XCR0 is decided once, in the zygote, before the LibOS runs (pal_main.c, svsm.avx512). On a
 * PAL that executes the instruction on hardware, a kept answer is what Linux gives a process that
 * migrates between CPUs: an answer from one of them.
 *
 * Keyed by the exact (leaf, subleaf) pair: no leaf is assumed to ignore ECX. The glibc side passes
 * subleaf 0 for its __cpuid sites (the ones without an ECX input), whose leaves ignore ECX both
 * architecturally and in the monitor (which reads ECX as 0 for every leaf outside its indexed
 * list), so the garbage ECX those sites used to execute with never becomes part of a key.
 *
 * Freestanding - <stdint.h> and GCC's __atomic builtins only - so that tools/fn/test/ldso_cpuid
 * runs this very file on the host. Lock-free: a slot is claimed with a compare-and-swap on
 * `claimed`, filled, and published by a release store of its `ready` word; a lookup skips a slot
 * that is not ready yet. Two threads that miss the same pair at once each fill a slot with the
 * same answer, which is harmless. A full table still answers, it just keeps nothing more.
 */

#pragma once

#include <stdint.h>

/* ld.so asks for 22 distinct pairs on jamie's Zen 4 (leaf 0xD alone for 10 subleaves). */
#define CPUID_TABLE_SLOTS 64

struct cpuid_table_slot {
    uint32_t leaf;
    uint32_t subleaf;
    uint32_t regs[4];   /* EAX, EBX, ECX, EDX */
    uint32_t ready;     /* 1 once leaf, subleaf and regs are written (release) */
};

struct cpuid_table {
    uint32_t claimed;   /* slots handed out, never more than CPUID_TABLE_SLOTS */
    struct cpuid_table_slot slots[CPUID_TABLE_SLOTS];
};

/* What a miss asks: 0 and the four words, or a negative errno. */
typedef int (*cpuid_table_retrieve_t)(uint32_t leaf, uint32_t subleaf, uint32_t regs[4]);

/*
 * Answer (leaf, subleaf) into `out`. Returns 1 for an answer from the table, 0 for one that
 * `retrieve` gave (kept when a slot was free), or retrieve's negative errno with `out` untouched.
 */
static inline int cpuid_table_get(struct cpuid_table* t, uint32_t leaf, uint32_t subleaf,
                                  uint32_t out[4], cpuid_table_retrieve_t retrieve) {
    uint32_t n = __atomic_load_n(&t->claimed, __ATOMIC_ACQUIRE);
    if (n > CPUID_TABLE_SLOTS)
        n = CPUID_TABLE_SLOTS;
    for (uint32_t i = 0; i < n; i++) {
        const struct cpuid_table_slot* s = &t->slots[i];
        if (!__atomic_load_n(&s->ready, __ATOMIC_ACQUIRE))
            continue;
        if (s->leaf == leaf && s->subleaf == subleaf) {
            for (int r = 0; r < 4; r++)
                out[r] = s->regs[r];
            return 1;
        }
    }

    uint32_t regs[4];
    int ret = retrieve(leaf, subleaf, regs);
    if (ret < 0)
        return ret;
    for (int r = 0; r < 4; r++)
        out[r] = regs[r];

    /* Claim a slot; never past the end, so `claimed` cannot wrap onto a published slot. */
    uint32_t i = __atomic_load_n(&t->claimed, __ATOMIC_RELAXED);
    while (i < CPUID_TABLE_SLOTS
           && !__atomic_compare_exchange_n(&t->claimed, &i, i + 1, /*weak=*/0, __ATOMIC_RELAXED,
                                           __ATOMIC_RELAXED))
        ;
    if (i < CPUID_TABLE_SLOTS) {
        struct cpuid_table_slot* s = &t->slots[i];
        s->leaf = leaf;
        s->subleaf = subleaf;
        for (int r = 0; r < 4; r++)
            s->regs[r] = regs[r];
        __atomic_store_n(&s->ready, 1, __ATOMIC_RELEASE);
    }
    return 0;
}
