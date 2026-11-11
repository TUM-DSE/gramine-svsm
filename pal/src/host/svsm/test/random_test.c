/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Host-side test of the PAL's random bytes (pal_svsm_random.h, the code
 * _PalRandomBitsRead runs):
 *   - the ChaCha20 block against RFC 8439 2.3.2 and the keystream of 2.4.2
 *     (counter 1; here the PAL's counter starts at 0, so block 1 is checked);
 *   - up to 32 bytes are the hardware words themselves, little-endian, and
 *     more is the keystream under the first four words (nonce 0, counter 0);
 *   - a new key every PAL_RNG_CHUNK bytes;
 *   - RDSEED retried, then RDRAND; 0 and ~0 words skipped; no usable word
 *     is a failure that writes nothing guessable (the caller fails the vault);
 *   - two fills from the CPU (when it has RDSEED) differ;
 *   - the cost per call against one 32-bit RDSEED per 4 bytes (the old loop),
 *     printed for the record.
 *
 *   make -C pal/src/host/svsm/test check
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

#include "../pal_svsm_random.h"

static int g_fail, g_pass;
#define CHECK(cond, ...)                                    \
    do {                                                    \
        if (cond) {                                         \
            g_pass++;                                       \
        } else {                                            \
            g_fail++;                                       \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);     \
            printf(__VA_ARGS__);                            \
            printf("\n");                                   \
        }                                                   \
    } while (0)

/* ---- a scripted source: each call takes the next entry; an entry with
 * ok == 0 is a failed instruction. */
struct step { int ok; uint64_t v; };
static const struct step* g_seed_script; static size_t g_seed_n, g_seed_i;
static const struct step* g_rand_script; static size_t g_rand_n, g_rand_i;
static uint64_t g_counter;          /* the "default" words once a script ends */
static int g_pauses;

static bool s_rdseed(uint64_t* v) {
    if (g_seed_i < g_seed_n) {
        const struct step* s = &g_seed_script[g_seed_i++];
        *v = s->v;
        return s->ok;
    }
    if (g_seed_script && g_seed_n == 0)
        return false;                /* an empty script: RDSEED always fails */
    *v = ++g_counter * 0x9E3779B97F4A7C15ULL;
    return true;
}
static bool s_rdrand(uint64_t* v) {
    if (g_rand_i < g_rand_n) {
        const struct step* s = &g_rand_script[g_rand_i++];
        *v = s->v;
        return s->ok;
    }
    if (g_rand_script && g_rand_n == 0)
        return false;
    *v = ++g_counter * 0xBF58476D1CE4E5B9ULL;
    return true;
}
static void s_pause(void) { g_pauses++; }
static const struct pal_rng_src g_script = { s_rdseed, s_rdrand, s_pause };

static void script(const struct step* seed, size_t ns, const struct step* rnd, size_t nr) {
    g_seed_script = seed; g_seed_n = ns; g_seed_i = 0;
    g_rand_script = rnd; g_rand_n = nr; g_rand_i = 0;
    g_counter = 0; g_pauses = 0;
}

/* ---- the CPU */
static bool c_rdseed(uint64_t* v) {
    unsigned long long x;
    int ok = _rdseed64_step(&x);
    *v = x;
    return ok;
}
static bool c_rdrand(uint64_t* v) {
    unsigned long long x;
    int ok = _rdrand64_step(&x);
    *v = x;
    return ok;
}
static void c_pause(void) { _mm_pause(); }
static const struct pal_rng_src g_cpu = { c_rdseed, c_rdrand, c_pause };

/* The old loop (pal_misc.c before): a 32-bit RDSEED per 4 bytes. */
static void old_fill(void* buf, size_t n) {
    uint8_t* b = buf;
    for (size_t i = 0; i < n;) {
        unsigned int w;
        while (!_rdseed32_step(&w))
            ;
        for (int j = 0; j < 4 && i < n; j++)
            b[i++] = (uint8_t)(w >> (8 * j));
    }
}

static uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void test_rfc_block(void) {
    /* RFC 8439 2.3.2: key 00..1f, nonce 00:00:00:09:00:00:00:4a:00:00:00:00, counter 1. */
    static const uint8_t want[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    uint8_t kb[32], nb[12] = { 0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0 }, out[64];
    uint32_t key[8], nonce[3];
    for (int i = 0; i < 32; i++)
        kb[i] = (uint8_t)i;
    for (int i = 0; i < 8; i++)
        key[i] = le32(kb + 4 * i);
    for (int i = 0; i < 3; i++)
        nonce[i] = le32(nb + 4 * i);
    pal_chacha20_block(key, 1, nonce, out);
    CHECK(!memcmp(out, want, 64), "RFC 8439 2.3.2 block mismatch");

    /* RFC 8439 A.1 test vector #1: all-zero key, nonce, counter 0. */
    static const uint8_t want0[16] = { 0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
                                       0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28 };
    uint32_t zk[8] = { 0 }, zn[3] = { 0 };
    pal_chacha20_block(zk, 0, zn, out);
    CHECK(!memcmp(out, want0, 16), "RFC 8439 A.1 #1 block mismatch");
}

static void test_raw_small(void) {
    static const struct step seed[] = { { 1, 0x0807060504030201ULL }, { 1, 0x100f0e0d0c0b0a09ULL } };
    uint8_t b[12];
    script(seed, 2, NULL, 0);
    CHECK(pal_rng_fill(&g_script, b, sizeof b) == 0, "fill 12 failed");
    CHECK(b[0] == 1 && b[7] == 8 && b[8] == 9 && b[11] == 0x0c, "raw words not little-endian in order");
    CHECK(g_seed_i == 2, "12 bytes took %zu words, want 2", g_seed_i);

    uint8_t z[1] = { 0xAA };
    script(NULL, 0, NULL, 0);
    CHECK(pal_rng_fill(&g_script, z, 0) == 0 && z[0] == 0xAA, "size 0 wrote or failed");
}

static void test_keystream_large(void) {
    /* 33 bytes: the ChaCha path, key = words 1..4 of the default script. */
    uint8_t got[200], want[256];
    uint32_t key[8], nonce[3] = { 0, 0, 0 };
    script(NULL, 0, NULL, 0);
    g_seed_script = NULL;
    CHECK(pal_rng_fill(&g_script, got, sizeof got) == 0, "fill 200 failed");
    CHECK(g_counter == 4, "200 bytes took %llu words, want 4 (one key)", (unsigned long long)g_counter);
    for (int i = 0; i < 4; i++) {
        uint64_t w = (uint64_t)(i + 1) * 0x9E3779B97F4A7C15ULL;
        key[2 * i] = (uint32_t)w;
        key[2 * i + 1] = (uint32_t)(w >> 32);
    }
    for (uint32_t c = 0; c < 4; c++)
        pal_chacha20_block(key, c, nonce, want + 64 * c);
    CHECK(!memcmp(got, want, sizeof got), "200 bytes are not the keystream under the 4 words");

    /* The partial last block and an unaligned destination. */
    uint8_t buf[101];
    script(NULL, 0, NULL, 0);
    g_seed_script = NULL;
    CHECK(pal_rng_fill(&g_script, buf + 1, 33) == 0, "fill 33 failed");
    CHECK(!memcmp(buf + 1, want, 33), "33 bytes (unaligned) are not the keystream's first 33");
}

static void test_rekey_per_chunk(void) {
    size_t n = PAL_RNG_CHUNK + 100;
    uint8_t* b = malloc(n);
    uint8_t want[64];
    uint32_t key[8], nonce[3] = { 0, 0, 0 };
    script(NULL, 0, NULL, 0);
    g_seed_script = NULL;
    CHECK(b && pal_rng_fill(&g_script, b, n) == 0, "fill 1 MiB + 100 failed");
    CHECK(g_counter == 8, "1 MiB + 100 took %llu words, want 8 (two keys)", (unsigned long long)g_counter);
    for (int i = 0; i < 4; i++) {
        uint64_t w = (uint64_t)(i + 5) * 0x9E3779B97F4A7C15ULL;
        key[2 * i] = (uint32_t)w;
        key[2 * i + 1] = (uint32_t)(w >> 32);
    }
    pal_chacha20_block(key, 0, nonce, want);
    CHECK(b && !memcmp(b + PAL_RNG_CHUNK, want, 64), "the second chunk is not under the second key");
    free(b);
}

static void test_retries(void) {
    uint8_t b[8];
    /* RDSEED fails 5 times, then a 0 and a ~0 word, then a good one. */
    static const struct step seed[] = { { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 },
                                        { 1, 0 }, { 1, UINT64_MAX }, { 1, 0x1122334455667788ULL } };
    script(seed, 8, NULL, 0);
    CHECK(pal_rng_fill(&g_script, b, 8) == 0 && b[0] == 0x88 && b[7] == 0x11,
          "RDSEED retries / bad words: wrong word taken");
    CHECK(g_pauses == 7, "%d pauses, want 7", g_pauses);

    /* RDSEED never works: RDRAND after PAL_RNG_RDSEED_TRIES. */
    static const struct step rnd[] = { { 0, 0 }, { 1, 0 }, { 1, 0x0102030405060708ULL } };
    script(seed, 0, rnd, 3);
    CHECK(pal_rng_fill(&g_script, b, 8) == 0 && b[0] == 0x08, "RDRAND fallback: wrong word");
    CHECK(g_pauses == PAL_RNG_RDSEED_TRIES + 2, "%d pauses, want %d", g_pauses, PAL_RNG_RDSEED_TRIES + 2);

    /* Neither: a failure, and the large path writes no keystream. */
    uint8_t big[100];
    memset(big, 0xA5, sizeof big);
    script(seed, 0, rnd, 0);
    CHECK(pal_rng_fill(&g_script, b, 8) == -1, "no randomness must fail (small)");
    script(seed, 0, rnd, 0);
    CHECK(pal_rng_fill(&g_script, big, sizeof big) == -1, "no randomness must fail (large)");
    int untouched = 1;
    for (size_t i = 0; i < sizeof big; i++)
        untouched &= big[i] == 0xA5;
    CHECK(untouched, "a failed large fill wrote output");
}

static int has_rdseed(void) {
    unsigned a, b, c, d;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 18));
}

static int cmpu(const void* a, const void* b) {
    unsigned long long x = *(const unsigned long long*)a, y = *(const unsigned long long*)b;
    return x < y ? -1 : x > y;
}

static void bench(size_t n) {
    enum { R = 2001 };
    static unsigned long long t_new[R], t_old[R];
    uint8_t* b = malloc(n);
    for (int r = 0; r < R; r++) {
        unsigned long long t0 = __rdtsc();
        pal_rng_fill(&g_cpu, b, n);
        unsigned long long t1 = __rdtsc();
        old_fill(b, n);
        t_old[r] = __rdtsc() - t1;
        t_new[r] = t1 - t0;
    }
    qsort(t_new, R, sizeof t_new[0], cmpu);
    qsort(t_old, R, sizeof t_old[0], cmpu);
    printf("cost %5zu bytes: new median %7llu p99 %7llu TSC ticks, old (RDSEED32 per 4 B) median %7llu p99 %7llu\n",
           n, t_new[R / 2], t_new[R * 99 / 100], t_old[R / 2], t_old[R * 99 / 100]);
    free(b);
}

static void test_cpu(void) {
    if (!has_rdseed()) {
        printf("skip: this CPU has no RDSEED\n");
        return;
    }
    uint8_t a[2496], b[2496], c[16], d[16];
    CHECK(pal_rng_fill(&g_cpu, a, sizeof a) == 0 && pal_rng_fill(&g_cpu, b, sizeof b) == 0,
          "CPU fill failed");
    CHECK(memcmp(a, b, sizeof a), "two 2496-byte CPU fills are equal");
    CHECK(pal_rng_fill(&g_cpu, c, sizeof c) == 0 && pal_rng_fill(&g_cpu, d, sizeof d) == 0
          && memcmp(c, d, sizeof c), "two 16-byte CPU fills are equal");
    if (getenv("PAL_RNG_BENCH")) {
        bench(16);
        bench(32);
        bench(48);
        bench(2496);
        bench(65536);
    }
}

int main(void) {
    test_rfc_block();
    test_raw_small();
    test_keystream_large();
    test_rekey_per_chunk();
    test_retries();
    test_cpu();
    printf("random_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
