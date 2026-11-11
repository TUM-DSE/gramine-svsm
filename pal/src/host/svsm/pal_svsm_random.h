/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * The svsm PAL's random bytes (_PalRandomBitsRead: getrandom, /dev/urandom,
 * the LibOS's own draws).
 *
 * It used to be one 32-bit RDSEED per 4 bytes: ~270 ns per word on the
 * jamie hosts (Zen 4), so CPython's random.seed() - 2496 bytes from
 * os.urandom, which every clone of a Python zygote runs (the clone reseed,
 * notes/security/CLONE-RESEED.md) - spent ~170 us in this loop alone. And
 * the 16/32-bit RDSEED of some parts returns 0 with CF set (AMD-SB-7055),
 * which it took as a random word.
 *
 * Now, per call, and with NO state kept between calls:
 *   - up to PAL_RNG_RAW_MAX (32) bytes: the hardware words themselves;
 *   - more: a fresh 256-bit key of hardware words, and the ChaCha20
 *     keystream under it (RFC 8439 block function, nonce 0, block counter
 *     from 0), a new key every PAL_RNG_CHUNK bytes; the key and the last
 *     block are wiped before returning.
 * A hardware word is RDSEED's 64-bit form, retried PAL_RNG_RDSEED_TRIES
 * times with a pause, then RDRAND's (PAL_RNG_RDRAND_TRIES); an all-zero or
 * all-one word counts as a failed draw whatever CF said. The same policy as
 * the monitor's clone seed (monitor/kernel clone_seed.rs draw_word).
 *
 * Why this is as good as a word per 4 bytes for a vault, clones included:
 * every call starts from 256 bits the CPU's conditioned entropy source gave
 * it alone, and nothing of a call outlives it, so there is no state in the
 * vault's memory that a copy-on-write clone could share with its zygote or
 * its siblings, or that a later compromise could wind back. The bytes of
 * one call are ChaCha20's keystream under that key - the construction the
 * Linux kernel's getrandom serves from - and are as unpredictable as the
 * key is, to the vault's siblings and to the host alike (the host sees
 * neither the vault's registers nor its memory).
 *
 * Inline, with the CPU behind a small table, so that the host test
 * (test/random_test.c) runs this code against the RFC's vectors and a
 * scripted source.
 */
#ifndef PAL_SVSM_RANDOM_H
#define PAL_SVSM_RANDOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAL_RNG_RAW_MAX       32u           /* bytes served as raw hardware words */
#define PAL_RNG_CHUNK         (1u << 20)    /* bytes of keystream per key */
#define PAL_RNG_RDSEED_TRIES  128
#define PAL_RNG_RDRAND_TRIES  10

/* Where a word comes from: the CPU (pal_misc.c), or a test's script. */
struct pal_rng_src {
    bool (*rdseed)(uint64_t* v);
    bool (*rdrand)(uint64_t* v);
    void (*pause)(void);
};

/* One usable word, or false when neither instruction gave one. */
static inline bool pal_rng_word(const struct pal_rng_src* src, uint64_t* out) {
    uint64_t v;
    for (int i = 0; i < PAL_RNG_RDSEED_TRIES; i++) {
        if (src->rdseed(&v) && v != 0 && v != UINT64_MAX) {
            *out = v;
            return true;
        }
        src->pause();
    }
    for (int i = 0; i < PAL_RNG_RDRAND_TRIES; i++) {
        if (src->rdrand(&v) && v != 0 && v != UINT64_MAX) {
            *out = v;
            return true;
        }
        src->pause();
    }
    return false;
}

#define PAL_CC_ROTL(v, s) (((v) << (s)) | ((v) >> (32 - (s))))
#define PAL_CC_QR(a, b, c, d)                                                       \
    a += b; d ^= a; d = PAL_CC_ROTL(d, 16); c += d; b ^= c; b = PAL_CC_ROTL(b, 12); \
    a += b; d ^= a; d = PAL_CC_ROTL(d, 8);  c += d; b ^= c; b = PAL_CC_ROTL(b, 7)

/* One ChaCha20 block (RFC 8439 2.3), little-endian into out. */
static inline void pal_chacha20_block(const uint32_t key[8], uint32_t counter,
                                      const uint32_t nonce[3], uint8_t out[64]) {
    uint32_t s[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                       key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                       counter, nonce[0], nonce[1], nonce[2] };
    uint32_t x[16];
    for (int i = 0; i < 16; i++)
        x[i] = s[i];
    for (int i = 0; i < 10; i++) {
        PAL_CC_QR(x[0], x[4], x[8], x[12]); PAL_CC_QR(x[1], x[5], x[9], x[13]);
        PAL_CC_QR(x[2], x[6], x[10], x[14]); PAL_CC_QR(x[3], x[7], x[11], x[15]);
        PAL_CC_QR(x[0], x[5], x[10], x[15]); PAL_CC_QR(x[1], x[6], x[11], x[12]);
        PAL_CC_QR(x[2], x[7], x[8], x[13]); PAL_CC_QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + s[i];
        out[4 * i]     = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
    for (int i = 0; i < 16; i++)
        ((volatile uint32_t*)x)[i] = 0;
}

#undef PAL_CC_QR
#undef PAL_CC_ROTL

static inline void pal_rng_wipe(void* p, size_t n) {
    volatile uint8_t* b = p;
    while (n--)
        *b++ = 0;
}

/* size bytes into buf. 0, or -1 when the CPU gave no usable word (the
 * caller fails the vault, as before: no output is better than a guessable
 * one). */
static inline int pal_rng_fill(const struct pal_rng_src* src, void* buf, size_t size) {
    uint8_t* o = buf;
    uint64_t w;

    if (size <= PAL_RNG_RAW_MAX) {
        while (size) {
            size_t k = size < sizeof(w) ? size : sizeof(w);
            if (!pal_rng_word(src, &w))
                return -1;
            for (size_t j = 0; j < k; j++)
                o[j] = (uint8_t)(w >> (8 * j));
            o += k;
            size -= k;
        }
        pal_rng_wipe(&w, sizeof(w));
        return 0;
    }

    static const uint32_t nonce[3] = { 0, 0, 0 };
    uint32_t key[8];
    uint8_t blk[64];
    int ret = 0;
    while (size) {
        size_t chunk = size < PAL_RNG_CHUNK ? size : PAL_RNG_CHUNK;
        for (int i = 0; i < 4; i++) {
            if (!pal_rng_word(src, &w)) {
                ret = -1;
                goto out;
            }
            key[2 * i]     = (uint32_t)w;
            key[2 * i + 1] = (uint32_t)(w >> 32);
        }
        for (uint32_t ctr = 0; chunk; ctr++) {
            size_t k = chunk < sizeof(blk) ? chunk : sizeof(blk);
            if (k == sizeof(blk)) {
                pal_chacha20_block(key, ctr, nonce, o);
            } else {
                pal_chacha20_block(key, ctr, nonce, blk);
                for (size_t j = 0; j < k; j++)
                    o[j] = blk[j];
            }
            o += k;
            chunk -= k;
            size -= k;
        }
    }
out:
    pal_rng_wipe(key, sizeof(key));
    pal_rng_wipe(blk, sizeof(blk));
    pal_rng_wipe(&w, sizeof(w));
    return ret;
}

#endif /* PAL_SVSM_RANDOM_H */
