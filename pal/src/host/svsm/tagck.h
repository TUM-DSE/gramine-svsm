/* The wrong-data hunt's tag checker (net_client_tagged, 2026-11-08; NOT for
 * merge). Fed the bytes of one connection's stream in order, it skips the
 * HTTP response header and checks the first 8 MiB of body as 16-byte words of
 * scripts/net_http_tag.py: sid u32 (constant), offset u64 (the word's own),
 * magic u32 0x4D564247. Its first bad word is reported once. */
#ifndef TAGCK_H
#define TAGCK_H
#include <stdbool.h>
#include <stdint.h>

#define TAGCK_MAGIC 0x4D564247u
#define TAGCK_LIMIT (8ull << 20)
struct tagck {
    uint32_t hdr;          /* how much of "\r\n\r\n" has been seen; 4: in the body */
    uint64_t body;         /* body bytes seen */
    uint8_t  word[16];
    uint32_t wfill;
    uint32_t sid;
    bool     have_sid, done, bad;
    uint64_t bad_pos;      /* the first bad word's body offset */
    uint32_t bad_sid, bad_magic;
    uint64_t bad_off;
};
/* Feed `n` bytes; true the first time a bad word is seen. */
static inline bool tagck_feed(struct tagck* t, const uint8_t* p, uint64_t n) {
    bool now = false;
    while (n && !t->done) {
        if (t->hdr < 4) {
            static const char end[4] = {'\r', '\n', '\r', '\n'};
            t->hdr = (*p == (uint8_t)end[t->hdr]) ? t->hdr + 1 : (*p == '\r' ? 1 : 0);
            p++; n--;
            continue;
        }
        uint32_t take = 16 - t->wfill;
        if (take > n)
            take = (uint32_t)n;
        __builtin_memcpy(t->word + t->wfill, p, take);
        t->wfill += take; p += take; n -= take;
        if (t->wfill < 16)
            continue;
        t->wfill = 0;
        uint32_t sid, magic;
        uint64_t off;
        __builtin_memcpy(&sid, t->word, 4);
        __builtin_memcpy(&off, t->word + 4, 8);
        __builtin_memcpy(&magic, t->word + 12, 4);
        if (!t->have_sid) {
            t->sid = sid;
            t->have_sid = true;
        }
        if (!t->bad && (sid != t->sid || off != t->body || magic != TAGCK_MAGIC)) {
            t->bad = true;
            now = true;
            t->bad_pos = t->body;
            t->bad_sid = sid;
            t->bad_off = off;
            t->bad_magic = magic;
        }
        t->body += 16;
        if (t->body >= TAGCK_LIMIT)
            t->done = true;
    }
    return now;
}
#endif
