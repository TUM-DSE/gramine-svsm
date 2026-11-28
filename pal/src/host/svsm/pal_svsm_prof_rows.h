/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * The bd profile's DIAGNOSTIC rows in VAULT_PROF's mc table (MicroVault notes/libos/O1-WAKE.md, the O1 stall
 * hunt 2026-11-28), in one place, with the rows REAL monitor calls own.
 *
 * The mc table is indexed by a monitor call's code & 0xff (pal_monitor_call.c prof_account), and a pseudo row
 * shares it: a pseudo row on a real call's low byte adds into that call's count and time, and the call's into
 * it. 722a40f4/cfb65fb8 put the run-queue (0xE0+) and watchless (0xD0+) rows on Park, Sleep and most of the
 * scheduler's calls - both sides' numbers meaningless. So: every row below is checked against PROF_REAL_ROWS
 * at run time (pal_svsm_prof_mc refuses one and counts it in PROF_ROW_REFUSED) and at build time by the
 * host test (test/prof_rows_test.c), which also checks that no two families overlap.
 *
 * PROF_REAL_ROWS: the low bytes of every monitor call code this PAL issues (pal_monitor_call.h and the
 * call sites, 2026-11-28): 00 02 04 A4 AC C0 C1 D3-D5 D7-DF E0-E5 E7-EF F5-F7 F9-FF.
 */
#ifndef PAL_SVSM_PROF_ROWS_H
#define PAL_SVSM_PROF_ROWS_H
#include <stdbool.h>

static inline bool prof_row_is_real(unsigned r) {
    switch (r & 0xff) {
        case 0x00: case 0x02: case 0x04: case 0xA4: case 0xAC: case 0xC0: case 0xC1:
        case 0xD3: case 0xD4: case 0xD5:
        case 0xD7: case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        case 0xE0: case 0xE1: case 0xE2: case 0xE3: case 0xE4: case 0xE5:
        case 0xE7: case 0xE8: case 0xE9: case 0xEA: case 0xEB: case 0xEC: case 0xED: case 0xEE: case 0xEF:
        case 0xF5: case 0xF6: case 0xF7:
        case 0xF9: case 0xFA: case 0xFB: case 0xFC: case 0xFD: case 0xFE: case 0xFF:
            return true;
        default:
            return false;
    }
}

/* the missed-test check (cad2a452) */
#define PROF_ROW_MISS(k)        (0x10 + (k))        /* k 0..7: count */
#define PROF_ROW_MISS_US(k)     (0x18 + (k))        /* k 0..7: blocked us in the count column */
#define PROF_ROW_LOOKS          0x20
#define PROF_ROW_AUDITS         0x21
#define PROF_ROW_MARKER         0x22                /* 1: this vault has the check */
#define PROF_ROW_LAYOUT         0x23                /* the row layout's version: 2 = this file's */
#define PROF_ROW_REFUSED        0x24                /* pseudo-row writes refused (a real call's row) */
/* the discriminator (cfb65fb8) */
#define PROF_ROW_CONN_PENDING   0x26
#define PROF_ROW_CONN_RETRY     0x27
#define PROF_ROW_CONN_FAILED    0x28
#define PROF_ROW_ADV(i)         (0x2A + (i))        /* i 0..3: connect done, mux routed, credit, FIN */
#define PROF_ROW_CONN_EST(b)    (0xB0 + (b))        /* b 0..15: pending -> established, 32 us << b */
/* the blocked-time histograms (layout 2) */
#define PROF_ROW_BT_DEADLINE(k) (0x30 + (k))        /* k 0..7: waits that ended on their deadline */
#define PROF_ROW_BT_NODL(k)     (0x38 + (k))        /* k 0..7: waits with no deadline */
#define PROF_BT_BUCKETS         8                   /* x4 apart: 64us 256us 1ms 4ms 16ms 65ms 262ms >=1.05s */
#define PROF_ROW_BT(k, b)       (0x40 + (k) * PROF_BT_BUCKETS + (b))   /* 0x40..0x7F */
/* step 3 (layout 2) */
#define PROF_ROW_WL(b)          (0x80 + (b))        /* b 0..15: watchless block-to-wake, 64 us << b */
#define PROF_ROW_RQ(b)          (0x90 + (b))        /* b 0..15: run-queue delay, 1 us << b */
#define PROF_ROW_WL_DEADLINE    0xF0

/* [64us << 2b, 64us << 2(b+1)), b 7 = 1.05 s and over */
static inline unsigned prof_bt_bucket(uint64_t us) {
    unsigned b = 0;
    while (b < PROF_BT_BUCKETS - 1 && us >= (64ull << (2 * (b + 1))))
        b++;
    return b;
}
#endif
