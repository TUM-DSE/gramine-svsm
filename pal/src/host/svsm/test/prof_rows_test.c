/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * The bd profile's diagnostic rows (pal_svsm_prof_rows.h): none on a real monitor call's row, no two families
 * on one row, none on the older pseudo rows (01 03 05 06 07 08: pal_svsm.h PROF_ROW_*), all in the table -
 * the check 722a40f4/cfb65fb8 lacked (their run-queue and watchless rows sat on Park/Sleep's).
 *
 *   make -C pal/src/host/svsm/test check
 */
#include <stdint.h>
#include <stdio.h>
#include "../pal_svsm_prof_rows.h"

static int g_fail, g_pass;
static const char* g_owner[256];
#define CHECK(c, ...) do { if (c) g_pass++; else { g_fail++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void claim(unsigned row, const char* who) {
    CHECK(row < 256, "%s: row %#x outside the table", who, row);
    if (row >= 256)
        return;
    CHECK(!prof_row_is_real(row), "%s: row %#x is a real monitor call's", who, row);
    CHECK(!g_owner[row], "%s: row %#x already %s's", who, row, g_owner[row] ? g_owner[row] : "");
    g_owner[row] = who;
}

int main(void) {
    const unsigned older[] = { 0x01, 0x03, 0x05, 0x06, 0x07, 0x08 };
    for (unsigned i = 0; i < sizeof older / sizeof older[0]; i++)
        claim(older[i], "older pseudo row");
    for (unsigned k = 0; k < 8; k++) {
        claim(PROF_ROW_MISS(k), "miss");
        claim(PROF_ROW_MISS_US(k), "miss us");
        claim(PROF_ROW_BT_DEADLINE(k), "bt deadline");
        claim(PROF_ROW_BT_NODL(k), "bt no-deadline");
        for (unsigned b = 0; b < PROF_BT_BUCKETS; b++)
            claim(PROF_ROW_BT(k, b), "bt bucket");
    }
    claim(PROF_ROW_LOOKS, "looks");
    claim(PROF_ROW_AUDITS, "audits");
    claim(PROF_ROW_MARKER, "marker");
    claim(PROF_ROW_LAYOUT, "layout");
    claim(PROF_ROW_REFUSED, "refused");
    claim(PROF_ROW_CONN_PENDING, "conn pending");
    claim(PROF_ROW_CONN_RETRY, "conn retry");
    claim(PROF_ROW_CONN_FAILED, "conn failed");
    for (unsigned i = 0; i < 4; i++)
        claim(PROF_ROW_ADV(i), "advance");
    for (unsigned b = 0; b < 16; b++) {
        claim(PROF_ROW_CONN_EST(b), "conn established");
        claim(PROF_ROW_WL(b), "watchless");
        claim(PROF_ROW_RQ(b), "run-queue");
    }
    claim(PROF_ROW_WL_DEADLINE, "watchless deadline");
    for (unsigned b = 0; b < PROF_SLICE_BUCKETS; b++) {
        claim(PROF_ROW_SLICE_BLOCKED(b), "slice blocked");
        claim(PROF_ROW_SLICE_RUNNABLE(b), "slice runnable");
    }
    claim(PROF_ROW_PREEMPTS, "preempts");
    CHECK(prof_slice_bucket(3) == 0 && prof_slice_bucket(4) == 1 && prof_slice_bucket(4095) == 5
          && prof_slice_bucket(4096) == 6 && prof_slice_bucket(16384) == 7, "slice bucket edges");
    /* the real rows the guard knows: Park and Sleep among them */
    CHECK(prof_row_is_real(0xE1) && prof_row_is_real(0xDE), "Park/Sleep not known as real");
    /* the x4 blocked-time buckets */
    CHECK(prof_bt_bucket(0) == 0 && prof_bt_bucket(255) == 0 && prof_bt_bucket(256) == 1, "bt bucket 0/1 edge");
    CHECK(prof_bt_bucket(262143) == 5 && prof_bt_bucket(262144) == 6, "bt bucket 5/6 edge (262 ms)");
    CHECK(prof_bt_bucket(1048576) == 7 && prof_bt_bucket(100000000) == 7, "bt bucket 7 (>= 1.05 s)");
    printf("prof_rows_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
