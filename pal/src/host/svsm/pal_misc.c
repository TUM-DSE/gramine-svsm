/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "api.h"
#include "assert.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"
#include "pal_svsm_random.h"

/* How fast the clock runs, and where its zero is. Asked of the monitor once
 * at startup (pal_svsm_time_init) rather than baked in, because libpal.so is
 * measured and a constant here would make the same digest wrong on a host
 * with a different clock. Until that call happens these hold the shape of
 * the old behaviour - a tick counted as a microsecond - so that a failure to
 * ask is visibly wrong rather than a division by zero. */
static uint64_t g_tsc_hz = 1000000;
static uint64_t g_epoch_us = 0;
static bool g_time_ready = false;

void pal_svsm_time_init(void) {
    uint64_t hz = 0, epoch = 0;
    pal_svsm_time_info(&hz, &epoch);
    /* A frequency the monitor could not answer, or one so low that the
     * conversion below would be nonsense, is worth dying for: every timeout
     * in the vault would silently be off by whatever the real ratio is, and
     * that failure shows up far from here. */
    if (hz < 1000000)
        pal_svsm_fail("monitor reported no usable TSC frequency", (int)hz);
    g_tsc_hz = hz;
    g_epoch_us = epoch;
    g_time_ready = true;
}

uint64_t pal_svsm_tsc_hz(void) {
    return g_tsc_hz;
}

static inline uint64_t rdtsc_now(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* Split so that neither half can overflow: the remainder is below g_tsc_hz
 * (~2.4e9), and 2.4e9 * 1e6 is still well inside 64 bits. */
uint64_t pal_svsm_tsc_to_usec(uint64_t tsc) {
    return (tsc / g_tsc_hz) * 1000000ULL + ((tsc % g_tsc_hz) * 1000000ULL) / g_tsc_hz;
}

uint64_t pal_svsm_now_usec(void) {
    return pal_svsm_tsc_to_usec(rdtsc_now()) + g_epoch_us;
}

/* Microseconds, not tick counts. Monotonic and shared by every vault on this
 * VM, because the guest TSC starts at zero when the VM does; absolute only
 * once someone tells the monitor the wall clock, which nobody does yet, so
 * dates inside a vault are still wrong even though durations are right. */
int _PalSystemTimeQuery(uint64_t* out_usec) {
    assert(g_time_ready);
    *out_usec = pal_svsm_now_usec();
    return 0;
}

/* The CPU's two instructions, 64-bit forms only (pal_svsm_random.h says
 * why: the 16/32-bit RDSEED of some parts returns 0 with CF set). */
static bool cpu_rdseed64(uint64_t* v) {
    uint8_t ok;
    __asm__ volatile("rdseed %0\n\tsetc %1" : "=r"(*v), "=qm"(ok) :: "cc");
    return ok;
}

static bool cpu_rdrand64(uint64_t* v) {
    uint8_t ok;
    __asm__ volatile("rdrand %0\n\tsetc %1" : "=r"(*v), "=qm"(ok) :: "cc");
    return ok;
}

static void cpu_pause(void) {
    __asm__ volatile("pause");
}

static const struct pal_rng_src g_cpu_rng = {
    .rdseed = cpu_rdseed64,
    .rdrand = cpu_rdrand64,
    .pause  = cpu_pause,
};

/* Up to PAL_RNG_OLD_MAX (44) bytes: the loop this PAL always had - one
 * 32-bit RDSEED per 4 bytes, 10 tries - unchanged: below that size it is
 * the cheaper one (the CPU keeps a 32-bit word ready after an idle
 * stretch; the new path costs four 64-bit words and a block, ~2.4 us
 * flat), and the owner's rule is that nothing gets slower (2026-11-11).
 * Measured on jamie (Zen 4, TSC ticks, median of 1001; new/old): 40 B
 * after idle 5784/5472, 48 B 5784/6768, 64 B 5784/9360, 2496 B
 * 16392/403080. More than 44 bytes: ChaCha20 under a fresh RDSEED key per
 * call (pal_svsm_random.h) - 2496 bytes ~7 us where the loop took ~170 us.
 * Nothing is kept between calls either way, so a clone of a zygote shares
 * no generator state with it. */
#define PAL_RNG_OLD_MAX 44
int _PalRandomBitsRead(void* buffer, size_t size) {
    if (size > PAL_RNG_OLD_MAX) {
        if (pal_rng_fill(&g_cpu_rng, buffer, size) < 0)
            pal_svsm_fail("random: neither RDSEED nor RDRAND gave a usable word", (int)size);
        return 0;
    }

    uint8_t rnd_num[4];
    int success = 1;
    int retry_max = 10;
    uint8_t* buf = buffer;

    for(size_t i = 0; i < size;){
        int retry = 0;
        while (retry < retry_max) {
            // Gets a 32-bit random number
            __asm__ volatile (
                "mov $0, %%ebx\n\t"
                "rdseed %%eax\n\t"
                "jc 1f\n\t"
                "mov $1, %%ebx\n\t"
                "1:\n\t"
                : "=a" (rnd_num), "=b" (success));
            if(success == 0){
                break;
            }
            retry++;
        }
        if(success != 0) {
            // Reached max retries here
            pal_svsm_fail("This should not happen",0);
        }

        for(size_t j = 0; j < 4; j++){
            buf[i] = rnd_num[j];
            i++;
            if(i == size)
                break;
        }

    }

    return 0;
}

int _PalSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr) {
    switch (reg) {
        case PAL_SEGMENT_FS:
            *addr = (uintptr_t)rdfsbase();
            return 0;
        case PAL_SEGMENT_GS:
            /* GS is internally used, deny any access to it */
            return -PAL_ERROR_DENIED;
        default:
            return -PAL_ERROR_INVAL;
    }
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr) {
    switch (reg) {
        case PAL_SEGMENT_FS:
            wrfsbase((uint64_t)addr);
            return 0;
        case PAL_SEGMENT_GS:
            /* GS is internally used, deny any access to it */
            return -PAL_ERROR_DENIED;
        default:
            return -PAL_ERROR_INVAL;
    }
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* A plain CPUID: the #VC is reflected to the monitor, which answers out of
 * the SNP CPUID page. It is what /proc/cpuinfo's flags line is built from. */
int _PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    cpuid(leaf, subleaf, values);
    return 0;
}

int _PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                          void* target_info, size_t* target_info_size, void* report,
                          size_t* report_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(target_info);
    __UNUSED(target_info_size);
    __UNUSED(report);
    __UNUSED(report_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalAttestationQuote(const void* user_report_data, size_t user_report_data_size, void* quote,
                         size_t* quote_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(quote);
    __UNUSED(quote_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalGetSpecialKey(const char* name, void* key, size_t* key_size) {
    __UNUSED(name);
    __UNUSED(key);
    __UNUSED(key_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* Linux's delay-loop calibration, which by convention comes out at about
 * twice the clock in MHz. Derived rather than invented, and only ever read
 * out of /proc/cpuinfo. */
double _PalGetBogomips(void) {
    return (double)(g_tsc_hz / 1000000ULL) * 2.0;
}
