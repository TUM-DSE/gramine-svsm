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

int _PalSystemTimeQuery(uint64_t* out_usec) {
   // TODO: Get real time from guest maybe?
   // For now it is just the clock cycles
   uint32_t lo, hi;
   __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
   *out_usec = ((uint64_t)hi << 32 | lo);
   return 0;
}

int _PalRandomBitsRead(void* buffer, size_t size) {
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
                "jc .done\n\t"
                "mov $1, %%ebx\n\t"
                ".done:\n\t"
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

int _PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    return -PAL_ERROR_NOTIMPLEMENTED;
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

double _PalGetBogomips(void) {
    /* this has to be implemented */
    return 0.0;
}
