/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attributes of streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"

int _PalSendHandle(PAL_HANDLE target_process, PAL_HANDLE cargo) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalInitDebugStream(const char* path) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalDebugLog(const void* buf, size_t size) {

    /* 32 bytes a call, the terminating 0 in the last one (or a call of its
     * own when the line fills its last chunk exactly). */
    const uint8_t* log_string = buf;
    uint8_t chunk[32];
    size_t i = 0;
    while (i < size) {
        size_t n = size - i < 32 ? size - i : 32;
        memcpy(chunk, log_string + i, n);
        i += n;
        if (i == size && n < 32) {
            chunk[n] = 0;
            pal_svsm_debug_write(chunk, n + 1);
            return 0;
        }
        pal_svsm_debug_write(chunk, n);
    }
    pal_svsm_debug_putc(0);
    return 0;
}
