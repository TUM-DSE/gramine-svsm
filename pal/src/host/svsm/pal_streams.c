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

    const uint8_t* log_string = buf;
    for(size_t i = 0; i < size; i++){
        pal_svsm_debug_putc(log_string[i]);
    }
    pal_svsm_debug_putc(0);
    return 0;
}
