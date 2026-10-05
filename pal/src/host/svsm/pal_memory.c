/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    return pal_svsm_virt_alloc(addr, size, prot);
}

int _PalVirtualMemoryFree(void* addr, uint64_t size) {
    return pal_svsm_free(addr, size);
}

int _PalVirtualMemoryProtect(void* addr, uint64_t size, pal_prot_flags_t prot) {
    return pal_svsm_mprotect(addr, size, prot);
}

/* Zero-copy alias of runtime image pages: the monitor's map call with the
 * runtime pseudo-fd (-3), like the LibOS blob's -2. */
#define FD_RUNTIME_IMAGE (-3)
int _PalLineageFsAttach(uint64_t pages, void** base, size_t* size) {
    void* b = NULL;
    size_t sz = 0;
    pal_svsm_lineage_fs(pages, &b, &sz);
    if (!sz)
        return -PAL_ERROR_DENIED;
    *base = b;
    *size = sz;
    return 0;
}

int _PalRuntimeImageMap(void* addr, uint64_t size, pal_prot_flags_t prot, uint64_t image_off) {
    if (!g_pal_public_state.runtime_images[0].size)
        return -PAL_ERROR_NOTIMPLEMENTED;
    if (!pal_svsm_mmap(addr, size, prot, prot, FD_RUNTIME_IMAGE, image_off))
        return -PAL_ERROR_DENIED;
    return 0;
}

unsigned long _PalMemoryQuota(void) {
    return g_pal_public_state.memory_address_end - g_pal_public_state.memory_address_start;
}

void pal_read_next_reserved_range(uintptr_t last_range_start, uintptr_t* out_next_range_start,
                                  uintptr_t* out_next_range_end) {
    *out_next_range_start = 0;
    *out_next_range_end = 0;
}
