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
#include "pal_svsm_chan.h"

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
/* The filesystem region's DATA base, remembered so the two readers below can
 * find the monitor's header one page before it. Set by the attach; a forked
 * child inherits the value and the mapping together, which is correct - it is
 * the same region at the same address, that being the whole point of a
 * lineage. */
static void* g_lineage_fs_base;

int _PalLineageFsAttach(uint64_t pages, void** base, size_t* size) {
    void* b = NULL;
    size_t sz = 0;
    pal_svsm_lineage_fs(pages, PAL_SVSM_LINEAGE_FS, &b, &sz);
    if (!sz)
        return -PAL_ERROR_DENIED;
    *base = b;
    *size = sz;
    g_lineage_fs_base = b;
    return 0;
}

/*
 * This process's own serial, as the monitor stamped it.
 *
 * The only identity in reach that is never reused. A pid is a store slot and
 * a successor gets the same number; a serial is stamped once per process, so
 * it is what a shared structure must record when it writes down who holds
 * something.
 *
 * READ EVERY TIME, never cached in a caller. A copy-on-write fork gives the
 * child every byte of its parent's memory, so a cached serial in a LibOS
 * global would be the PARENT's - and a child that signed a lock with it would
 * be indistinguishable from its parent to everyone including itself.
 */
int _PalLineageSelf(uint64_t* out) {
    if (!g_lineage_fs_base)
        return -PAL_ERROR_DENIED;   /* no region held: not in any lineage */
    uint64_t s = pal_chan_u64(PAL_CHAN_DIR_VADDR, PAL_CHAN_DIR_SERIAL);
    if (!s)
        return -PAL_ERROR_DENIED;
    *out = s;
    return 0;
}

/*
 * Is `serial` still a member of this lineage?
 *
 * The monitor's roster, read straight out of the region header. ABSENCE is
 * the death criterion and a timeout is never one: a live member can be off
 * its processor for a preemption tick, for a service slice, or indefinitely
 * between invokes, and none of that makes it dead. A member leaves this list
 * only in `drop_mapper`, which runs before anything it held is freed.
 */
int _PalLineageMemberAlive(uint64_t serial, bool* out) {
    if (!g_lineage_fs_base)
        return -PAL_ERROR_DENIED;
    if (!serial) {
        *out = false;
        return 0;
    }
    uintptr_t hdr = (uintptr_t)g_lineage_fs_base - PAGE_SIZE;
    for (unsigned i = 0; i < PAL_CHAN_MAX_MEMBERS; i++) {
        if (pal_chan_u64(hdr, PAL_CHAN_HDR_MEMBERS + i * 8) == serial) {
            *out = true;
            return 0;
        }
    }
    *out = false;
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
