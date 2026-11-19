/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains host-specific code related to linking and reporting ELFs to debugger.
 */

#include <asm/errno.h>

#include "api.h"
#include "pal_rtld.h"
#include "pal_svsm.h"

/* What has been loaded where - the LibOS (pal_rtld.c), ld.so and the
 * executable (libos append_r_debug) - kept only so that svsm.stall_report
 * can say where the addresses it prints are (pal_svsm_stall_report). */
struct pal_svsm_dbg_map g_pal_svsm_dbg_maps[PAL_SVSM_DBG_MAPS];
size_t g_pal_svsm_dbg_maps_n;

void _PalDebugMapAdd(const char* name, void* addr) {
    if (g_pal_svsm_dbg_maps_n >= PAL_SVSM_DBG_MAPS || !name)
        return;
    struct pal_svsm_dbg_map* m = &g_pal_svsm_dbg_maps[g_pal_svsm_dbg_maps_n++];
    m->addr = (uintptr_t)addr;
    size_t n = strlen(name);
    const char* tail = n >= sizeof(m->name) ? name + n - (sizeof(m->name) - 1) : name;
    memcpy(m->name, tail, strlen(tail) + 1);
}

void _PalDebugMapRemove(void* addr) {}

int _PalDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size) {
    __UNUSED(addr);
    __UNUSED(buf);
    __UNUSED(buf_size);
    return -ENOSYS;
}
