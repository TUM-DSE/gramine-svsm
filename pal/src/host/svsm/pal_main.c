/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains the main function of the PAL loader, which loads and processes environment,
 * arguments and manifest.
 */

#include <stdint.h>
#include "api.h"
#include "pal.h"
#include "init.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_monitor_call.h"
#include "pal_svsm.h"
#include "pal_rtld.h"
#include "toml_utils.h"

#define MONITOR_PAGE_SIZE 4096
#define MANIFEST_START (void*)0x10000000000
typedef void (*loader_callback)(void);

static void pal_initilize_memory() {

   g_pal_public_state.memory_address_start = (void*)0x40000000000;
   g_pal_public_state.memory_address_end = (void*)0x80000000000;
   g_pal_public_state.initial_mem_ranges_len = 100;

}

noreturn void pal_svsm_main(void) 
{

	uint64_t instance_id = 0; // Will be initialized in pal_main via _PalRandomBitsRead function
	PAL_HANDLE parent_process = NULL;
	PAL_HANDLE first_thread;
	const char** arguments;
	const char** environments;
	loader_callback callback;
    int ret;

	__UNUSED(first_thread);
	__UNUSED(arguments);
	__UNUSED(environments);
	__UNUSED(callback);

    /* we don't yet have a TCB in the GS register, but GCC's stack protector will look for a canary
     * at gs:[0x8] in functions called below, so let's install a dummy TCB with a default canary */
    PAL_SVSM_TCB dummy_tcb_for_stack_protector = { 0 };
    dummy_tcb_for_stack_protector.common.self = &dummy_tcb_for_stack_protector.common;
    ret = pal_svsm_set_tcb(&dummy_tcb_for_stack_protector.common);
    if (ret < 0) {
        /* We failed to install a TCB (and haven't applied relocations yet), so no other code will
         * work anyway */
        pal_svsm_fail("pal_svsm_set_tcb() failed: ", ret);;
    }

    uint64_t start_time;
    ret = _PalSystemTimeQuery(&start_time);
    if(ret < 0)
        pal_svsm_fail("_PalSystemTimeQuery() failed: ", ret);

    ret = setup_pal_binary();
    if(ret < 0){
        INIT_FAIL("Pal reallocation failed %d", ret);
    }


    call_init_array();

    g_pal_public_state.alloc_align = MONITOR_PAGE_SIZE;
    assert(IS_POWER_OF_2(g_pal_public_state.alloc_align)); //Not required since the page size is fixed

    //TODO: Check if froce stack to grow is required

    //TODO: Memory?
    pal_initilize_memory();
    // We use random provided by hardware

    // TODO: Get arguments
    int first_process = 1;


    // Setting binary name
    set_pal_binary_name("SVSMOS");

    // TODO: Verify Hardware

    // For now we are always the first process
    // Since arguments are not processed

    if (first_process) {
        // TODO:
    }
    init_slab_mgr();
    //pal_svsm_fail("After slab", 0);

    void* raw_manifest = MANIFEST_START;
    g_pal_common_state.raw_manifest_data = raw_manifest;
    char errbuf[256];
    //pal_svsm_fail("Test error", 0);

    // Parsing the Manifest located at a fixed address
    g_pal_public_state.manifest_root = toml_parse(raw_manifest, errbuf, sizeof(errbuf));
    if(!g_pal_public_state.manifest_root)
        INIT_FAIL_MANIFEST(errbuf);

    /* Runtime images (LibOS/runtime split): the monitor mapped them at zygote creation,
       ask where. The LibOS mounts them in init_fs(). */
    for (size_t i = 0; i < PAL_MAX_RUNTIME_IMAGES; i++) {
        void* base = NULL;
        size_t size = 0;
        pal_svsm_runtime_info(i, &base, &size);
        g_pal_public_state.runtime_images[i].base = base;
        g_pal_public_state.runtime_images[i].size = size;
        if (!size)
            break;
    }

    /* What this vault offers other vaults, if anything - the declaration
     * that makes it a service. From the manifest, so it is measured: a
     * vault cannot decide at runtime that it is something else. A device is
     * one thing to provide and by far the most machinery, but a vault that
     * offers a model, a key or an answer is a service on the same terms and
     * needs none of what follows. */
    toml_table_t* manifest_svsm_early = toml_table_in(g_pal_public_state.manifest_root, "svsm");
    if (manifest_svsm_early) {
        char* service_name = NULL;
        if (toml_string_in(manifest_svsm_early, "service", &service_name) == 0 && service_name) {
            uint64_t packed = 0;
            for (size_t i = 0; i < 8 && service_name[i]; i++)
                packed |= (uint64_t)(unsigned char)service_name[i] << (i * 8);
            if (packed)
                pal_svsm_service_declare(packed);
            free(service_name);
        }
    }

    /* A device, and memory it can reach - in that order, and only when the
     * manifest names both.
     *
     * The order is not cosmetic: the monitor refuses a window to a vault
     * that owns no device, so the device has to be claimed first. And the
     * pairing is a manifest rule, because that is where it can be seen
     * before anything runs: a window is host-readable by construction, so
     * asking for one without a device is a hole in this vault's
     * confidentiality with nothing on the other side of it. It is also not
     * the way to reach another vault - that is a channel, which is private
     * between the two of them.
     *
     * Absent keys = neither, which is every vault that is not a driver. */
    int64_t window_pages = 0, mmio_vendor = 0, mmio_device = 0;
    toml_table_t* manifest_svsm = toml_table_in(g_pal_public_state.manifest_root, "svsm");
    if (manifest_svsm) {
        toml_int_in(manifest_svsm, "device_window_pages", 0, &window_pages);
        toml_int_in(manifest_svsm, "device_mmio_vendor", 0, &mmio_vendor);
        toml_int_in(manifest_svsm, "device_mmio_device", 0, &mmio_device);
    }
    if (window_pages > 0 && mmio_vendor <= 0) {
        /* A manifest error, and a measured one, so it can only be fixed by
         * changing the manifest - which is the right place for it. Loud,
         * because the monitor would refuse the window anyway and a vault
         * that quietly started without the memory it asked for would fail
         * later and somewhere less obvious. */
        pal_svsm_fail("manifest asks for svsm.device_window_pages without "
                      "svsm.device_mmio_vendor: a window is only reachable by a "
                      "device (or the host)", 0);
    }

    if (mmio_vendor > 0) {
        void* base = NULL;
        size_t size = 0;
        uint64_t phys = 0;
        pal_svsm_device_mmio(((uint64_t)mmio_vendor & 0xFFFF) |
                             (((uint64_t)mmio_device & 0xFFFF) << 16),
                             &base, &size, &phys);
        g_pal_public_state.device_mmio.base = base;   /* always NULL */
        g_pal_public_state.device_mmio.size = size;
        g_pal_public_state.device_mmio.phys = phys;
        g_pal_public_state.device_mmio.io = pal_svsm_device_io;
    }

    if (window_pages > 0) {
        void* base = NULL;
        size_t size = 0;
        pal_svsm_device_window((uint64_t)window_pages, &base, &size);
        /* The monitor writes {magic, gpa, size, base} at offset 0. Checking
         * the magic is how this side knows it got a window and not a
         * coincidence, and the second word is the physical address a device
         * descriptor would name - the only way a vault learns one. */
        if (base && size >= 32 && ((volatile uint64_t*)base)[0] == 0x4D56445700000001ULL) {
            g_pal_public_state.device_window.base = base;
            g_pal_public_state.device_window.size = size;
            g_pal_public_state.device_window.gpa  = ((volatile uint64_t*)base)[1];
        }
    }

    // Entering the actual pal_main

    pal_main(instance_id, parent_process, NULL, NULL, NULL, NULL);
}
