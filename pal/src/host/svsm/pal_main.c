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

#define MONITOR_PAGE_SIZE 4096
#define MANIFEST_START (void*)0x10000000000
typedef void (*loader_callback)(void);

static void pal_initilize_memory() {

   g_pal_public_state.memory_address_start = (void*)0x10000000000;
   g_pal_public_state.memory_address_end = (void*)0x40000000000;
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

    // Entering the actual pal_main

    pal_main(instance_id, parent_process, NULL, NULL, NULL, NULL);
}
