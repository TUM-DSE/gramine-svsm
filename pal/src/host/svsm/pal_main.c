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

/*
 * The one CPU a vault has.
 *
 * Nothing filled this in before, so threads_cnt was 0 and every caller that
 * asks the system how many CPUs there are got zero back: os.cpu_count(),
 * len(sched_getaffinity(0)), nproc. A library that sizes a worker pool by
 * that divides by zero. /proc/cpuinfo was empty for the same reason.
 *
 * One thread on one core in one socket in one NUMA node is the truth as a
 * vault can see it: the monitor runs its single VMSA on whichever vCPU it
 * likes, and the threads in pal_threading.c share that one CPU. Caches and
 * NUMA distances are left empty rather than invented - /sys entries for them
 * simply do not appear, which is a shape Linux itself produces.
 */
static struct pal_cpu_thread_info g_topo_thread;
static struct pal_cpu_core_info   g_topo_core;
static struct pal_socket_info     g_topo_socket;
static struct pal_numa_node_info  g_topo_node;
static size_t                     g_topo_distance = 10;  /* local, as ACPI SLIT spells it */

static void pal_initialize_topology(void) {
    g_topo_thread.is_online = true;
    g_topo_thread.core_id   = 0;
    for (size_t i = 0; i < MAX_CACHES; i++)
        g_topo_thread.ids_of_caches[i] = (size_t)-1;   /* no cache is described */

    g_topo_core.socket_id = 0;
    g_topo_core.node_id   = 0;

    g_topo_node.is_online = true;
    for (size_t i = 0; i < HUGEPAGES_MAX; i++)
        g_topo_node.nr_hugepages[i] = 0;

    struct pal_topo_info* topo = &g_pal_public_state.topo_info;
    topo->caches_cnt     = 0;
    topo->caches         = NULL;
    topo->threads_cnt    = 1;
    topo->threads        = &g_topo_thread;
    topo->cores_cnt      = 1;
    topo->cores          = &g_topo_core;
    topo->sockets_cnt    = 1;
    topo->sockets        = &g_topo_socket;
    topo->numa_nodes_cnt = 1;
    topo->numa_nodes     = &g_topo_node;
    topo->numa_distance_matrix = &g_topo_distance;
}

/*
 * What /proc/cpuinfo says about that CPU. Read out of CPUID, which reaches
 * the monitor as a reflected #VC and is answered from the SNP CPUID page.
 * The vendor and brand strings must exist because /proc/cpuinfo prints them
 * with %s; when the CPUID page has no brand leaves, say so rather than print
 * whatever happened to be in the buffer.
 */
static const char* g_cpu_vendor = "Unknown";
static char g_cpu_brand[49];

static void pal_initialize_cpu_info(void) {
    static char vendor[13];
    uint32_t words[4];

    cpuid(0, 0, words);
    uint32_t max_leaf = words[0];
    memcpy(&vendor[0], &words[1], 4);   /* ebx */
    memcpy(&vendor[4], &words[3], 4);   /* edx */
    memcpy(&vendor[8], &words[2], 4);   /* ecx */
    vendor[12] = '\0';
    if (vendor[0])
        g_cpu_vendor = vendor;

    uint64_t family = 0, model = 0, stepping = 0;
    if (max_leaf >= 1) {
        cpuid(1, 0, words);
        uint32_t eax = words[0];
        family   = (eax >> 8) & 0xf;
        model    = (eax >> 4) & 0xf;
        stepping = eax & 0xf;
        if (family == 0xf)
            family += (eax >> 20) & 0xff;
        if (family == 0xf || family == 0x6)
            model += ((eax >> 16) & 0xf) << 4;
    }

    cpuid(0x80000000, 0, words);
    if (words[0] >= 0x80000004) {
        for (uint32_t leaf = 0x80000002, off = 0; leaf <= 0x80000004; leaf++, off += 16) {
            cpuid(leaf, 0, words);
            memcpy(&g_cpu_brand[off], words, 16);
        }
        g_cpu_brand[48] = '\0';
    }
    if (!g_cpu_brand[0])
        memcpy(g_cpu_brand, "Unknown", sizeof("Unknown"));

    g_pal_public_state.cpu_info.cpu_vendor   = g_cpu_vendor;
    g_pal_public_state.cpu_info.cpu_brand    = g_cpu_brand;
    g_pal_public_state.cpu_info.cpu_family   = family;
    g_pal_public_state.cpu_info.cpu_model    = model;
    g_pal_public_state.cpu_info.cpu_stepping = stepping;
    g_pal_public_state.cpu_info.cpu_bogomips = _PalGetBogomips();
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

	first_thread = NULL;
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

    /* Before anything asks the time. Until this runs, a tick is counted as a
     * microsecond and every duration is wrong by whatever the clock rate is. */
    pal_svsm_time_init();

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

    pal_initialize_topology();
    pal_initialize_cpu_info();

    /* Threads in a vault are cooperative contexts, not CPUs; see
     * pal_threading.c. LibOS reads this to decide whether a spin that waits
     * on another thread has to yield. */
    g_pal_public_state.cooperative_threading = true;

    /* Needs the slab allocator, and has to be in place before anything can
     * block or spin - which includes everything below. */
    ret = pal_svsm_threading_init(&first_thread);
    if (ret < 0)
        pal_svsm_fail("pal_svsm_threading_init() failed: ", ret);

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

    pal_main(instance_id, parent_process, first_thread, NULL, NULL, NULL);
}
