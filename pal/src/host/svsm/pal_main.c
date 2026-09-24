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

    /* Tell the monitor where to bring a fault it will not handle itself.
     * From here on a SIGSEGV in this vault reaches the application instead
     * of retiring it from outside. */
    pal_svsm_exception_init();

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
            /* How urgent this service is, 0..7, higher being more
             * urgent. From the manifest for the same reason the name is:
             * a vault that could raise its own priority at runtime would
             * make the scheduler's guarantees mean nothing, and an
             * attestation covering the manifest covers this with it.
             * Absent = 4, the middle. */
            int64_t priority = 4;
            toml_int_in(manifest_svsm_early, "priority", 4, &priority);
            if (priority < 0) priority = 0;
            if (priority > 7) priority = 7;
            if (packed)
                pal_svsm_service_declare(packed, (uint64_t)priority);
            free(service_name);
        }
    }

    /* Does this image run inference? 512 pages at INFERENCE_VADDR in
     * every trustlet of this lineage, or none - it used to be 2.00 of the
     * 2.09 MiB a trustlet cost at creation, whether or not it ever ran
     * inference, and almost none do.
     *
     * A trait of the image and not a runtime request, for a reason that
     * is not about policy: the inference client writes the context page
     * at INFERENCE_VADDR and only then calls REGISTER, so the first the
     * monitor could otherwise hear of it is after the vault has faulted.
     * Measured, like the service name above.
     *
     *   [svsm.inference]
     *   enabled = true
     */
    if (manifest_svsm_early) {
        toml_table_t* inf = toml_table_in(manifest_svsm_early, "inference");
        if (inf) {
            bool enabled = false;
            if (toml_bool_in(inf, "enabled", false, &enabled) < 0)
                pal_svsm_fail("svsm.inference.enabled is not a boolean", 0);
            if (enabled && pal_svsm_inference_declare(1) < 0)
                pal_svsm_fail("svsm.inference: the monitor refused the declaration", 0);
        }
    }

    /* What the APPS on this base image may claim in their own frames -
     * the delegate envelope (PLAN.md phase 2). One base zygote serves
     * many apps, each app's frame carries its claims, and the monitor
     * seals them at create; this is the measured bound on what such a
     * claim may say. An app cannot widen it, and declaring one LOCKS this
     * image out of sealing a channel policy of its own, because that
     * policy would be inherited by every app on it.
     *
     *   [svsm.delegate]
     *   policy = true                   # apps may seal a channel policy
     *   device = false                  # apps on a DRIVER image: see below
     *   endpoints = ["echo"]            # the only names an app may offer
     *   max_accepts = 2                 # ceilings a claim may not exceed
     *   max_channels = 8
     *   levels = [0, 1, 3]
     *   guest_visible = false
     */
    if (manifest_svsm_early) {
        toml_table_t* del = toml_table_in(manifest_svsm_early, "delegate");
        if (del) {
            static uint8_t delegate_record[0x0C + 8 * 32] __attribute__((aligned(4096)));
            memset(delegate_record, 0, sizeof(delegate_record));
            memcpy(delegate_record, "MVD1", 4);
            bool allow_policy = false, allow_device = false, guest_visible = false;
            if (toml_bool_in(del, "policy", false, &allow_policy) < 0)
                pal_svsm_fail("svsm.delegate.policy is not a boolean", 0);
            if (toml_bool_in(del, "device", false, &allow_device) < 0)
                pal_svsm_fail("svsm.delegate.device is not a boolean", 0);
            if (toml_bool_in(del, "guest_visible", false, &guest_visible) < 0)
                pal_svsm_fail("svsm.delegate.guest_visible is not a boolean", 0);
            int64_t max_accepts = 0, max_channels = 0;
            toml_int_in(del, "max_accepts", 0, &max_accepts);
            toml_int_in(del, "max_channels", 0, &max_channels);
            if (max_accepts < 0 || max_accepts > 8)
                pal_svsm_fail("svsm.delegate.max_accepts is outside 0..8", (int)max_accepts);
            if (max_channels < 0 || max_channels > 64)
                pal_svsm_fail("svsm.delegate.max_channels is outside 0..64", (int)max_channels);
            delegate_record[0x04] = allow_policy;
            delegate_record[0x05] = allow_device;
            delegate_record[0x06] = (uint8_t)max_accepts;
            /* Which levels a claimed accept rule may admit. Absent means
             * the monitor's default (0, 1 and 3 - never the guest's). */
            uint8_t levels = 0;
            toml_array_t* lv = toml_array_in(del, "levels");
            if (lv) {
                for (int i = 0; ; i++) {
                    toml_datum_t d = toml_int_at(lv, i);
                    if (!d.ok)
                        break;
                    if (d.u.i < 0 || d.u.i > 3)
                        pal_svsm_fail("svsm.delegate.levels holds a level that is not 0..3",
                                      (int)d.u.i);
                    levels |= (uint8_t)(1u << d.u.i);
                }
            }
            delegate_record[0x07] = levels;
            delegate_record[0x08] = (uint8_t)(max_channels & 0xFF);
            delegate_record[0x09] = (uint8_t)((max_channels >> 8) & 0xFF);
            delegate_record[0x0A] = guest_visible;
            /* The endpoint names an app may offer. No list means an app
             * may offer nothing - it can still CONNECT OUT, which needs
             * no policy of its own. */
            int n_names = 0;
            toml_array_t* eps = toml_array_in(del, "endpoints");
            if (eps) {
                for (int i = 0; ; i++) {
                    toml_datum_t d = toml_string_at(eps, i);
                    if (!d.ok)
                        break;
                    if (n_names >= 8)
                        pal_svsm_fail("svsm.delegate.endpoints has more than 8 names", 0);
                    size_t n = strlen(d.u.s);
                    if (n == 0 || n > 32)
                        pal_svsm_fail("svsm.delegate.endpoints holds an empty or "
                                      "over-long name", (int)n);
                    memcpy(delegate_record + 0x0C + n_names * 32, d.u.s, n);
                    n_names++;
                    free(d.u.s);
                }
            }
            delegate_record[0x0B] = (uint8_t)n_names;
            if (pal_svsm_delegate(delegate_record, 0x0C + n_names * 32) != 0)
                pal_svsm_fail("svsm.delegate: the monitor refused the envelope", 0);
        }
    }

    /* And what it offers other VAULTS: the channel policy (PLAN.md,
     * "Vault-to-vault channels and an optional router"). Sealed here, from
     * the measured manifest, before any application code runs - that is
     * what makes "who may connect to me, and on what terms" part of what an
     * attestation covers rather than something a vault decides at runtime.
     *
     * The record is packed little-endian, exactly as `ipc::seal_policy`
     * reads it. Anything malformed stops the vault here: a policy that
     * silently fell back to "no channels" would look like a working vault
     * that nobody can reach.
     *
     *   [svsm]
     *   name = "kv"                     # who this vault is, to others
     *   [svsm.endpoint]                 # omit to offer nothing
     *   id = "rpc"
     *   direction = "both"              # both | in | out
     *   in  = { slot = 256, depth = 64 }
     *   out = { slot = 256, depth = 64 }
     *   max_channels = 64
     *   guest_visible = false
     *   [[svsm.accept]]                 # who may connect; none = nobody
     *   name = "frontend"               # or any = true, or same = true,
     *   pin = "function:<128 hex>"      # or a measurement to pin
     *   levels = [1, 3]                 # default: 0, 1 and 3, never 2
     *   max = 4                         # channels per requester instance
     */
    if (manifest_svsm_early) {
        /* Page-aligned: the monitor copies the record from one page,
         * which is all a call argument may span. */
        static uint8_t policy_record[0x44 + 8 * 0x68] __attribute__((aligned(4096)));
        memset(policy_record, 0, sizeof(policy_record));
        memcpy(policy_record, "VCP1", 4);
        bool wanted = false;

        char* vault_name = NULL;
        if (toml_string_in(manifest_svsm_early, "name", &vault_name) == 0 && vault_name) {
            size_t n = strlen(vault_name);
            if (n > 32)
                pal_svsm_fail("svsm.name is longer than 32 bytes", 0);
            memcpy(policy_record + 0x04, vault_name, n);
            wanted = true;
            free(vault_name);
        }

        /* [svsm.net]: who this vault may open a socket to. Measured, like
         * everything else a vault claims about itself - `socket()` works
         * without it, `connect()` does not, and the attestation says so.
         *
         *   [svsm.net]
         *   service  = "echo"      # the name that vault declares
         *   endpoint = "rpc"       # which of its endpoints
         */
        toml_table_t* net = toml_table_in(manifest_svsm_early, "net");
        if (net) {
            char* svc = NULL;
            if (toml_string_in(net, "service", &svc) != 0 || !svc)
                pal_svsm_fail("svsm.net needs a service name", 0);
            size_t n = strlen(svc);
            if (n == 0 || n > sizeof(g_pal_svsm_net_name))
                pal_svsm_fail("svsm.net.service is empty or longer than 32 bytes", (int)n);
            memcpy(g_pal_svsm_net_name, svc, n);
            free(svc);

            char* nep = NULL;
            if (toml_string_in(net, "endpoint", &nep) != 0 || !nep)
                pal_svsm_fail("svsm.net needs an endpoint", 0);
            uint64_t packed = 0;
            for (size_t i = 0; i < 8 && nep[i]; i++)
                packed |= (uint64_t)(unsigned char)nep[i] << (i * 8);
            if (!packed)
                pal_svsm_fail("svsm.net.endpoint is empty", 0);
            g_pal_svsm_net_endpoint = packed;
            free(nep);

            /* Whether that service is a NETWORK service - one that will
             * open a TCP connection on this vault's behalf - or just
             * another vault on the other end of a pipe. It changes what
             * `connect()` puts on the wire first (the MVN1 record in
             * tools/netsvc/src/mvnet.h), so it is measured rather than
             * guessed: a vault that started speaking a protocol its peer
             * does not know would hand it the application's first bytes
             * as if they were an address.
             *
             *   protocol = "mvnet"   # absent = a raw channel to a peer
             */
            char* proto = NULL;
            if (toml_string_in(net, "protocol", &proto) == 0 && proto) {
                if (!strcmp(proto, "mvnet"))
                    g_pal_svsm_net_protocol = 1;
                else
                    pal_svsm_fail("svsm.net.protocol: only \"mvnet\" is known", 0);
                free(proto);
            }
        }

        toml_table_t* ep = toml_table_in(manifest_svsm_early, "endpoint");
        if (ep) {
            char* id = NULL;
            if (toml_string_in(ep, "id", &id) != 0 || !id)
                pal_svsm_fail("svsm.endpoint needs an id", 0);
            uint64_t packed = 0;
            for (size_t i = 0; i < 8 && id[i]; i++)
                packed |= (uint64_t)(unsigned char)id[i] << (i * 8);
            if (!packed)
                pal_svsm_fail("svsm.endpoint.id is empty", 0);
            memcpy(policy_record + 0x24, &packed, 8);
            free(id);

            uint8_t dir = 3;
            char* direction = NULL;
            if (toml_string_in(ep, "direction", &direction) == 0 && direction) {
                if (!strcmp(direction, "in")) dir = 1;
                else if (!strcmp(direction, "out")) dir = 2;
                else if (!strcmp(direction, "both")) dir = 3;
                else pal_svsm_fail("svsm.endpoint.direction is not in, out or both", 0);
                free(direction);
            }
            policy_record[0x3C] = dir;

            /* in = { slot, depth } and out = { slot, depth }: the message
             * size and how many may be in flight, fixed here so a requester
             * cannot ask for a bigger ring than the service sized. */
            const char* which[2] = { "in", "out" };
            for (int i = 0; i < 2; i++) {
                toml_table_t* ring = toml_table_in(ep, which[i]);
                if (!ring) {
                    if (dir & (i == 0 ? 1 : 2))
                        pal_svsm_fail("svsm.endpoint names a direction without its ring", 0);
                    continue;
                }
                int64_t slot = 0, depth = 0;
                toml_int_in(ring, "slot", 0, &slot);
                toml_int_in(ring, "depth", 0, &depth);
                if (slot <= 0 || depth <= 0)
                    pal_svsm_fail("svsm.endpoint ring needs slot and depth", 0);
                uint32_t s32 = (uint32_t)slot, d32 = (uint32_t)depth;
                memcpy(policy_record + 0x2C + i * 8, &s32, 4);
                memcpy(policy_record + 0x30 + i * 8, &d32, 4);
            }

            int64_t max_channels = 64;
            toml_int_in(ep, "max_channels", 64, &max_channels);
            if (max_channels <= 0 || max_channels > 64)
                pal_svsm_fail("svsm.endpoint.max_channels is out of range", 0);
            uint16_t mc = (uint16_t)max_channels;
            memcpy(policy_record + 0x3E, &mc, 2);

            bool guest_visible = false;
            toml_bool_in(ep, "guest_visible", false, &guest_visible);
            policy_record[0x3D] = guest_visible ? 1 : 0;
            wanted = true;
        }

        toml_array_t* accepts = toml_array_in(manifest_svsm_early, "accept");
        int n_accepts = accepts ? toml_array_nelem(accepts) : 0;
        if (n_accepts > 8)
            pal_svsm_fail("svsm.accept has more than eight rules", 0);
        for (int i = 0; i < n_accepts; i++) {
            toml_table_t* a = toml_table_at(accepts, i);
            if (!a)
                pal_svsm_fail("svsm.accept holds something that is not a rule", 0);
            uint8_t* rec = policy_record + 0x44 + (size_t)i * 0x68;
            bool any = false, same = false;
            toml_bool_in(a, "any", false, &any);
            toml_bool_in(a, "same", false, &same);
            char* who = NULL;
            char* pin = NULL;
            toml_string_in(a, "name", &who);
            toml_string_in(a, "pin", &pin);
            if (any) {
                rec[0] = 2;
            } else if (same) {
                rec[0] = 3;
            } else if (pin) {
                /* "<field>:<128 hex>", the field being one the monitor
                 * measured: init (the PAL), manifest, libos, runtime or
                 * function. */
                const char* colon = strchr(pin, ':');
                if (!colon || strlen(colon + 1) != 128)
                    pal_svsm_fail("svsm.accept.pin is not <field>:<128 hex>", 0);
                size_t flen = (size_t)(colon - pin);
                static const char* fields[] = { "init", "manifest", "libos", "runtime", "function" };
                rec[1] = 0;
                for (uint8_t f = 0; f < 5; f++)
                    if (flen == strlen(fields[f]) && !memcmp(pin, fields[f], flen))
                        rec[1] = f + 1;
                if (!rec[1])
                    pal_svsm_fail("svsm.accept.pin names no measured field", 0);
                for (int b = 0; b < 64; b++) {
                    uint8_t byte = 0;
                    for (int half = 0; half < 2; half++) {
                        char c = colon[1 + b * 2 + half];
                        uint8_t v = 0;
                        if (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
                        else if (c >= 'a' && c <= 'f') v = (uint8_t)(c - 'a' + 10);
                        else if (c >= 'A' && c <= 'F') v = (uint8_t)(c - 'A' + 10);
                        else pal_svsm_fail("svsm.accept.pin is not hex", 0);
                        byte = (uint8_t)((byte << 4) | v);
                    }
                    rec[40 + b] = byte;
                }
                rec[0] = 4;
            } else if (who) {
                size_t n = strlen(who);
                if (n > 32)
                    pal_svsm_fail("svsm.accept.name is longer than 32 bytes", 0);
                memcpy(rec + 8, who, n);
                rec[0] = 1;
            } else {
                pal_svsm_fail("svsm.accept rule says nothing", 0);
            }
            free(who);
            free(pin);

            /* Which levels a requester may run at. Absent: 0, 1 and 3 -
             * never 2, the guest's own, which the endpoint must make
             * guest_visible to admit at all. */
            toml_array_t* levels = toml_array_in(a, "levels");
            if (levels) {
                uint8_t mask = 0;
                for (int l = 0; l < toml_array_nelem(levels); l++) {
                    toml_datum_t d = toml_int_at(levels, l);
                    if (!d.ok || d.u.i < 0 || d.u.i > 3)
                        pal_svsm_fail("svsm.accept.levels holds a level that is not 0..3", 0);
                    mask |= (uint8_t)(1u << d.u.i);
                }
                rec[2] = mask;
            }

            int64_t max = 0;
            toml_int_in(a, "max", 0, &max);
            if (max < 0 || max > 0xFFFF)
                pal_svsm_fail("svsm.accept.max is out of range", 0);
            uint16_t m16 = (uint16_t)max;
            memcpy(rec + 4, &m16, 2);
            wanted = true;
        }
        policy_record[0x40] = (uint8_t)n_accepts;

        if (wanted) {
            int64_t sealed = pal_svsm_channel_policy(policy_record,
                                                     0x44 + (uint64_t)n_accepts * 0x68);
            if (sealed != 0)
                pal_svsm_fail("the monitor refused this vault's channel policy", sealed);
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
    int64_t window_pages = 0, mmio_vendor = 0, mmio_device = 0, mmio_bar = 0;
    toml_table_t* manifest_svsm = toml_table_in(g_pal_public_state.manifest_root, "svsm");
    if (manifest_svsm) {
        toml_int_in(manifest_svsm, "device_window_pages", 0, &window_pages);
        toml_int_in(manifest_svsm, "device_mmio_vendor", 0, &mmio_vendor);
        toml_int_in(manifest_svsm, "device_mmio_device", 0, &mmio_device);
        /* Which BAR the registers are in. Zero unless the manifest says
         * otherwise, which is right for everything that keeps them where
         * they have always been - and wrong for modern virtio, which is
         * why this is a manifest key rather than an assumption. */
        toml_int_in(manifest_svsm, "device_mmio_bar", 0, &mmio_bar);
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
                             (uint8_t)(mmio_bar & 0xFF), &base, &size, &phys);
        g_pal_public_state.device_mmio.base = base;   /* always NULL */
        g_pal_public_state.device_mmio.size = size;
        g_pal_public_state.device_mmio.phys = phys;
        g_pal_public_state.device_mmio.io = pal_svsm_device_io;
        g_pal_public_state.device_mmio.cfg = pal_svsm_device_config;
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
