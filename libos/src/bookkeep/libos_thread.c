/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains code for maintaining bookkeeping of threads in library OS.
 */

#include "api.h"
#include "asan.h"
#include "assert.h"
#include "cpu.h"
#include "libos_checkpoint.h"
#include "libos_defs.h"
#include "libos_flags_conv.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_rwlock.h"
#include "libos_signal.h"
#include "libos_thread.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "list.h"
#include "pal.h"
#include "toml_utils.h"

/* TODO: consider changing this list to a tree. */
static LISTP_TYPE(libos_thread) g_thread_list = LISTP_INIT;
struct libos_lock g_thread_list_lock;

/*
 * Thread reuse (MicroVault notes/libos/THREAD-REUSE.md, C; owner 2026-11-23).
 *
 * An exited thread's LibOS stack (7 pages + a guard) is kept, up to [svsm] thread_cache of them,
 * and handed to the next thread: no VirtAlloc, no guard mprotect, no VirtFree. Its VMA stays
 * bookkept as internal (not in /proc/self/maps) and its guard page stays PROT_NONE. The usable
 * pages are zeroed on the way out, so a reused stack reads as a fresh one. In a debug vault they
 * are poisoned on the way in, and the way out counts poison seen and residue after the zeroing
 * (the lane's thread_kit_scrubbed row).
 *
 * The struct itself is not cached: it is refcounted and reachable from IPC, wait and signal paths
 * until its last put_thread. With the real-time signal queues out of line (libos_thread.h) it is a
 * slab object, reused the way any malloc is.
 */
static_assert(sizeof(struct libos_thread) <= 8192,
              "struct libos_thread must stay within the slab's top class (THREAD-REUSE.md, A)");

#define THREAD_CACHE_MAX    64
#define THREAD_CACHE_POISON 0xA5
static spinlock_t g_tc_lock = INIT_SPINLOCK_UNLOCKED;
static int   g_tc_cap = 16;     /* [svsm] thread_cache; the PAL's default (pal_svsm.h) */
static bool  g_tc_poison;       /* [svsm] debug */
static void* g_tc_stacks[THREAD_CACHE_MAX];  /* the stacks' lowest address (the guard) */
static int   g_tc_stacks_n;
static struct {
    uint64_t hits, misses, full, trimmed, poison_seen, residue;
} g_tc_stat;

static bool g_tc_suspended;     /* a fork child's after-fork steps: nothing is cached */
/* A fork child's record (-1 until it forked): what the begin hook freed, and what all three
 * caches held at the end hook - 0, or something of the parent's got through. */
static long g_tc_fork_trimmed = -1, g_tc_fork_end_cached = -1;

int thread_cache_cap(void) {
    if (__atomic_load_n(&g_tc_suspended, __ATOMIC_RELAXED))
        return 0;
    return __atomic_load_n(&g_tc_cap, __ATOMIC_RELAXED);
}

/* The cap as configured, whatever the suspension (thread_cache = 0 is the old platform, which
 * alloc_new_thread and the madvise skip ask about - not whether caching is paused). */
static int thread_cache_configured(void) {
    return __atomic_load_n(&g_tc_cap, __ATOMIC_RELAXED);
}

int init_thread_cache(void) {
    int64_t cap = 16;
    if (toml_int_in(g_manifest_root, "svsm.thread_cache", /*defaultval=*/16, &cap) < 0
            || cap < 0 || cap > THREAD_CACHE_MAX) {
        log_error("Cannot parse 'svsm.thread_cache' (an integer 0..%d)", THREAD_CACHE_MAX);
        return -EINVAL;
    }
    bool debug = false;
    if (toml_bool_in(g_manifest_root, "svsm.debug", /*defaultval=*/false, &debug) < 0) {
        log_error("Cannot parse 'svsm.debug'");
        return -EINVAL;
    }
    __atomic_store_n(&g_tc_cap, (int)cap, __ATOMIC_RELAXED);
    g_tc_poison = debug;
    return 0;
}

static void free_libos_stack(char* addr) {
#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, LIBOS_THREAD_LIBOS_STACK_SIZE);
#endif
    void* tmp_vma = NULL;
    if (bkeep_munmap(addr, LIBOS_THREAD_LIBOS_STACK_SIZE, /*is_internal=*/true, &tmp_vma) < 0) {
        log_error("[put_thread] Failed to remove bookkeeped memory at %p-%p!",
                  addr, addr + LIBOS_THREAD_LIBOS_STACK_SIZE);
        BUG();
    }
    if (PalVirtualMemoryFree(addr, LIBOS_THREAD_LIBOS_STACK_SIZE) < 0) {
        BUG();
    }
    bkeep_remove_tmp_vma(tmp_vma);
}

static bool libos_stack_cache_push(char* addr) {
    if (g_tc_poison) {
#ifdef ASAN
        asan_unpoison_region((uintptr_t)addr, LIBOS_THREAD_LIBOS_STACK_SIZE);
#endif
        memset(addr + PAGE_SIZE, THREAD_CACHE_POISON, LIBOS_THREAD_LIBOS_STACK_SIZE - PAGE_SIZE);
    }
    bool kept = false;
    spinlock_lock(&g_tc_lock);
    if (g_tc_stacks_n < thread_cache_cap()) {
        g_tc_stacks[g_tc_stacks_n++] = addr;
        kept = true;
    } else {
        g_tc_stat.full++;
    }
    spinlock_unlock(&g_tc_lock);
    return kept;
}

static char* libos_stack_cache_pop(void) {
    char* addr = NULL;
    spinlock_lock(&g_tc_lock);
    if (g_tc_stacks_n) {
        addr = g_tc_stacks[--g_tc_stacks_n];
        g_tc_stacks[g_tc_stacks_n] = NULL;
        g_tc_stat.hits++;
    } else {
        g_tc_stat.misses++;
    }
    spinlock_unlock(&g_tc_lock);
    if (!addr)
        return NULL;

    char* usable = addr + PAGE_SIZE;
    size_t usable_size = LIBOS_THREAD_LIBOS_STACK_SIZE - PAGE_SIZE;
#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, LIBOS_THREAD_LIBOS_STACK_SIZE);
#endif
    bool poisoned = g_tc_poison && (uint8_t)usable[0] == THREAD_CACHE_POISON
                    && (uint8_t)usable[usable_size - 1] == THREAD_CACHE_POISON;
    /* The scrub: a reused stack reads as a fresh one. */
    memset(usable, 0, usable_size);
    bool residue = false;
    if (g_tc_poison) {
        const uint64_t* w = (const uint64_t*)usable;
        for (size_t i = 0; i < usable_size / sizeof(*w); i++) {
            if (w[i]) {
                residue = true;
                break;
            }
        }
    }
    spinlock_lock(&g_tc_lock);
    if (poisoned)
        g_tc_stat.poison_seen++;
    if (residue)
        g_tc_stat.residue++;
    spinlock_unlock(&g_tc_lock);
    return addr;
}

/* The LibOS's stacks only; the events and the PAL's blocks are trimmed by thread_cache_trim. */
static size_t libos_stack_cache_trim(void) {
    size_t freed = 0;
    while (1) {
        char* addr = NULL;
        spinlock_lock(&g_tc_lock);
        if (g_tc_stacks_n) {
            addr = g_tc_stacks[--g_tc_stacks_n];
            g_tc_stacks[g_tc_stacks_n] = NULL;
            g_tc_stat.trimmed++;
        }
        spinlock_unlock(&g_tc_lock);
        if (!addr)
            break;
        free_libos_stack(addr);
        freed++;
    }
    return freed;
}

static size_t thread_cache_trim_count(void) {
    uint64_t before[PAL_THREAD_CACHE_NSTATS];
    uint64_t after[PAL_THREAD_CACHE_NSTATS];
    PalThreadCacheStats(before);
    size_t freed = libos_stack_cache_trim();
    freed += pollable_event_cache_trim();
    PalThreadCacheTrim();
    PalThreadCacheStats(after);
    freed += after[PAL_THREAD_CACHE_TRIMMED] - before[PAL_THREAD_CACHE_TRIMMED];
    return freed;
}

bool thread_cache_trim(void) {
    return thread_cache_trim_count() > 0;
}

void thread_cache_fork_child_begin(void) {
    __atomic_store_n(&g_tc_suspended, true, __ATOMIC_RELAXED);
    /* The child's copies of what the parent's threads released: freed in the child's address
     * space. */
    g_tc_fork_trimmed = (long)thread_cache_trim_count();
}

void thread_cache_fork_child_end(void) {
    uint64_t pal[PAL_THREAD_CACHE_NSTATS];
    struct pollable_event_cache_stats ev;
    PalThreadCacheStats(pal);
    pollable_event_cache_stats(&ev);
    spinlock_lock(&g_tc_lock);
    g_tc_fork_end_cached = g_tc_stacks_n + (long)ev.cached + (long)pal[PAL_THREAD_CACHE_CACHED];
    spinlock_unlock(&g_tc_lock);
    __atomic_store_n(&g_tc_suspended, false, __ATOMIC_RELAXED);
}

int thread_cache_format(char* buf, size_t size) {
    uint64_t pal[PAL_THREAD_CACHE_NSTATS];
    PalThreadCacheStats(pal);
    struct pollable_event_cache_stats ev;
    pollable_event_cache_stats(&ev);
    spinlock_lock(&g_tc_lock);
    int n = snprintf(buf, size,
                     "cap %d libos_stack cached %d hits %lu misses %lu full %lu trimmed %lu"
                     " poison_seen %lu residue %lu"
                     " ; event cached %lu hits %lu misses %lu full %lu trimmed %lu drained %lu"
                     " ; pal_block cap %lu cached %lu hits %lu misses %lu full %lu trimmed %lu"
                     " poison_seen %lu residue %lu ; fork trimmed %ld end_cached %ld\n",
                     thread_cache_configured(), g_tc_stacks_n, g_tc_stat.hits, g_tc_stat.misses,
                     g_tc_stat.full, g_tc_stat.trimmed, g_tc_stat.poison_seen, g_tc_stat.residue,
                     ev.cached, ev.hits, ev.misses, ev.full, ev.trimmed, ev.drained,
                     pal[PAL_THREAD_CACHE_CAP], pal[PAL_THREAD_CACHE_CACHED],
                     pal[PAL_THREAD_CACHE_HITS], pal[PAL_THREAD_CACHE_MISSES],
                     pal[PAL_THREAD_CACHE_FULL], pal[PAL_THREAD_CACHE_TRIMMED],
                     pal[PAL_THREAD_CACHE_POISON_SEEN], pal[PAL_THREAD_CACHE_RESIDUE],
                     g_tc_fork_trimmed, g_tc_fork_end_cached);
    spinlock_unlock(&g_tc_lock);
    return n;
}

static struct libos_signal_dispositions* alloc_default_signal_dispositions(void) {
    struct libos_signal_dispositions* dispositions = malloc(sizeof(*dispositions));
    if (!dispositions) {
        return NULL;
    }

    if (!create_lock(&dispositions->lock)) {
        free(dispositions);
        return NULL;
    }
    refcount_set(&dispositions->ref_count, 1);
    for (size_t i = 0; i < ARRAY_SIZE(dispositions->actions); i++) {
        sigaction_make_defaults(&dispositions->actions[i]);
    }

    return dispositions;
}

static struct libos_thread* alloc_new_thread(void) {
    struct libos_thread* thread = calloc(1, sizeof(struct libos_thread));
    if (!thread) {
        return NULL;
    }

    /* thread_cache = 0 is the platform as it was, for the A/B: the real-time queues then come with
     * every thread, as they did when they were inline (one VirtAlloc and one VirtFree each). */
    if (!thread_cache_configured()) {
        thread->signal_queue.rt_signal_queues =
            calloc(RT_SIGNAL_QUEUES_CNT, sizeof(*thread->signal_queue.rt_signal_queues));
        if (!thread->signal_queue.rt_signal_queues) {
            free(thread);
            return NULL;
        }
    }

    if (!create_lock(&thread->lock)) {
        free(thread->signal_queue.rt_signal_queues);
        free(thread);
        return NULL;
    }

    int ret = create_pollable_event(&thread->pollable_event);
    if (ret < 0) {
        destroy_lock(&thread->lock);
        free(thread->signal_queue.rt_signal_queues);
        free(thread);
        return NULL;
    }

    refcount_set(&thread->ref_count, 1);
    INIT_LIST_HEAD(thread, list);
    /* default value as sigalt stack isn't specified yet */
    thread->signal_altstack.ss_flags = SS_DISABLE;
    return thread;
}

int alloc_thread_libos_stack(struct libos_thread* thread) {
    assert(thread->libos_stack_bottom == NULL);

    /* An exited thread's, scrubbed (thread reuse, above): bookkept, mapped and guarded already. */
    char* cached = libos_stack_cache_pop();
    if (cached) {
        thread->libos_stack_bottom = cached + LIBOS_THREAD_LIBOS_STACK_SIZE;
        return 0;
    }

    void* addr = NULL;
    int prot = PROT_READ | PROT_WRITE;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL;
    int ret = bkeep_mmap_any(LIBOS_THREAD_LIBOS_STACK_SIZE, prot, flags, /*file=*/NULL,
                             /*offset=*/0, "libos_stack", &addr);
    if (ret < 0) {
        return ret;
    }

    bool need_mem_free = false;
    ret = PalVirtualMemoryAlloc(addr, LIBOS_THREAD_LIBOS_STACK_SIZE,
                                LINUX_PROT_TO_PAL(prot, flags));
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto unmap;
    }
    need_mem_free = true;

    /* Create a stack guard page. */
    ret = PalVirtualMemoryProtect(addr, PAGE_SIZE, /*prot=*/0);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto unmap;
    }

    thread->libos_stack_bottom = (char*)addr + LIBOS_THREAD_LIBOS_STACK_SIZE;

    return 0;

unmap:;
    void* tmp_vma = NULL;
    if (bkeep_munmap(addr, LIBOS_THREAD_LIBOS_STACK_SIZE, /*is_internal=*/true, &tmp_vma) < 0) {
        log_error("[alloc_thread_libos_stack]"
                  " Failed to remove bookkeeped memory that was not allocated at %p-%p!",
                  addr, (char*)addr + LIBOS_THREAD_LIBOS_STACK_SIZE);
        BUG();
    }
    if (need_mem_free) {
        if (PalVirtualMemoryFree(addr, LIBOS_THREAD_LIBOS_STACK_SIZE) < 0) {
            BUG();
        }
    }
    bkeep_remove_tmp_vma(tmp_vma);
    return ret;
}

static int init_main_thread(void) {
    struct libos_thread* cur_thread = get_cur_thread();
    if (cur_thread) {
        /* Thread already initialized (e.g. received via checkpoint). */
        add_thread(cur_thread);
        assert(cur_thread->tid);
        return init_id_ranges(cur_thread->tid);
    }

    int ret = init_id_ranges(/*preload_tid=*/0);
    if (ret < 0) {
        return ret;
    }

    cur_thread = alloc_new_thread();
    if (!cur_thread) {
        return -ENOMEM;
    }

    cur_thread->tid = get_new_id(/*move_ownership_to=*/0);
    if (!cur_thread->tid) {
        log_error("Cannot allocate pid for the initial thread!");
        put_thread(cur_thread);
        return -ESRCH;
    }
    g_process.pid = cur_thread->tid;
    rwlock_write_lock(&g_process_id_lock);
    g_process.pgid = g_process.pid;
    rwlock_write_unlock(&g_process_id_lock);

    int64_t uid_int64;
    ret = toml_int_in(g_manifest_root, "loader.uid", /*defaultval=*/0, &uid_int64);
    if (ret < 0) {
        log_error("Cannot parse 'loader.uid'");
        put_thread(cur_thread);
        return -EINVAL;
    }

    int64_t gid_int64;
    ret = toml_int_in(g_manifest_root, "loader.gid", /*defaultval=*/0, &gid_int64);
    if (ret < 0) {
        log_error("Cannot parse 'loader.gid'");
        put_thread(cur_thread);
        return -EINVAL;
    }

    if (uid_int64 < 0 || uid_int64 > IDTYPE_MAX) {
        log_error("'loader.uid' = %ld is negative or greater than %u", uid_int64, IDTYPE_MAX);
        put_thread(cur_thread);
        return -EINVAL;
    }

    if (gid_int64 < 0 || gid_int64 > IDTYPE_MAX) {
        log_error("'loader.gid' = %ld is negative or greater than %u", gid_int64, IDTYPE_MAX);
        put_thread(cur_thread);
        return -EINVAL;
    }

    cur_thread->uid = uid_int64;
    cur_thread->euid = uid_int64;
    cur_thread->suid = uid_int64;
    cur_thread->gid = gid_int64;
    cur_thread->egid = gid_int64;
    cur_thread->sgid = gid_int64;

    cur_thread->signal_dispositions = alloc_default_signal_dispositions();
    if (!cur_thread->signal_dispositions) {
        put_thread(cur_thread);
        return -ENOMEM;
    }

    __sigset_t set;
    __sigemptyset(&set);
    lock(&cur_thread->lock);
    set_sig_mask(cur_thread, &set);
    unlock(&cur_thread->lock);

    ret = PalEventCreate(&cur_thread->scheduler_event, /*init_signaled=*/false,
                         /*auto_clear=*/true);
    if (ret < 0) {
        put_thread(cur_thread);
        return pal_to_unix_errno(ret);
    }

    /* TODO: I believe there is some PAL allocated initial stack which could be reused by the first
     * thread. Tracked in https://github.com/gramineproject/gramine/issues/84. */
    ret = alloc_thread_libos_stack(cur_thread);
    if (ret < 0) {
        put_thread(cur_thread);
        return ret;
    }

    cur_thread->pal_handle = g_pal_public_state->first_thread;

    cur_thread->cpu_affinity_mask = calloc(GET_CPU_MASK_LEN(),
                                           sizeof(*cur_thread->cpu_affinity_mask));
    if (!cur_thread->cpu_affinity_mask) {
        put_thread(cur_thread);
        return -ENOMEM;
    }
    ret = PalThreadGetCpuAffinity(cur_thread->pal_handle, cur_thread->cpu_affinity_mask,
                                  GET_CPU_MASK_LEN());
    if (ret < 0) {
        log_error("Failed to get thread CPU affinity mask: %s", pal_strerror(ret));
        ret = pal_to_unix_errno(ret);
        put_thread(cur_thread);
        return ret;
    }

    set_cur_thread(cur_thread);
    add_thread(cur_thread);

    return 0;
}

int init_threading(void) {
    int ret = init_thread_cache();
    if (ret < 0) {
        return ret;
    }
    if (!create_lock(&g_thread_list_lock)) {
        return -ENOMEM;
    }

    return init_main_thread();
}

static struct libos_thread* __lookup_thread(IDTYPE tid) {
    assert(locked(&g_thread_list_lock));

    struct libos_thread* tmp;

    LISTP_FOR_EACH_ENTRY(tmp, &g_thread_list, list) {
        if (tmp->tid == tid) {
            get_thread(tmp);
            return tmp;
        }
    }

    return NULL;
}

struct libos_thread* lookup_thread(IDTYPE tid) {
    lock(&g_thread_list_lock);
    struct libos_thread* thread = __lookup_thread(tid);
    unlock(&g_thread_list_lock);
    return thread;
}

struct libos_thread* get_new_thread(void) {
    struct libos_thread* thread = alloc_new_thread();
    if (!thread) {
        return NULL;
    }

    struct libos_thread* cur_thread = get_cur_thread();
    size_t groups_size = cur_thread->groups_info.count * sizeof(cur_thread->groups_info.groups[0]);
    if (groups_size > 0) {
        thread->groups_info.groups = malloc(groups_size);
        if (!thread->groups_info.groups) {
            put_thread(thread);
            return NULL;
        }
        thread->groups_info.count = cur_thread->groups_info.count;
        memcpy(thread->groups_info.groups, cur_thread->groups_info.groups, groups_size);
    }

    thread->cpu_affinity_mask = malloc(GET_CPU_MASK_LEN() * sizeof(*thread->cpu_affinity_mask));
    if (!thread->cpu_affinity_mask) {
        put_thread(thread);
        return NULL;
    }

    lock(&cur_thread->lock);

    thread->uid       = cur_thread->uid;
    thread->gid       = cur_thread->gid;
    thread->euid      = cur_thread->euid;
    thread->egid      = cur_thread->egid;
    thread->suid      = cur_thread->suid;
    thread->sgid      = cur_thread->sgid;

    thread->stack     = cur_thread->stack;
    thread->stack_top = cur_thread->stack_top;
    thread->stack_red = cur_thread->stack_red;

    thread->signal_dispositions = cur_thread->signal_dispositions;
    get_signal_dispositions(thread->signal_dispositions);

    /* No need for this lock as we have just created `thread`, but `set_sig_mask` has an assert for
     * it. Also there is no problem with locking order as `thread` is not yet shared. */
    lock(&thread->lock);
    set_sig_mask(thread, &cur_thread->signal_mask);
    unlock(&thread->lock);
    thread->has_saved_sigmask = false;

    struct libos_handle_map* map = get_thread_handle_map(cur_thread);
    assert(map);
    set_handle_map(thread, map);

    memcpy(thread->cpu_affinity_mask, cur_thread->cpu_affinity_mask,
           GET_CPU_MASK_LEN() * sizeof(*thread->cpu_affinity_mask));

    unlock(&cur_thread->lock);

    int ret = PalEventCreate(&thread->scheduler_event, /*init_signaled=*/false,
                             /*auto_clear=*/true);
    if (ret < 0) {
        put_thread(thread);
        return NULL;
    }

    return thread;
}

struct libos_thread* get_new_internal_thread(void) {
    return alloc_new_thread();
}

void get_signal_dispositions(struct libos_signal_dispositions* dispositions) {
    refcount_inc(&dispositions->ref_count);
}

void put_signal_dispositions(struct libos_signal_dispositions* dispositions) {
    refcount_t ref_count = refcount_dec(&dispositions->ref_count);

    if (!ref_count) {
        destroy_lock(&dispositions->lock);
        free(dispositions);
    }
}

void get_thread(struct libos_thread* thread) {
    refcount_inc(&thread->ref_count);
}

void put_thread(struct libos_thread* thread) {
    refcount_t ref_count = refcount_dec(&thread->ref_count);

    if (!ref_count) {
        assert(LIST_EMPTY(thread, list));

        if (thread->libos_stack_bottom) {
            char* addr = (char*)thread->libos_stack_bottom - LIBOS_THREAD_LIBOS_STACK_SIZE;
            /* Kept for the next thread when there is room (thread reuse, above). */
            if (!libos_stack_cache_push(addr))
                free_libos_stack(addr);
        }

        free(thread->groups_info.groups);

        if (thread->pal_handle && thread->pal_handle != g_pal_public_state->first_thread)
            PalObjectDestroy(thread->pal_handle);

        if (thread->handle_map) {
            put_handle_map(thread->handle_map);
        }

        if (thread->signal_dispositions) {
            put_signal_dispositions(thread->signal_dispositions);
        }

        free_signal_queue(&thread->signal_queue);

        /* `signal_altstack` is provided by the user, no need for a clean up. */

        if (thread->scheduler_event) {
            PalObjectDestroy(thread->scheduler_event);
        }

        /* `wake_queue` is only meaningful when `thread` is part of some wake up queue (is just
         * being woken up), which would imply `ref_count > 0`. */

        if (thread->tid && !is_internal(thread)) {
            release_id(thread->tid);
        }

        free(thread->cpu_affinity_mask);

        destroy_pollable_event(&thread->pollable_event);

        destroy_lock(&thread->lock);

        free(thread);
    }
}

void add_thread(struct libos_thread* thread) {
    assert(!is_internal(thread) && LIST_EMPTY(thread, list));

    struct libos_thread* tmp;
    struct libos_thread* prev = NULL;
    lock(&g_thread_list_lock);

    /* keep it sorted */
    LISTP_FOR_EACH_ENTRY_REVERSE(tmp, &g_thread_list, list) {
        if (tmp->tid < thread->tid) {
            prev = tmp;
            break;
        }
        assert(tmp->tid != thread->tid);
    }

    get_thread(thread);
    LISTP_ADD_AFTER(thread, prev, &g_thread_list, list);
    unlock(&g_thread_list_lock);
}

/*
 * Checks whether there are any other threads on `g_thread_list` (i.e. if we are the last thread).
 * If `mark_self_dead` is true additionally takes us off the `g_thread_list`.
 */
bool check_last_thread(bool mark_self_dead) {
    struct libos_thread* self = get_cur_thread();
    bool ret = true;

    lock(&g_thread_list_lock);

    struct libos_thread* thread;
    LISTP_FOR_EACH_ENTRY(thread, &g_thread_list, list) {
        if (thread != self) {
            ret = false;
            break;
        }
    }

    if (mark_self_dead) {
        LISTP_DEL_INIT(self, &g_thread_list, list);
    }

    unlock(&g_thread_list_lock);

    if (mark_self_dead) {
        put_thread(self);
    }

    return ret;
}

/*
 * In a copy-on-write fork's child: take every thread but the caller off the
 * list.
 *
 * They are the parent's threads, copied with the rest of its memory, and the
 * PAL has already taken their contexts off its ring
 * (pal_svsm_threads_child_after_fork) - so in this process they will never
 * run again. Left on the list they were waited for as if they would: exit and
 * exec mark every thread on it to die and wait until it has
 * (kill_other_threads), signals were routed to them, and their tids - the
 * PARENT's - were released into this process's id ranges when they went.
 *
 * Not put: each reference, each tid and each PAL handle they hold is a copy of
 * the parent's, and giving one back here gives back something this process
 * never had. Their memory is a copy too, so leaving it is a leak of a copy.
 * No lock: the caller is the only thread there is, and the PAL waited for the
 * others' holds to drain before the copy (pal_svsm_fork_quiesce).
 */
void threads_after_cow_fork(void) {
    struct libos_thread* self = get_cur_thread();
    struct libos_thread* tmp;
    struct libos_thread* n;
    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &g_thread_list, list) {
        if (tmp != self)
            LISTP_DEL_INIT(tmp, &g_thread_list, list);
    }
}

/* This function is called by async worker thread to wait on thread->clear_child_tid_pal to be
 * zeroed (PAL does it when thread finally exits). Since it is a callback to async worker thread,
 * this function must follow the `void (*callback) (IDTYPE caller, void* arg)` signature. */
void cleanup_thread(IDTYPE caller, void* arg) {
    __UNUSED(caller);

    struct libos_thread* thread = (struct libos_thread*)arg;
    assert(thread);

    /* wait on clear_child_tid_pal; this signals that PAL layer exited child thread */
    while (__atomic_load_n(&thread->clear_child_tid_pal, __ATOMIC_ACQUIRE) != 0)
        CPU_RELAX();

    /* notify parent if any */
    release_clear_child_tid(thread->clear_child_tid);

    /* Put down our (possibly last) reference to this thread - we got the ownership from the caller.
     */
    put_thread(thread);
}

int walk_thread_list(int (*callback)(struct libos_thread*, void*), void* arg, bool one_shot) {
    struct libos_thread* tmp;
    struct libos_thread* n;
    bool success = false;
    int ret = -ESRCH;

    lock(&g_thread_list_lock);

    LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &g_thread_list, list) {
        ret = callback(tmp, arg);
        if (ret < 0 && ret != -ESRCH) {
            goto out;
        }
        if (ret > 0) {
            if (one_shot) {
                ret = 0;
                goto out;
            }
            success = true;
        }
    }

    ret = success ? 0 : -ESRCH;
out:
    unlock(&g_thread_list_lock);
    return ret;
}

BEGIN_CP_FUNC(signal_dispositions) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_signal_dispositions));

    struct libos_signal_dispositions* dispositions = (struct libos_signal_dispositions*)obj;
    struct libos_signal_dispositions* new_dispositions = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_signal_dispositions));
        ADD_TO_CP_MAP(obj, off);
        new_dispositions = (struct libos_signal_dispositions*)(base + off);

        lock(&dispositions->lock);

        *new_dispositions = *dispositions;
        clear_lock(&new_dispositions->lock);
        refcount_set(&new_dispositions->ref_count, 0);

        unlock(&dispositions->lock);

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_dispositions = (struct libos_signal_dispositions*)(base + off);
    }

    if (objp) {
        *objp = (void*)new_dispositions;
    }
}
END_CP_FUNC(signal_dispositions)

BEGIN_RS_FUNC(signal_dispositions) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct libos_signal_dispositions* dispositions = (void*)(base + GET_CP_FUNC_ENTRY());

    if (!create_lock(&dispositions->lock)) {
        return -ENOMEM;
    }
}
END_RS_FUNC(signal_dispositions)

BEGIN_CP_FUNC(thread) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_thread));

    struct libos_thread* thread = (struct libos_thread*)obj;
    struct libos_thread* new_thread = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_thread));
        ADD_TO_CP_MAP(obj, off);
        new_thread = (struct libos_thread*)(base + off);
        *new_thread = *thread;

        INIT_LIST_HEAD(new_thread, list);

        new_thread->libos_stack_bottom = NULL;

        if (thread->groups_info.count > 0) {
            size_t groups_size = thread->groups_info.count * sizeof(thread->groups_info.groups[0]);
            size_t toff = ADD_CP_OFFSET(groups_size);
            new_thread->groups_info.groups = (void*)(base + toff);
            memcpy(new_thread->groups_info.groups, thread->groups_info.groups, groups_size);
        }

        new_thread->pal_handle = NULL;

        size_t mask_off = ADD_CP_OFFSET(GET_CPU_MASK_LEN() * sizeof(*thread->cpu_affinity_mask));
        new_thread->cpu_affinity_mask = (void*)(base + mask_off);
        memcpy(new_thread->cpu_affinity_mask, thread->cpu_affinity_mask,
               GET_CPU_MASK_LEN() * sizeof(*thread->cpu_affinity_mask));

        memset(&new_thread->pollable_event, 0, sizeof(new_thread->pollable_event));

        new_thread->handle_map = NULL;
        memset(&new_thread->signal_queue, 0, sizeof(new_thread->signal_queue));
        new_thread->robust_list = NULL;
        refcount_set(&new_thread->ref_count, 0);

        DO_CP_MEMBER(signal_dispositions, thread, new_thread, signal_dispositions);

        DO_CP_MEMBER(handle_map, thread, new_thread, handle_map);

        ADD_CP_FUNC_ENTRY(off);

        if (thread->libos_tcb) {
            size_t toff = ADD_CP_OFFSET(sizeof(libos_tcb_t));
            new_thread->libos_tcb = (void*)(base + toff);
            struct libos_tcb* new_tcb = new_thread->libos_tcb;
            *new_tcb = *thread->libos_tcb;
            /* don't export stale pointers */
            new_tcb->self      = NULL;
            new_tcb->tp        = NULL;
            new_tcb->vma_cache = NULL;

            new_tcb->log_prefix[0] = '\0';

            size_t roff = ADD_CP_OFFSET(sizeof(*thread->libos_tcb->context.regs));
            new_thread->libos_tcb->context.regs = (void*)(base + roff);
            pal_context_copy(new_thread->libos_tcb->context.regs, thread->libos_tcb->context.regs);
        }
    } else {
        new_thread = (struct libos_thread*)(base + off);
    }

    if (objp)
        *objp = (void*)new_thread;
}
END_CP_FUNC(thread)

BEGIN_RS_FUNC(thread) {
    struct libos_thread* thread = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(thread->list);
    if (thread->groups_info.count) {
        CP_REBASE(thread->groups_info.groups);
    } else {
        assert(!thread->groups_info.groups);
    }
    CP_REBASE(thread->handle_map);
    CP_REBASE(thread->signal_dispositions);

    if (!create_lock(&thread->lock)) {
        return -ENOMEM;
    }

    int ret = create_pollable_event(&thread->pollable_event);
    if (ret < 0) {
        return ret;
    }

    ret = PalEventCreate(&thread->scheduler_event, /*init_signaled=*/false, /*auto_clear=*/true);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    if (thread->handle_map) {
        get_handle_map(thread->handle_map);
    }

    if (thread->signal_dispositions) {
        get_signal_dispositions(thread->signal_dispositions);
    }

    if (thread->set_child_tid) {
        *thread->set_child_tid = thread->tid;
        thread->set_child_tid = NULL;
    }

    CP_REBASE(thread->cpu_affinity_mask);

    assert(!get_cur_thread());

    ret = alloc_thread_libos_stack(thread);
    if (ret < 0) {
        return ret;
    }

    CP_REBASE(thread->libos_tcb);
    CP_REBASE(thread->libos_tcb->context.regs);

    libos_tcb_t* tcb = libos_get_tcb();
    *tcb = *thread->libos_tcb;
    __libos_tcb_init(tcb);

    assert(tcb->context.regs);
    set_tls(tcb->context.tls);

    thread->pal_handle = g_pal_public_state->first_thread;

    set_cur_thread(thread);
    log_setprefix(thread->libos_tcb);
}
END_RS_FUNC(thread)
