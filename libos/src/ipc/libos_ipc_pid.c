/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/* This file contains code for management of global ID ranges. */

#include "api.h"
#include "assert.h"
#include "avl_tree.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "libos_types.h"

/* Represents a range of ids `[start; end]` (i.e. `end` is included). There is no representation of
 * an empty range, but it's not needed. */
struct id_range {
    struct avl_tree_node node;
    IDTYPE start;
    IDTYPE end;
    IDTYPE owner;
};

struct ipc_id_range_msg {
    IDTYPE start;
    IDTYPE end;
};

struct ipc_id_owner_msg {
    IDTYPE id;
    IDTYPE owner;
};

static bool id_range_cmp(struct avl_tree_node* _a, struct avl_tree_node* _b) {
    struct id_range* a = container_of(_a, struct id_range, node);
    struct id_range* b = container_of(_b, struct id_range, node);
    /*
     * This is equivalent to:
     * ```return a->start <= b->start;```
     * because overlapping ranges in one tree are disallowed, but it also enables easy lookups of
     * ranges overlapping any given point.
     */
    return a->start <= b->end;
}

/* These are ranges of all used IDs. This tree is only meaningful in IPC leader.
 * No two ranges in this tree shall overlap. */
static struct avl_tree g_id_owners_tree = { .cmp = id_range_cmp };
static struct libos_lock g_id_owners_tree_lock;
static IDTYPE g_last_id = 0;

int init_ipc_ids(void) {
    if (!create_lock(&g_id_owners_tree_lock)) {
        return -ENOMEM;
    }
    return 0;
}

/*
 * Where this process's ids come from: one BLOCK of the id space, and a cursor
 * that wraps inside it.
 *
 * On this host a process is named by the MONITOR - a copy-on-write fork's
 * child runs under its monitor id (do_clone_cow_fork), which is a process
 * table slot, below ID_MONITOR_LIMIT - while its threads are named here. Both
 * used to come out of one space: the allocator started at 1, a child's pid
 * could be one of its own threads' tids, and a child, whose allocator is a
 * COPY of its parent's, handed out exactly the tids its parent handed out
 * next. A tid is what a futex owner word, a robust list and a tgkill name, so
 * two threads with one tid are one thread to all of them.
 *
 * So the space is cut up:
 *   [1, ID_MONITOR_LIMIT)          process ids: the monitor's, plus the root
 *                                  process's own pid 1 (its first id)
 *   block 0, from ID_MONITOR_LIMIT the root process's threads
 *   block C (C << ID_BLOCK_SHIFT)  the threads of the forked child C
 * A live monitor id names one process, so no two live processes share a
 * block, and every block is clear of every pid.
 *
 * The cursor wraps, which upstream refuses (it BUGs at PID_MAX): a block is
 * 4096 ids, and a vault that churns threads would run through it. Wrapping
 * reuses only ranges that are no longer in the tree, and a range stays in it
 * while any id in it is taken (release_id gives a range back only at a count
 * of zero), so a tid still held is never handed out again. Upstream's reason
 * for refusing - `libos_handle::id` is the process id shifted, and a reissued
 * PROCESS id would alias it - does not apply to thread ids, and process ids
 * are not issued here. A block that is full refuses (-EAGAIN, clone's EAGAIN)
 * rather than spill into a neighbour's.
 */
static IDTYPE g_ids_lo = ID_MONITOR_LIMIT;
static IDTYPE g_ids_hi = ((IDTYPE)1 << ID_BLOCK_SHIFT) - 1;
/* A forked child allocates out of its own block, locally, whatever the IPC
 * leader is: the leader's tree knows nothing of the block. */
static bool g_ids_own_block = false;

/* The first free run in `[from, to]`, at most MAX_RANGE_SIZE long. */
static bool find_free_in(IDTYPE from, IDTYPE to, IDTYPE* start, IDTYPE* end) {
    assert(locked(&g_id_owners_tree_lock));
    if (from > to)
        return false;
    IDTYPE next_id = from;
    struct id_range dummy = {
        .start = next_id,
        .end = next_id,
    };
    struct avl_tree_node* node = avl_tree_lower_bound(&g_id_owners_tree, &dummy.node);
    while (node) {
        struct id_range* range = container_of(node, struct id_range, node);
        if (range->start > to)
            break;
        if (next_id < range->start) {
            /* `next_id` does not overlap any existing range. */
            *start = next_id;
            *end   = MIN(MIN(next_id + MAX_RANGE_SIZE - 1, to), range->start - 1);
            return true;
        }
        /* `next_id` overlaps `range`. */
        if (range->end >= to)
            return false;
        next_id = range->end + 1;
        node = avl_tree_next(node);
    }
    /* Nothing in use from `next_id` to `to`. */
    *start = next_id;
    *end   = MIN(next_id + MAX_RANGE_SIZE - 1, to);
    return true;
}

/* If a free range was found, sets `*start` and `*end` and returns `true`, if nothing was found
 * returns `false`. If a range was returned, it is not larger than `MAX_RANGE_SIZE`. */
static bool _find_free_id_range(IDTYPE* start, IDTYPE* end) {
    assert(locked(&g_id_owners_tree_lock));

    static_assert(!IS_SIGNED(IDTYPE), "IDTYPE must be unsigned");
    static_assert((((IDTYPE)ID_MONITOR_LIMIT - 1) << ID_BLOCK_SHIFT)
                  + ((IDTYPE)1 << ID_BLOCK_SHIFT) - 1 <= PID_MAX,
                  "the last monitor id's block must fit below PID_MAX");

    /* The root process's very first id is its own pid, 1 - a range of one, so
     * that its threads start in block 0 rather than at 2, among the pids. */
    if (!g_ids_own_block && g_last_id == 0
            && !avl_tree_first(&g_id_owners_tree)) {
        *start = 1;
        *end   = 1;
        return true;
    }

    IDTYPE from = g_last_id + 1;
    if (from < g_ids_lo || from > g_ids_hi)
        from = g_ids_lo;
    if (find_free_in(from, g_ids_hi, start, end))
        return true;
    /* Wrapped: the start of the block, up to where this search began. */
    return from > g_ids_lo && find_free_in(g_ids_lo, from - 1, start, end);
}

/* In a copy-on-write fork's child, from id_ranges_after_cow_fork: the
 * allocator copied from the parent becomes one of the child's own, in block
 * `self_id`. The tree is the parent's - its ranges are its threads' - and is
 * dropped, nodes freed: they are this process's copies. No lock: the caller is
 * the only thread there is. */
void ipc_ids_after_cow_fork(IDTYPE self_id) {
    if (!self_id || self_id >= ID_MONITOR_LIMIT) {
        /* Not a monitor id this layout has a block for: keep the copy, which
         * is what every child did before. */
        log_warning("fork: id %u has no id block - the child shares its parent's ids", self_id);
        return;
    }
    struct avl_tree_node* node;
    while ((node = avl_tree_first(&g_id_owners_tree))) {
        avl_tree_delete(&g_id_owners_tree, node);
        free(container_of(node, struct id_range, node));
    }
    g_ids_lo = self_id << ID_BLOCK_SHIFT;
    g_ids_hi = g_ids_lo + ((IDTYPE)1 << ID_BLOCK_SHIFT) - 1;
    g_last_id = 0;
    g_ids_own_block = true;
}

static int alloc_id_range(IDTYPE owner, IDTYPE* start, IDTYPE* end) {
    assert(owner);
    struct id_range* new_range = malloc(sizeof(*new_range));
    if (!new_range) {
        return -ENOMEM;
    }

    lock(&g_id_owners_tree_lock);
    bool found = _find_free_id_range(start, end);
    if (!found) {
        /* Every id in the block is held by a live thread (_find_free_id_range
         * has already wrapped): refuse, and clone says EAGAIN. */
        log_warning("no free thread id in [%u, %u]: every one is held", g_ids_lo, g_ids_hi);
    }

    int ret = 0;
    if (found) {
        assert(*start && *end);
        new_range->start = *start;
        new_range->end = *end;
        new_range->owner = owner;
        avl_tree_insert(&g_id_owners_tree, &new_range->node);
        /* Not necessarily past it: the cursor wraps (_find_free_id_range). */
        g_last_id = *end;
    } else {
        free(new_range);
        ret = -EAGAIN;
    }
    unlock(&g_id_owners_tree_lock);
    return ret;
}

static int change_id_owner(IDTYPE id, IDTYPE new_owner) {
    struct id_range* new_range1 = malloc(sizeof(*new_range1));
    if (!new_range1) {
        return -ENOMEM;
    }
    struct id_range* new_range2 = malloc(sizeof(*new_range1));
    if (!new_range2) {
        free(new_range1);
        return -ENOMEM;
    }
    new_range1->start = id;
    new_range1->end = id;
    new_range1->owner = new_owner;

    lock(&g_id_owners_tree_lock);
    struct id_range dummy = {
        .start = id,
        .end = id,
    };
    struct avl_tree_node* node = avl_tree_lower_bound(&g_id_owners_tree, &dummy.node);
    if (!node) {
        log_debug("ID %u unknown!", id);
        BUG();
    }
    struct id_range* range = container_of(node, struct id_range, node);
    if (id < range->start || range->end < id) {
        log_debug("ID %u unknown!", id);
        BUG();
    }

    /* These `range` modifications are in place since we know they won't change the position of
     * `range` inside `g_id_owners_tree`. Otherwise we would have to remove it, modify and then
     * re-add. */
    if (range->start == range->end) {
        assert(id == range->start);
        range->owner = new_owner;
    } else if (range->start == id) {
        range->start++;
        avl_tree_insert(&g_id_owners_tree, &new_range1->node);
        new_range1 = NULL;
    } else if (range->end == id) {
        range->end--;
        avl_tree_insert(&g_id_owners_tree, &new_range1->node);
        new_range1 = NULL;
    } else {
        assert(range->end - range->start + 1 >= 3);
        new_range2->start = id + 1;
        new_range2->end = range->end;
        new_range2->owner = range->owner;
        range->end = id - 1;
        avl_tree_insert(&g_id_owners_tree, &new_range1->node);
        avl_tree_insert(&g_id_owners_tree, &new_range2->node);
        new_range1 = NULL;
        new_range2 = NULL;
    }

    unlock(&g_id_owners_tree_lock);
    free(new_range1);
    free(new_range2);
    return 0;
}

static void release_id_range(IDTYPE start, IDTYPE end) {
    lock(&g_id_owners_tree_lock);
    struct id_range dummy = {
        .start = start,
        .end = end,
    };
    struct avl_tree_node* node = avl_tree_find(&g_id_owners_tree, &dummy.node);
    if (!node) {
        log_debug("Releasing invalid ID range!");
        BUG();
    }
    struct id_range* range = container_of(node, struct id_range, node);
    if (range->start != start || range->end != end) {
        BUG();
    }
    avl_tree_delete(&g_id_owners_tree, &range->node);

    unlock(&g_id_owners_tree_lock);
    free(range);
}

static IDTYPE find_id_owner(IDTYPE id) {
    IDTYPE owner = 0;

    struct id_range dummy = {
        .start = id,
        .end = id,
    };
    lock(&g_id_owners_tree_lock);
    struct avl_tree_node* node = avl_tree_lower_bound(&g_id_owners_tree, &dummy.node);
    if (!node) {
        goto out;
    }
    struct id_range* range = container_of(node, struct id_range, node);
    if (id < range->start || range->end < id) {
        goto out;
    }
    owner = range->owner;

out:
    unlock(&g_id_owners_tree_lock);
    return owner;
}

int ipc_alloc_id_range(IDTYPE* out_start, IDTYPE* out_end) {
    if (!g_process_ipc_ids.leader_vmid || g_ids_own_block) {
        return alloc_id_range(g_process_ipc_ids.self_vmid, out_start, out_end);
    }

    size_t msg_size = get_ipc_msg_size(0);
    struct libos_ipc_msg* msg = malloc(msg_size);
    if (!msg) {
        return -ENOMEM;
    }
    init_ipc_msg(msg, IPC_MSG_ALLOC_ID_RANGE, msg_size);

    log_debug("sending a request");

    void* resp = NULL;
    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, &resp);
    if (ret < 0) {
        goto out;
    }

    struct ipc_id_range_msg* range = resp;
    if (range->start && range->end) {
        *out_start = range->start;
        *out_end = range->end;
        ret = 0;
    } else {
        ret = -EAGAIN;
    }

    log_debug("got a response: [%u..%u]", range->start, range->end);

out:
    free(resp);
    free(msg);
    return ret;
}

int ipc_alloc_id_range_callback(IDTYPE src, void* data, uint64_t seq) {
    __UNUSED(data);
    IDTYPE start = 0;
    IDTYPE end = 0;
    int ret = alloc_id_range(src, &start, &end);
    if (ret < 0) {
        start = 0;
        end = 0;
    }

    log_debug("alloc_id_range: %s", unix_strerror(ret));

    struct ipc_id_range_msg range = {
        .start = start,
        .end = end,
    };
    size_t msg_size = get_ipc_msg_size(sizeof(range));
    struct libos_ipc_msg* msg = __alloca(msg_size);
    init_ipc_response(msg, seq, msg_size);
    memcpy(&msg->data, &range, sizeof(range));

    return ipc_send_message(src, msg);
}

int ipc_release_id_range(IDTYPE start, IDTYPE end) {
    if (!g_process_ipc_ids.leader_vmid || g_ids_own_block) {
        release_id_range(start, end);
        return 0;
    }

    struct ipc_id_range_msg range = {
        .start = start,
        .end = end,
    };
    size_t msg_size = get_ipc_msg_size(sizeof(range));
    struct libos_ipc_msg* msg = malloc(msg_size);
    if (!msg) {
        return -ENOMEM;
    }
    init_ipc_msg(msg, IPC_MSG_RELEASE_ID_RANGE, msg_size);
    memcpy(&msg->data, &range, sizeof(range));

    log_debug("sending a request: [%u..%u]", start, end);

    int ret = ipc_send_message(g_process_ipc_ids.leader_vmid, msg);
    log_debug("ipc_send_message: %s", unix_strerror(ret));
    free(msg);
    return ret;
}

int ipc_release_id_range_callback(IDTYPE src, void* data, uint64_t seq) {
    __UNUSED(src);
    __UNUSED(seq);
    struct ipc_id_range_msg* range = data;
    release_id_range(range->start, range->end);
    log_debug("release_id_range(%u..%u)", range->start, range->end);
    return 0;
}

int ipc_change_id_owner(IDTYPE id, IDTYPE new_owner) {
    if (!g_process_ipc_ids.leader_vmid) {
        return change_id_owner(id, new_owner);
    }

    struct ipc_id_owner_msg owner_msg = {
        .id = id,
        .owner = new_owner,
    };
    size_t msg_size = get_ipc_msg_size(sizeof(owner_msg));
    struct libos_ipc_msg* msg = malloc(msg_size);
    if (!msg) {
        return -ENOMEM;
    }
    init_ipc_msg(msg, IPC_MSG_CHANGE_ID_OWNER, msg_size);
    memcpy(&msg->data, &owner_msg, sizeof(owner_msg));

    log_debug("sending a request (%u, %u)", id, new_owner);

    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, /*resp=*/NULL);
    log_debug("ipc_send_msg_and_get_response: %s", unix_strerror(ret));
    free(msg);
    return ret;
}

int ipc_change_id_owner_callback(IDTYPE src, void* data, uint64_t seq) {
    struct ipc_id_owner_msg* owner_msg = data;
    int ret = change_id_owner(owner_msg->id, owner_msg->owner);
    log_debug("change_id_owner(%u, %u): %s", owner_msg->id, owner_msg->owner, unix_strerror(ret));
    if (ret < 0) {
        return ret;
    }

    /* Respond with a dummy empty message. */
    size_t msg_size = get_ipc_msg_size(0);
    struct libos_ipc_msg* msg = __alloca(msg_size);
    init_ipc_response(msg, seq, msg_size);
    return ipc_send_message(src, msg);
}

int ipc_get_id_owner(IDTYPE id, IDTYPE* out_owner) {
    if (!g_process_ipc_ids.leader_vmid) {
        *out_owner = find_id_owner(id);
        return 0;
    }

    size_t msg_size = get_ipc_msg_size(sizeof(id));
    struct libos_ipc_msg* msg = malloc(msg_size);
    if (!msg) {
        return -ENOMEM;
    }
    init_ipc_msg(msg, IPC_MSG_GET_ID_OWNER, msg_size);
    memcpy(&msg->data, &id, sizeof(id));

    log_debug("sending a request: %u", id);

    void* resp = NULL;
    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, &resp);
    if (ret < 0) {
        goto out;
    }

    *out_owner = *(IDTYPE*)resp;
    ret = 0;

    log_debug("got a response: %u", *out_owner);

out:
    free(resp);
    free(msg);
    return ret;
}

int ipc_get_id_owner_callback(IDTYPE src, void* data, uint64_t seq) {
    IDTYPE* id = data;
    IDTYPE owner = find_id_owner(*id);
    log_debug("find_id_owner(%u): %u", *id, owner);

    size_t msg_size = get_ipc_msg_size(sizeof(owner));
    struct libos_ipc_msg* msg = __alloca(msg_size);
    init_ipc_response(msg, seq, msg_size);
    memcpy(&msg->data, &owner, sizeof(owner));

    return ipc_send_message(src, msg);
}
