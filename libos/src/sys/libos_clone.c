/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_internal.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "libos_rwlock.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "linux_abi/process.h"
#include "linux_abi/sched.h"
#include "pal.h"
#include "toml_utils.h"

struct libos_clone_args {
    PAL_HANDLE create_event;
    PAL_HANDLE initialize_event;
    bool is_thread_initialized;
    struct libos_thread* thread;
    void* stack;
    unsigned long tls;
    PAL_CONTEXT* regs;
};

static int clone_implementation_wrapper(void* arg_) {
    /* The child thread created by PAL is now running on the PAL allocated stack. We need to switch
     * to the user provided stack. */

    /* We acquired ownership of arg->thread from the caller, hence there is
     * no need to call get_thread. */
    struct libos_clone_args* arg = (struct libos_clone_args*)arg_;
    struct libos_thread* my_thread = arg->thread;
    assert(my_thread);

    libos_tcb_init();
    set_cur_thread(my_thread);

    /* only now we can call LibOS/PAL functions because they require a set-up TCB;
     * do not move the below functions before libos_tcb_init/set_cur_thread()! */
    int ret = event_wait_with_retry(arg->create_event);
    if (ret < 0) {
        return ret;
    }

    libos_tcb_t* tcb = my_thread->libos_tcb;

    log_setprefix(tcb);

    if (my_thread->set_child_tid) {
        *(my_thread->set_child_tid) = my_thread->tid;
        my_thread->set_child_tid = NULL;
    }

    void* stack = arg->stack;

    struct libos_vma_info vma_info;
    if (lookup_vma(ALLOC_ALIGN_DOWN_PTR(stack), &vma_info) < 0) {
        return -EFAULT;
    }
    my_thread->stack_top = (char*)vma_info.addr + vma_info.length;
    my_thread->stack_red = my_thread->stack = vma_info.addr;
    if (vma_info.file) {
        put_handle(vma_info.file);
    }

    add_thread(my_thread);

    /* Copy regs before we let the parent release them. */
    PAL_CONTEXT regs;
    pal_context_copy(&regs, arg->regs);
    pal_context_set_sp(&regs, (unsigned long)stack);
    tcb->context.regs = &regs;
    tcb->context.tls = arg->tls;

    /* Inform the parent thread that we finished initialization. */
    PalEventSet(arg->initialize_event);
    __atomic_store_n(&arg->is_thread_initialized, true, __ATOMIC_RELEASE);
    /* We are not allowed to use `arg` after this point. */

    put_thread(my_thread);

    restore_child_context_after_clone(&tcb->context);
}

static BEGIN_MIGRATION_DEF(fork, struct libos_process* process_description,
                           struct libos_thread* thread_description,
                           struct libos_ipc_ids* process_ipc_ids) {
    DEFINE_MIGRATE(process_ipc_ids, process_ipc_ids, sizeof(*process_ipc_ids));
    DEFINE_MIGRATE(all_encrypted_files_keys, NULL, 0);
    DEFINE_MIGRATE(dentry_root, NULL, 0);
    DEFINE_MIGRATE(all_mounts, NULL, 0);
    DEFINE_MIGRATE(all_vmas, NULL, 0);
    DEFINE_MIGRATE(process_description, process_description, sizeof(*process_description));
    DEFINE_MIGRATE(thread, thread_description, sizeof(*thread_description));
    DEFINE_MIGRATE(migratable, NULL, 0);
    DEFINE_MIGRATE(brk, NULL, 0);
    DEFINE_MIGRATE(loaded_elf_objects, NULL, 0);
    DEFINE_MIGRATE(topo_info, NULL, 0);
    DEFINE_MIGRATE(etc_info, NULL, 0);
#ifdef DEBUG
    DEFINE_MIGRATE(gdb_map, NULL, 0);
#endif
}
END_MIGRATION_DEF(fork)

static int migrate_fork(struct libos_cp_store* store, struct libos_process* process_description,
                        struct libos_thread* thread_description,
                        struct libos_ipc_ids* process_ipc_ids, va_list ap) {
    __UNUSED(ap);
    /* Take `g_dcache_lock` for the whole checkpointing operation, so that we can access data from
     * dentries. We recursively checkpoint various connected structures, so it's not practical to
     * take the lock just for some part of this operation. */
    lock(&g_dcache_lock);
    int ret = START_MIGRATE(store, fork, process_description, thread_description, process_ipc_ids);
    unlock(&g_dcache_lock);
    return ret;
}

/*
 * fork(2) where the host can copy an address space.
 *
 * Gramine's own fork is a checkpoint: start a fresh process, serialise the
 * whole LibOS state, ship it down a stream, restore it on the other side.
 * That exists because a normal PAL cannot copy an address space. This one
 * can - the monitor marks the pages copy-on-write and builds a second
 * process whose page tables and registers are copies - so there is nothing
 * to serialise, because the child already IS the memory.
 *
 * What that leaves is small and is all of it: the two processes are
 * identical, so the only things wrong in the child are the ones that NAME
 * it. Its pid, its parent, and the children list it inherited - which are
 * its parent's children and not its own.
 *
 * The child is created RESIDENT, i.e. handed to the host's scheduler. A
 * parked child would never reach its execve and its parent would wait for
 * ever; that a fork must actually run is the difference between this and
 * the worker-pool fork the C vaults use.
 *
 * Caveat, and it is the usual one: a fork from a process with other threads
 * running copies whatever locks those threads were holding, locked. POSIX
 * says the same thing about fork in a threaded program, and the usual user
 * - a subprocess launch, which execs at once - never touches them.
 */
static long do_clone_cow_fork(unsigned long flags, int* set_parent_tid) {
    uint64_t child_id = 0;
    uint64_t self_id = 0;

    /*
     * Root the lineage filesystem BEFORE the fork, if this manifest asked for
     * one. Not in the parent's branch afterwards: the monitor maps the region
     * into the child DURING the fork call (fork_share), so a parent that is
     * not yet a member at that instant has nothing to share.
     *
     * What this fixes is older than the locks and worse than them. vaultfs
     * attaches lazily, on first ACCESS, because an attach at mount time would
     * happen in the ZYGOTE and give every instance of a function the same
     * filesystem. But lazily also meant that a program which forked before it
     * ever touched its lineage filesystem gave the child nothing - and then
     * BOTH sides attached, each got a region of its own, and a parent and
     * child of one process tree had two private filesystems that silently
     * agreed about nothing. Every existing test touched the filesystem first,
     * which is why nothing caught it.
     *
     * Idempotent and cheap: a no-op once attached, and -ENODEV - ignored here
     * - for the manifests that declared no lineage region, which pay nothing.
     */
    (void)vfs_attach();

    int pret = PalProcessFork(PAL_PROCESS_FORK_RESIDENT, &child_id, &self_id);
    if (pret < 0)
        return pal_to_unix_errno(pret);

    if (child_id == 0) {
        /* ---- the child ---- */
        /* Before anything else looks at threads: the parent's others are
         * copies that will never run here (the PAL took them off its ring on
         * the way out of the fork), and its async worker is one of them. */
        threads_after_cow_fork();
        async_worker_after_cow_fork();
        ipc_cld_exit_by_host();

        rwlock_write_lock(&g_process_id_lock);
        g_process.ppid = g_process.pid;
        g_process.pid  = (IDTYPE)self_id;
        rwlock_write_unlock(&g_process_id_lock);

        /* Its IPC identity and its own worker, TOGETHER and only if this
         * process uses IPC at all - see reinit_ipc_worker_after_fork, which
         * does nothing when there is no worker to rebuild.
         *
         * Together, because the ids are not independently safe. `leader_vmid`
         * of ZERO MEANS "I AM THE LEADER", which every user of IPC tests to
         * decide whether to answer locally or ask: giving a child a non-zero
         * one without a worker to ask through makes it reach for an IPC
         * round trip that cannot complete. Giving it a zero, with a worker,
         * makes it answer out of its COPY of the leader's tables - which is
         * how a child took a POSIX lock its parent was holding and was told
         * nothing. One switch, both halves. */
        int ipc_ret = reinit_ipc_worker_after_fork((IDTYPE)self_id);
        if (ipc_ret < 0) {
            log_error("fork: child %u has no IPC worker: %s", g_process.pid,
                      unix_strerror(ipc_ret));
        }

        /* The parent's children are not ours, and its zombies are not ours
         * to reap. Inheriting either would let the child wait for - and
         * collect - a process it never created. */
        lock(&g_process.children_lock);
        INIT_LISTP(&g_process.children);
        INIT_LISTP(&g_process.zombies);
        unlock(&g_process.children_lock);

        id_ranges_after_cow_fork((IDTYPE)self_id);
        get_cur_thread()->tid = (IDTYPE)self_id;
        return 0;
    }

    /* ---- the parent ---- */
    struct libos_child_process* child = create_child_process();
    if (!child) {
        /* The child exists and we cannot track it. Nothing can be undone
         * here - it is already running - so say so rather than pretend the
         * fork failed. */
        log_error("fork: child %lu is running but could not be recorded", (unsigned long)child_id);
        return -ENOMEM;
    }
    child->pid  = (IDTYPE)child_id;
    /* `vmid` is what the monitor knows it by, which for this host is the
     * same number - and it is what PalProcessWait is asked about. */
    child->vmid = (IDTYPE)child_id;
    child->child_termination_signal = flags & CSIGNAL;
    child->uid = get_cur_thread()->uid;
    child->by_host = true;              /* reap_host_children, not IPC */

    lock(&g_process.children_lock);
    LISTP_ADD_TAIL(child, &g_process.children, list);
    unlock(&g_process.children_lock);

    if (set_parent_tid)
        *set_parent_tid = (IDTYPE)child_id;
    return (long)child_id;
}

static long do_clone_new_vm(IDTYPE child_vmid, unsigned long flags, struct libos_thread* thread,
                            unsigned long tls, unsigned long user_stack_addr, int* set_parent_tid) {
    assert(!(flags & CLONE_VM));

    struct libos_child_process* child_process = create_child_process();
    if (!child_process) {
        return -ENOMEM;
    }

    struct libos_thread* self = get_cur_thread();

    /* Associate new cpu context to the new process (its main and only thread) for migration
     * since we might need to modify some registers. */
    libos_tcb_t libos_tcb = { 0 };
    __libos_tcb_init(&libos_tcb);
    /* We are copying our own tcb, which should be ok to do, even without any locks. Note this is
     * a shallow copy, so `libos_tcb.context.regs` will be shared with the parent. */
    libos_tcb.context.regs = self->libos_tcb->context.regs;
    libos_tcb.context.tls = tls;

    thread->libos_tcb = &libos_tcb;

    unsigned long parent_stack = 0;
    if (user_stack_addr) {
        struct libos_vma_info vma_info;
        if (lookup_vma((void*)ALLOC_ALIGN_DOWN(user_stack_addr), &vma_info) < 0) {
            destroy_child_process(child_process);
            return -EFAULT;
        }
        thread->stack_top = (char*)vma_info.addr + vma_info.length;
        thread->stack_red = thread->stack = vma_info.addr;
        parent_stack = pal_context_get_sp(self->libos_tcb->context.regs);
        pal_context_set_sp(thread->libos_tcb->context.regs, user_stack_addr);

        if (vma_info.file) {
            put_handle(vma_info.file);
        }
    }

    lock(&g_process.fs_lock);
    rwlock_read_lock(&g_process_id_lock);
    struct libos_process process_description = {
        .pid = thread->tid,
        .ppid = g_process.pid,
        .pgid = g_process.pgid,
        .sid = g_process.sid,
        .root = g_process.root,
        .cwd = g_process.cwd,
        .umask = g_process.umask,
        .exec = g_process.exec,
    };
    rwlock_read_unlock(&g_process_id_lock);

    get_dentry(process_description.root);
    get_dentry(process_description.cwd);
    get_handle(process_description.exec);

    unlock(&g_process.fs_lock);

    INIT_LISTP(&process_description.children);
    INIT_LISTP(&process_description.zombies);

    clear_lock(&process_description.fs_lock);
    clear_lock(&process_description.children_lock);

    child_process->pid = process_description.pid;
    child_process->child_termination_signal = flags & CSIGNAL;
    child_process->uid = thread->uid;
    child_process->vmid = child_vmid;

    long ret = create_process_and_send_checkpoint(&migrate_fork, child_process,
                                                  &process_description, thread);

    if (parent_stack) {
        pal_context_set_sp(self->libos_tcb->context.regs, parent_stack);
    }

    thread->libos_tcb = NULL;

    put_handle(process_description.exec);
    put_dentry(process_description.cwd);
    put_dentry(process_description.root);

    if (ret >= 0) {
        if (set_parent_tid) {
            *set_parent_tid = thread->tid;
        }

        ret = process_description.pid;
    } else {
        /* Child creation failed, so it was not added to the children list. */
        destroy_child_process(child_process);
    }

    return ret;
}

long libos_syscall_clone(unsigned long flags, unsigned long user_stack_addr, int* parent_tidptr,
                         int* child_tidptr, unsigned long tls) {
    /*
     * Currently not supported:
     * CLONE_PARENT
     * CLONE_IO
     * CLONE_PIDFD
     * CLONE_NEWNS and friends
     */
    const unsigned long supported_flags =
        CLONE_CHILD_CLEARTID |
        CLONE_CHILD_SETTID |
        CLONE_DETACHED |
        CLONE_FILES |
        CLONE_FS |
        CLONE_PARENT_SETTID |
        CLONE_PTRACE |
        CLONE_SETTLS |
        CLONE_SIGHAND |
        CLONE_SYSVSEM |
        CLONE_THREAD |
        CLONE_UNTRACED |
        CLONE_VFORK |
        CLONE_VM |
        CSIGNAL;

    if (flags & ~supported_flags) {
        log_warning("clone called with unsupported flags argument.");
        return -EINVAL;
    }

    /* CLONE_DETACHED is deprecated and ignored. */
    flags &= ~CLONE_DETACHED;

    /* These 2 flags modify ptrace behavior and can be ignored in Gramine. */
    flags &= ~(CLONE_PTRACE | CLONE_UNTRACED);

    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;

    /* Explicitly disallow CLONE_VM without either of CLONE_THREAD or CLONE_VFORK in Gramine. While
     * the Linux allows for such combinations, they do not happen in the wild, so they are
     * explicitly disallowed for now. */
    if (flags & CLONE_VM) {
        if (!((flags & CLONE_THREAD) || (flags & CLONE_VFORK))) {
            log_warning("CLONE_VM without either CLONE_THREAD or CLONE_VFORK is unsupported");
            return -EINVAL;
        }
    }

    if (flags & CLONE_VFORK) {
        /* Instead of trying to support Linux semantics for vfork() -- which requires adding
         * corner-cases in signal handling and syscalls -- we simply treat vfork() as fork(). We
         * assume that performance hit is negligible (Gramine has to migrate internal state anyway
         * which is slow) and apps do not rely on insane Linux-specific semantics of vfork().  */
        log_warning("vfork was called by the application, implemented as an alias to fork in "
                    "Gramine");
        flags &= ~(CLONE_VFORK | CLONE_VM);
    }

    if (!(flags & CLONE_VM)) {
        /* If thread/process does not share VM we cannot handle these flags. */
        if (flags & (CLONE_FILES | CLONE_FS | CLONE_SYSVSEM)) {
            return -EINVAL;
        }
    } else {
        /* If it does share VM, we currently assume these flags are set. Supposedly erroring out
         * here would break too many applications ... */
        // TODO: either implement these flags (shouldn't be hard) or return an error
        flags |= CLONE_FS | CLONE_SYSVSEM;
    }

    int* set_parent_tid = NULL;
    if (flags & CLONE_PARENT_SETTID) {
        if (!is_user_memory_writable(parent_tidptr, sizeof(*parent_tidptr)))
            return -EFAULT;
        set_parent_tid = parent_tidptr;
    }

    bool clone_new_process = false;
    if (!(flags & CLONE_VM)) {
        /* New process has its own address space - currently in Gramine that means it's just
         * another process. */
        assert(!(flags & CLONE_THREAD));
        clone_new_process = true;
    }

    long ret = 0;

    if (clone_new_process) {
        assert(g_manifest_root);
        bool disallow_subprocesses;
        ret = toml_bool_in(g_manifest_root, "sys.disallow_subprocesses", /*defaultval=*/false,
                           &disallow_subprocesses);
        if (ret < 0) {
            log_error("Cannot parse \'sys.disallow_subprocesses\' (the value must be `true` or "
                      "`false`)");
            return -ENOSYS;
        }
        if (disallow_subprocesses) {
            if (FIRST_TIME()) {
                log_warning("The app tried to create a subprocess, but this is disabled "
                            "(sys.disallow_subprocesses = true)");
            }
            return -EAGAIN;
        }
    }

    struct libos_thread* thread = get_new_thread();
    if (!thread) {
        return -ENOMEM;
    }

    if (flags & CLONE_CHILD_SETTID) {
        if (!is_user_memory_writable(child_tidptr, sizeof(*child_tidptr))) {
            ret = -EFAULT;
            goto failed;
        }
        thread->set_child_tid = child_tidptr;
    }

    if (flags & CLONE_CHILD_CLEARTID)
        thread->clear_child_tid = child_tidptr;

    if (!(flags & CLONE_SETTLS)) {
        tls = get_tls();
    }

    /* The copy-on-write fork comes FIRST, and before any of the bookkeeping
     * below, because it needs none of it: no vmid from the IPC leader and no
     * tid from the global allocator, since the monitor names the child and
     * the child's whole LibOS state is a copy of this one's. Asking IPC for
     * an id would be asking another process for permission to do something
     * this one can already do.
     *
     * NOTIMPLEMENTED means a host that cannot copy an address space, and
     * then gramine's own checkpoint fork below is the right answer - so this
     * is a fast path, not a replacement. */
    if (clone_new_process) {
        long cow = do_clone_cow_fork(flags, set_parent_tid);
        if (cow != -ENOSYS) {
            put_thread(thread);
            return cow;
        }
    }

    IDTYPE new_vmid = 0;
    if (clone_new_process) {
        ret = ipc_get_new_vmid(&new_vmid);
        if (ret < 0) {
            log_error("Cound not allocate new vmid!");
            ret = -EAGAIN;
            goto failed;
        }
    }

    IDTYPE tid = get_new_id(/*move_ownership_to=*/new_vmid);
    if (!tid) {
        log_error("Could not allocate a tid!");
        ret = -EAGAIN;
        goto failed;
    }
    thread->tid = tid;

    if (clone_new_process) {
        ret = do_clone_new_vm(new_vmid, flags, thread, tls, user_stack_addr, set_parent_tid);

        /* We should not have saved any references to this thread anywhere and `put_thread` below
         * should free it. */
        assert(refcount_get(&thread->ref_count) == 1);

        /* We do not own `thread->tid` aka `tid` anymore, clean it so that `put_thread` does not
         * try to release it. */
        thread->tid = 0;
        put_thread(thread);

        if (ret < 0) {
            /* The child process have already taken the ownership of `tid`, let's change it back. */
            int tmp_ret = ipc_change_id_owner(tid, g_process_ipc_ids.self_vmid);
            if (tmp_ret < 0) {
                log_debug("Failed to change back ID %u owner: %s", tid, unix_strerror(tmp_ret));
                /* No way to recover gracefully. */
                PalProcessExit(1);
            }
            /* ... and release it. */
            tmp_ret = ipc_release_id_range(tid, tid);
            if (tmp_ret < 0) {
                log_debug("Failed to release ID %u: %s", tid, unix_strerror(tmp_ret));
                /* No way to recover gracefully. */
                PalProcessExit(1);
            }
        }
        return ret;
    }

    assert(flags & CLONE_THREAD);

    ret = alloc_thread_libos_stack(thread);
    if (ret < 0) {
        goto failed;
    }

    /* Threads do not generate signals on death, ignore it. */
    flags &= ~CSIGNAL;

    if (!(flags & CLONE_FILES)) {
        /* If CLONE_FILES is not given, the new thread should receive its own copy of the
         * descriptors table. */
        struct libos_handle_map* new_map = NULL;

        dup_handle_map(&new_map, thread->handle_map);
        set_handle_map(thread, new_map);
        put_handle_map(new_map);
    }

    /* Currently CLONE_SIGHAND is always set here, since CLONE_VM implies CLONE_THREAD (which
     * implies CLONE_SIGHAND). */
    assert(flags & CLONE_SIGHAND);

    struct libos_thread* self = get_cur_thread();
    struct libos_clone_args new_args = {
        .is_thread_initialized = false,
        .stack = (void*)(user_stack_addr ?: pal_context_get_sp(self->libos_tcb->context.regs)),
        .tls = tls,
        .regs = self->libos_tcb->context.regs,
        .thread = thread,
    };

    /* Increasing refcount due to copy above. Passing ownership of the new copy
     * of this pointer to the new thread (receiver of new_args). */
    get_thread(thread);

    ret = PalEventCreate(&new_args.create_event, /*init_signaled=*/false, /*auto_clear=*/false);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto clone_thread_failed;
    }

    ret = PalEventCreate(&new_args.initialize_event, /*init_signaled=*/false, /*auto_clear=*/false);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto clone_thread_failed;
    }

    PAL_HANDLE pal_handle = NULL;
    ret = PalThreadCreate(clone_implementation_wrapper, &new_args, &pal_handle);
    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        goto clone_thread_failed;
    }

    thread->pal_handle = pal_handle;

    if (set_parent_tid)
        *set_parent_tid = thread->tid;

    PalEventSet(new_args.create_event);
    ret = event_wait_with_retry(new_args.initialize_event);
    if (ret < 0) {
        /* XXX: Currently it doesn't seem possible to cleanly handle this error - the child thread
         * might be running correctly. */
        log_error("event_wait_with_retry failed with: %s", unix_strerror(ret));
        PalProcessExit(1);
    }
    /* Wait for the new thread to finish initialization. We need to make sure that it's done using
     * `new_args`, as we did not pass ownership (nor made a copy) of it. */
    while (!__atomic_load_n(&new_args.is_thread_initialized, __ATOMIC_ACQUIRE)) {
        CPU_RELAX();
    }
    PalObjectDestroy(new_args.initialize_event);
    PalObjectDestroy(new_args.create_event);

    put_thread(thread);
    return tid;

clone_thread_failed:
    if (new_args.thread)
        put_thread(new_args.thread);
    if (new_args.create_event)
        PalObjectDestroy(new_args.create_event);
    if (new_args.initialize_event)
        PalObjectDestroy(new_args.initialize_event);
failed:
    put_thread(thread);
    return ret;
}
