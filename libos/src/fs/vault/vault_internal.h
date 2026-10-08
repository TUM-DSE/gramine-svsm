/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * What fs.c and lock.c share.
 *
 * The two halves of vaultfs are split because they are different problems:
 * fs.c is a namespace and an allocator over the region, lock.c is POSIX
 * byte-range locking over the lock area. They share the region, the lock that
 * serialises mutations of it, and the notion of who a member is - and nothing
 * else, which is why this header is short.
 *
 * Nothing here is a public interface. The region's format is in
 * libos_fs_vault.h because the host-side image tools and the tests need it;
 * these are the running LibOS's own internals.
 */

#ifndef LIBOS_FS_VAULT_INTERNAL_H_
#define LIBOS_FS_VAULT_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>

#include "libos_fs_vault.h"

/* --------------------------------------------------------------- the region */

/* All NULL until vfs_attach() has run once in this process. */
extern struct vfs_super*  g_vfs;
extern struct vfs_entry*  g_vfs_table;
extern struct vfs_flock*  g_vfs_locks;
extern uint32_t           g_vfs_entries;

/* Attach to this lineage's region, formatting it if nobody has yet.
 * Idempotent, and deliberately lazy - see the comment on its definition. */
int vfs_attach(void);

/* ----------------------------------------------------------------- the lock */

/* The superblock lock, which serialises every mutation of the table, the
 * bitmap AND the lock area. One lock for all three because every critical
 * section is short and a second lock would only add an ordering to get
 * wrong. */
void vfs_lock(void);
void vfs_unlock(void);

/* This member's lineage serial, or VFS_LOCK_ANON if the monitor would not
 * say. Deliberately NOT cached - a copy-on-write fork would hand the child
 * its parent's copy. See the definition. */
uint64_t vfs_self(void);

/* Does the monitor's roster say this serial is no longer a member? False for
 * 0, for VFS_LOCK_ANON, and whenever the question cannot be answered - a
 * missing answer is not a death certificate. */
bool vfs_holder_dead(uint64_t serial);

/* ------------------------------------------------------- byte-range locking */

/* The identity of a file within a lineage: the slot and the generation that
 * slot held when the handle was opened. A bare index is not an identity,
 * because slots are recycled - see struct vfs_entry's `gen`. */
struct vfs_fileid {
    uint32_t idx;
    uint64_t gen;
};

/* The file identity behind an open HANDLE (fs.c), or false if the handle is
 * not a vaultfs file. */
struct libos_handle;
bool vaultfs_handle_fileid(struct libos_handle* hdl, struct vfs_fileid* out);

/* F_SETLK / F_SETLKW's inner test, and F_GETLK.
 *
 * `type` is F_RDLCK, F_WRLCK or F_UNLCK; `end` is INCLUSIVE and UINT64_MAX
 * means to end of file, matching struct libos_file_lock. `pid` is recorded
 * only so F_GETLK can report l_pid.
 *
 * vfs_flock_set returns 0, -EAGAIN if another member holds a conflicting
 * range (never blocking - the caller implements F_SETLKW), -ENOLCK if the
 * lock area is full, or -ESTALE if the file is gone.
 *
 * vfs_flock_get fills `*out` with the first conflicting record, or sets
 * out->used to 0 when the range is free.
 */
int vfs_flock_set(const struct vfs_fileid* id, uint32_t type, uint64_t start, uint64_t end,
                  uint64_t pid);
int vfs_flock_get(const struct vfs_fileid* id, uint32_t type, uint64_t start, uint64_t end,
                  struct vfs_flock* out);

/* Drop every record this member holds on one file (close, or F_UNLCK of
 * everything), or every record it holds anywhere (process exit). Both are
 * idempotent and neither can fail. */
void vfs_flock_clear_file(const struct vfs_fileid* id);
void vfs_flock_clear_self(void);

/* Every record naming this SLOT, whatever generation, dropped. Caller holds
 * the superblock lock. Called when a slot's file goes away and again when the
 * slot is handed to a new one - see the definition for why both. */
void vfs_flock_drop_slot_locked(uint32_t idx);

#endif /* LIBOS_FS_VAULT_INTERNAL_H_ */
