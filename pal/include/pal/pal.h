/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file pal.h
 * \brief This file contains definition of PAL host ABI.
 */

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "iovec.h"

// TODO: fix this (but see pal/include/arch/x86_64/pal_arch.h)
#define INSIDE_PAL_H

#if defined(__i386__) || defined(__x86_64__)
#include "cpu.h"
#endif

/* TODO: we should `#include "toml.h"` here. However, this is currently inconvenient to do in Meson,
 * because `toml.h` is a generated (patched) file, and all targets built using `pal.h` would need to
 * declare a dependency on it. */
typedef struct toml_table_t toml_table_t;

typedef uint32_t    PAL_IDX; /*!< an index */

/* maximum length of URIs */
#define URI_MAX 4096

/* maximum length of hostname */
#define PAL_HOSTNAME_MAX 255

/* DNS limits, used in resolv.conf emulation */
#define PAL_MAX_NAMESPACES 3
#define PAL_MAX_DN_SEARCH  6

#define MAX_IPV6_ADDR_LEN  40

/* Common types used by host specific header. */
enum pal_socket_domain {
    PAL_DISCONNECT,
    PAL_IPV4,
    PAL_IPV6,
};

enum pal_socket_type {
    PAL_SOCKET_TCP,
    PAL_SOCKET_UDP,
};

#ifdef IN_PAL

typedef struct {
    PAL_IDX type;
    struct handle_ops* ops;
} PAL_HDR;

/*
 * This header provides `PAL_HANDLE` type definition.
 * All host resources being part of `PAL_HANDLE` must be released when spawning another process
 * (`PalProcessCreate`), e.g. Linux PAL must set `OCLOEXEC` flag on all open file descriptors.
 * LibOS layer takes care of migrating all necessary handles using `PalSendHandle`.
 */
#include "pal_host.h"

static inline void init_handle_hdr(PAL_HANDLE handle, int pal_type) {
    handle->hdr.type = pal_type;
}

#else /* IN_PAL */

typedef struct _pal_handle_undefined_type* PAL_HANDLE;

#endif /* IN_PAL */

#include "pal_arch.h"
#include "pal_topology.h"

/********** PAL TYPE DEFINITIONS **********/
enum {
    PAL_TYPE_FILE,
    PAL_TYPE_PIPE,
    PAL_TYPE_PIPESRV,
    PAL_TYPE_PIPECLI,
    PAL_TYPE_CONSOLE,
    PAL_TYPE_DEV,
    PAL_TYPE_DIR,
    PAL_TYPE_SOCKET,
    PAL_TYPE_PROCESS,
    PAL_TYPE_THREAD,
    PAL_TYPE_EVENT,
    PAL_TYPE_EVENTFD,
    PAL_HANDLE_TYPE_BOUND,
};

/********** PAL APIs **********/

struct pal_dns_host_conf_addr {
    bool is_ipv6;
    union {
        uint32_t ipv4;
        uint16_t ipv6[8];
    };
};

/* Used in resolv.conf emulation */
struct pal_dns_host_conf {
    struct pal_dns_host_conf_addr nsaddr_list[PAL_MAX_NAMESPACES];
    size_t nsaddr_list_count;

    char dn_search[PAL_MAX_DN_SEARCH][PAL_HOSTNAME_MAX];
    size_t dn_search_count;

    bool edns0;
    bool inet6;
    bool rotate;
    bool use_vc;

    char hostname[PAL_HOSTNAME_MAX];
};

/* A runtime image the host mapped read-only into the process (svsm: the monitor maps it at
 * zygote creation and reports it through the RuntimeInfo process call). size 0 = none. The
 * LibOS mounts each one as pseudo roots (libos/src/fs/libos_fs_image.c). */
struct pal_runtime_image {
    void* base;
    size_t size;
};
#define PAL_MAX_RUNTIME_IMAGES 4

/* The filesystem this vault's LINEAGE shares (svsm: the monitor places the
 * pages and maps them into every member; see the LineageFs process call and
 * libos/src/fs/vault/fs.c). size 0 = none, which is the default: a vault gets
 * one only when its manifest asks, because it costs real pool.
 *
 * Unlike a runtime image this is WRITABLE and shared with other processes -
 * every member of the lineage, which is what POSIX fork means by sharing a
 * filesystem. The monitor never reads what is in it. */
struct pal_lineage_fs {
    /* What the manifest asked for: data pages, 0 = the host's default, and
     * NEGATIVE = the manifest did not ask at all, which is the default and is
     * why adding vaultfs changed nothing for a manifest that does not mention
     * it. A missing key cannot be read as 0: they are different answers.
     *
     * Only the request lives here. Where the region IS cannot, because this
     * struct is filled in the zygote and inherited by every instance cloned
     * from it - see #PalLineageFsAttach. */
    int64_t pages;
};

/* Memory this process and the HOST can both see (svsm: the monitor carves it
 * from its pool, converts it to host-shared and maps it without the
 * encryption bit; see the DeviceWindow process call). It exists only when
 * the manifest asked for it, because it is the one region of a vault the
 * host can read. `gpa` is the guest-physical address a device descriptor
 * would name; size 0 = none. */
struct pal_device_window {
    void* base;
    size_t size;
    uint64_t gpa;
};

/* A device's registers, mapped uncached and unencrypted (svsm: the monitor
 * checked the BAR is not guest RAM before mapping it). `phys` is the address
 * the BAR decodes at, which is what a descriptor elsewhere would name;
 * size 0 = none. */
struct pal_device_mmio {
    /* Always NULL. Registers are NOT mapped: under SEV-SNP a guest cannot
     * reach MMIO by touching it, so every access goes through the monitor.
     * The field is kept so the shape matches pal_device_window and so that
     * anything that dereferences it faults immediately. */
    void* base;
    size_t size;
    uint64_t phys;
    /* How to actually reach a register, since `base` cannot be used. The
     * PAL that has a device sets this; everywhere else it stays NULL and
     * the LibOS reports ENODEV. Returns the value read, or all ones if the
     * monitor refused the access. */
    uint64_t (*io)(uint64_t offset, uint32_t width, int write, uint64_t value);
    /* One read of this device's PCI configuration space, which is where a
     * modern device says where its registers actually are - virtio puts
     * the location of its common configuration, notification and ISR
     * structures in a capability chain. Reads only: writing here would let
     * a driver move the BAR that every register access is bounds-checked
     * against. All ones if the monitor refused. */
    uint64_t (*cfg)(uint32_t offset, uint32_t width);
};

/* Part of PAL state which is shared between all PALs and accessible (read-only) by the binary
 * started by PAL (usually our LibOS). */
struct pal_public_state {
    uint64_t instance_id;
    const char* host_type;
    const char* attestation_type; /* currently only for Linux-SGX */

    /*
     * Handles and executables
     */

    toml_table_t* manifest_root; /*!< program manifest */
    PAL_HANDLE parent_process;   /*!< handle of parent process */
    PAL_HANDLE first_thread;     /*!< handle of first thread */
    int log_level;               /*!< what log messages to enable */

    /*
     * Memory layout
     */
    bool disable_aslr;                      /*!< disable ASLR */
    void* memory_address_start;             /*!< usable memory start address */
    void* memory_address_end;               /*!< usable memory end address */
    uintptr_t early_libos_mem_range_start;  /*!< start of memory usable before checkpoint restore */
    uintptr_t early_libos_mem_range_end;    /*!< end of memory usable before checkpoint restore */
    void* shared_address_start;             /*!< usable shared memory start address */
    void* shared_address_end;               /*!< usable shared memory end address */

    struct pal_initial_mem_range* initial_mem_ranges; /*!< array of initial memory ranges, see
                                                           `pal_memory.c` for more details */
    size_t initial_mem_ranges_len;

    struct pal_runtime_image runtime_images[PAL_MAX_RUNTIME_IMAGES]; /*!< see above; unused
                                                                        entries have size 0 */

    struct pal_lineage_fs lineage_fs;       /*!< see above; size 0 = none */

    struct pal_device_window device_window; /*!< see above; size 0 = none */
    struct pal_device_mmio device_mmio;     /*!< see above; size 0 = none */

    /*
     * Host information
     */

    /*!
     * \brief Host allocation alignment.
     *
     * This currently is (and most likely will always be) indistinguishable from the page size,
     * looking from the LibOS perspective. The two values can be different on the PAL level though,
     * see e.g. SYSTEM_INFO::dwAllocationGranularity on Windows.
     */
    size_t alloc_align;

    size_t mem_total;

    /*!
     * \brief Every thread of a process shares one CPU and is scheduled
     * cooperatively by the PAL.
     *
     * True on the SVSM PAL: the monitor runs one VMSA per vault and refuses a
     * second entrant to it, so PAL threads are contexts inside one thread of
     * execution rather than CPUs. The consequence that reaches beyond the PAL
     * is that a spin waiting on another thread never ends unless spinning
     * yields, so LibOS installs `g_cpu_relax_yield` when this is set.
     */
    bool cooperative_threading;

    struct pal_cpu_info cpu_info;
    struct pal_topo_info topo_info; /* received from untrusted host, but sanitized */

    bool extra_runtime_domain_names_conf;
    struct pal_dns_host_conf dns_host;
};

/* We cannot mark this as returning a pointer to `const` object, because LibOS can
 * change `pal_public_state.topo_info` during checkpoint restore in the child */
struct pal_public_state* PalGetPalPublicState(void);

/*
 * MEMORY ALLOCATION
 */

/*! memory protection flags */
typedef uint32_t pal_prot_flags_t; /* bitfield */
#define PAL_PROT_READ      0x1
#define PAL_PROT_WRITE     0x2
#define PAL_PROT_EXEC      0x4
#define PAL_PROT_WRITECOPY 0x8
#define PAL_PROT_MASK      0xF

/*!
 * \brief The protection to use while WRITING a region that will end up
 *        with `prot`.
 *
 * Loaders and checkpoint restore repeatedly need a region writable for a
 * moment - to relocate it, to read a file into it, to zero its tail -
 * and then put `prot` back. The obvious `prot | PAL_PROT_WRITE` makes a
 * text segment WRITABLE AND EXECUTABLE for the length of that moment.
 *
 * The SVSM monitor refuses exactly that combination to any vault whose
 * measured manifest did not declare `[svsm.jit]` (`refused_wx`,
 * monitor/kernel/src/process_runtime/process/memory.rs), because it is
 * what a JIT needs and what turns a memory bug into code execution.
 * Nothing executes from a region while it is being written, so dropping
 * EXEC costs nothing and keeps every loader inside the rule rather than
 * exempting the code that loads programs from it.
 *
 * Callers restore `prot` afterwards, guarded on `pal_prot_for_writing(p)
 * != p` so that a region that really was W|X gets its X back too.
 */
static inline pal_prot_flags_t pal_prot_for_writing(pal_prot_flags_t prot) {
    return (prot & ~PAL_PROT_EXEC) | PAL_PROT_WRITE;
}

struct pal_initial_mem_range {
    uintptr_t start;
    uintptr_t end;
    pal_prot_flags_t prot;
    /* Denotes whether the range was present (was used at some point), but is now free (is not used
     * anymore). */
    bool is_free;
    /* These structs are stored in a global array, so keep the total size of this struct aligned to
     * it's alignment requirement. */
    char comment[0x13];
};

/*!
 * \brief Allocate virtual memory and zero it out.
 *
 * \param addr  Requested address. Must be aligned and non-NULL.
 * \param size  Must be a positive number, aligned at the allocation alignment.
 * \param prot  A combination of the `PAL_PROT_*` flags.
 *
 * `addr` can be any valid address aligned at the allocation alignment, but there must be no memory
 * previously allocated at the same address.
 * This function must not dynamically allocate any internal memory (must not use `malloc`)!
 */
int PalVirtualMemoryAlloc(void* addr, size_t size, pal_prot_flags_t prot);

/*!
 * \brief Deallocate a previously allocated memory mapping.
 *
 * \param addr  The address.
 * \param size  The size.
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 * `[addr; addr+size)` must be a continuous memory range without any holes.
 */
int PalVirtualMemoryFree(void* addr, size_t size);

/*!
 * \brief Modify the permissions of a previously allocated memory mapping.
 *
 * \param addr  The address.
 * \param size  The size.
 * \param prot  See #PalVirtualMemoryAlloc.
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 * `[addr; addr+size)` must be a continuous memory range without any holes.
 */
int PalVirtualMemoryProtect(void* addr, size_t size, pal_prot_flags_t prot);

/*!
 * \brief Map a range of the runtime image (pal_public_state.runtime_images[0]) at `addr`
 *        without copying it.
 *
 * \param addr       Destination, aligned at the allocation alignment.
 * \param size       Aligned size.
 * \param prot       See #PalVirtualMemoryAlloc; must not include PAL_PROT_WRITE.
 * \param image_off  Aligned offset inside the image (the file's `data_off` plus the mapping
 *                   offset).
 *
 * The host aliases the image's pages read-only (svsm: the monitor maps the runtime store's
 * physical pages, LibOS/runtime split); a later #PalVirtualMemoryProtect to writable turns the
 * range into a private copy. Hosts without runtime images return -PAL_ERROR_NOTIMPLEMENTED.
 */
int PalRuntimeImageMap(void* addr, size_t size, pal_prot_flags_t prot, uint64_t image_off);

/*!
 * \brief Attach to the filesystem this vault's LINEAGE shares, creating it if
 *        this vault is the lineage's root.
 *
 * \param pages  Data pages wanted; 0 asks for the host's default.
 * \param base   Out: where it is mapped.
 * \param size   Out: how big it is, in bytes.
 *
 * Called LAZILY, on the first access to a vaultfs mount, and that is not an
 * optimisation. The heavy init of a vault runs in its ZYGOTE, which is cloned
 * copy-on-write into every instance; a region acquired there would be
 * inherited by every instance of that zygote, so two unrelated invocations
 * would share one filesystem. Asking at first use instead means the caller is
 * the running instance, which is the lineage root it should be. (The svsm host
 * refuses a zygote outright, so this is belt and braces.)
 *
 * Idempotent: a vault already in a lineage is told where its filesystem is
 * rather than given a second one. That is how a forked child - which inherits
 * its parent's mapping - and an exec'd program - which keeps it, the mapping
 * not being a VMA the LibOS can free - both find the SAME filesystem.
 *
 * Hosts without lineages return -PAL_ERROR_NOTIMPLEMENTED.
 */
int PalLineageFsAttach(uint64_t pages, void** base, size_t* size);

/*!
 * \brief This process's own serial - the one identity in reach that is never
 *        reused.
 *
 * A pid is a slot and a successor is given the same number; a serial is
 * stamped once per process. Anything shared between the members of a lineage
 * that has to record WHO holds something must record this.
 *
 * Must be read each time it is needed and never kept in a variable that
 * outlives a fork: a copy-on-write child inherits its parent's memory, so a
 * cached serial is the parent's and a child signing with it is invisible.
 *
 * \returns 0 on success, -PAL_ERROR_DENIED if this process is in no lineage.
 */
int PalLineageSelf(uint64_t* out);

/*!
 * \brief Is `serial` still a member of this process's lineage?
 *
 * Absence from the monitor's roster, which is the only sound death criterion
 * here - a live member can be off its processor indefinitely, so no timeout
 * means anything. A member leaves the roster before anything it held is
 * freed.
 *
 * \returns 0 on success (`*out` set), -PAL_ERROR_DENIED if in no lineage.
 */
int PalLineageMemberAlive(uint64_t serial, bool* out);

/*!
 * \brief Copy this process, copy-on-write, and run the copy.
 *
 * \param      flags      0, or PAL_PROCESS_FORK_RESIDENT.
 * \param[out] out_child  The child's id in the parent, and 0 in the child.
 * \param[out] out_self   The CHILD's own id, in the child only. It cannot
 *                        learn this any other way: \p out_child must be 0
 *                        to say which side it is on, so without this the
 *                        two sides would disagree about what the child is
 *                        called - the parent knowing the id it waits on,
 *                        the child knowing nothing.
 *
 * \returns 0 on success, negative on failure.
 *
 * RETURNS TWICE, which no other PAL call does, and that is the point: on a
 * host whose monitor can copy an address space there is nothing to
 * serialise and nothing to ship, so fork is one call rather than
 * #PalProcessCreate plus a checkpoint down a stream. The caller tells the
 * two returns apart by \p out_child, exactly as fork(2) does by its return
 * value - and a FAILED fork returns once and looks like the parent, so the
 * error must be checked.
 *
 * With PAL_PROCESS_FORK_RESIDENT the child is handed to the host's
 * scheduler and runs on its own. Without it the child exists but is parked,
 * which is what a host-driven worker pool wants and NOT what fork(2) means:
 * a child nobody dispatches never reaches its execve and its parent waits
 * for ever.
 */
#define PAL_PROCESS_FORK_RESIDENT 1UL
/* What a fork tells each side (lineage-vmid, 2026-10-20). `child` is set in
 * the parent and 0 in the child, which is how each knows which it is; `self`
 * is the child's own monitor id, in the child. `serial` and `name` are the
 * CHILD's on both sides: the serial is never reused (ask the monitor about a
 * child by id AND serial), and the name is the child's in its lineage, never
 * reused within a full cycle - the LibOS's pid is `name << 12`, so a pid is
 * never the reusable monitor id. */
struct pal_fork_ids {
    uint64_t child;
    uint64_t self;
    uint64_t serial;
    uint32_t name;
};
int PalProcessFork(uint64_t flags, struct pal_fork_ids* out);

/*!
 * \brief How did my child end?
 *
 * \param      child       the child's id, as #PalProcessFork reported it.
 * \param      child_serial  its serial (#pal_fork_ids), so that a reused id
 *                         can never answer for it; 0 asks by id alone.
 * \param[out] out_reason  0 while it is still running, >0 for a reason it
 *                         ended, and the call fails rather than reporting a
 *                         negative one.
 * \param[out] out_value   the exit code, errno, or fault vector that goes
 *                         with the reason.
 *
 * \returns 0 on success, negative if the id is not this process's child.
 *
 * NON-BLOCKING. A caller that must wait does so itself, because the host
 * already has one answer to "who runs next" and a second waiting mechanism
 * here would give it two.
 */
int PalProcessWait(uint64_t child, uint64_t child_serial, int64_t* out_reason,
                   uint64_t* out_value);

/*!
 * \brief Set upcalls for memory bookkeeping
 *
 * \param alloc  Function to call to get a memory range.
 * \param free   Function to call to release the memory range.
 *
 * Both \p alloc and \p free must be thread-safe.
 */
void PalSetMemoryBookkeepingUpcalls(int (*alloc)(size_t size, uintptr_t* out_addr),
                                    int (*free)(uintptr_t addr, size_t size));

/*
 * PROCESS CREATION
 */

/*!
 * \brief Create a new process.
 *
 * \param      args                     An array of strings -- the arguments to be passed to the new
 *                                      process.
 * \param      reserved_mem_ranges      List of memory ranges that should not be used by the child
 *                                      process until app memory is restored from a checkpoint. Must
 *                                      be sorted in descending order.
 * \param      reserved_mem_ranges_len  Length of \p reserved_mem_ranges.
 * \param[out] out_handle               On success contains the process handle.
 *
 * Loads and executes the same binary as currently executed one (`loader.entrypoint`), and passes
 * the new arguments.
 *
 * TODO: `args` is only used by PAL regression tests, and should be removed at some point.
 */
int PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                     size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle);

/*!
 * \brief Terminate all threads in the process immediately.
 *
 * \param exit_code  The exit value returned to the host.
 */
noreturn void PalProcessExit(int exit_code);

/*
 * STREAMS
 */

/*! Stream Access Flags */
enum pal_access {
    PAL_ACCESS_RDONLY,
    PAL_ACCESS_WRONLY,
    PAL_ACCESS_RDWR,
    PAL_ACCESS_BOUND,
};

/*! stream sharing flags */
// FIXME: These flags currently must correspond 1-1 to Linux flags, which is totally unportable.
//        They should be redesigned when we'll be rewriting the filesystem layer.
typedef uint32_t pal_share_flags_t; /* bitfield */
#define PAL_SHARE_GLOBAL_X    01
#define PAL_SHARE_GLOBAL_W    02
#define PAL_SHARE_GLOBAL_R    04
#define PAL_SHARE_GROUP_X    010
#define PAL_SHARE_GROUP_W    020
#define PAL_SHARE_GROUP_R    040
#define PAL_SHARE_OWNER_X   0100
#define PAL_SHARE_OWNER_W   0200
#define PAL_SHARE_OWNER_R   0400
#define PAL_SHARE_STICKY   01000
#define PAL_SHARE_SET_GID  02000
#define PAL_SHARE_SET_UID  04000
#define PAL_SHARE_MASK     07777

/*! stream create mode */
enum pal_create_mode {
    PAL_CREATE_NEVER,     /*!< Fail if file does not exist */
    PAL_CREATE_TRY,       /*!< Create file if file does not exist */
    PAL_CREATE_ALWAYS,    /*!< Create file and fail if file already exists */
    PAL_CREATE_IGNORED,   /*!< Magic value for calls to handle types which ignore creation mode */
};

/*! stream misc flags */
typedef uint32_t pal_stream_options_t; /* bitfield */
#define PAL_OPTION_EFD_SEMAPHORE   0x1 /*!< specific to `eventfd` syscall */
#define PAL_OPTION_NONBLOCK        0x2
#define PAL_OPTION_PASSTHROUGH     0x4 /*!< Disregard `sgx.{allowed,trusted}_files` */
/*!
 * \brief This pipe may be INHERITED BY A FORKED CHILD, so both processes have
 *        to see the same buffer.
 *
 * Only the SVSM PAL acts on it, and only for a pipe: a pair so marked is
 * placed in the lineage arena the monitor shares with this vault's
 * descendants ([svsm.pipes] in the measured manifest), rather than on this
 * process's private heap.
 *
 * It has to be asked for rather than assumed, because the arena is a scarce
 * VM-WIDE resource - 32 pairs - and the things that hold a pipe in this LibOS
 * are mostly not application pipes at all. Every thread owns a pollable
 * event, which is a pipe pair; so does the async worker and so does the IPC
 * worker. None of them is an fd, so none is closed by `detach_all_fds` when a
 * process exits, and their only destructor is PalObjectDestroy - which was
 * `return; // ignore` in this tree when this flag was added, so putting them
 * in the arena leaked pairs until the 32 ran out and pipe() returned ENOMEM:
 * measured at four slots per invocation, dead by the seventh. The stub is
 * fixed and they are released now; the flag stays because the arena is a
 * VM-WIDE 32 pairs and a per-thread wakeup object never crosses a fork, so
 * spending one on it is wrong even when it is given back.
 *
 * `libos_syscall_pipe2` sets it; nothing else does.
 */
#define PAL_OPTION_INHERITABLE     0x8
#define PAL_OPTION_MASK            0xf

/*!
 * \brief Open/create a stream resource specified by `uri`.
 *
 * \param typed_uri    The URI of the stream to be opened/created, prefixed with the type.
 * \param access       See #pal_access.
 * \param share_flags  A combination of the `PAL_SHARE_*` flags.
 * \param create       See #pal_create_mode.
 * \param options      A combination of the `PAL_OPTION_*` flags.
 * \param handle[out]  If the resource is successfully opened or created, a PAL handle is returned
 *                     in `*handle` for further access such as reading or writing.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Supported URI types:
 * * `%file:...`, `dir:...`: Files or directories on the host file system. If #PAL_CREATE_TRY or
 *   #PAL_CREATE_ALWAYS is given in `create` flags, the file/directory will be created.
 * * `dev:...`: Open a device as a stream.
 * * `console:`: Open a console (PAL-specific input/output) as a stream. In case of Linux and
 *   Linux-SGX PALs, the "input/output" are the stdin and stdout streams of the host process.
 * * `pipe.srv:<name>`, `pipe:<name>`, `pipe:`: Open a byte stream that can be used for RPC between
 *   processes. The server side of a pipe can accept any number of connections. If `pipe:` is given
 *   as the URI (i.e., without a name), it will open an anonymous bidirectional pipe.
 */
int PalStreamOpen(const char* typed_uri, enum pal_access access, pal_share_flags_t share_flags,
                  enum pal_create_mode create, pal_stream_options_t options, PAL_HANDLE* handle);

/*!
 * \brief Block until a new connection is accepted and return the PAL handle for the connection.
 *
 * \param      handle   Handle to accept a new connection on.
 * \param[out] client   On success holds handle for the new connection.
 * \param      options  Flags to set on \p client handle.
 *
 * This API is only available for handles that are opened with `pipe.srv:...`.
 */
int PalStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client, pal_stream_options_t options);

/*!
 * \brief Read data from an open stream.
 *
 * \param         handle  Handle to the stream.
 * \param         offset  Offset to read at. If \p handle is a file, \p offset must be specified at
 *                        each call.
 * \param[in,out] count   Contains size of \p buffer. On success, will be set to the number of bytes
 *                        read.
 * \param         buffer  Pointer to the buffer to read into.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * If \p handle is a directory, PalStreamRead fills the buffer with the null-terminated names of the
 * directory entries.
 */
int PalStreamRead(PAL_HANDLE handle, uint64_t offset, size_t* count, void* buffer);

/*!
 * \brief Write data to an open stream.
 *
 * \param         handle  Handle to the stream.
 * \param         offset  Offset to write to. If \p handle is a file, \p offset must be specified at
 *                        each call.
 * \param[in,out] count   Contains size of \p buffer. On success, will be set to the number of bytes
 *                        written.
 * \param         buffer  Pointer to the buffer to write from.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalStreamWrite(PAL_HANDLE handle, uint64_t offset, size_t* count, void* buffer);

enum pal_delete_mode {
    PAL_DELETE_ALL,  /*!< delete the whole resource / shut down both directions */
    PAL_DELETE_READ,  /*!< shut down the read side only */
    PAL_DELETE_WRITE, /*!< shut down the write side only */
};

/*!
 * \brief Delete files or directories on the host or shut down the connection of TCP/UDP sockets.
 *
 * \param access  Which side to shut down (see #pal_delete_mode values).
 */
int PalStreamDelete(PAL_HANDLE handle, enum pal_delete_mode delete_mode);

/*!
 * \brief Let go of every stream shared with other processes that is not in `keep`.
 *
 * \param keep   The streams this process still uses.
 * \param count  How many there are.
 *
 * For a process image that is being replaced (execve): any such stream this
 * process inherited by a fork that the LibOS does not list is one only the
 * old image could reach - a copy of a pipe end another thread of its parent
 * was still creating or using, which no fd of the child names. Its share is
 * given back, so the other processes on that stream are not kept waiting for
 * a process that can never close it. The handles themselves stay allocated.
 *
 * \returns 0, or -PAL_ERROR_NOTIMPLEMENTED on a host with no shared streams.
 */
int PalStreamsKeepOnly(PAL_HANDLE* keep, size_t count);

/*!
 * \brief Map a file to a virtual memory address in the current process.
 *
 * \param handle  Handle to the stream to be mapped.
 * \param addr    See #PalVirtualMemoryAlloc.
 * \param prot    See #PalVirtualMemoryAlloc.
 * \param offset  Offset in the stream to be mapped. Must be properly aligned.
 * \param size    Size of the requested mapping. Must be non-zero and properly aligned.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Use `PalVirtualMemoryFree` to unmap the file.
 */
int PalStreamMap(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                 size_t size);

/*!
 * \brief Set the length of the file referenced by handle to `length`.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalStreamSetLength(PAL_HANDLE handle, uint64_t length);

/*!
 * \brief Flush the buffer of a file stream.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalStreamFlush(PAL_HANDLE handle);

/*!
 * \brief Send a PAL handle to a process.
 *
 * \param target_process  The handle to the target process where \p cargo will be sent.
 * \param cargo           The handle to send.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalSendHandle(PAL_HANDLE target_process, PAL_HANDLE cargo);

/*!
 * \brief Receive a handle from another process.
 *
 * \param      source_process  The handle to the source process from which \p cargo will be
 *                             received.
 * \param[out] out_cargo       The received handle.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo);

// TODO: this needs to be redesigned, most of these fields are type specific
/* stream attribute structure */
typedef struct _PAL_STREAM_ATTR {
    PAL_IDX handle_type;
    bool nonblocking;
    pal_share_flags_t share_flags;
    size_t pending_size;
    union {
        struct {
            uint64_t linger;
            size_t recv_buf_size;
            size_t send_buf_size;
            uint64_t receivetimeout_us, sendtimeout_us;
            bool reuseaddr;
            bool reuseport;
            bool keepalive;
            bool broadcast;
            bool tcp_cork;
            uint32_t tcp_user_timeout;
            uint32_t tcp_keepidle;
            uint32_t tcp_keepintvl;
            uint8_t tcp_keepcnt;
            bool tcp_nodelay;
            bool ipv6_v6only;
        } socket;
    };
} PAL_STREAM_ATTR;

/*!
 * \brief Query the attributes of a named stream.
 *
 * This API only applies for URIs such as `%file:...`, `dir:...`, and `dev:...`.
 */
int PalStreamAttributesQuery(const char* typed_uri, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the attributes of an open stream.
 *
 * This API applies to any stream handle.
 */
int PalStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Set the attributes of an open stream.
 *
 * Calling this function on the same handle concurrently is not allowed (i.e. callers must ensure
 * mutual exclusion).
 */
int PalStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief This API changes the name of an open stream.
 */
int PalStreamChangeName(PAL_HANDLE handle, const char* typed_uri);

struct pal_socket_addr {
    enum pal_socket_domain domain;
    union {
        struct {
            uint32_t addr;
            uint16_t port;
        } ipv4;
        struct {
            uint32_t flowinfo;
            uint32_t scope_id;
            uint8_t addr[16];
            uint16_t port;
        } ipv6;
    };
};

/*!
 * \brief Create a socket handle.
 *
 * \param      domain      Domain of the socket.
 * \param      type        Type of the socket.
 * \param      options     Flags to set on the handle.
 * \param[out] out_handle  On success contains the socket handle.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                    pal_stream_options_t options, PAL_HANDLE* out_handle);

/*!
 * \brief Bind a socket to a local address.
 *
 * \param         handle  Handle to the socket.
 * \param[in,out] addr    Address to bind to. If the protocol allows for some ephemeral data (e.g.
 *                        port `0` in IPv4), it will be overwritten to the actual data used.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Can be called only once per socket.
 */
int PalSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr);

/*!
 * \biref Turn a socket into a listening one.
 *
 * \param handle   Handle to the socket.
 * \param backlog  Size of the pending connections queue.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Can be called multiple times, to change \p backlog.
 */
int PalSocketListen(PAL_HANDLE handle, unsigned int backlog);

/*!
 * \brief Accept a new connection on a socket.
 *
 * \param      handle           Handle to the socket. Must be in listening mode.
 * \param      options          Flags to set on the new handle.
 * \param[out] out_client       On success contains a handle for the new connection.
 * \param[out] out_client_addr  On success contains the remote address of the new connection.
 *                              Can be NULL, to ignore the result.
 * \param[out] out_local_addr   On success contains the local address of the new connection.
 *                              Can be NULL, to ignore the result.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * This function can be safely called concurrently.
 */
int PalSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                    struct pal_socket_addr* out_client_addr,
                    struct pal_socket_addr* out_local_addr);

/*!
 * \brief Connect a socket to a remote address.
 *
 * \param      handle          Handle to the socket.
 * \param      addr            Address to connect to.
 * \param[out] out_local_addr  On success contains the local address of the socket.
 *                             Can be NULL, to ignore the result.
 * \param[out] out_inprogress  On success, returns true in special case of an in-progress connection
 *                             on a non-blocking socket.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Can also be used to disconnect the socket, if #PAL_DISCONNECT is passed in \p addr.
 */
int PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                     struct pal_socket_addr* out_local_addr, bool* out_inprogress);

/*!
 * \brief Send data.
 *
 * \param      handle             Handle to the socket.
 * \param      iov                Array of buffers with data to send.
 * \param      iov_len            Length of \p iov array.
 * \param[out] out_size           On success contains the number of bytes sent.
 * \param      addr               Destination address. Can be NULL if the socket was connected.
 * \param      force_nonblocking  If `true` this request should not block. Otherwise just use
 *                                whatever mode the handle is in.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Data is sent atomically, i.e. data from two `PalSocketSend` calls will not be interleaved.
 *
 * We use Linux `struct iovec` as argument here, because the alternative is to use a custom
 * structure, but it would contain exactly the same fields, which would achieve nothing, but could
 * worsen performance in certain cases.
 */
int PalSocketSend(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                  struct pal_socket_addr* addr, bool force_nonblocking);

/*!
 * \brief Receive data.
 *
 * \param      handle             Handle to the socket.
 * \param      iov                Array of buffers for received data.
 * \param      iov_len            Length of \p iov array.
 * \param[out] out_total_size     On success contains the number of bytes received (TCP) or the size
 *                                of the packet (UDP), which might be greater than the total size of
 *                                buffers in \p iov array.
 * \param[out] addr               Source address. Can be NULL to ignore the source address.
 * \param      force_nonblocking  If `true` this request should not block. Otherwise just use
 *                                whatever mode the handle is in.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * Data is received atomically, i.e. data from two `PalSocketRecv` calls will not be interleaved.
 *
 * We use Linux `struct iovec` as argument here, because the alternative is to use a custom
 * structure, but it would contain exactly the same fields, which would achieve nothing, but could
 * worsen performance in certain cases.
 */
int PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                  struct pal_socket_addr* addr, bool force_nonblocking);

/*
 * Thread creation
 */

/*!
 * \brief Create a thread in the current process.
 *
 * \param      addr    Address of an entry point of execution for the new thread.
 * \param      param   Pointer argument that is passed to the new thread.
 * \param[out] handle  On success contains the thread handle.
 */
int PalThreadCreate(int (*callback)(void*), void* param, PAL_HANDLE* handle);

/*!
 * \brief Yield the current thread such that the host scheduler can reschedule it.
 */
void PalThreadYieldExecution(void);

/*!
 * \brief Terminate the current thread.
 *
 * \param clear_child_tid  Pointer to memory that is erased on thread exit to notify LibOS (which in
 *                         turn notifies the parent thread if any); if `clear_child_tid` is NULL,
 *                         then PAL doesn't do the clearing.
 */
noreturn void PalThreadExit(int* clear_child_tid);

/*!
 * \brief Resume a thread.
 */
int PalThreadResume(PAL_HANDLE thread);

/*!
 * \brief Set the CPU affinity of a thread.
 *
 * \param thread        PAL thread for which to set the CPU affinity.
 * \param cpu_mask      Pointer to the new CPU mask.
 * \param cpu_mask_len  Length of the \p cpu_mask array.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * All bit positions exceeding the count of host CPUs are ignored. \p cpu_mask should select at
 * least one online CPU.
 */
int PalThreadSetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len);

/*!
 * \brief Get the CPU affinity of a thread.
 *
 * \param thread        PAL thread for which to get the CPU affinity.
 * \param cpu_mask      Pointer to hold the current CPU mask.
 * \param cpu_mask_len  Length of the \p cpu_mask array.
 *
 * \returns 0 on success, negative error code on failure.
 *
 * \p cpu_mask must be able to fit all the processors on the host.
 */
int PalThreadGetCpuAffinity(PAL_HANDLE thread, unsigned long* cpu_mask, size_t cpu_mask_len);

/*
 * Exception Handling
 */

/* These values are used as indices in an array of PAL_EVENT_NUM_BOUND elements, be careful when
 * changing them. */
enum pal_event {
    /*! pseudo event, used in some APIs to denote a lack of event */
    PAL_EVENT_NO_EVENT,
    /*! arithmetic error (div-by-zero, floating point exception, etc.) */
    PAL_EVENT_ARITHMETIC_ERROR,
    /*! segmentation fault, protection fault, bus fault */
    PAL_EVENT_MEMFAULT,
    /*! illegal instructions */
    PAL_EVENT_ILLEGAL,
    /*! terminated by external program (see "sys.enable_sigterm_injection" manifest option) */
    PAL_EVENT_QUIT,
    /*! interrupted (usually internally to handle aync event) */
    PAL_EVENT_INTERRUPTED,

    PAL_EVENT_NUM_BOUND,
};

/*!
 * \brief Type of exception handlers (upcalls).
 *
 * \param is_in_pal  `true` if the exception happened inside PAL.
 * \param addr       Address of the exception (meaningful only for sync exceptions).
 * \param context    CPU context at the moment of exception.
 */
typedef void (*pal_event_handler_t)(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context);

/*!
 * \brief Set the handler for the specific exception event.
 *
 * \param event  One of #pal_event values.
 */
void PalSetExceptionHandler(pal_event_handler_t handler, enum pal_event event);

/*
 * Synchronization
 */

/*!
 * \brief Create an event handle.
 *
 * \param[out] handle         On success `*handle` contains pointer to the event handle.
 * \param      init_signaled  Initial state of the event (`true` - set, `false` - not set).
 * \param      auto_clear     `true` if a successful wait for the event should also reset (consume)
 *                            it.
 *
 * Creates a handle to an event that resembles WinAPI synchronization events. A thread can set
 * (signal) the event using #PalEventSet, clear (unset) it using #PalEventClear or wait until
 * the event becomes set (signaled) using #PalEventWait.
 */
int PalEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear);

/*!
 * \brief Set (signal) an event.
 *
 * If the event is already set, does nothing.
 *
 * This function has release semantics and synchronizes with #PalEventWait.
 */
void PalEventSet(PAL_HANDLE handle);

/*!
 * \brief Clear (unset) an event.
 *
 * If the event is not set, does nothing.
 */
void PalEventClear(PAL_HANDLE handle);

/*!
 * \brief Wait for an event handle.
 *
 * \param         handle      Handle to wait on, must be of "event" type.
 * \param[in,out] timeout_us  Timeout for the wait.
 *
 * \returns 0 if the event was triggered, negative error code otherwise (#PAL_ERROR_TRYAGAIN in case
 *          of timeout triggering)
 *
 * \p timeout_us points to a value that specifies the maximal time (in microseconds) that this
 * function should sleep if this event is not signaled in the meantime. Specifying `NULL` blocks
 * indefinitely. Note that in any case this function can return earlier, e.g. if a signal has
 * arrived, but this will be indicated by the returned error code.
 * After returning (both successful and not), \p timeout_us will contain the remaining time (time
 * that need to pass before we hit original \p timeout_us).
 *
 * This function has acquire semantics and synchronizes with #PalEventSet.
 */
int PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us);

/*!
 * \brief Count a LibOS lock hold, so that a fork can wait until no other thread holds one.
 *
 * \param word   If not NULL, \p delta is added to `*word` (an atomic fetch-add, sequentially
 *               consistent) in the same step - the reader fast path of an rwlock, whose hold IS
 *               that add. NULL counts a hold only (a mutex taken around it, a spinlock).
 * \param delta  > 0 takes a hold, < 0 gives it back.
 *
 * \returns the previous value of `*word`, or 0 when \p word is NULL.
 *
 * Called with \p delta > 0 BEFORE the lock is acquired and with < 0 after it is released, so a
 * hold is counted for at least as long as the lock is held (an extra moment either side only
 * delays a fork). On the SVSM PAL the count and the add happen in PAL code, which the monitor
 * never preempts, and a fork (#PalProcessFork) waits until the holds of every other context have
 * drained: a CoW fork copies memory, and a lock some other thread held at that instant would be
 * held for ever in the child. A context that holds nothing waits out a fork in progress before
 * taking its first hold; one that already holds some does not, so it can finish and drain.
 * Other PALs count nothing and only do the add.
 */
int64_t PalLockHold(int64_t* word, int64_t delta);

/*!
 * \brief Count one hold of a lock JUST TAKEN, unless a fork is waiting for this thread to hold
 *        none.
 *
 * \returns true if the hold was counted. false - nothing counted - when this thread holds
 *          nothing and a fork is in progress: the caller must give the lock back, wait out the
 *          fork (#PalLockHold +1/-1 does) and take it again, rather than sit at the fork's gate
 *          holding a lock the fork does not know about.
 *
 * For a lock counted only once held (a socket's, held across long waits): counting it before the
 * wait would make every queued waiter a hold the fork waits for.
 */
bool PalLockHoldTry(void);

/*!
 * \brief Pause (\p n > 0) or resume (\p n < 0) \p n of this thread's lock holds for a fork.
 *
 * Around a blocking wait made while holding locks (a socket's recv): paused holds are not counted
 * for a fork, so the fork does not wait for the wait, and while any are paused the thread never
 * waits at a fork's gate - its holds drain when it finishes. Whoever owns such locks remakes them
 * in a forked child. Other PALs do nothing.
 */
void PalLockHoldPause(int64_t n);

typedef uint32_t pal_wait_flags_t; /* bitfield */
#define PAL_WAIT_READ     1
#define PAL_WAIT_WRITE    2
#define PAL_WAIT_ERROR    4
#define PAL_WAIT_HANG_UP  8

/*!
 * \brief Poll - wait for an event to happen on at least one handle.
 *
 * \param         count         The number of items in \p handle_array.
 * \param         handle_array  Array of handles to poll.
 * \param         events        Requested events for each handle.
 * \param[out]    ret_events    Events that were detected on each handle.
 * \param[in,out] timeout_us    Timeout for the wait (`NULL` to block indefinitely).
 *
 * \returns 0 if there was an event on at least one handle, negative error code otherwise.
 *
 * \p timeout_us contains remaining timeout both on successful and failed calls.
 *
 * \p handle_array can contain empty elements (NULL) which are ignored.
 */
int PalStreamsWaitEvents(size_t count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                         pal_wait_flags_t* ret_events, uint64_t* timeout_us);

/*!
 * \brief Close and deallocate a PAL handle.
 */
void PalObjectDestroy(PAL_HANDLE handle);

/*
 * MISC
 */

/*!
 * \brief Output a message to the debug stream.
 *
 * \param buffer  Message to write.
 * \param size    \p buffer size.
 *
 * \returns 0 on success, negative error code on failure.
 */
int PalDebugLog(const void* buffer, size_t size);

/*!
 * \brief Get the current time.
 *
 * \param[out] time  On success holds the current time in microseconds.
 */
int PalSystemTimeQuery(uint64_t* time);

/*!
 * \brief Cryptographically secure RNG.
 *
 * \param[out] buffer  Output buffer.
 * \param      size    \p buffer size.
 *
 * \returns 0 on success, negative on failure.
 */
int PalRandomBitsRead(void* buffer, size_t size);

enum pal_segment_reg {
    PAL_SEGMENT_FS,
    PAL_SEGMENT_GS,
};

/*!
 * \brief Get segment register base.
 *
 * \param reg   The register base to get (#pal_segment_reg).
 * \param addr  The address where result will be stored.
 *
 * \returns 0 on success, negative error value on failure.
 */
int PalSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr);

/*!
 * \brief Set segment register.
 *
 * \param reg   The register base to be set (#pal_segment_reg).
 * \param addr  The address to be set.
 *
 * \returns 0 on success, negative error value on failure.
 */
int PalSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr);

/*!
 * \brief Perform a device-specific operation `cmd`.
 *
 * \param         handle   Handle of the device.
 * \param         cmd      Device-dependent request/control code.
 * \param[in,out] arg      Arbitrary argument to `cmd`. May be unused or used as a 64-bit integer
 *                         or used as a pointer to a buffer that contains the data required to
 *                         perform the operation as well as the data returned by the operation. For
 *                         some PALs (currently Linux and Linux-SGX), the manifest must describe the
 *                         layout of this buffer in order to correctly copy the data to/from the
 *                         host.
 * \param[out]    out_ret  Typically zero, but some device-specific operations return a
 *                         device-specific value (in addition to or instead of \p arg).
 *
 * \returns 0 on success, negative error value on failure.
 *
 * Note that this function returns a negative error value only for PAL-internal errors (like errors
 * during finding/parsing of the corresponding IOCTL data struct in the manifest). The host's error
 * value, if any, is always passed in `out_ret`.
 *
 * This function corresponds to ioctl() in UNIX systems and DeviceIoControl() in Windows.
 */
int PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret);

/*!
 * \brief Obtain the attestation report (local) with `user_report_data` embedded into it.
 *
 * \param         user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param[in,out] user_report_data_size  Caller specifies size of `user_report_data`; on return,
 *                                       contains PAL-enforced size of `user_report_data` (64B in
 *                                       case of SGX PAL).
 * \param[in,out] target_info            Target info of target enclave for attestation. If it
 *                                       contains all zeros, it is populated with this enclave's
 *                                       target info. Must be a 512B buffer in case of SGX PAL.
 * \param[in,out] target_info_size       Caller specifies size of `target_info`; on return,
 *                                       contains PAL-enforced size of `target_info` (512B in case
 *                                       of SGX PAL).
 * \param[out]    report                 Attestation report with `user_report_data` embedded,
 *                                       targeted for an enclave with provided `target_info`. Must
 *                                       be a 432B buffer in case of SGX PAL.
 * \param[in,out] report_size            Caller specifies size of `report`; on return, contains
 *                                       PAL-enforced size of `report` (432B in case of SGX PAL).
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B,
 * `target_info` is an SGX target_info struct of exactly 512B, and `report` is an SGX report
 * obtained via the EREPORT instruction (exactly 432B). If `target_info` contains all zeros,
 * then this function additionally returns this enclave's target info in `target_info`. Useful
 * for local attestation.
 *
 * The caller may specify `*user_report_data_size`, `*target_info_size`, and `*report_size` as 0
 * and other fields as NULL to get PAL-enforced sizes of these three structs.
 */
int PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                         void* target_info, size_t* target_info_size, void* report,
                         size_t* report_size);

/*!
 * \brief Obtain the attestation quote with `user_report_data` embedded into it.
 *
 * \param         user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param         user_report_data_size  Size in bytes of `user_report_data`. Must be exactly 64B
 *                                       in case of SGX PAL.
 * \param[out]    quote                  Attestation quote with `user_report_data` embedded.
 * \param[in,out] quote_size             Caller specifies maximum size allocated for `quote`; on
 *                                       return, contains actual size of obtained quote.
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B
 * and `quote` is an SGX quote obtained from Quoting Enclave via AESM service.
 */
int PalAttestationQuote(const void* user_report_data, size_t user_report_data_size, void* quote,
                        size_t* quote_size);
/*!
 * \brief Get special key (specific to PAL host).
 *
 * \param         name      Key name.
 * \param[out]    key       On success, will be set to retrieved key.
 * \param[in,out] key_size  Caller specifies maximum size for `key`. On success, will contain actual
 *                          size.
 *
 * Retrieve the value of a special key. Currently implemented for Linux-SGX PAL, which supports two
 * such keys: `_sgx_mrenclave` and `_sgx_mrsigner` (see macros below).
 *
 * If a given key is not supported by the current PAL host, the function will return
 * -PAL_ERROR_NOTIMPLEMENTED.
 */
int PalGetSpecialKey(const char* name, void* key, size_t* key_size);

#define PAL_KEY_NAME_SGX_MRENCLAVE "_sgx_mrenclave"
#define PAL_KEY_NAME_SGX_MRSIGNER  "_sgx_mrsigner"

#ifdef __GNUC__
#define symbol_version_default(real, name, version) \
    __asm__(".symver " #real "," #name "@@" #version "\n")
#else
#define symbol_version_default(real, name, version)
#endif

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Return CPUID information, based on the leaf/subleaf.
 *
 * \param[out] values  The array of the results.
 */
int PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[CPUID_WORD_NUM]);
#endif

void PalDebugMapAdd(const char* uri, void* start_addr);
void PalDebugMapRemove(void* start_addr);

/* Describe the code under given address (see `describe_location()` in `callbacks.h`). Without
 * DEBUG, falls back to raw value ("0x1234"). */
void PalDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size);

#undef INSIDE_PAL_H
