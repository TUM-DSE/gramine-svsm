#ifndef PAL_MONITOR_CALL_H_
#define PAL_MONITOR_CALL_H_
#include <stdint.h>
#include "pal.h"

struct monitor_call_data {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t r8;
    uint64_t r9;
};

void monitor_call(struct monitor_call_data* data);
void extended_monitor_call(struct monitor_call_data* data);
/* Where a monitor call that did not reach the monitor ends: rax came back
 * changed. Executes VMMCALL with CallForged (0x4EFFFFFD) in rax, never
 * CPUID, so the monitor retires the vault; does not return. */
noreturn void monitor_call_forged(void);
noreturn void pal_svsm_fail(const char* err, int errno);
void pal_svsm_exit(int exitcode);
void pal_svsm_debug_putc(char c);
void pal_svsm_debug_write(const uint8_t* bytes, size_t n);

int pal_svsm_free(void* addr, uint64_t size);
int pal_svsm_virt_alloc(void* addr, uint64_t size, pal_prot_flags_t prot);
int pal_svsm_mprotect(void* addr, uint64_t size, pal_prot_flags_t prot);
void* pal_svsm_mmap(void* addr, size_t size, int prot, int flags, int fd, size_t offset);
int pal_svsm_set_tcb(PAL_TCB* tcb);
/* RuntimeInfo: where the monitor mapped runtime image `index` (size 0 = none). */
void pal_svsm_runtime_info(uint64_t index, void** out_base, size_t* out_size);
/* DeviceWindow: memory the HOST can also see, for descriptor rings and the
 * buffers they point at. `pages` = 0 only asks what this vault already has.
 * The guest-physical address is not returned here; it is the second word of
 * the header the monitor writes at the start of the window. */
/* LineageFs (0x4FFFFFD4): a region shared with this vault's descendants.
 *
 * `purpose` picks WHICH: 0 is the filesystem a manifest mounts, 1 is the
 * PAL's own arena. Two, because the LibOS sizes a whole filesystem to the
 * first - anything else allocating there would be allocating inside its
 * superblock. Idempotent per purpose: asking twice reports the same region.
 */
#define PAL_SVSM_LINEAGE_FS    0
#define PAL_SVSM_LINEAGE_PIPES 1
void pal_svsm_lineage_fs(uint64_t pages, uint64_t purpose, void** out_base, size_t* out_size);

/* Fork (0x4FFFFFE4): a copy-on-write copy of this vault.
 *
 * Returns the child's id in the parent, 0 in the child, and UINT64_MAX if
 * the fork failed - the one case a caller MUST check, because a failed fork
 * returns once and is otherwise indistinguishable from being the parent.
 *
 * `flags` bit 0 is PAL_SVSM_FORK_RESIDENT: hand the child to the scheduler
 * so it runs without a host invoke. POSIX fork needs it - a child nobody
 * dispatches would never reach its execve, and its parent would wait for
 * ever. */
#define PAL_SVSM_FORK_RESIDENT 1UL
/* bit 1: the fork went ahead with lock holds of other threads it could not
 * wait out (pal_events.c) - the monitor counts it, GetStat FORK_FOREIGN_HOLDS. */
#define PAL_SVSM_FORK_FOREIGN_HOLDS 2UL
/* `out_self` receives the CHILD's own id, and is 0 in the parent. The child
 * cannot learn it any other way: rcx must be 0 to say which side it is, so
 * the id travels in the register the flags came in on.
 *
 * `out_serial` receives the CHILD's serial on both sides - its own in the
 * child, its child's in the parent (0 if the fork failed). The parent needs
 * it to say whose record of shared-pipe holds it filled for the child
 * (pal_pipes.c, the ledger). */
uint64_t pal_svsm_fork(uint64_t flags, uint64_t* out_self, uint64_t* out_serial,
                       uint32_t* out_name);

/* Wait (0x4FFFFFD5): how did my child end?
 *
 * Non-blocking by design: a live child answers EXIT_LIVE (0) and the caller
 * decides what to do about it. `out_value` carries the exit code, the
 * errno, the fault vector or a MONITOR_* code, depending on the reason.
 * A NEGATIVE reason is a refusal - the id is not this vault's child, or its
 * slot has been reissued - and must not be read as "still running". */
#define PAL_SVSM_EXIT_LIVE 0
int64_t pal_svsm_wait(uint64_t child_id, uint64_t child_serial, uint64_t* out_value);
int64_t pal_svsm_kill_child(uint64_t child_id, uint64_t child_serial);
void pal_svsm_device_window(uint64_t pages, void** out_base, size_t* out_size);
/* DeviceMmio: a device's registers. `id` is vendor | device << 16, 0 only
 * asks what this vault already has. `bar` says which BAR to map, because a
 * modern device does not necessarily keep its registers in BAR0. Returns
 * where they are mapped and the physical address the BAR decodes at. */
void pal_svsm_device_mmio(uint64_t id, uint8_t bar, uint8_t index, int32_t bdf,
                          void** out_base, size_t* out_size, uint64_t* out_phys,
                          uint32_t* out_granted);
/* DeviceConfig: one read of this vault's own device's PCI configuration
 * space. `width` is 1, 2 or 4. All ones if refused. A vault never learns
 * where its device sits on the bus - it says "mine, at this offset". */
uint64_t pal_svsm_device_config(uint32_t offset, uint32_t width);
/* One register access, performed BY THE MONITOR: a vault cannot reach MMIO
 * by touching it - under SEV-SNP the access is intercepted and has to be
 * completed through a GHCB by a #VC handler, and a vault has neither.
 * Returns the value read, or all ones if the access was refused. */
uint64_t pal_svsm_device_io(uint64_t offset, uint32_t width, int write, uint64_t value);
/* TimeInfo (0x4FFFFFEA): how many TSC ticks make a second, and how many
 * microseconds to add to a converted reading to get wall clock (0 = the
 * monitor does not know what time it is). A vault has no other clock. */
void pal_svsm_time_info(uint64_t* out_tsc_hz, uint64_t* out_epoch_us);
/* Nop (0x4FFFFFF5): a round trip to the monitor that does nothing. The only
 * way a vault can give the vCPU back - interrupts are off inside it, so a
 * spin produces no exits at all and the monitor cannot take the core back,
 * run its watchdog, or let the host in until the vault calls out. */
void pal_svsm_nop(void);
/* Sleep (0x4FFFFFDE): give the processor back until `usec` has passed.
 * Returns 0 once woken, or a negative status when the monitor will not park
 * this vault (a host invoke is on the stack) and the caller must wait the
 * hard way. */
long pal_svsm_sleep(uint64_t usec);
/* Sleep with words to watch: the same arm encoding as Park, refused the
 * same way while a host invoke is on the stack. */
long pal_svsm_sleep_arms(const uint64_t* arms, uint64_t count, uint64_t usec);
int64_t pal_svsm_channel_grant(const void* request, uint64_t len, uint64_t* out_addr);
int64_t pal_svsm_channel_close(uint64_t window);
int64_t pal_svsm_channel_notify(uint64_t window);
int64_t pal_svsm_park(const uint64_t* arms, uint64_t count, uint64_t usec);
/* SetExceptionEntry (0x4FFFFFE9): where the monitor should enter this PAL
 * when it has a fault for it rather than a reason to retire the process.
 * 0 stops asking, which is the state a PAL that never calls this is in.
 * `tcb_alt_stack_offset` is where, in the running thread's TCB (which the
 * monitor finds through the GS base), this PAL keeps the top and size of
 * that thread's alternate stack - the stack a fault is delivered on, which
 * must not be the one it interrupted. `preempt_ctl` is the three-word block
 * that governs preemption (struct pal_svsm_preempt_ctl). */
uint64_t pal_svsm_set_exception_entry(void* entry, uint64_t tcb_alt_stack_offset,
                                      void* preempt_ctl);
/* ExceptionReturn (0x4FFFFFE8): resume from `context`. Does not return -
 * restoring rip, rsp and rflags together is what an iretq is for, and this
 * side of the boundary runs at CPL3 and has none. */
noreturn void pal_svsm_exception_return(PAL_CONTEXT* context);
/* Declare what this vault offers other vaults - the thing that makes it a
 * service. `name` is up to eight ASCII bytes packed little-endian. */
int pal_svsm_service_declare(uint64_t name, uint64_t priority);
/* Take the inference scratch for this lineage - 512 pages at
 * INFERENCE_VADDR in every trustlet of it. From the measured manifest,
 * in the zygote, because no trustlet can ask in time. */
int pal_svsm_inference_declare(uint64_t want);
/* JitDeclare: this lineage may hold a page that is writable and
 * executable at once. Zygote only, from the measured manifest. */
int pal_svsm_jit_declare(uint64_t want);
/* Avx512Declare: run this lineage at XCR0 0xE7. Zygote only, from the
 * measured manifest; refused when hosted or on a host without AVX-512. */
int pal_svsm_avx512_declare(uint64_t want);
int pal_svsm_console_declare(uint64_t monitor);
void pal_svsm_console_write(const void* buf, size_t size);
/* Declare what the apps on this base image may claim in their frames
 * (0x4FFFFFDC). Once, from the zygote, and it locks this image out of
 * sealing a channel policy its apps would inherit. */
int64_t pal_svsm_delegate(const void* record, uint64_t len);
/* ChannelPolicy (0x4FFFFFE0): seal what this vault offers other vaults,
 * from the measured manifest, before any application code runs. */
int64_t pal_svsm_channel_policy(const void* record, uint64_t len);

typedef enum {
    PAL_SVSM_GUEST_REQUEST_FILEATTR=0,
    PAL_SVSM_GUEST_REQUEST_OPEN,
    PAL_SVSM_GUEST_REQUEST_READ,
} pal_svsm_guest_request_type_t;

struct pal_svsm_guest_request_arg {
    union {
        struct {
            char path[256];
            uint64_t size;
            uint32_t mode;
            int32_t ret;
        } fileattr;
        struct {
            char path[256];
            uint32_t fd;
        } open;
        struct {
            char buf[1024];
            uint64_t count;
            uint64_t offset;
            uint32_t fd;
        } read;
    };
};

int pal_svsm_guest_request(pal_svsm_guest_request_type_t type, void *arg, size_t size);

#endif // PAL_MONITOR_CALL_H_
