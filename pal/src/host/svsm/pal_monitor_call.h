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
void pal_svsm_fail(const char* err, int errno);
void pal_svsm_exit(int exitcode);
void pal_svsm_debug_putc(char c);

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
void pal_svsm_device_window(uint64_t pages, void** out_base, size_t* out_size);
/* DeviceMmio: a device's registers. `id` is vendor | device << 16, 0 only
 * asks what this vault already has. `bar` says which BAR to map, because a
 * modern device does not necessarily keep its registers in BAR0. Returns
 * where they are mapped and the physical address the BAR decodes at. */
void pal_svsm_device_mmio(uint64_t id, uint8_t bar, void** out_base, size_t* out_size,
                          uint64_t* out_phys);
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
int pal_svsm_set_exception_entry(void* entry, uint64_t tcb_alt_stack_offset,
                                 void* preempt_ctl);
/* ExceptionReturn (0x4FFFFFE8): resume from `context`. Does not return -
 * restoring rip, rsp and rflags together is what an iretq is for, and this
 * side of the boundary runs at CPL3 and has none. */
noreturn void pal_svsm_exception_return(PAL_CONTEXT* context);
/* Declare what this vault offers other vaults - the thing that makes it a
 * service. `name` is up to eight ASCII bytes packed little-endian. */
int pal_svsm_service_declare(uint64_t name, uint64_t priority);
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
