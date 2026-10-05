#include "pal_monitor_call.h"
#include <string.h>
#define vc_injection "cpuid"

void monitor_call(struct monitor_call_data* data){

    __asm__ volatile(
        vc_injection
        : "+a" (data->rax), "+b" (data->rbx),
          "+c" (data->rcx), "+d" (data->rdx)
        );

}

void extended_monitor_call(struct monitor_call_data* data) {
    // Additional registers are used
    // This only affects the gramine side
    // since the Monitor receives the whole
    // VMSA regardless
    __asm__ volatile(
        "mov %4, %%r8\r\n"
        "mov %5, %%r9\r\n"
        vc_injection
        : "+a" (data->rax), "+b" (data->rbx),
          "+c" (data->rcx), "+d" (data->rdx)
        : "r" (data->r8), "r" (data->r9)
        : "r8", "r9"
        );

}

size_t max_string_length = 100;

//Forwards the errors in the pal to the monitor
void pal_svsm_fail(const char* err, int errno){
    struct monitor_call_data data;
    data.rax = 0x4FFFFFFF;
    data.rbx = (uint64_t)err;
    data.rcx = errno;
    data.rdx = 0;
    monitor_call(&data);
}

void pal_svsm_exit(int exitcode) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFFE;
    data.rbx = exitcode;
    monitor_call(&data);
}

/* RuntimeInfo (0x4FFFFFEF): rbx = image index -> rcx = size in bytes (0 = none),
 * rdx = base VA. The monitor mapped the image at zygote creation; this only asks where. */
void pal_svsm_runtime_info(uint64_t index, void** out_base, size_t* out_size) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEF;
    data.rbx = index;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    *out_size = data.rcx;
    *out_base = (void*)data.rdx;
}

/* LineageFs (0x4FFFFFD4): rbx = data pages wanted (0 = the monitor's default)
 * -> rcx = size in bytes (0 = none), rdx = base VA. Deliberately the same
 * shape as RuntimeInfo and DeviceWindow.
 *
 * Idempotent, and that is the whole mechanism: holding the region IS being in
 * the lineage, so a vault that already holds one is told where rather than
 * given a second. A forked child holds its parent's (the monitor maps it in at
 * fork) and an execve keeps it (the mapping is not a VMA the LibOS can free),
 * so both find the same filesystem by asking the same question. */
void pal_svsm_lineage_fs(uint64_t pages, void** out_base, size_t* out_size) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFD4;
    data.rbx = pages;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    *out_size = data.rcx;
    *out_base = (void*)data.rdx;
}

/* DeviceWindow (0x4FFFFFEE): rbx = pages wanted (0 = only ask) -> rcx = size
 * in bytes (0 = none), rdx = base VA. Deliberately the same shape as
 * RuntimeInfo. The window's first four words are {magic, guest-physical
 * address, size, base VA} written by the monitor, so the physical address a
 * descriptor needs is read from the window itself rather than carried in a
 * third register - and a window whose magic is wrong is not a window. */
void pal_svsm_device_window(uint64_t pages, void** out_base, size_t* out_size) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEE;
    data.rbx = pages;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    *out_size = data.rcx;
    *out_base = (void*)data.rdx;
}

/* DeviceMmio (0x4FFFFFED): rbx = vendor | device << 16 -> rcx = size,
 * rdx = base VA, r8 = physical address. The physical address comes back in
 * a register here, unlike the window's: these are somebody else's registers
 * and there is no header the monitor could have written it into. */
void pal_svsm_device_mmio(uint64_t id, uint8_t bar, void** out_base, size_t* out_size,
                          uint64_t* out_phys) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFED;
    data.rbx = id | ((uint64_t)bar << 32);
    data.rcx = 0;
    data.rdx = 0;
    data.r8  = 0;
    data.r9  = 0;
    extended_monitor_call(&data);
    *out_size = data.rcx;
    *out_base = (void*)data.rdx;
    *out_phys = data.r8;
}

/* DeviceIo (0x4FFFFFEC): rbx = offset, rcx = width, rdx = 1 to write,
 * r8 = value to write -> rcx = value read (all ones = refused). */
uint64_t pal_svsm_device_io(uint64_t offset, uint32_t width, int write, uint64_t value) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEC;
    data.rbx = offset;
    data.rcx = width;
    data.rdx = write ? 1 : 0;
    data.r8  = value;
    data.r9  = 0;
    extended_monitor_call(&data);
    return data.rcx;
}

/* DeviceConfig (0x4FFFFFE7): rbx = offset, rcx = width -> rcx = value. */
uint64_t pal_svsm_device_config(uint32_t offset, uint32_t width) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE7;
    data.rbx = offset;
    data.rcx = width;
    data.rdx = 0;
    monitor_call(&data);
    return data.rcx;
}

/* ServiceDeclare (0x4FFFFFEB): rbx = the packed name, rcx = priority
 * 0..7 (higher is more urgent) -> rcx = 0 accepted. */
int pal_svsm_service_declare(uint64_t name, uint64_t priority) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEB;
    data.rbx = name;
    data.rcx = priority;
    data.rdx = 0;
    monitor_call(&data);
    return data.rcx == 0 ? 0 : -1;
}

/* Delegate (0x4FFFFFDC): rbx = the record, rcx = its length -> rcx = 0,
 * or a negative status. Once, from the zygote: what the apps on this base
 * image may claim in their frames. */
int64_t pal_svsm_delegate(const void* record, uint64_t len) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFDC;
    data.rbx = (uint64_t)record;
    data.rcx = len;
    data.rdx = 0;
    monitor_call(&data);
    return (int64_t)data.rcx;
}

/* InferenceDeclare (0x4FFFFFDD): rbx = 1 to take the inference scratch
 * -> rcx = 0 accepted. From the ZYGOTE only: the scratch has to exist
 * before any application code runs, because the inference client writes
 * the context page before it calls REGISTER. */
int pal_svsm_inference_declare(uint64_t want) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFDD;
    data.rbx = want;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    return data.rcx == 0 ? 0 : -1;
}

/* JitDeclare (0x4FFFFFDB): rbx = 1 to ask for pages that may be writable
 * and executable at once -> rcx = 0 accepted. From the ZYGOTE only, like
 * the two above: a permission a vault could grant itself at run time
 * would be one its attestation never saw. Every vault gets executable
 * memory without this; what this permits is W and X at the same moment,
 * which is what a compiler needs and nothing else does. */
int pal_svsm_jit_declare(uint64_t want) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFDB;
    data.rbx = want;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    return data.rcx == 0 ? 0 : -1;
}

/* ChannelPolicy (0x4FFFFFE0): rbx = the record, rcx = its length.
 * -> rcx = 0, or a negative status. Once per lineage, from the zygote. */
int64_t pal_svsm_channel_policy(const void* record, uint64_t len) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE0;
    data.rbx = (uint64_t)record;
    data.rcx = len;
    data.rdx = 0;
    monitor_call(&data);
    return (int64_t)data.rcx;
}

/* ChannelGrant (0x4FFFFFE5): rbx = the request, rcx = its length
 * -> rcx = this vault's window for the new channel, or a negative status;
 * rdx = the window's address, so the caller needs no constant. */
int64_t pal_svsm_channel_grant(const void* request, uint64_t len, uint64_t* out_addr) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE5;
    data.rbx = (uint64_t)request;
    data.rcx = len;
    data.rdx = 0;
    monitor_call(&data);
    if (out_addr)
        *out_addr = data.rdx;
    return (int64_t)data.rcx;
}

/* ChannelClose (0x4FFFFFE3): rbx = the window. */
int64_t pal_svsm_channel_close(uint64_t window) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE3;
    data.rbx = window;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    return (int64_t)data.rcx;
}

/* Notify (0x4FFFFFE2): rbx = the window -> rcx = holders told. */
int64_t pal_svsm_channel_notify(uint64_t window) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE2;
    data.rbx = window;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    return (int64_t)data.rcx;
}

/* Park (0x4FFFFFE1): rbx = an array of arm words, rcx = how many, rdx =
 * microseconds -> rcx = why it was woken. An arm word is
 * `expected:32 | which:4 | window:28`; which 0 is the peer's tail ("until
 * there is something to read"), 1 its head ("until there is room"). */
int64_t pal_svsm_park(const uint64_t* arms, uint64_t count, uint64_t usec) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE1;
    data.rbx = (uint64_t)arms;
    data.rcx = count;
    data.rdx = usec;
    monitor_call(&data);
    return (int64_t)data.rcx;
}

/* TimeInfo (0x4FFFFFEA): -> rcx = TSC ticks per second, rdx = microseconds
 * from the epoch to this VM's zero, or 0 if unknown. */
void pal_svsm_time_info(uint64_t* out_tsc_hz, uint64_t* out_epoch_us) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEA;
    data.rbx = 0;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    *out_tsc_hz   = data.rcx;
    *out_epoch_us = data.rdx;
}

/* Sleep (0x4FFFFFDE): rbx = microseconds -> rcx = 0 once woken, or a
 * negative status meaning the monitor will not park this vault (a host
 * invoke is on the stack, and a park would end it). The caller then waits
 * the way it always did.
 *
 * This is what a cooperative scheduler with nothing runnable should do:
 * one dispatch instead of a processor held for the whole wait. */
long pal_svsm_sleep_arms(const uint64_t* arms, uint64_t count, uint64_t usec) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFDE;
    data.rbx = (uint64_t)arms;
    data.rcx = count;
    data.rdx = usec;
    monitor_call(&data);
    return (long)data.rcx;
}

long pal_svsm_sleep(uint64_t usec) {
    return pal_svsm_sleep_arms(NULL, 0, usec);
}

/* Nop (0x4FFFFFF5): costs one exit and does nothing, which is the point. */
void pal_svsm_nop(void) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFF5;
    data.rbx = 0;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
}

/* SetExceptionEntry (0x4FFFFFE9): rbx = the entry, rcx = where in the TCB
 * the alternate stack is described, rdx = the preempt control block
 * -> rcx = what the monitor can do for this vault (PAL_SVSM_CAP_*).
 *
 * It answered a bare 0 until 2026-09-27 and this returned an error for
 * anything else, which is why the answer is a BITMAP and not a version:
 * a vault built before a capability existed sees 0 for it and keeps the
 * path it always had. */
uint64_t pal_svsm_set_exception_entry(void* entry, uint64_t tcb_alt_stack_offset,
                                      void* preempt_ctl) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE9;
    data.rbx = (uint64_t)entry;
    data.rcx = tcb_alt_stack_offset;
    data.rdx = (uint64_t)preempt_ctl;
    monitor_call(&data);
    return data.rcx;
}

/* ExceptionReturn (0x4FFFFFE8): rbx = the context. The monitor overwrites
 * this process's registers from it, so nothing after the call runs. */
noreturn void pal_svsm_exception_return(PAL_CONTEXT* context) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE8;
    data.rbx = (uint64_t)context;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    /* The monitor refused, which it only does when it could not read the
     * context back - there is nothing to resume to. */
    pal_svsm_fail("exception return did not resume", 0);
    die_or_inf_loop();
}

void pal_svsm_debug_putc(char c){
    struct monitor_call_data data;
    data.rax = 0x4FFFFFFD;
    data.rbx = c;
    data.rcx = 0;
    monitor_call(&data);
}


int pal_svsm_virt_alloc(void* addr, uint64_t size, pal_prot_flags_t flags){
    struct monitor_call_data data;
    data.rax = 0x4FFFFFFC;
    data.rbx = (uint64_t)addr;
    data.rcx = size;
    data.rdx = flags;

    monitor_call(&data);

    return data.rcx;
}

int pal_svsm_free(void* addr, uint64_t size) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFF6;
    data.rbx = (uint64_t)addr;
    data.rcx = size;

    monitor_call(&data);

    return data.rcx;
}

void* pal_svsm_mmap(void* addr, size_t size, int prot, int flags, int fd, size_t offset){
    struct monitor_call_data data;
    data.rax = 0x4FFFFFFB;
    data.rbx = (uint64_t)addr;
    data.rcx = size;
    data.rdx = flags;
    data.r8 = (uint64_t)(int64_t)fd;
    data.r9 = offset;

    extended_monitor_call(&data);

    if (data.rcx == 0)
        return addr;

    return NULL;
}

int pal_svsm_set_tcb(PAL_TCB* tcb) {
  struct monitor_call_data data;
  data.rax = 0x4FFFFFFA;
  data.rbx = (uint64_t)tcb;

  monitor_call(&data);

  return 0;
}

int pal_svsm_mprotect(void* addr, uint64_t size, pal_prot_flags_t flags){
    struct monitor_call_data data;
    data.rax = 0x4FFFFFF9;
    data.rbx = (uint64_t)addr;
    data.rcx = size;
    data.rdx = flags;

    monitor_call(&data);

    return data.rcx;
}

int pal_svsm_guest_request(pal_svsm_guest_request_type_t type, void *arg, size_t size) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFF7;
    data.rbx = (int)type;
    data.rcx = (uint64_t)arg;
    data.rdx = size;
    monitor_call(&data);
    return data.rcx;
}
