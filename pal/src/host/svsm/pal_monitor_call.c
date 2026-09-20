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
void pal_svsm_device_mmio(uint64_t id, void** out_base, size_t* out_size, uint64_t* out_phys) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFED;
    data.rbx = id;
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

/* ServiceDeclare (0x4FFFFFEB): rbx = the packed name -> rcx = 0 accepted. */
int pal_svsm_service_declare(uint64_t name) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFEB;
    data.rbx = name;
    data.rcx = 0;
    data.rdx = 0;
    monitor_call(&data);
    return data.rcx == 0 ? 0 : -1;
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
 * -> rcx = 0 accepted. */
int pal_svsm_set_exception_entry(void* entry, uint64_t tcb_alt_stack_offset,
                                 void* preempt_ctl) {
    struct monitor_call_data data;
    data.rax = 0x4FFFFFE9;
    data.rbx = (uint64_t)entry;
    data.rcx = tcb_alt_stack_offset;
    data.rdx = (uint64_t)preempt_ctl;
    monitor_call(&data);
    return data.rcx == 0 ? 0 : -1;
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
