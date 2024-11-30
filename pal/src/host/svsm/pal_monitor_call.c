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
    data.rax = 0;
    data.rbx = (uint64_t)err;
    data.rcx = errno;
    data.rdx = 0;
    monitor_call(&data);
}

void pal_svsm_exit(int exitcode) {
    struct monitor_call_data data;
    data.rax = 1;
    data.rbx = exitcode;
    monitor_call(&data);
}

void pal_svsm_debug_putc(char c){
    struct monitor_call_data data;
    data.rax = 2;
    data.rbx = c;
    data.rcx = 0;
    monitor_call(&data);
}


int pal_svsm_virt_alloc(void* addr, uint64_t size, pal_prot_flags_t flags){
    struct monitor_call_data data;
    data.rax = 4;
    data.rbx = (uint64_t)addr;
    data.rcx = size;
    data.rdx = flags;

    monitor_call(&data);

    return data.rcx;
}

void* pal_svsm_mmap(void* addr, size_t size, int prot, int flags, int fd, size_t offset){
    struct monitor_call_data data;
    data.rax = 5;
    data.rbx = (uint64_t)addr;
    data.rcx = size;
    data.rdx = flags;
    data.r8 = fd;
    data.r9 = offset;

    extended_monitor_call(&data);

    return (void*)data.rcx;
}

int pal_svsm_set_tcb(PAL_TCB* tcb) {
  struct monitor_call_data data;
  data.rax = 6;
  data.rbx = (uint64_t)tcb;

  monitor_call(&data);

  return 0;
}
