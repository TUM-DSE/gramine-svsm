#include "pal_monitor_call.h"

#define vc_injection "cpuid"

void monitor_call(struct monitor_call_data* data){

    __asm__ volatile(
        vc_injection
        : "+a" (data->rax), "+b" (data->rbx),
          "+c" (data->rcx), "+d" (data->rdx)
        );

}


//Forwards the errors in the pal to the monitor
void pal_svsm_fail(const char* err, int errno){
    struct monitor_call_data data;
    data.rax = 0;
    data.rbx = (uint64_t)err;
    data.rcx = errno;
    data.rdx = 0;
    monitor_call(&data);
}
