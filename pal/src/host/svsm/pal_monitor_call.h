#ifndef PAL_MONITOR_CALL_H_
#define PAL_MONITOR_CALL_H_
#include <stdint.h>

struct monitor_call_data {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

void monitor_call(struct monitor_call_data* data);
void pal_svsm_fail(const char* err, int errno);

#endif // PAL_MONITOR_CALL_H_
