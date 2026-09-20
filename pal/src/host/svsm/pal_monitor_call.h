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
