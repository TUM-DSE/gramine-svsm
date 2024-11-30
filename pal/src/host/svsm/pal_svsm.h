#pragma once

/* PAL main function */
noreturn void pal_svsm_main(void);

typedef struct pal_svsm_tcb {
    PAL_TCB common;
    struct {
        /* private to Linux PAL */
        PAL_HANDLE handle;
        void*      alt_stack;
        int        (*callback)(void*);
        void*      param;
    };
} PAL_SVSM_TCB;
