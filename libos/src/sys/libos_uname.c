/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls `uname`, `sethostname` and `setdomainname`.
 */

#include "api.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "linux_abi/errors.h"
#include "linux_abi/sysinfo.h"

/* This structure is *not* shared between Gramine processes, despite it should. As a result,
 * effects of set{host,domain}name in process A will not be visible in process B.
 * These syscalls are rarely used and are implemented in Gramine mainly to enable LTP to test
 * our `uname` implementation. */
static struct linux_new_utsname g_current_uname = {
    .sysname  = "Linux",
    .nodename = "(none)", /* overwritten by PAL-provided value at startup */
    .release  = "3.10.0",
    .version  = "1",
#ifdef __x86_64__
    .machine  = "x86_64",
#else
#error "Not implemented"
#endif
    .domainname = "(none)", /* this seems to be the default on Linux */
};

/* Set by sethostname: from then on the app's name, not the PAL's. */
static bool g_hostname_by_app;

long libos_syscall_uname(struct linux_new_utsname* buf) {
    if (!is_user_memory_writable(buf, sizeof(*buf)))
        return -EFAULT;

    /* A PAL that learns the hostname after init (svsm auto-peering, in the
     * clone that runs the app) is followed until the app names itself. */
    if (g_pal_public_state->refresh_dns_host && !g_hostname_by_app) {
        g_pal_public_state->refresh_dns_host();
        const char* h = g_pal_public_state->dns_host.hostname;
        size_t n = strnlen(h, sizeof(g_pal_public_state->dns_host.hostname));
        if (n && n < sizeof(g_current_uname.nodename) && strcmp(h, g_current_uname.nodename))
            set_hostname(h, n);
    }

    memcpy(buf, &g_current_uname, sizeof(g_current_uname));
    return 0;
}

int set_hostname(const char* name, size_t len) {
    if (len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    memcpy(&g_current_uname.nodename, name, len);
    memset(&g_current_uname.nodename[len], 0, sizeof(g_current_uname.nodename) - len);

    return 0;
}

long libos_syscall_sethostname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    if (!is_user_memory_readable(name, len))
        return -EFAULT;

    g_hostname_by_app = true;
    return set_hostname(name, len);
}

long libos_syscall_setdomainname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.domainname))
        return -EINVAL;

    if (!is_user_memory_readable(name, len))
        return -EFAULT;

    memcpy(&g_current_uname.domainname, name, len);
    memset(&g_current_uname.domainname[len], 0, sizeof(g_current_uname.domainname) - len);
    return 0;
}
