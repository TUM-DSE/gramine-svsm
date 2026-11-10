/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls `uname`, `sethostname` and `setdomainname`.
 */

#include "api.h"
#include "libos_fs.h"
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

    libos_refresh_names(/*first_entry=*/0);

    memcpy(buf, &g_current_uname, sizeof(g_current_uname));
    return 0;
}

/* A PAL that learns its names after init (svsm auto-peering's lease, in the
 * clone that runs the app) is followed: the hostname until the app names
 * itself, and the emulated /etc/resolv.conf mounted once a lease filled it.
 * first_entry (PAL_AUTO_MEMBER): a member clone's first code after Finalize
 * (/dev/mvlease written by the runtime's finalize wrapper) - the PAL leases
 * there unless the manifest says join = "lazy"; 0: any use (uname), which
 * leases if not yet and if this instance may. */
void libos_refresh_names(int first_entry) {
    if (first_entry) {
        if (!g_pal_public_state->auto_first_entry)
            return;
        g_pal_public_state->auto_first_entry(first_entry);
    } else {
        if (!g_pal_public_state->refresh_dns_host)
            return;
        g_pal_public_state->refresh_dns_host();
    }
    if (!g_hostname_by_app) {
        const char* h = g_pal_public_state->dns_host.hostname;
        size_t n = strnlen(h, sizeof(g_pal_public_state->dns_host.hostname));
        if (n && n < sizeof(g_current_uname.nodename) && strcmp(h, g_current_uname.nodename))
            set_hostname(h, n);
    }
    etcfs_mount_late();
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
