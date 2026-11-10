/* Auto-peering, the PAL's half, phase 1 (notes/net/AUTO-PEER.md §10.1, A3):
 * JOIN, the one small channel to the address service (ChannelGrant selector
 * 5), HELLO and the LEASE with a bounded wait, the generation-tagged lookup
 * cache, and the resolv.conf / hostname fill. See pal_svsm_auto.h.
 *
 * The service is never trusted for identity: what it says is a name
 * (§3.3). It is trusted for nothing the monitor does not check again - and
 * in phase 1 nothing is granted on its word at all.
 *
 * WHEN (owner, 2026-11-10): IMMEDIATELY by default. Every clone, on its first
 * entry after Finalize and before any app code, JOINs and holds its lease:
 * the runtime's finalize wrapper writes /dev/mvlease (services/common/include/
 * mv_first_entry.h), the LibOS calls auto_first_entry, and ensure() runs with
 * the bounded wait (Q18: up to PAL_SVSM_IPAM_WAIT_US, then the app starts
 * without an address and new binds fail closed). A fork child takes its own
 * lease in the PAL's fork return, before its code. `[svsm.auto] join = "lazy"`
 * (measured) opts out: the lease is then taken on the first use (uname or
 * gethostname, a query to the stub, the emulated resolv.conf once mounted).
 * Either way the LibOS mounts the emulated /etc/resolv.conf once a lease is
 * held (dns_host_leased) - at the first entry when immediate - and a vault in
 * no deployment keeps the resolver and hostname it had.
 *
 * States of THIS instance (a zygote never leaves UNTRIED: its JOIN answers
 * BAD_STATE, and nothing is cached; a zygote never reaches a first entry):
 *   UNTRIED  nothing asked yet
 *   OFF      not in a deployment, auto-peering opted out, or a monitor
 *            without AutoNet: the vault's resolver and hostname stay as they
 *            were
 *   JOINED   a member; no lease yet (no service, or it did not answer):
 *            tried again at most once a second
 *   LEASED   a lease; if the service channel goes (a restart), it is
 *            granted again and HELLO re-sent with the address as a claim */
#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"
#include "toml_utils.h"

#include "pal_monitor_call.h"
#include "pal_svsm.h"
#include "pal_svsm_auto.h"
#include "pal_svsm_chan.h"
#include "pal_svsm_ipam.h"

enum { A_UNTRIED, A_OFF, A_JOINED, A_LEASED };

static bool g_enabled = true;
static bool g_lazy;                      /* [svsm.auto] join = "lazy" */
static int g_state = A_UNTRIED;
static uint32_t g_upstream;              /* [svsm.dns] nameserver, host order */
static uint16_t g_upstream_port = PAL_SVSM_DNS_PORT;
static unsigned long g_win;              /* the service channel's window, 0 = none */
static struct pal_chan_ring g_tx, g_rx;
static struct pal_svsm_lease g_lease;
static uint32_t g_gen;                   /* the newest generation seen */
static uint32_t g_reqid;
static uint64_t g_retry_us;
static spinlock_t g_lock = INIT_SPINLOCK_UNLOCKED;

#define CACHE_N 32
struct cache_e {
    bool used;
    uint32_t gen;
    int status;
    int n;
    uint32_t addrs[MVA_ADDRS_MAX];
    char name[MVA_NAME_MAX];
};
static struct cache_e g_cache[CACHE_N];
static unsigned g_cache_next;

uint32_t pal_svsm_auto_upstream(void) {
    return g_upstream;
}

uint16_t pal_svsm_auto_upstream_port(void) {
    return g_upstream_port;
}

const struct pal_svsm_lease* pal_svsm_auto_lease(void) {
    return g_state == A_LEASED ? &g_lease : NULL;
}

bool pal_svsm_auto_in_space(uint32_t ip) {
    if (g_state != A_LEASED || !g_lease.prefix)
        return false;
    uint32_t mask = ~0u << (32 - g_lease.prefix);
    return (ip & mask) == (g_lease.subnet & mask);
}

void pal_svsm_auto_config(toml_table_t* svsm) {
    toml_table_t* a = svsm ? toml_table_in(svsm, "auto") : NULL;
    if (a) {
        bool on = true;
        if (toml_bool_in(a, "enabled", true, &on) < 0)
            pal_svsm_fail("svsm.auto.enabled is not a boolean", 0);
        g_enabled = on;
        /* Where the upstream resolver listens: 53 unless a test stands one
         * up elsewhere (host_auto's auto_dns_forward_rebind). Measured. */
        int64_t port = PAL_SVSM_DNS_PORT;
        if (toml_int_in(a, "dns_upstream_port", PAL_SVSM_DNS_PORT, &port) < 0
                || port < 1 || port > 65535)
            pal_svsm_fail("svsm.auto.dns_upstream_port is not a port", 0);
        g_upstream_port = (uint16_t)port;
        /* When this instance takes its lease: "immediate" (the default) at
         * its first entry after Finalize, "lazy" on first use. Measured. */
        if (toml_table_in(a, "join") || toml_array_in(a, "join"))
            pal_svsm_fail("svsm.auto.join is not a string", 0);
        char* join = NULL;
        if (toml_string_in(a, "join", &join) < 0)
            pal_svsm_fail("svsm.auto.join is not a string", 0);
        if (join) {
            bool lazy = !strcmp(join, "lazy"), immediate = !strcmp(join, "immediate");
            free(join);
            if (!lazy && !immediate)
                pal_svsm_fail("svsm.auto.join must be \"immediate\" or \"lazy\"", 0);
            g_lazy = lazy;
        }
    }
    if (!g_enabled) {
        g_state = A_OFF;
        return;
    }
    if (g_pal_public_state.dns_host.nsaddr_list_count > 0
            && !g_pal_public_state.dns_host.nsaddr_list[0].is_ipv6)
        g_upstream = g_pal_public_state.dns_host.nsaddr_list[0].ipv4;
    /* The emulated /etc/resolv.conf is NOT mounted for this (only [svsm.dns]
     * mounts it at init): the LibOS mounts it once dns_host_leased says a
     * lease filled it, so a vault that never leases keeps its own file. */
    g_pal_public_state.refresh_dns_host = pal_svsm_auto_refresh;
    g_pal_public_state.auto_first_entry = pal_svsm_auto_first_entry;
    g_pal_public_state.auto_lease_text = pal_svsm_auto_lease_text;
}

static void cache_clear(void) {
    for (int i = 0; i < CACHE_N; i++)
        g_cache[i].used = false;
}

static void forget_channel(void) {
    if (g_win)
        pal_svsm_channel_close(g_win);
    g_win = 0;
    memset(&g_tx, 0, sizeof g_tx);
    memset(&g_rx, 0, sizeof g_rx);
}

void pal_svsm_auto_after_fork(void) {
    /* The parent's service channel was shared into this child with its
     * other channels (fork_share): the child's own copy goes, and it joins
     * as the instance it is - its own lease, its own address. */
    if (g_state == A_OFF && !g_enabled)
        return;
    if (g_win)
        pal_svsm_channel_close(g_win);
    g_win = 0;
    memset(&g_tx, 0, sizeof g_tx);
    memset(&g_rx, 0, sizeof g_rx);
    g_state = A_UNTRIED;
    g_retry_us = 0;
    cache_clear();
    /* The child's first code is the return of this fork: immediate means its
     * own lease before it (bounded, as at a clone's first entry). */
    if (g_enabled && !g_lazy)
        (void)pal_svsm_auto_ensure();
}

static bool channel_alive(void) {
    return g_win && !pal_chan_peer_gone(pal_chan_window_addr(g_win), 0);
}

/* Messages the service sends unasked: GEN (drop older answers) and REVOKE
 * (the lease is gone). */
static void absorb(const uint8_t* m, uint32_t n) {
    struct mva_hdr h;
    if (n < sizeof h)
        return;
    memcpy(&h, m, sizeof h);
    if (h.magic != MVA_MAGIC)
        return;
    if ((int32_t)(h.gen - g_gen) > 0)
        g_gen = h.gen;
    if (h.type == MVA_REVOKE && g_state == A_LEASED) {
        log_warning("auto: the address service revoked this vault's lease");
        g_state = A_JOINED;
        g_retry_us = pal_svsm_now_usec() + 1000000;
        cache_clear();
    }
}

/* One ring slot: a message larger than what is expected must still be
 * taken off the ring, or it would block everything behind it. Under g_lock. */
static uint8_t g_msg[4096];

static void drain(void) {
    uint8_t* buf = g_msg;
    uint32_t n;
    for (int k = 0; k < 64 && g_win && pal_chan_recv(&g_rx, buf, sizeof g_msg, &n) == 0; k++)
        absorb(buf, n);
}

/* Wait (bounded) for the reply of type `type` to request `id`, absorbing
 * whatever else comes. Sleeps on the ring when the monitor lets this vault
 * sleep, spins when it does not (inside a host invoke). */
static bool await(uint16_t type, uint32_t id, void* out, uint32_t outlen, uint64_t until_us) {
    uint8_t* buf = g_msg;
    for (;;) {
        uint32_t n;
        while (g_win && pal_chan_recv(&g_rx, buf, sizeof g_msg, &n) == 0) {
            struct mva_hdr h;
            if (n >= sizeof h) {
                memcpy(&h, buf, sizeof h);
                if (h.magic == MVA_MAGIC && h.type == type && h.id == id && n >= outlen) {
                    memcpy(out, buf, outlen);
                    if ((int32_t)(h.gen - g_gen) > 0)
                        g_gen = h.gen;
                    return true;
                }
            }
            absorb(buf, n);
        }
        if (!channel_alive() || pal_svsm_now_usec() >= until_us)
            return false;
        uint64_t arm = pal_chan_arm(g_win, PAL_CHAN_ARM_TAIL, *g_rx.peer_tail);
        if (pal_chan_readable(&g_rx))
            continue;
        if (pal_svsm_sleep_arms(&arm, 1, 1000) < 0) {
            for (int i = 0; i < 2000 && !pal_chan_readable(&g_rx); i++)
                __asm__ volatile("pause");
        }
    }
}

static bool send_req(const void* m, uint32_t n) {
    if (!channel_alive() || pal_chan_send(&g_tx, m, n) != 0)
        return false;
    pal_svsm_channel_notify(g_win);
    return true;
}

static int64_t autonet(uint64_t sub, uint64_t rcx, uint64_t rdx, uint64_t* out_rdx,
                       uint64_t* out_r8, uint64_t* out_r9) {
    struct monitor_call_data d = { .rax = MVA_AUTONET_CALL, .rbx = sub, .rcx = rcx, .rdx = rdx,
                                   .r8 = 0, .r9 = 0 };
    extended_monitor_call(&d);
    if (out_rdx) *out_rdx = d.rdx;
    if (out_r8)  *out_r8 = d.r8;
    if (out_r9)  *out_r9 = d.r9;
    return (int64_t)d.rcx;
}

static bool open_channel(void) {
    struct {
        uint32_t magic;
        uint8_t selector, dir, pad[2];
        uint64_t endpoint;
        uint8_t name[32];
        uint8_t vault_id[64];
        uint32_t inst_pid;
    } __attribute__((packed)) g;
    memset(&g, 0, sizeof g);
    memcpy(&g.magic, "MVG1", 4);
    g.selector = MVA_SELECTOR_SERVICE;
    uint64_t addr = 0;
    int64_t w = pal_svsm_channel_grant(&g, sizeof g, &addr);
    if (w <= 0)
        return false;
    g_win = (unsigned long)w;
    unsigned long base = pal_chan_window_addr(g_win);
    pal_chan_ring_init(&g_tx, base, 0, 1);
    pal_chan_ring_init(&g_rx, base, 0, 0);
    return true;
}

static void apply_lease(const struct mva_lease* l) {
    g_lease.addr = l->addr;
    g_lease.subnet = l->subnet;
    g_lease.prefix = l->prefix;
    g_lease.open = l->open;
    g_lease.stub = l->stub;
    memcpy(g_lease.domain, l->domain, sizeof g_lease.domain);
    g_lease.domain[sizeof g_lease.domain - 1] = '\0';
    memcpy(g_lease.hostname, l->hostname, sizeof g_lease.hostname);
    g_lease.hostname[sizeof g_lease.hostname - 1] = '\0';
    /* resolv.conf: the stub, and the deployment's domain to search. */
    struct pal_dns_host_conf* dh = &g_pal_public_state.dns_host;
    dh->nsaddr_list[0].is_ipv6 = false;
    dh->nsaddr_list[0].ipv4 = PAL_SVSM_DNS_STUB;
    dh->nsaddr_list_count = 1;
    size_t dl = strlen(g_lease.domain);
    if (dl && dl < PAL_HOSTNAME_MAX) {
        memcpy(dh->dn_search[0], g_lease.domain, dl + 1);
        dh->dn_search_count = 1;
    }
    size_t hl = strlen(g_lease.hostname);
    if (hl && hl < PAL_HOSTNAME_MAX)
        memcpy(dh->hostname, g_lease.hostname, hl + 1);
    g_pal_public_state.dns_host_leased = true;
}

/* HELLO and its LEASE. `claim` is the address held before a service restart. */
static bool hello(uint32_t claim) {
    struct mva_hello h;
    memset(&h, 0, sizeof h);
    h.h.magic = MVA_MAGIC;
    h.h.type = MVA_HELLO;
    h.h.len = sizeof h - sizeof h.h;
    h.h.id = ++g_reqid;
    h.h.gen = g_gen;
    h.explicit_addr = (uint32_t)g_pal_svsm_self_addr[0] << 24 | (uint32_t)g_pal_svsm_self_addr[1] << 16
                      | (uint32_t)g_pal_svsm_self_addr[2] << 8 | g_pal_svsm_self_addr[3];
    h.claim_addr = claim;
    h.flags = claim ? MVA_HELLO_RECLAIM : 0;
    if (!send_req(&h, sizeof h))
        return false;
    struct mva_lease l;
    if (!await(MVA_LEASE, h.h.id, &l, sizeof l, pal_svsm_now_usec() + PAL_SVSM_IPAM_WAIT_US))
        return false;
    if (l.status != MVA_OK) {
        /* An explicit address that someone else holds (explicit means
         * exact), or no room: fail closed - no lease, no names. */
        log_warning("auto: the address service refused a lease (status %d)", l.status);
        return false;
    }
    apply_lease(&l);
    cache_clear();
    return true;
}

static bool ensure_locked(void) {
    if (!g_enabled || g_state == A_OFF)
        return false;
    uint64_t now = pal_svsm_now_usec();
    if (g_state == A_LEASED) {
        if (channel_alive()) {
            drain();
            return g_state == A_LEASED;
        }
        /* The service went (a restart): existing leases go on; the channel
         * is granted again and the address claimed, as DHCP's INIT-REBOOT. */
        if (now >= g_retry_us) {
            forget_channel();
            g_retry_us = now + 1000000;
            if (open_channel())
                hello(g_lease.addr);
        }
        return true;
    }
    if (g_state == A_JOINED && now < g_retry_us)
        return false;
    if (g_state == A_UNTRIED) {
        uint8_t rec[16] = { 'M', 'V', 'A', 'E' };   /* default geometry and cap */
        uint64_t flags = 0;
        int64_t rc = autonet(MVA_SUB_JOIN, (uint64_t)rec, sizeof rec, &flags, NULL, NULL);
        if (rc == PAL_SVSM_STATUS_BAD_STATE)
            return false;                 /* the zygote: its clones join */
        if (rc < 0 || !(flags & 1)) {
            g_state = A_OFF;              /* no deployment, or no AutoNet */
            return false;
        }
        g_state = A_JOINED;
    }
    g_retry_us = now + 1000000;
    if (!channel_alive()) {
        forget_channel();
        if (!open_channel())
            return false;                 /* no service attached (yet) */
    }
    if (!hello(0))
        return false;
    g_state = A_LEASED;
    return true;
}

bool pal_svsm_auto_ensure(void) {
    if (!g_enabled)
        return false;
    spinlock_lock(&g_lock);
    bool ok = ensure_locked();
    spinlock_unlock(&g_lock);
    return ok;
}

void pal_svsm_auto_refresh(void) {
    (void)pal_svsm_auto_ensure();
}

void pal_svsm_auto_first_entry(void) {
    if (g_enabled && !g_lazy)
        (void)pal_svsm_auto_ensure();
}

static size_t put_ip(char* o, size_t cap, uint32_t a) {
    size_t n = 0;
    for (int i = 3; i >= 0 && n + 4 < cap; i--) {
        unsigned v = (a >> (8 * i)) & 0xFF;
        if (v >= 100) o[n++] = (char)('0' + v / 100);
        if (v >= 10) o[n++] = (char)('0' + v / 10 % 10);
        o[n++] = (char)('0' + v % 10);
        if (i) o[n++] = '.';
    }
    return n;
}

static size_t put_str(char* o, size_t cap, const char* s) {
    size_t n = 0;
    while (s[n] && n + 1 < cap) {
        o[n] = s[n];
        n++;
    }
    return n;
}

/* "lease addr A.B.C.D host H domain D join immediate|lazy\n", or "lease none
 * state untried|off|joined join ...\n". Never joins: what the instance holds
 * NOW (the lane's auto_ipam_lease_before_app reads it as the app's first act). */
size_t pal_svsm_auto_lease_text(char* buf, size_t cap) {
    if (!cap)
        return 0;
    spinlock_lock(&g_lock);
    size_t n = put_str(buf, cap, "lease ");
    if (g_state == A_LEASED) {
        n += put_str(buf + n, cap - n, "addr ");
        n += put_ip(buf + n, cap - n, g_lease.addr);
        n += put_str(buf + n, cap - n, " host ");
        n += put_str(buf + n, cap - n, g_lease.hostname[0] ? g_lease.hostname : "-");
        n += put_str(buf + n, cap - n, " domain ");
        n += put_str(buf + n, cap - n, g_lease.domain[0] ? g_lease.domain : "-");
    } else {
        n += put_str(buf + n, cap - n, "none state ");
        n += put_str(buf + n, cap - n, g_state == A_OFF ? "off" : g_state == A_JOINED ? "joined"
                                                         : "untried");
    }
    n += put_str(buf + n, cap - n, g_lazy ? " join lazy\n" : " join immediate\n");
    spinlock_unlock(&g_lock);
    buf[n < cap ? n : cap - 1] = '\0';
    return n;
}

static int map_status(int32_t s) {
    return s == MVA_OK ? 0 : s == MVA_NXDOMAIN ? 1 : 2;
}

int pal_svsm_auto_resolve(const char* name, uint32_t* out, int max, int* out_n) {
    *out_n = 0;
    if (!pal_svsm_auto_ensure())
        return 2;
    spinlock_lock(&g_lock);
    drain();
    for (int i = 0; i < CACHE_N; i++) {
        struct cache_e* e = &g_cache[i];
        if (e->used && e->gen == g_gen && !strcmp(e->name, name)) {
            int n = e->n < max ? e->n : max;
            memcpy(out, e->addrs, (size_t)n * sizeof(uint32_t));
            *out_n = n;
            int st = e->status;
            spinlock_unlock(&g_lock);
            return st;
        }
    }
    struct mva_name q;
    memset(&q, 0, sizeof q);
    q.h.magic = MVA_MAGIC;
    q.h.type = MVA_RESOLVE_NAME;
    q.h.len = sizeof q - sizeof q.h;
    q.h.id = ++g_reqid;
    q.h.gen = g_gen;
    size_t nl = strlen(name);
    if (nl >= sizeof q.name) {
        spinlock_unlock(&g_lock);
        return 1;
    }
    memcpy(q.name, name, nl + 1);
    struct mva_answer an;
    if (!send_req(&q, sizeof q)
        || !await(MVA_ANSWER, q.h.id, &an, sizeof an, pal_svsm_now_usec() + PAL_SVSM_IPAM_WAIT_US)) {
        spinlock_unlock(&g_lock);
        return 2;                         /* the service down: SERVFAIL (§3.2) */
    }
    int st = map_status(an.status);
    int n = (int)(an.n < MVA_ADDRS_MAX ? an.n : MVA_ADDRS_MAX);
    if (an.status != MVA_RATE) {
        struct cache_e* e = &g_cache[g_cache_next++ % CACHE_N];
        e->used = true;
        e->gen = an.h.gen;
        e->status = st;
        e->n = n;
        memcpy(e->addrs, an.addrs, sizeof e->addrs);
        memcpy(e->name, name, nl + 1);
    }
    n = n < max ? n : max;
    memcpy(out, an.addrs, (size_t)n * sizeof(uint32_t));
    *out_n = n;
    spinlock_unlock(&g_lock);
    return st;
}

int pal_svsm_auto_reverse(uint32_t ip, char* out, size_t outlen) {
    if (!pal_svsm_auto_ensure())
        return 2;
    spinlock_lock(&g_lock);
    struct mva_addr q;
    memset(&q, 0, sizeof q);
    q.h.magic = MVA_MAGIC;
    q.h.type = MVA_REVERSE_ADDR;
    q.h.len = sizeof q - sizeof q.h;
    q.h.id = ++g_reqid;
    q.addr = ip;
    struct mva_answer an;
    bool ok = send_req(&q, sizeof q)
              && await(MVA_ANSWER, q.h.id, &an, sizeof an,
                       pal_svsm_now_usec() + PAL_SVSM_IPAM_WAIT_US);
    spinlock_unlock(&g_lock);
    if (!ok)
        return 2;
    if (an.status == MVA_OK && outlen) {
        an.name[MVA_NAME_MAX - 1] = '\0';
        size_t n = strlen(an.name);
        if (n >= outlen)
            n = outlen - 1;
        memcpy(out, an.name, n);
        out[n] = '\0';
    }
    return map_status(an.status);
}
