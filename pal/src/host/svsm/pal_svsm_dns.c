/* The DNS stub of auto-peering, phase 1 (notes/net/AUTO-PEER.md §10.1, A3).
 *
 * A vault in a deployment has the stub as its only nameserver (its
 * /etc/resolv.conf, filled from the lease: pal_svsm_ipam.c). The stub sits in
 * this PAL's datagram path (pal_sockets.c's hooks) and answers on the spot:
 *
 *   - deployment names - a single label, or anything under .mv.internal -
 *     and PTR queries for the deployment's space: from the address service,
 *     through the generation-tagged cache. A for the addresses, an empty
 *     NOERROR for AAAA (no IPv6), NXDOMAIN for a name it does not know,
 *     SERVFAIL when the service cannot be asked (down, timed out, rate);
 *   - everything else is FORWARDED through [svsm.net] to the resolver
 *     [svsm.dns] names (never through the address service, which so never
 *     learns an external name, Q20), and the answer is shown as the stub's.
 *     An outside answer that points into the deployment's subnet is turned
 *     into SERVFAIL: the rebinding drop (§8). No [svsm.net] or no resolver:
 *     SERVFAIL.
 *
 * TCP to the stub is refused (ECONNREFUSED): every answer here fits a
 * datagram. The pure message code at the top is host-tested
 * (test/dns_test.c compiles this file with PAL_DNS_HOSTTEST). */
#ifndef PAL_DNS_HOSTTEST
#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "socket_utils.h"
#include "spinlock.h"

#include "pal_svsm.h"
#include "pal_svsm_auto.h"
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
struct pal_dns_q {
    uint16_t id, flags, qtype, qclass;
    char name[256];
    size_t qend;
};
#endif

#define DNS_HDR 12
#define T_A     1
#define T_PTR   12
#define T_AAAA  28
#define RC_OK       0
#define RC_SERVFAIL 2
#define RC_NXDOMAIN 3
#define DNS_TTL 5             /* seconds: the PAL's cache is what lasts */

static uint16_t be16(const uint8_t* p) { return (uint16_t)(p[0] << 8 | p[1]); }
static void put16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

int pal_dns_parse_query(const uint8_t* m, size_t n, struct pal_dns_q* q) {
    if (n < DNS_HDR + 5)
        return -1;
    q->id = be16(m);
    q->flags = be16(m + 2);
    if ((q->flags & 0x8000) || ((q->flags >> 11) & 0xF) != 0 || be16(m + 4) != 1)
        return -1;                        /* a response, not QUERY, or not one question */
    size_t o = DNS_HDR, w = 0;
    for (;;) {
        if (o >= n)
            return -1;
        uint8_t l = m[o++];
        if (l == 0)
            break;
        if (l > 63 || o + l > n || w + l + 1 >= sizeof q->name)
            return -1;                    /* no compression in a question */
        if (w)
            q->name[w++] = '.';
        for (uint8_t k = 0; k < l; k++) {
            char c = (char)m[o + k];
            q->name[w++] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
        }
        o += l;
    }
    q->name[w] = '\0';
    if (o + 4 > n)
        return -1;
    q->qtype = be16(m + o);
    q->qclass = be16(m + o + 2);
    q->qend = o + 4;
    return 0;
}

/* `name` as DNS labels into out; its length, 0 if it does not fit. */
static size_t encode_name(const char* name, uint8_t* out, size_t cap) {
    size_t o = 0;
    const char* p = name;
    while (*p) {
        const char* dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63 || o + l + 2 > cap)
            return 0;
        out[o++] = (uint8_t)l;
        memcpy(out + o, p, l);
        o += l;
        p += l;
        if (*p == '.')
            p++;
    }
    if (o + 1 > cap)
        return 0;
    out[o++] = 0;
    return o;
}

size_t pal_dns_answer(const uint8_t* m, const struct pal_dns_q* q, int rcode,
                      const uint32_t* a, int na, const char* ptr, uint8_t* out, size_t cap) {
    if (q->qend > cap)
        return 0;
    memcpy(out, m, q->qend);
    /* QR, AA, RA; the opcode and RD as asked; the rcode */
    uint16_t fl = (uint16_t)(0x8000 | 0x0400 | 0x0080 | (q->flags & 0x0100) | (rcode & 0xF));
    put16(out + 2, fl);
    put16(out + 4, 1);
    put16(out + 8, 0);
    put16(out + 10, 0);                   /* the query's EDNS OPT is not echoed */
    size_t o = q->qend;
    int n = 0;
    if (rcode == RC_OK && ptr) {
        uint8_t nm[256];
        size_t nl = encode_name(ptr, nm, sizeof nm);
        if (!nl || o + 12 + nl > cap)
            return 0;
        put16(out + o, 0xC00C); put16(out + o + 2, T_PTR); put16(out + o + 4, 1);
        put32(out + o + 6, DNS_TTL); put16(out + o + 10, (uint16_t)nl);
        memcpy(out + o + 12, nm, nl);
        o += 12 + nl;
        n = 1;
    } else if (rcode == RC_OK) {
        for (int i = 0; i < na; i++) {
            if (o + 16 > cap)
                return 0;
            put16(out + o, 0xC00C); put16(out + o + 2, T_A); put16(out + o + 4, 1);
            put32(out + o + 6, DNS_TTL); put16(out + o + 10, 4);
            put32(out + o + 12, a[i]);
            o += 16;
            n++;
        }
    }
    put16(out + 6, (uint16_t)n);
    return o;
}

/* Past a (possibly compressed) name at o; 0 on a malformed one. */
static size_t skip_name(const uint8_t* m, size_t n, size_t o) {
    for (int guard = 0; guard < 128; guard++) {
        if (o >= n)
            return 0;
        uint8_t l = m[o];
        if (l == 0)
            return o + 1;
        if ((l & 0xC0) == 0xC0)
            return o + 2 <= n ? o + 2 : 0;
        if (l > 63)
            return 0;
        o += 1 + l;
    }
    return 0;
}

bool pal_dns_points_into(const uint8_t* m, size_t n, uint32_t base, uint8_t prefix) {
    if (n < DNS_HDR || prefix == 0 || prefix > 32)
        return false;
    uint32_t mask = prefix == 32 ? ~0u : ~0u << (32 - prefix);
    size_t o = DNS_HDR;
    for (uint16_t i = 0, qd = be16(m + 4); i < qd; i++) {
        o = skip_name(m, n, o);
        if (!o || o + 4 > n)
            return false;
        o += 4;
    }
    /* answers, authority and additional: any A in the space counts */
    uint32_t rr = (uint32_t)be16(m + 6) + be16(m + 8) + be16(m + 10);
    for (uint32_t i = 0; i < rr; i++) {
        o = skip_name(m, n, o);
        if (!o || o + 10 > n)
            return false;
        uint16_t type = be16(m + o), len = be16(m + o + 8);
        o += 10;
        if (o + len > n)
            return false;
        if (type == T_A && len == 4) {
            uint32_t a = (uint32_t)m[o] << 24 | (uint32_t)m[o + 1] << 16 | (uint32_t)m[o + 2] << 8 | m[o + 3];
            if ((a & mask) == (base & mask))
                return true;
        }
        o += len;
    }
    return false;
}

void pal_dns_servfail(uint8_t* m, size_t n) {
    if (n < DNS_HDR)
        return;
    uint16_t fl = be16(m + 2);
    put16(m + 2, (uint16_t)((fl & ~0xFu) | 0x8000 | RC_SERVFAIL));
    put16(m + 6, 0);
    put16(m + 8, 0);
    put16(m + 10, 0);
}

bool pal_dns_ptr_addr(const char* name, uint32_t* out) {
    const char* suf = ".in-addr.arpa";
    size_t n = strlen(name), sl = strlen(suf);
    if (n <= sl || strcmp(name + n - sl, suf))
        return false;
    uint32_t oct[4];
    int k = 0;
    const char* p = name;
    while (p < name + n - sl) {
        if (k == 4 || *p < '0' || *p > '9')
            return false;
        uint32_t v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (uint32_t)(*p - '0');
            if (v > 255)
                return false;
            p++;
        }
        oct[k++] = v;
        if (*p == '.')
            p++;
    }
    if (k != 4)
        return false;
    *out = oct[3] << 24 | oct[2] << 16 | oct[1] << 8 | oct[0];
    return true;
}

#ifndef PAL_DNS_HOSTTEST

/* ---- the stub in the datagram path ---- */

#define STUB_SOCKS 32
#define STUB_Q     4
#define STUB_MSG   512

struct stub_sock {
    PAL_HANDLE h;
    bool connected;               /* connect()ed to the stub */
    bool fwd;                     /* a query was forwarded from this socket */
    uint32_t stub_ip;             /* the stub address it talked to (host order) */
    int nq;
    uint16_t qlen[STUB_Q];
    uint8_t q[STUB_Q][STUB_MSG];
};
static struct stub_sock g_ss[STUB_SOCKS];
static spinlock_t g_ss_lock = INIT_SPINLOCK_UNLOCKED;

static bool is_stub(uint32_t ip) {
    if (ip == PAL_SVSM_DNS_STUB)
        return true;
    const struct pal_svsm_lease* l = pal_svsm_auto_lease();
    return l && l->stub && ip == l->stub;
}

static struct stub_sock* ss_of(PAL_HANDLE h, bool make) {
    struct stub_sock* free_ = NULL;
    for (int i = 0; i < STUB_SOCKS; i++) {
        if (g_ss[i].h == h)
            return &g_ss[i];
        if (!g_ss[i].h && !free_)
            free_ = &g_ss[i];
    }
    if (!make || !free_)
        return NULL;
    memset(free_, 0, sizeof *free_);
    free_->h = h;
    return free_;
}

static bool ours(const struct pal_dns_q* q, uint32_t* ptr_ip) {
    size_t n = strlen(q->name);
    const char* suf = ".mv.internal";
    size_t sl = strlen(suf);
    if (q->qtype == T_PTR && pal_dns_ptr_addr(q->name, ptr_ip))
        return pal_svsm_auto_in_space(*ptr_ip);
    if (!strchr(q->name, '.'))
        return true;                      /* a single label: never forwarded */
    return (n > sl && !strcmp(q->name + n - sl, suf)) || !strcmp(q->name, "mv.internal");
}

/* Answer `m` from the address service into `out`. */
static size_t answer_local(const uint8_t* m, const struct pal_dns_q* q, uint32_t ptr_ip,
                           uint8_t* out, size_t cap) {
    if (q->qtype == T_PTR) {
        char name[128];
        int st = pal_svsm_auto_reverse(ptr_ip, name, sizeof name);
        return pal_dns_answer(m, q, st == 0 ? RC_OK : st == 1 ? RC_NXDOMAIN : RC_SERVFAIL, NULL, 0,
                              st == 0 ? name : NULL, out, cap);
    }
    uint32_t a[8];
    int na = 0;
    /* The service answers the name as asked (bare, or under mv.internal). */
    int st = pal_svsm_auto_resolve(q->name, a, 8, &na);
    int rc = st == 0 ? RC_OK : st == 1 ? RC_NXDOMAIN : RC_SERVFAIL;
    if (rc == RC_OK && q->qtype != T_A)
        na = 0;                           /* AAAA and the rest: the name exists, no records */
    return pal_dns_answer(m, q, rc, a, na, NULL, out, cap);
}

static void queue(struct stub_sock* s, const uint8_t* m, size_t n, uint32_t from) {
    if (s->nq >= STUB_Q || n > STUB_MSG)
        return;                           /* a full stub queue drops, as a full socket does */
    memcpy(s->q[s->nq], m, n);
    s->qlen[s->nq] = (uint16_t)n;
    s->nq++;
    s->stub_ip = from;
}

bool pal_svsm_dns_connect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                          struct pal_socket_addr* out_local, bool* out_inprogress, int* ret) {
    if (!addr || addr->domain != PAL_IPV4)
        return false;
    uint32_t ip = ntohl(addr->ipv4.addr);
    uint16_t port = ntohs(addr->ipv4.port);
    bool stub = port == PAL_SVSM_DNS_PORT && is_stub(ip);
    if (handle->sock.type == PAL_SOCKET_TCP) {
        if (stub && pal_svsm_auto_lease()) {
            *ret = -PAL_ERROR_CONNREFUSED;     /* no TCP DNS: every answer fits a datagram */
            return true;
        }
        return false;
    }
    /* Joined and leased first, outside g_ss_lock: ensure may wait up to
     * PAL_SVSM_IPAM_WAIT_US for the service, and a poll on another thread
     * takes g_ss_lock (pal_svsm_dns_readable). */
    bool for_stub = stub && pal_svsm_auto_ensure();
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    if (!for_stub) {
        if (s)
            s->connected = false;         /* re-pointed elsewhere */
        spinlock_unlock(&g_ss_lock);
        return false;
    }
    s = ss_of(handle, true);
    if (!s) {
        spinlock_unlock(&g_ss_lock);
        *ret = -PAL_ERROR_NOMEM;
        return true;
    }
    s->connected = true;
    s->stub_ip = ip;
    spinlock_unlock(&g_ss_lock);
    put32((uint8_t*)handle->sock.peer_addr, ip);
    handle->sock.peer_port = port;
    handle->sock.has_peer = true;
    if (out_local) {
        memset(out_local, 0, sizeof *out_local);
        out_local->domain = PAL_IPV4;
        const struct pal_svsm_lease* l = pal_svsm_auto_lease();
        out_local->ipv4.addr = htonl(l ? l->addr : 0);
        if (!handle->sock.local.local_port) {
            static uint32_t next;
            handle->sock.local.local_port =
                (uint16_t)(32768 + __atomic_fetch_add(&next, 1, __ATOMIC_RELAXED) % 28232);
        }
        out_local->ipv4.port = htons(handle->sock.local.local_port);
    }
    if (out_inprogress)
        *out_inprogress = false;
    *ret = 0;
    return true;
}

int pal_svsm_dns_send(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                       struct pal_socket_addr* addr, int* ret, struct pal_socket_addr* fwd) {
    uint32_t ip = 0;
    uint16_t port = 0;
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    bool conn = s && s->connected;
    uint32_t conn_ip = s ? s->stub_ip : 0;
    spinlock_unlock(&g_ss_lock);
    if (addr && addr->domain == PAL_IPV4) {
        ip = ntohl(addr->ipv4.addr);
        port = ntohs(addr->ipv4.port);
    } else if (conn) {
        ip = conn_ip;
        port = PAL_SVSM_DNS_PORT;
    } else {
        return 0;
    }
    if (port != PAL_SVSM_DNS_PORT || !is_stub(ip))
        return 0;
    uint8_t m[STUB_MSG];
    size_t n = 0;
    for (size_t i = 0; i < iov_len; i++) {
        if (n + iov[i].iov_len > sizeof m) {
            *ret = -PAL_ERROR_TOOLONG;
            return 1;
        }
        memcpy(m + n, iov[i].iov_base, iov[i].iov_len);
        n += iov[i].iov_len;
    }
    *out_size = n;
    *ret = 0;
    struct pal_dns_q q;
    if (pal_dns_parse_query(m, n, &q) < 0)
        return 1;                         /* not a query: dropped, as a resolver would */
    uint8_t out[STUB_MSG];
    size_t ol = 0;
    uint32_t ptr_ip = 0;
    if (!pal_svsm_auto_ensure()) {
        ol = pal_dns_answer(m, &q, RC_SERVFAIL, NULL, 0, NULL, out, sizeof out);
    } else if (ours(&q, &ptr_ip)) {
        ol = answer_local(m, &q, ptr_ip, out, sizeof out);
    } else if (pal_svsm_auto_upstream() && g_pal_svsm_net_name[0]) {
        spinlock_lock(&g_ss_lock);
        s = ss_of(handle, true);
        if (s) {
            s->fwd = true;
            s->stub_ip = ip;
        }
        spinlock_unlock(&g_ss_lock);
        memset(fwd, 0, sizeof *fwd);
        fwd->domain = PAL_IPV4;
        fwd->ipv4.addr = htonl(pal_svsm_auto_upstream());
        fwd->ipv4.port = htons(pal_svsm_auto_upstream_port());
        return 2;
    } else {
        ol = pal_dns_answer(m, &q, RC_SERVFAIL, NULL, 0, NULL, out, sizeof out);
    }
    if (ol) {
        spinlock_lock(&g_ss_lock);
        s = ss_of(handle, true);
        if (s)
            queue(s, out, ol, ip);
        spinlock_unlock(&g_ss_lock);
    }
    return 1;
}

bool pal_svsm_dns_recv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len,
                       size_t* out_total_size, struct pal_socket_addr* addr, int* ret) {
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    if (!s) {
        spinlock_unlock(&g_ss_lock);
        return false;
    }
    if (!s->nq) {
        bool chanless = handle->sock.win == 0;
        spinlock_unlock(&g_ss_lock);
        if (!chanless)
            return false;                 /* a forwarded answer comes the ordinary way */
        *ret = -PAL_ERROR_TRYAGAIN;
        return true;
    }
    size_t n = s->qlen[0], done = 0;
    for (size_t i = 0; i < iov_len && done < n; i++) {
        size_t take = iov[i].iov_len < n - done ? iov[i].iov_len : n - done;
        memcpy(iov[i].iov_base, s->q[0] + done, take);
        done += take;
    }
    uint32_t from = s->stub_ip;
    for (int k = 1; k < s->nq; k++) {
        memcpy(s->q[k - 1], s->q[k], s->qlen[k]);
        s->qlen[k - 1] = s->qlen[k];
    }
    s->nq--;
    spinlock_unlock(&g_ss_lock);
    *out_total_size = done;
    if (addr) {
        memset(addr, 0, sizeof *addr);
        addr->domain = PAL_IPV4;
        addr->ipv4.addr = htonl(from ? from : PAL_SVSM_DNS_STUB);
        addr->ipv4.port = htons(PAL_SVSM_DNS_PORT);
    }
    *ret = 0;
    return true;
}

void pal_svsm_dns_filter(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t len,
                         struct pal_socket_addr* addr) {
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    bool fwd = s && s->fwd;
    uint32_t stub_ip = s ? s->stub_ip : 0;
    spinlock_unlock(&g_ss_lock);
    if (!fwd)
        return;
    uint32_t up = pal_svsm_auto_upstream();
    if (addr && addr->domain == PAL_IPV4 && ntohl(addr->ipv4.addr) == up
            && ntohs(addr->ipv4.port) == pal_svsm_auto_upstream_port()) {
        addr->ipv4.addr = htonl(stub_ip ? stub_ip : PAL_SVSM_DNS_STUB);
        addr->ipv4.port = htons(PAL_SVSM_DNS_PORT);
    }
    const struct pal_svsm_lease* l = pal_svsm_auto_lease();
    if (l && iov_len >= 1 && len <= iov[0].iov_len
            && pal_dns_points_into(iov[0].iov_base, len, l->subnet, l->prefix)) {
        /* An outside resolver naming a deployment address: never believed. */
        log_warning("auto: dropped an external DNS answer that points into the deployment");
        pal_dns_servfail(iov[0].iov_base, len);
    }
}

bool pal_svsm_dns_readable(PAL_HANDLE handle) {
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    bool r = s && s->nq > 0;
    spinlock_unlock(&g_ss_lock);
    return r;
}

void pal_svsm_dns_close(PAL_HANDLE handle) {
    spinlock_lock(&g_ss_lock);
    struct stub_sock* s = ss_of(handle, false);
    if (s)
        memset(s, 0, sizeof *s);
    spinlock_unlock(&g_ss_lock);
}

#endif /* PAL_DNS_HOSTTEST */
