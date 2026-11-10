/* Auto-peering in the svsm PAL, phase 1 (notes/net/AUTO-PEER.md §10.1, A3):
 * JOIN, the service channel to the address service (ChannelGrant selector
 * 5), HELLO and the LEASE with a bounded wait, the generation-tagged lookup
 * cache (pal_svsm_ipam.c), and the DNS stub (pal_svsm_dns.c): the vault's
 * /etc/resolv.conf names the stub, which answers deployment names from the
 * service and forwards the rest through [svsm.net], dropping any outside
 * answer that points into the deployment's subnet.
 *
 * Nothing here runs in the zygote: the monitor answers a zygote's JOIN
 * BAD_STATE and nothing is cached. The clone that runs the app joins at its
 * first entry after Finalize ([svsm.auto] join = "immediate", the default) or
 * on its first use (join = "lazy"). A vault in no deployment, or on a monitor
 * without AutoNet, keeps the resolver and hostname it had. */
#ifndef PAL_SVSM_AUTO_H
#define PAL_SVSM_AUTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pal.h"
#include "toml.h"

/* The stub's address in /etc/resolv.conf: link-local, so it is the same in
 * every deployment and known before the lease (the clone of a zygote that
 * read nothing has to be able to name it). The lease's own stub (.1 of the
 * subnet) is answered too. */
#define PAL_SVSM_DNS_STUB 0xA9FEA9FDu      /* 169.254.169.253 */
#define PAL_SVSM_DNS_PORT 53
/* How long a lookup that misses waits for the service (§3.2). */
#define PAL_SVSM_IPAM_WAIT_US 2000000ul

/* pal_main.c, after [svsm.dns]: [svsm.auto] enabled (default true). */
void pal_svsm_auto_config(toml_table_t* svsm);
/* pal_process.c, in a fork's child: its own instance joins again. */
void pal_svsm_auto_after_fork(void);
/* The LibOS's refresh_dns_host (any use: joins if not yet), auto_first_entry
 * (a clone's first code after Finalize: joins unless join = "lazy") and
 * auto_lease_text (never joins). */
void pal_svsm_auto_refresh(void);
void pal_svsm_auto_first_entry(int what);   /* PAL_AUTO_HOOK / PAL_AUTO_MEMBER */
size_t pal_svsm_auto_lease_text(char* buf, size_t cap);

/* The lease, after pal_svsm_auto_ensure() said true. */
struct pal_svsm_lease {
    uint32_t addr, subnet, stub;
    uint8_t prefix, open;
    char domain[64];
    char hostname[64];
};
/* Join and lease if this instance can (bounded); true when it holds one. */
bool pal_svsm_auto_ensure(void);
const struct pal_svsm_lease* pal_svsm_auto_lease(void);
/* Is `ip` (host order) in this vault's deployment space? */
bool pal_svsm_auto_in_space(uint32_t ip);

/* A name -> up to 8 addresses (host order), from the cache or the service.
 * 0 found, 1 NXDOMAIN, 2 SERVFAIL (no service, timeout, rate). */
int pal_svsm_auto_resolve(const char* name, uint32_t* out, int max, int* out_n);
/* An address -> its name (PTR); same answers. */
int pal_svsm_auto_reverse(uint32_t ip, char* out, size_t outlen);
/* The upstream resolver [svsm.dns] named (host order), 0 = none. */
uint32_t pal_svsm_auto_upstream(void);
/* Its port ([svsm.auto] dns_upstream_port, default 53). */
uint16_t pal_svsm_auto_upstream_port(void);

/* The DNS stub's hooks in pal_sockets.c. Each returns true when it handled
 * the call (its result in *ret). */
bool pal_svsm_dns_connect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                          struct pal_socket_addr* out_local, bool* out_inprogress, int* ret);
/* 0: not for the stub; 1: answered (*ret, *out_size); 2: an external name -
 * send it to *fwd (the upstream resolver) the ordinary way. */
int pal_svsm_dns_send(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                      struct pal_socket_addr* addr, int* ret, struct pal_socket_addr* fwd);
bool pal_svsm_dns_recv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len,
                       size_t* out_total_size, struct pal_socket_addr* addr, int* ret);
/* After a datagram came in through the network service: a forwarded
 * answer is shown as the stub's, and one pointing into the deployment's
 * subnet is turned into SERVFAIL (the rebinding drop). */
void pal_svsm_dns_filter(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t len,
                         struct pal_socket_addr* addr);
bool pal_svsm_dns_readable(PAL_HANDLE handle);
void pal_svsm_dns_close(PAL_HANDLE handle);

/* DNS messages, pure (host-tested: test/dns_test.c). */
struct pal_dns_q {
    uint16_t id, flags, qtype, qclass;
    char name[256];
    size_t qend;                 /* where the question ends */
};
int pal_dns_parse_query(const uint8_t* m, size_t n, struct pal_dns_q* q);
/* An answer to `q` (the query `m`, `n` bytes) into `out`: rcode, and A
 * records (or one PTR name). Returns its length, 0 if it does not fit. */
size_t pal_dns_answer(const uint8_t* m, const struct pal_dns_q* q, int rcode,
                      const uint32_t* a, int na, const char* ptr, uint8_t* out, size_t cap);
/* Does a response carry an A record inside [base, base + 2^(32-prefix))? */
bool pal_dns_points_into(const uint8_t* m, size_t n, uint32_t base, uint8_t prefix);
/* Make response `m` a SERVFAIL with no records, in place. */
void pal_dns_servfail(uint8_t* m, size_t n);
/* "d.c.b.a.in-addr.arpa" -> a.b.c.d (host order), or false. */
bool pal_dns_ptr_addr(const char* name, uint32_t* out);

#endif
