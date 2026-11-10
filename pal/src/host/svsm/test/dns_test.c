/* Host tests of the auto-peering DNS stub's message code (pal_svsm_dns.c,
 * compiled here with PAL_DNS_HOSTTEST: the pure half only). */
#define PAL_DNS_HOSTTEST 1
#include <stdio.h>
#include "../pal_svsm_dns.c"

int pal_dns_parse_query(const uint8_t* m, size_t n, struct pal_dns_q* q);

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; \
    fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); } } while (0)

/* A query as glibc sends one: id, RD, one question, an EDNS OPT. */
static size_t query(uint8_t* m, const char* name, uint16_t type, int edns) {
    size_t o = 12;
    memset(m, 0, 12);
    m[0] = 0x12; m[1] = 0x34; m[2] = 0x01; m[5] = 1;
    o += encode_name(name, m + o, 256);
    m[o++] = (uint8_t)(type >> 8); m[o++] = (uint8_t)type; m[o++] = 0; m[o++] = 1;
    if (edns) {
        m[11] = 1;
        uint8_t opt[] = { 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0 };
        memcpy(m + o, opt, sizeof opt);
        o += sizeof opt;
    }
    return o;
}

int main(void) {
    uint8_t m[512], out[512];
    struct pal_dns_q q;

    size_t n = query(m, "Search.MV.internal", T_A, 1);
    CHECK(pal_dns_parse_query(m, n, &q) == 0);
    CHECK(!strcmp(q.name, "search.mv.internal") && q.qtype == T_A && q.id == 0x1234);

    uint32_t a[2] = { 0x64400003, 0x64400004 };
    size_t ol = pal_dns_answer(m, &q, RC_OK, a, 2, NULL, out, sizeof out);
    CHECK(ol == q.qend + 32);
    CHECK(out[2] & 0x80);                          /* QR */
    CHECK((out[3] & 0xF) == 0 && be16(out + 6) == 2 && be16(out + 10) == 0);  /* no OPT echoed */
    CHECK(out[ol - 4] == 100 && out[ol - 3] == 64 && out[ol - 1] == 4);
    /* our own answer points into 100.64/10; an outside one must not */
    CHECK(pal_dns_points_into(out, ol, 0x64400000, 10));
    CHECK(!pal_dns_points_into(out, ol, 0x0A000000, 8));
    pal_dns_servfail(out, ol);
    CHECK((out[3] & 0xF) == RC_SERVFAIL && be16(out + 6) == 0 && (out[2] & 0x80));
    CHECK(!pal_dns_points_into(out, ol, 0x64400000, 10));

    ol = pal_dns_answer(m, &q, RC_NXDOMAIN, NULL, 0, NULL, out, sizeof out);
    CHECK((out[3] & 0xF) == RC_NXDOMAIN && be16(out + 6) == 0 && ol == q.qend);

    n = query(m, "4.0.64.100.in-addr.arpa", T_PTR, 0);
    CHECK(pal_dns_parse_query(m, n, &q) == 0);
    uint32_t ip;
    CHECK(pal_dns_ptr_addr(q.name, &ip) && ip == 0x64400004);
    CHECK(!pal_dns_ptr_addr("1.2.3.in-addr.arpa", &ip));
    CHECK(!pal_dns_ptr_addr("300.2.3.4.in-addr.arpa", &ip));
    ol = pal_dns_answer(m, &q, RC_OK, NULL, 0, "search.mv.internal", out, sizeof out);
    CHECK(ol > q.qend && be16(out + 6) == 1 && be16(out + q.qend + 2) == T_PTR);

    /* refused shapes: a response, two questions, a short packet, a pointer */
    n = query(m, "x", T_A, 0);
    m[2] |= 0x80;
    CHECK(pal_dns_parse_query(m, n, &q) < 0);
    m[2] &= 0x7F;
    m[5] = 2;
    CHECK(pal_dns_parse_query(m, n, &q) < 0);
    m[5] = 1;
    CHECK(pal_dns_parse_query(m, 14, &q) < 0);
    m[12] = 0xC0;
    CHECK(pal_dns_parse_query(m, n, &q) < 0);

    /* an answer with a compressed name and authority records parses */
    uint8_t r[] = { 0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
                    3, 'w', 'w', 'w', 0, 0, 1, 0, 1,
                    0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 100, 64, 9, 9 };
    CHECK(pal_dns_points_into(r, sizeof r, 0x64400000, 10));
    CHECK(!pal_dns_points_into(r, sizeof r - 1, 0x64400000, 10));   /* truncated */

    printf("dns_test: %d checks, %d failed\n", checks, fails);
    return fails ? 1 : 0;
}
