/* The PAL's copy of MicroVault's services/network/ipam/src/mvipam.h: the MVA1 messages
 * between this PAL and the address service (notes/net/AUTO-PEER.md §3.2). Byte-identical from
 * the include guard on (services/network/ipam/test/run.sh compares them). */
#ifndef MVIPAM_H
#define MVIPAM_H

#include <stdint.h>

#define MVA_MAGIC 0x3141564Du            /* "MVA1" */

enum mva_type {
    /* PAL -> service */
    MVA_HELLO        = 1,   /* the instance's lease; explicit/claim addresses */
    MVA_RESOLVE_NAME = 4,   /* a name -> its addresses */
    MVA_REVERSE_ADDR = 5,   /* an address -> its name (PTR) */
    MVA_REVERSE      = 6,   /* an instance (pid, serial) -> its address */
    /* service -> PAL */
    MVA_LEASE        = 16,
    MVA_ANSWER       = 17,
    MVA_GEN          = 18,  /* something in this space changed */
    MVA_REVOKE       = 19,  /* the lease is gone */
};

enum mva_status {
    MVA_OK          = 0,
    MVA_NXDOMAIN    = 1,
    MVA_SERVFAIL    = 2,    /* refused: no deployment, no record, malformed */
    MVA_RATE        = 3,    /* over the per-vault lookup rate */
    MVA_IN_USE      = 4,    /* an explicit address someone else holds */
    MVA_OUT_OF_RANGE = 5,   /* an explicit address outside the subnet */
    MVA_FULL        = 6,    /* no address left */
};

/* HELLO flags */
#define MVA_HELLO_RECLAIM 1u    /* re-sent after a service restart (claim_addr) */

struct mva_hdr {
    uint32_t magic;
    uint16_t type;
    uint16_t len;               /* bytes after the header */
    uint32_t id;                /* the request's, echoed by its answer */
    uint32_t gen;
} __attribute__((packed));

struct mva_hello {
    struct mva_hdr h;
    uint32_t explicit_addr;     /* [svsm] address, 0 = none */
    uint32_t claim_addr;        /* the address held before a restart, 0 = none */
    uint32_t flags;
    uint32_t pad;
} __attribute__((packed));

#define MVA_NAME_MAX 128

struct mva_name {
    struct mva_hdr h;
    char name[MVA_NAME_MAX];    /* NUL-terminated, as asked (no trailing dot needed) */
} __attribute__((packed));

struct mva_addr {
    struct mva_hdr h;
    uint32_t addr;              /* REVERSE_ADDR */
    uint32_t pid;               /* REVERSE */
    uint64_t serial;            /* REVERSE */
} __attribute__((packed));

struct mva_lease {
    struct mva_hdr h;
    int32_t  status;
    uint32_t addr;
    uint32_t subnet;
    uint8_t  prefix;
    uint8_t  open;              /* the open space (c) */
    uint8_t  pad[2];
    uint32_t stub;              /* the DNS stub's address (the PAL answers it) */
    char     domain[64];        /* search domain: mv.internal, or <d8>.mv.internal */
    char     hostname[64];
} __attribute__((packed));

#define MVA_ADDRS_MAX 8

struct mva_answer {
    struct mva_hdr h;
    int32_t  status;
    uint32_t n;
    uint32_t addrs[MVA_ADDRS_MAX];
    uint32_t pid;
    uint32_t pad;
    uint64_t serial;
    char     name[MVA_NAME_MAX];
} __attribute__((packed));

struct mva_revoke {
    struct mva_hdr h;
    uint32_t addr;
    uint32_t pad;
} __attribute__((packed));

/* The monitor's AutoNet call (0x4FFFFFB2) and its sub-ops (kernel ipc/auto.rs). */
#define MVA_AUTONET_CALL   0x4FFFFFB2UL
#define MVA_SUB_JOIN       1UL
#define MVA_SUB_ATTACH     5UL
#define MVA_SUB_NEXT       6UL
#define MVA_SUB_LIVE       7UL
#define MVA_SUB_RECORDS    8UL
#define MVA_NOTE_DEATH     1UL
#define MVA_NOTE_RECORD    2UL
#define MVA_NOTE_RESYNC    0x100UL
#define MVA_CAUSE_IPAM     2048UL
#define MVA_SELECTOR_SERVICE 5
/* The END block's deployment id (kernel ipc/mod.rs write_header). */
#define MVA_END_HAS_D      0x001
#define MVA_END_D          0x078

#endif
