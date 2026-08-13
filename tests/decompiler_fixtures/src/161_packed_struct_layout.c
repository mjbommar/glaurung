/* 161_packed_struct_layout.c
 *
 * `__attribute__((packed))` wire records: the same four members declared twice,
 * once with natural alignment and once packed. The natural struct is 12 bytes
 * (kind @0, 3 bytes of padding, seq @4, port @8, ttl @10, 1 byte of tail
 * padding); the packed struct is 8 bytes with seq @1 and port @5 -- both of them
 * unaligned. Nothing in the C source says "1" and "5"; the attribute does, and
 * every offset in the emitted code is a resolved constant.
 *
 * Why this stresses a decompiler: after lowering, the two layouts are just
 * different immediate displacements off a base register, and a packed 4-byte
 * load at displacement 1 looks exactly like a natural one at displacement 4.
 * A decompiler that re-types the buffer with a *plausible* aggregate rather
 * than the actual one produces C that compiles, type-checks, reads well, and
 * decodes a different byte range -- a shift of the whole record by three bytes,
 * structurally invisible and behaviorally fatal. The size/offset probes here
 * pin the layout as an observable, and encode/decode pin that the packed member
 * accesses really do straddle the alignment boundaries.
 *
 * UB notes: the wire bytes are moved through an `unsigned char *` view of a
 * whole struct object (character-type access aliases everything, C11 6.5p7),
 * never by casting a byte buffer to a struct pointer, and never by taking the
 * address of a packed member (which is both a diagnostic and a misaligned
 * pointer). Every packed byte is covered by a member, so no indeterminate
 * padding is ever read.
 */
#include <stddef.h>
#include <stdint.h>

#define PK161_WIRE_BYTES 8
#define PK161_MAX_BUF    16

/* Host-natural layout: the compiler is free to insert padding. */
struct pk161_natural {
    uint8_t  kind;
    uint32_t seq;
    uint16_t port;
    uint8_t  ttl;
};

/* The wire layout: no padding anywhere, so seq and port are unaligned. */
struct pk161_wire {
    uint8_t  kind; /* offset 0 */
    uint32_t seq;  /* offset 1 -- unaligned 4-byte member */
    uint16_t port; /* offset 5 -- unaligned 2-byte member */
    uint8_t  ttl;  /* offset 7 */
} __attribute__((packed));

_Static_assert(sizeof(struct pk161_wire) == PK161_WIRE_BYTES,
               "packed wire record must be exactly 8 bytes");
_Static_assert(sizeof(struct pk161_natural) > sizeof(struct pk161_wire),
               "the natural layout must be the padded one");

/* Clamp any caller-supplied length into [0, PK161_MAX_BUF] before it is used in
 * arithmetic, so a hostile INT_MIN can never overflow a subtraction. */
static int32_t pk161_clamp(int32_t n) {
    if (n < 0) {
        return 0;
    }
    if (n > PK161_MAX_BUF) {
        return PK161_MAX_BUF;
    }
    return n;
}

/* sizeof(natural) - sizeof(packed): the padding the attribute removes. */
__attribute__((noinline)) int32_t pk161_layout_delta(void) {
    return (int32_t)(sizeof(struct pk161_natural) - sizeof(struct pk161_wire));
}

/* Every member offset in both layouts. Cases 0..3 are the natural struct,
 * 4..7 the packed one; the pairwise difference IS the specification. */
__attribute__((noinline)) int32_t pk161_member_offset(int32_t which) {
    switch (which & 7) {
    case 0:
        return (int32_t)offsetof(struct pk161_natural, kind);
    case 1:
        return (int32_t)offsetof(struct pk161_natural, seq);
    case 2:
        return (int32_t)offsetof(struct pk161_natural, port);
    case 3:
        return (int32_t)offsetof(struct pk161_natural, ttl);
    case 4:
        return (int32_t)offsetof(struct pk161_wire, kind);
    case 5:
        return (int32_t)offsetof(struct pk161_wire, seq);
    case 6:
        return (int32_t)offsetof(struct pk161_wire, port);
    default:
        return (int32_t)offsetof(struct pk161_wire, ttl);
    }
}

/* Fill a packed record member-by-member (the stores land at 0/1/5/7), then emit
 * its 8 bytes to the caller's buffer. Returns the byte sum, or a negative code.
 */
__attribute__((noinline)) int32_t
pk161_encode(uint8_t *out, int32_t out_len, uint32_t seq, int32_t kind) {
    struct pk161_wire record = {0, 0, 0, 0};
    const unsigned char *raw;
    int32_t limit = pk161_clamp(out_len);
    int32_t sum = 0;
    int32_t i;

    if (out == NULL) {
        return -1;
    }
    if (limit < PK161_WIRE_BYTES) {
        return -2;
    }

    record.kind = (uint8_t)((uint32_t)kind & 0xFFu);
    record.seq  = seq;
    record.port = (uint16_t)(((uint32_t)kind >> 8) & 0xFFFFu);
    record.ttl  = (uint8_t)((seq >> 24) & 0xFFu);

    raw = (const unsigned char *)&record;
    for (i = 0; i < PK161_WIRE_BYTES; i++) {
        out[i] = (uint8_t)raw[i];
        sum += (int32_t)raw[i];
    }
    return sum;
}

/* Refill a packed record from wire bytes, then read one member back. The read
 * of `seq` is a 4-byte access at offset 1. Returns 0xFFFFFFFF on rejection;
 * no member of this record can legitimately produce that value except `seq`,
 * which is documented as ambiguous. */
__attribute__((noinline)) uint32_t
pk161_read_field(const uint8_t *in, int32_t in_len, int32_t which) {
    struct pk161_wire record = {0, 0, 0, 0};
    unsigned char *raw;
    int32_t limit = pk161_clamp(in_len);
    int32_t i;

    if (in == NULL) {
        return 0xFFFFFFFFu;
    }
    if (limit < PK161_WIRE_BYTES) {
        return 0xFFFFFFFFu;
    }

    raw = (unsigned char *)&record;
    for (i = 0; i < PK161_WIRE_BYTES; i++) {
        raw[i] = (unsigned char)in[i];
    }

    switch (which & 3) {
    case 0:
        return (uint32_t)record.kind;
    case 1:
        return record.seq; /* unaligned load at wire offset 1 */
    case 2:
        return (uint32_t)record.port; /* unaligned load at wire offset 5 */
    default:
        return (uint32_t)record.ttl;
    }
}

/* Encode into a local frame and decode straight back: the roundtrip only holds
 * if both directions agree on offsets 1 and 5. */
__attribute__((noinline)) int32_t
pk161_roundtrip(uint32_t seq, int32_t kind) {
    uint8_t frame[PK161_MAX_BUF];
    int32_t rc;
    int32_t i;

    for (i = 0; i < PK161_MAX_BUF; i++) {
        frame[i] = 0;
    }
    rc = pk161_encode(frame, PK161_WIRE_BYTES, seq, kind);
    if (rc < 0) {
        return rc;
    }
    if (pk161_read_field(frame, PK161_WIRE_BYTES, 1) != seq) {
        return -3;
    }
    if (pk161_read_field(frame, PK161_WIRE_BYTES, 2) !=
        (((uint32_t)kind >> 8) & 0xFFFFu)) {
        return -4;
    }
    return rc;
}
