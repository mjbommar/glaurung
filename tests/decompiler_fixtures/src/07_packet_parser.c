/* 07_packet_parser.c
 *
 * Structure-preservation fixture modeling a realistic bounded binary-message
 * parser. It exercises packed and naturally-aligned structs, a nested struct,
 * a union, and bitfields, plus portable (byte-shift) endian conversion and a
 * length-checked variable-length payload read. The target bug class is a
 * decompiler that loses the relationship between the input length, the header's
 * declared length field, pointer/offset advancement, and the final bounded
 * buffer access — the exact structure a security analyst relies on to reason
 * about out-of-bounds reads.
 *
 * Targets realistic security-analysis structure preservation. Each validation
 * failure returns a DISTINCT negative code; a successful parse returns an int
 * summarizing the parse. Differential-testable via a const uint8_t* buffer and
 * int len; no libc, no bswap intrinsics.
 */
#include <stdint.h>

/* Wire header, 8 bytes, byte-for-byte as it appears on the wire:
 *   off 0: magic   (u16, big-endian)
 *   off 2: version:4, type:4        (one byte of bitfields)
 *   off 3: flags   (u8)
 *   off 4: length  (u16, big-endian)   -- declared payload length
 *   off 6: reserved(u16)
 * We do NOT rely on struct layout for parsing the wire bytes (that is done with
 * explicit shifts below); the packed struct exists so the decompiler must
 * preserve a packed aggregate and its bitfield byte.
 */
#pragma pack(push, 1)
struct wire_header {
    uint16_t magic;        /* stored big-endian on the wire */
    uint8_t  ver_type;     /* version:4 | type:4 */
    uint8_t  flags;
    uint16_t length;       /* big-endian */
    uint16_t reserved;
};
#pragma pack(pop)

/* Bitfield view of the ver_type byte. */
struct ver_type_bits {
    uint8_t version : 4;
    uint8_t type    : 4;
};

/* Naturally-aligned decoded header (host layout) with a nested struct. */
struct endpoint {
    uint16_t port;
    uint8_t  kind;
};

struct decoded_header {
    uint16_t magic;
    uint8_t  version;
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
    struct endpoint src;   /* nested struct */
};

/* A union: the same 4 payload bytes viewed either as one u32 or as an id/code
 * pair. Exercises union structure preservation. */
union payload_head {
    uint32_t raw;
    struct {
        uint16_t id;
        uint16_t code;
    } fields;
    uint8_t bytes[4];
};

#define WIRE_MAGIC   0xC0DEu
#define HEADER_SIZE  8

/* Portable big-endian 16-bit read (no bswap intrinsic). */
static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* Portable big-endian 32-bit read. */
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

/* Validate the header alone. Distinct negative codes per failure mode so a
 * mis-structured bounds check surfaces immediately. Returns 0 on success. */
int validate_header(const uint8_t *buf, int len) {
    if (buf == 0)
        return -1;
    if (len < HEADER_SIZE)
        return -2;                       /* not enough bytes for a header */

    uint16_t magic = read_be16(buf + 0);
    if (magic != WIRE_MAGIC)
        return -3;                       /* bad magic */

    uint8_t ver_type = buf[2];
    uint8_t version = (uint8_t)(ver_type >> 4);       /* high nibble */
    uint8_t type    = (uint8_t)(ver_type & 0x0F);     /* low nibble */
    if (version != 1)
        return -4;                       /* unsupported version */
    if (type == 0 || type > 7)
        return -5;                       /* out-of-range type */

    uint16_t length = read_be16(buf + 4);
    /* The declared payload length must fit within the remaining buffer. This
     * is the critical relationship the decompiler must preserve. */
    if ((int)length > len - HEADER_SIZE)
        return -6;                       /* declared length overruns buffer */

    return 0;
}

/* Decode the wire header into the host-layout struct. Returns 0 on success or
 * the validate_header error code. `out` is written only on success. */
static int decode_header(const uint8_t *buf, int len, struct decoded_header *out) {
    int rc = validate_header(buf, len);
    if (rc != 0)
        return rc;

    struct ver_type_bits vt;
    vt.version = (uint8_t)(buf[2] >> 4);
    vt.type    = (uint8_t)(buf[2] & 0x0F);

    out->magic   = read_be16(buf + 0);
    out->version = vt.version;
    out->type    = vt.type;
    out->flags   = buf[3];
    out->length  = read_be16(buf + 4);
    /* reserved (buf+6) folded into a nested endpoint for structure coverage */
    out->src.port = read_be16(buf + 6);
    out->src.kind = vt.type;
    return 0;
}

/* Full parse: validate, decode, advance past the header, then read the
 * variable-length payload with a bounds check BEFORE touching the bytes.
 * Returns a positive summary on success, or a distinct negative error.
 *
 * The summary deliberately combines the header fields and a checksum over
 * exactly `length` payload bytes, so if pointer advancement or the length
 * bound is mis-decompiled the summary (or an OOB access) diverges. */
int parse_packet(const uint8_t *buf, int len) {
    struct decoded_header hdr;
    int rc = decode_header(buf, len, &hdr);
    if (rc != 0)
        return rc;

    /* Advance the cursor past the fixed header. */
    const uint8_t *cursor = buf + HEADER_SIZE;
    int remaining = len - HEADER_SIZE;

    uint16_t declared = hdr.length;

    /* Redundant, explicit bound before the payload access — must be preserved
     * relative to `declared` and `remaining`. */
    if ((int)declared > remaining)
        return -7;                       /* should have been caught, defensive */

    /* Optional 4-byte payload head viewed through a union when present. */
    uint32_t head_word = 0;
    if (declared >= 4) {
        union payload_head ph;
        ph.raw = read_be32(cursor);
        head_word = (uint32_t)ph.fields.id + (uint32_t)ph.fields.code +
                    (uint32_t)ph.bytes[0];
    }

    /* Bounded checksum over exactly `declared` payload bytes. The loop index
     * must never exceed `declared`, and cursor[i] must stay within buf+len. */
    uint32_t sum = 0;
    for (int i = 0; i < (int)declared; i++) {
        sum += cursor[i];
        sum = (sum << 1) | (sum >> 31);  /* rotate to spread the bits */
    }

    /* Trailing flag: bit 0 of flags requests that the last payload byte equal
     * the low byte of the checksum. Distinct negative on mismatch. */
    if ((hdr.flags & 0x01) && declared > 0) {
        uint8_t last = cursor[declared - 1];
        if (last != (uint8_t)(sum & 0xFF))
            return -8;
    }

    /* Positive summary folding header + payload, kept in a modest range. */
    int summary = 100
                + (int)hdr.type * 7
                + (int)hdr.version
                + (int)(declared & 0xFF)
                + (int)(sum & 0x7F)
                + (int)(head_word & 0x3F);
    return summary;
}
