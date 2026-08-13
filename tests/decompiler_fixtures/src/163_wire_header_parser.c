/* 163_wire_header_parser.c
 *
 * A real-shaped framing header: 10 fixed bytes, all multi-byte fields
 * big-endian, followed by a variable payload whose length the header declares.
 *
 *   off 0..1  magic      u16 be, must be 0x5A47
 *   off 2     version    u8,      must be 2
 *   off 3     flags      u8,      the top nibble is reserved and must be zero
 *   off 4..7  stream_id  u32 be
 *   off 8..9  payload_len u16 be, must be <= 6 AND <= (len - 10)
 *   off 10..  payload    payload_len bytes
 *
 * Why this stresses a decompiler: the whole security property of this parser is
 * one relationship -- the DECLARED length must be bounded by the RECEIVED
 * length minus the header size -- and after lowering it is a single compare
 * between two registers whose provenance the decompiler has to reconstruct. The
 * two checks on `payload_len` are not redundant (one bounds the field against
 * the format's own maximum, one against the bytes actually present), and a
 * decompiler that merges them, drops either, flips the direction, or loses the
 * `- 10` produces C that still parses every valid frame identically and reads
 * out of bounds on a crafted one. Every rejection path returns a DISTINCT
 * negative code so a mis-recovered check shows up as the wrong code rather than
 * as a coin flip.
 *
 * The big-endian assembly is done with explicit shifts over individual bytes,
 * so no unaligned access and no host-endianness dependence exists anywhere.
 *
 * UB notes: every length is clamped into [0, 16] before it participates in
 * arithmetic; the declared length is compared as an unsigned before any cast to
 * int32_t; the payload loop is bounded by the validated declared length.
 */
#include <stddef.h>
#include <stdint.h>

#define HDR163_MAGIC        0x5A47u
#define HDR163_VERSION      2u
#define HDR163_HEADER_BYTES 10
#define HDR163_MAX_TOTAL    16
#define HDR163_MAX_PAYLOAD  6
#define HDR163_BAD_ID       0xFFFFFFFFu

_Static_assert(HDR163_HEADER_BYTES + HDR163_MAX_PAYLOAD <= HDR163_MAX_TOTAL,
               "a maximal frame must fit inside the clamped buffer bound");

/* Clamp a caller length into [0, HDR163_MAX_TOTAL] before any arithmetic. */
static int32_t hdr163_clamp(int32_t n) {
    if (n < 0) {
        return 0;
    }
    if (n > HDR163_MAX_TOTAL) {
        return HDR163_MAX_TOTAL;
    }
    return n;
}

/* Big-endian 16-bit assembly from two individual byte loads. */
static uint32_t hdr163_be16(const uint8_t *p) {
    return ((uint32_t)p[0] << 8) | (uint32_t)p[1];
}

/* Big-endian 32-bit assembly from four individual byte loads. */
static uint32_t hdr163_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* The whole validation policy in one place. `limit` must already be clamped.
 * On success returns 0 and writes the declared payload length to *payload_len;
 * otherwise returns a distinct negative code and writes 0. */
static int32_t hdr163_check(const uint8_t *buf, int32_t limit,
                            int32_t *payload_len) {
    uint32_t declared;

    *payload_len = 0;
    if (limit < HDR163_HEADER_BYTES) {
        return -2; /* truncated before the fixed header ends */
    }
    if (hdr163_be16(buf + 0) != HDR163_MAGIC) {
        return -3; /* not our framing */
    }
    if ((uint32_t)buf[2] != HDR163_VERSION) {
        return -4; /* unsupported version */
    }
    if (((uint32_t)buf[3] & 0xF0u) != 0u) {
        return -5; /* reserved flag bits set */
    }
    declared = hdr163_be16(buf + 8);
    if (declared > (uint32_t)HDR163_MAX_PAYLOAD) {
        return -6; /* larger than the format allows */
    }
    if ((int32_t)declared > limit - HDR163_HEADER_BYTES) {
        return -7; /* larger than the bytes we actually received */
    }
    *payload_len = (int32_t)declared;
    return 0;
}

/* Validate a frame. Returns the declared payload length (0..6) when the frame
 * is well formed, or a distinct negative code. */
__attribute__((noinline)) int32_t
hdr163_validate(const uint8_t *buf, int32_t len) {
    int32_t payload_len = 0;
    int32_t rc;

    if (buf == NULL) {
        return -1;
    }
    rc = hdr163_check(buf, hdr163_clamp(len), &payload_len);
    return (rc != 0) ? rc : payload_len;
}

/* The big-endian 32-bit stream id, or 0xFFFFFFFF when the frame is rejected. */
__attribute__((noinline)) uint32_t
hdr163_stream_id(const uint8_t *buf, int32_t len) {
    int32_t payload_len = 0;

    if (buf == NULL) {
        return HDR163_BAD_ID;
    }
    if (hdr163_check(buf, hdr163_clamp(len), &payload_len) != 0) {
        return HDR163_BAD_ID;
    }
    return hdr163_be32(buf + 4);
}

/* Fold exactly `payload_len` payload bytes -- never one more, never one fewer.
 * Returns a positive summary, or the validation code. */
__attribute__((noinline)) int32_t
hdr163_payload_digest(const uint8_t *buf, int32_t len) {
    int32_t payload_len = 0;
    int32_t rc;
    int32_t i;
    uint32_t acc = 0x9E37u;

    if (buf == NULL) {
        return -1;
    }
    rc = hdr163_check(buf, hdr163_clamp(len), &payload_len);
    if (rc != 0) {
        return rc;
    }
    for (i = 0; i < payload_len; i++) {
        acc += (uint32_t)buf[HDR163_HEADER_BYTES + i];
        acc = (acc << 3) ^ (acc >> 29);
    }
    acc += (uint32_t)buf[3]; /* flags participate, so a dropped byte shows up */
    return 1000 + payload_len * 100 + (int32_t)(acc & 0x3FFu);
}

/* Copy the validated payload out to a caller buffer. Returns the number of
 * bytes copied (0..6), or a distinct negative code. */
__attribute__((noinline)) int32_t
hdr163_copy_payload(const uint8_t *buf, int32_t len, uint8_t *out,
                    int32_t out_len) {
    int32_t payload_len = 0;
    int32_t room = hdr163_clamp(out_len);
    int32_t rc;
    int32_t i;

    if (buf == NULL || out == NULL) {
        return -1;
    }
    rc = hdr163_check(buf, hdr163_clamp(len), &payload_len);
    if (rc != 0) {
        return rc;
    }
    if (payload_len > room) {
        return -8; /* the caller's sink is smaller than the declared payload */
    }
    for (i = 0; i < payload_len; i++) {
        out[i] = buf[HDR163_HEADER_BYTES + i];
    }
    return payload_len;
}

/* Emit a well-formed frame, so the accepting path is reachable without a
 * hand-built vector. Returns the total frame size, or a negative code. */
__attribute__((noinline)) int32_t
hdr163_build(uint8_t *out, int32_t out_len, uint32_t stream_id,
             int32_t payload_len) {
    int32_t room = hdr163_clamp(out_len);
    int32_t want = payload_len;
    int32_t total;
    int32_t i;

    if (out == NULL) {
        return -1;
    }
    if (want < 0) {
        want = 0;
    }
    if (want > HDR163_MAX_PAYLOAD) {
        want = HDR163_MAX_PAYLOAD;
    }
    total = HDR163_HEADER_BYTES + want;
    if (room < total) {
        return -2;
    }

    out[0] = (uint8_t)((HDR163_MAGIC >> 8) & 0xFFu);
    out[1] = (uint8_t)(HDR163_MAGIC & 0xFFu);
    out[2] = (uint8_t)HDR163_VERSION;
    out[3] = 0x03u;
    out[4] = (uint8_t)((stream_id >> 24) & 0xFFu);
    out[5] = (uint8_t)((stream_id >> 16) & 0xFFu);
    out[6] = (uint8_t)((stream_id >> 8) & 0xFFu);
    out[7] = (uint8_t)(stream_id & 0xFFu);
    out[8] = (uint8_t)(((uint32_t)want >> 8) & 0xFFu);
    out[9] = (uint8_t)((uint32_t)want & 0xFFu);
    for (i = 0; i < want; i++) {
        out[HDR163_HEADER_BYTES + i] = (uint8_t)(0x40u + (uint32_t)i);
    }
    return total;
}
