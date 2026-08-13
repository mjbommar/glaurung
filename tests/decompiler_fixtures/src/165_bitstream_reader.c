/* 165_bitstream_reader.c
 *
 * A bit-level cursor: MSB-first, fields of arbitrary width laid end to end with
 * no byte alignment between them, exactly as in H.264/AV1 headers, LoRaWAN and
 * ZigBee PHY frames, DEFLATE-style codes and most register-packed firmware
 * telemetry. Bit 0 is the most significant bit of byte 0; a 13-bit field
 * starting at bit 3 occupies the low 5 bits of byte 0, all of byte 1, and does
 * not touch byte 2.
 *
 * Two readers compute the same thing on purpose:
 *   - the bit-at-a-time loop, which is what a naive implementation looks like;
 *   - the windowed reader, which touches ceil((skew + width) / 8) bytes,
 *     accumulates them into a 32-bit window, and extracts with one shift and
 *     one mask.
 * `bit165_cross_check` asserts they agree, so a decompilation that recovers one
 * of them wrongly is caught even when it looks self-consistent.
 *
 * Why this stresses a decompiler: the windowed reader's three derived
 * quantities -- `skew = bit_off & 7`, `need = (skew + width + 7) >> 3`, and
 * `trailing = need * 8 - skew - width` -- are pure arithmetic on the cursor,
 * they get folded and re-associated hard by the optimiser, and a decompiler
 * that emits an algebraically *plausible* rearrangement (say, `8 - skew` rather
 * than the trailing count, or `>> 3` where the source rounded up) still yields
 * correct answers for every byte-aligned field and wrong ones for exactly the
 * fields that cross a byte boundary. That is a bug class that survives every
 * similarity metric and every eyeball, and it is only visible by execution.
 *
 * UB notes: width is clamped to [1, 24] so no shift count ever reaches 32 and
 * the window can never overflow 32 bits; `bit_off` is range-checked against
 * `limit * 8` BEFORE `bit_off + width` is formed, so that sum cannot overflow;
 * `limit` is clamped to [0, 16] first. Every buffer index is derived from an
 * already-validated bit range.
 */
#include <stddef.h>
#include <stdint.h>

#define BIT165_MAX_BUF     16
#define BIT165_MAX_WIDTH   24
#define BIT165_FRAME_BYTES 5
#define BIT165_BAD         0xFFFFFFFFu
#define BIT165_SYNC        0x5u

/* Clamp a caller length into [0, BIT165_MAX_BUF] before any arithmetic. */
static int32_t bit165_clamp(int32_t n) {
    if (n < 0) {
        return 0;
    }
    if (n > BIT165_MAX_BUF) {
        return BIT165_MAX_BUF;
    }
    return n;
}

/* 1 iff a `width`-bit field at `bit_off` lies wholly inside `limit` bytes.
 * `limit` is pre-clamped, so `limit * 8` is at most 128 and the `bit_off`
 * range check below makes `bit_off + width` safe to form. */
static int32_t bit165_fits(int32_t limit, int32_t bit_off, int32_t width) {
    int32_t total_bits = limit * 8;

    if (width < 1 || width > BIT165_MAX_WIDTH) {
        return 0;
    }
    if (bit_off < 0 || bit_off > total_bits) {
        return 0;
    }
    return (bit_off + width <= total_bits) ? 1 : 0;
}

/* Reference reader: one bit per iteration, MSB first. */
static uint32_t bit165_pull_bitwise(const uint8_t *buf, int32_t bit_off,
                                    int32_t width) {
    uint32_t acc = 0;
    int32_t i;

    for (i = 0; i < width; i++) {
        int32_t at = bit_off + i;
        uint32_t bit = ((uint32_t)buf[at >> 3] >> (7 - (at & 7))) & 1u;
        acc = (acc << 1) | bit;
    }
    return acc;
}

/* Windowed reader: gather the touched bytes, then one shift and one mask.
 * `need` is at most 4 for width <= 24, so the window holds at most 32 bits. */
static uint32_t bit165_pull_windowed(const uint8_t *buf, int32_t bit_off,
                                     int32_t width) {
    int32_t base = bit_off >> 3;
    int32_t skew = bit_off & 7;
    int32_t need = (skew + width + 7) >> 3;
    int32_t trailing = need * 8 - skew - width;
    uint32_t window = 0;
    int32_t i;

    for (i = 0; i < need; i++) {
        window = (window << 8) | (uint32_t)buf[base + i];
    }
    return (window >> trailing) & ((1u << width) - 1u);
}

/* Write `width` bits of `value`, MSB first, at `bit_off`. The caller must have
 * validated the range with bit165_fits. */
static void bit165_poke(uint8_t *buf, int32_t bit_off, int32_t width,
                        uint32_t value) {
    int32_t i;

    for (i = 0; i < width; i++) {
        int32_t at = bit_off + width - 1 - i;
        int32_t shift = 7 - (at & 7);
        uint32_t bit = (value >> i) & 1u;
        uint32_t byte = (uint32_t)buf[at >> 3];

        if (bit != 0u) {
            byte |= (1u << shift);
        } else {
            byte &= ~(1u << shift);
        }
        buf[at >> 3] = (uint8_t)(byte & 0xFFu);
    }
}

/* Read one field. Returns 0xFFFFFFFF on rejection, which no accepted read can
 * produce because width is capped at 24 bits. */
__attribute__((noinline)) uint32_t
bit165_read_bits(const uint8_t *buf, int32_t len, int32_t bit_off,
                 int32_t width) {
    int32_t limit = bit165_clamp(len);

    if (buf == NULL) {
        return BIT165_BAD;
    }
    if (!bit165_fits(limit, bit_off, width)) {
        return BIT165_BAD;
    }
    return bit165_pull_windowed(buf, bit_off, width);
}

/* 1 when both readers agree, 0 when they disagree, negative when the request
 * is out of range. */
__attribute__((noinline)) int32_t
bit165_cross_check(const uint8_t *buf, int32_t len, int32_t bit_off,
                   int32_t width) {
    int32_t limit = bit165_clamp(len);

    if (buf == NULL) {
        return -1;
    }
    if (!bit165_fits(limit, bit_off, width)) {
        return -2;
    }
    return (bit165_pull_bitwise(buf, bit_off, width) ==
            bit165_pull_windowed(buf, bit_off, width))
               ? 1
               : 0;
}

/* Pull consecutive `width`-bit fields until the buffer or the sink runs out.
 * Returns how many fields were produced. */
__attribute__((noinline)) int32_t
bit165_read_sequence(const uint8_t *buf, int32_t len, int32_t width,
                     int32_t *out, int32_t out_len) {
    int32_t limit = bit165_clamp(len);
    int32_t room = bit165_clamp(out_len);
    int32_t field_bits = width;
    int32_t count = 0;
    int32_t bit_off = 0;

    if (buf == NULL || out == NULL) {
        return -1;
    }
    if (field_bits < 1) {
        field_bits = 1;
    }
    if (field_bits > BIT165_MAX_WIDTH) {
        field_bits = BIT165_MAX_WIDTH;
    }
    while (count < room && bit165_fits(limit, bit_off, field_bits)) {
        out[count] = (int32_t)bit165_pull_windowed(buf, bit_off, field_bits);
        count++;
        bit_off += field_bits;
    }
    return count;
}

/* Lay out a 5-byte frame: 3-bit sync at bit 0, a 13-bit field at bit 3 (which
 * ends exactly on the byte-2 boundary), and a 19-bit field at bit 16 (which
 * ends 5 bits into byte 4). Returns the byte sum of the frame. */
__attribute__((noinline)) int32_t
bit165_write_frame(uint8_t *out, int32_t out_len, uint32_t small,
                   uint32_t large) {
    int32_t room = bit165_clamp(out_len);
    int32_t sum = 0;
    int32_t i;

    if (out == NULL) {
        return -1;
    }
    if (room < BIT165_FRAME_BYTES) {
        return -2;
    }
    for (i = 0; i < BIT165_FRAME_BYTES; i++) {
        out[i] = 0;
    }
    bit165_poke(out, 0, 3, BIT165_SYNC);
    bit165_poke(out, 3, 13, small);
    bit165_poke(out, 16, 19, large);
    for (i = 0; i < BIT165_FRAME_BYTES; i++) {
        sum += (int32_t)out[i];
    }
    return sum;
}

/* Write a frame into a local and read every field back: 1 for the sync, 2 for
 * the 13-bit field, 4 for the 19-bit field, 8 when both readers agree on the
 * boundary-crossing one. A perfect roundtrip returns 15. */
__attribute__((noinline)) int32_t
bit165_roundtrip(uint32_t small, uint32_t large) {
    uint8_t frame[BIT165_MAX_BUF];
    int32_t result = 0;
    int32_t rc;
    int32_t i;

    for (i = 0; i < BIT165_MAX_BUF; i++) {
        frame[i] = 0;
    }
    rc = bit165_write_frame(frame, BIT165_FRAME_BYTES, small, large);
    if (rc < 0) {
        return rc;
    }
    if (bit165_read_bits(frame, BIT165_FRAME_BYTES, 0, 3) == BIT165_SYNC) {
        result += 1;
    }
    if (bit165_read_bits(frame, BIT165_FRAME_BYTES, 3, 13) ==
        (small & 0x1FFFu)) {
        result += 2;
    }
    if (bit165_read_bits(frame, BIT165_FRAME_BYTES, 16, 19) ==
        (large & 0x7FFFFu)) {
        result += 4;
    }
    if (bit165_cross_check(frame, BIT165_FRAME_BYTES, 3, 13) == 1) {
        result += 8;
    }
    return result;
}
