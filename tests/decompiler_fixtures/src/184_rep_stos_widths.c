#include <stdint.h>
#include <string.h>

/* Block fills the compiler lowers to `rep stos` at three element widths.
 *
 * COVERAGE TARGET: `rep stosb` / `rep stosd` / `rep stosq`. The corpus reaches
 * `rep movs` (through `memcpy` in 162) but never `rep stos`, so the lifter's
 * store-and-advance expansion is checked at one width and one direction only.
 * The three functions below are the same fill at 1, 4 and 8 bytes, which is
 * exactly what selects `stosb`, `stosd` and `stosq`, and the width is the thing
 * a mis-lifted expansion gets wrong: a `stosq` modelled as `stosd` writes half
 * the buffer and leaves the rest holding whatever it held.
 *
 * Every fill is bounded by a caller-supplied count that is clamped first, and
 * every function reads back a single element so the differential compares a
 * value rather than trusting a buffer it cannot see. */

#define FILL184_LIMIT 16

/* Byte fill: `memset` of a non-constant length, which both compilers lower to
 * `rep stosb` at -O2 for a small runtime count. */
__attribute__((noinline)) int32_t fill_bytes_and_probe(uint8_t *buffer,
                                                       int32_t count,
                                                       int32_t probe) {
    if (buffer == 0 || count <= 0 || count > FILL184_LIMIT) {
        return -1;
    }
    memset(buffer, 0xA5, (size_t)count);
    if (probe < 0 || probe >= count) {
        return -2;
    }
    return (int32_t)buffer[probe];
}

/* Dword fill: an explicit loop over `uint32_t`, which is the `rep stosd`
 * idiom. Written as a loop rather than as `memset` so the ELEMENT width, not a
 * byte length, is what the recovery must preserve. */
__attribute__((noinline)) int32_t fill_dwords_and_probe(uint32_t *buffer,
                                                        int32_t count,
                                                        int32_t probe) {
    int32_t index;
    if (buffer == 0 || count <= 0 || count > FILL184_LIMIT) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        buffer[index] = 0xDEADBEEFu;
    }
    if (probe < 0 || probe >= count) {
        return -2;
    }
    /* Returned narrowed so the value is exactly comparable as an int32. */
    return (int32_t)(buffer[probe] >> 16);
}

/* Qword fill: the same loop at 8 bytes. A recovery that models the advance at
 * the wrong width leaves the odd elements untouched, which the probe finds. */
__attribute__((noinline)) int32_t fill_qwords_and_probe(uint64_t *buffer,
                                                        int32_t count,
                                                        int32_t probe) {
    int32_t index;
    if (buffer == 0 || count <= 0 || count > FILL184_LIMIT) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        buffer[index] = 0x0123456789ABCDEFull;
    }
    if (probe < 0 || probe >= count) {
        return -2;
    }
    return (int32_t)(buffer[probe] >> 32);
}

/* Zero fill through `memset` with a CONSTANT length: the form the optimiser
 * turns into a straight-line store sequence or a `rep stos` with a known count,
 * depending on size. Reads back the LAST element, which is the one a short fill
 * misses. */
__attribute__((noinline)) int32_t zero_fixed_block_and_probe(uint32_t *buffer,
                                                             int32_t seed) {
    if (buffer == 0) {
        return -1;
    }
    buffer[0] = (uint32_t)seed;
    buffer[FILL184_LIMIT - 1] = (uint32_t)seed;
    memset(buffer, 0, sizeof(uint32_t) * FILL184_LIMIT);
    return (int32_t)(buffer[FILL184_LIMIT - 1] | buffer[0]);
}

/* A fill followed by a partial overwrite, so the verdict depends on the ORDER
 * of the two block operations as well as on their widths. */
__attribute__((noinline)) int32_t fill_then_patch_and_probe(uint8_t *buffer,
                                                            int32_t count,
                                                            int32_t probe) {
    int32_t index;
    if (buffer == 0 || count <= 2 || count > FILL184_LIMIT) {
        return -1;
    }
    memset(buffer, 0x11, (size_t)count);
    for (index = 0; index < count / 2; ++index) {
        buffer[index] = (uint8_t)(0x20 + index);
    }
    if (probe < 0 || probe >= count) {
        return -2;
    }
    return (int32_t)buffer[probe];
}
