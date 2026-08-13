#include <stdint.h>

/* LEB128 varint encode/decode with zigzag mapping for signed values.  The
 * continuation-bit loop mixes a 64-bit accumulator with a 7-bit shift, so the
 * recovered shift amount and the accumulator width both matter. */

#define VARINT_MAX 16

__attribute__((noinline)) uint32_t zigzag_encode(int32_t value) {
    return ((uint32_t)value << 1) ^ (uint32_t)(value >> 31);
}

__attribute__((noinline)) int32_t zigzag_decode(uint32_t encoded) {
    return (int32_t)((encoded >> 1) ^ (uint32_t)(-(int32_t)(encoded & 1u)));
}

__attribute__((noinline)) int32_t
varint_encode(uint32_t value, uint8_t *output, int32_t capacity) {
    int32_t produced = 0;
    if (output == 0 || capacity < 1 || capacity > VARINT_MAX) {
        return -1;
    }
    do {
        uint8_t chunk = (uint8_t)(value & 0x7Fu);
        value >>= 7;
        if (value != 0u) {
            chunk |= 0x80u;
        }
        if (produced >= capacity) {
            return -2;
        }
        output[produced] = chunk;
        produced += 1;
    } while (value != 0u);
    return produced;
}

__attribute__((noinline)) int32_t
varint_decode(const uint8_t *input, int32_t length, uint32_t *value) {
    uint64_t accumulator = 0;
    int32_t shift = 0;
    int32_t index;
    if (input == 0 || value == 0 || length < 0 || length > VARINT_MAX) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        uint8_t chunk = input[index];
        if (shift > 28) {
            return -2;
        }
        accumulator |= (uint64_t)(chunk & 0x7Fu) << (uint32_t)shift;
        shift += 7;
        if ((chunk & 0x80u) == 0u) {
            if (accumulator > 0xFFFFFFFFULL) {
                return -3;
            }
            *value = (uint32_t)accumulator;
            return index + 1;
        }
    }
    return -4;
}
