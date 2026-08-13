#include <stdint.h>

/* Gray-code conversion and a bit-reversal permutation.  The decode is an
 * xor-shift reduction whose loop cannot be strength-reduced away, and the
 * reversal is a masked swap ladder. */

#define GRAY_MAX 16

__attribute__((noinline)) uint32_t binary_to_gray(uint32_t value) {
    return value ^ (value >> 1);
}

__attribute__((noinline)) uint32_t gray_to_binary(uint32_t gray) {
    uint32_t value = gray;
    value ^= value >> 16;
    value ^= value >> 8;
    value ^= value >> 4;
    value ^= value >> 2;
    value ^= value >> 1;
    return value;
}

__attribute__((noinline)) uint32_t reverse_bits32(uint32_t value) {
    value = ((value & 0x55555555u) << 1) | ((value >> 1) & 0x55555555u);
    value = ((value & 0x33333333u) << 2) | ((value >> 2) & 0x33333333u);
    value = ((value & 0x0F0F0F0Fu) << 4) | ((value >> 4) & 0x0F0F0F0Fu);
    value = ((value & 0x00FF00FFu) << 8) | ((value >> 8) & 0x00FF00FFu);
    return (value << 16) | (value >> 16);
}

__attribute__((noinline)) int32_t
gray_sequence(uint32_t *output, int32_t count) {
    int32_t index;
    if (output == 0 || count < 0 || count > GRAY_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        output[index] = binary_to_gray((uint32_t)index);
    }
    return count;
}
