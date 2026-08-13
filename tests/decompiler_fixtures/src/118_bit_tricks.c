#include <stdint.h>

/* Textbook bit manipulations. Each has a recognizable closed form, so a
 * recovered version that merely "looks similar" fails the differential on the
 * first boundary value. */

__attribute__((noinline)) uint32_t isolate_lowest_set(uint32_t value) {
    return value & (0u - value);
}

__attribute__((noinline)) uint32_t clear_lowest_set(uint32_t value) {
    return value & (value - 1u);
}

__attribute__((noinline)) int32_t is_power_of_two(uint32_t value) {
    return value != 0u && (value & (value - 1u)) == 0u;
}

__attribute__((noinline)) uint32_t round_up_to_power_of_two(uint32_t value) {
    if (value == 0u) {
        return 1u;
    }
    value -= 1u;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1u;
}

__attribute__((noinline)) int32_t
xor_swap(int32_t *left, int32_t *right) {
    if (left == 0 || right == 0 || left == right) {
        return -1;
    }
    *left ^= *right;
    *right ^= *left;
    *left ^= *right;
    return *left - *right;
}

__attribute__((noinline)) int32_t
sign_without_branch(int32_t value) {
    return (value > 0) - (value < 0);
}
