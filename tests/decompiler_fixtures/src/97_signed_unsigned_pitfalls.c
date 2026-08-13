#include <stdint.h>

/* The classic conversion traps, written with explicit casts so the intent is
 * unambiguous and the build stays warning-clean. Each returns a value that
 * differs from the naive signed reading. */

__attribute__((noinline)) int32_t
negative_compares_greater(int32_t value, uint32_t bound) {
    /* -1 converted to unsigned is UINT32_MAX, so it is NOT less than bound. */
    return ((uint32_t)value < bound) ? 1 : 0;
}

__attribute__((noinline)) uint32_t
unsigned_subtraction_wraps(uint32_t left, uint32_t right) {
    /* Defined modular arithmetic: 3 - 5 is UINT32_MAX - 1. */
    return left - right;
}

__attribute__((noinline)) int32_t
size_like_loop(int32_t count) {
    uint32_t index;
    int32_t iterations = 0;
    if (count < 0 || count > 16) {
        return -1;
    }
    /* A reverse loop on an unsigned counter must not test `index >= 0`; this
     * one tests the post-decrement value instead. */
    for (index = (uint32_t)count; index-- > 0u;) {
        iterations += 1;
    }
    return iterations;
}

__attribute__((noinline)) int32_t
division_truncates_toward_zero(int32_t numerator, int32_t denominator) {
    if (denominator == 0 || (numerator == (-2147483647 - 1) && denominator == -1)) {
        return 0;
    }
    /* C99 requires truncation toward zero, so -7/2 is -3 and -7%2 is -1. */
    return (numerator / denominator) * 100 + (numerator % denominator);
}
