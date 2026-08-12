#include <stdint.h>

/* Q16.16 fixed-point primitives.  The harness executes integer signatures
 * only, so the whole numeric half of this corpus is built on these: a multiply
 * that rounds through a 64-bit intermediate, a divide that shifts before
 * dividing, and an integer square root by digit-by-digit restoration. */

#define Q16_ONE 65536
#define Q16_LIMIT 1073741824

__attribute__((noinline)) int32_t fixed_multiply(int32_t left, int32_t right) {
    int64_t product = (int64_t)left * (int64_t)right;
    return (int32_t)(product >> 16);
}

__attribute__((noinline)) int32_t fixed_divide(int32_t numerator,
                                               int32_t denominator) {
    int64_t scaled;
    if (denominator == 0) {
        return 0;
    }
    scaled = ((int64_t)numerator << 16) / (int64_t)denominator;
    if (scaled > 2147483647LL) {
        return 2147483647;
    }
    if (scaled < -2147483648LL) {
        return -2147483647 - 1;
    }
    return (int32_t)scaled;
}

__attribute__((noinline)) int32_t fixed_sqrt(int32_t value) {
    uint64_t remainder;
    uint64_t root = 0;
    uint64_t bit = 1ULL << 46;
    if (value < 0) {
        return -1;
    }
    remainder = (uint64_t)value << 16;
    while (bit > remainder) {
        bit >>= 2;
    }
    while (bit != 0u) {
        if (remainder >= root + bit) {
            remainder -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    return (int32_t)root;
}

__attribute__((noinline)) int32_t fixed_lerp(int32_t from, int32_t to,
                                             int32_t alpha) {
    int64_t span;
    if (alpha < 0) {
        alpha = 0;
    }
    if (alpha > Q16_ONE) {
        alpha = Q16_ONE;
    }
    span = ((int64_t)(to - from) * (int64_t)alpha) >> 16;
    return (int32_t)((int64_t)from + span);
}
