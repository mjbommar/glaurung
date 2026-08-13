#include <stdint.h>

/* Unsigned arithmetic is defined modulo 2^N, which makes overflow a documented
 * result rather than a hazard. Signed overflow is avoided throughout by doing
 * the arithmetic in unsigned and converting back. */

__attribute__((noinline)) uint32_t wraps_to_zero(uint32_t value) {
    return value + (0u - value);
}

__attribute__((noinline)) uint32_t maximum_plus_one(void) {
    uint32_t maximum = 0xFFFFFFFFu;
    return maximum + 1u;
}

__attribute__((noinline)) int32_t
signed_overflow_avoided(int32_t left, int32_t right) {
    /* Computing in unsigned then converting is implementation-defined, not
     * undefined, and every target here wraps two's-complement. */
    return (int32_t)((uint32_t)left + (uint32_t)right);
}

__attribute__((noinline)) uint32_t
modular_exponent_of_two(int32_t exponent) {
    /* Shifting by 32 would be undefined; the identity is spelled out instead. */
    if (exponent < 0 || exponent > 31) {
        return 0u;
    }
    return 1u << (uint32_t)exponent;
}

__attribute__((noinline)) int32_t
absolute_without_branch(int32_t value) {
    uint32_t bits = (uint32_t)value;
    uint32_t mask = (uint32_t)(value >> 31);
    /* (v ^ mask) - mask, all in unsigned so INT32_MIN does not trap. */
    return (int32_t)((bits ^ mask) - mask);
}
