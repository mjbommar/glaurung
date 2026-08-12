#include <stdint.h>

/* Euclid, extended Euclid, modular exponentiation by square-and-multiply, and
 * a modular inverse.  Extended Euclid carries three simultaneous recurrences
 * through one loop, which is a strong test of value identity tracking. */

__attribute__((noinline)) int32_t gcd_i32(int32_t left, int32_t right) {
    int32_t guard;
    if (left < 0 || right < 0) {
        return -1;
    }
    for (guard = 0; guard < 64 && right != 0; ++guard) {
        int32_t remainder = left % right;
        left = right;
        right = remainder;
    }
    return left;
}

__attribute__((noinline)) int32_t
extended_gcd(int32_t a, int32_t b, int32_t *x_out, int32_t *y_out) {
    int32_t old_r, r, old_s, s, old_t, t;
    int32_t guard;
    if (x_out == 0 || y_out == 0 || a < 0 || b < 0 || a > 100000 ||
        b > 100000) {
        return -1;
    }
    old_r = a;
    r = b;
    old_s = 1;
    s = 0;
    old_t = 0;
    t = 1;
    for (guard = 0; guard < 64 && r != 0; ++guard) {
        int32_t quotient = old_r / r;
        int32_t next_r = old_r - quotient * r;
        int32_t next_s = old_s - quotient * s;
        int32_t next_t = old_t - quotient * t;
        old_r = r;
        r = next_r;
        old_s = s;
        s = next_s;
        old_t = t;
        t = next_t;
    }
    *x_out = old_s;
    *y_out = old_t;
    return old_r;
}

__attribute__((noinline)) uint32_t
mod_pow(uint32_t base, uint32_t exponent, uint32_t modulus) {
    uint64_t result = 1;
    uint64_t factor;
    int32_t guard;
    if (modulus == 0u || modulus == 1u) {
        return 0;
    }
    factor = (uint64_t)base % (uint64_t)modulus;
    for (guard = 0; guard < 32 && exponent != 0u; ++guard) {
        if ((exponent & 1u) != 0u) {
            result = (result * factor) % (uint64_t)modulus;
        }
        factor = (factor * factor) % (uint64_t)modulus;
        exponent >>= 1;
    }
    return (uint32_t)result;
}
