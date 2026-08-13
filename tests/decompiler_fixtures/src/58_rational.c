#include <stdint.h>

/* Exact rational arithmetic in lowest terms.  Every operation normalises by
 * the greatest common divisor and moves the sign to the numerator, so the
 * recovered code needs both the division idiom and the sign fixup. */

static int32_t rational_gcd(int32_t a, int32_t b) {
    int32_t guard;
    if (a < 0) {
        a = -a;
    }
    if (b < 0) {
        b = -b;
    }
    for (guard = 0; guard < 64 && b != 0; ++guard) {
        int32_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return (a == 0) ? 1 : a;
}

__attribute__((noinline)) int32_t
rational_add(int32_t left_num, int32_t left_den, int32_t right_num,
             int32_t right_den, int32_t *out_num, int32_t *out_den) {
    int32_t numerator;
    int32_t denominator;
    int32_t divisor;
    if (out_num == 0 || out_den == 0 || left_den == 0 || right_den == 0 ||
        left_num < -10000 || left_num > 10000 || right_num < -10000 ||
        right_num > 10000 || left_den < -10000 || left_den > 10000 ||
        right_den < -10000 || right_den > 10000) {
        return -1;
    }
    numerator = left_num * right_den + right_num * left_den;
    denominator = left_den * right_den;
    if (denominator < 0) {
        numerator = -numerator;
        denominator = -denominator;
    }
    divisor = rational_gcd(numerator, denominator);
    *out_num = numerator / divisor;
    *out_den = denominator / divisor;
    return 1;
}

__attribute__((noinline)) int32_t
rational_compare(int32_t left_num, int32_t left_den, int32_t right_num,
                 int32_t right_den) {
    int64_t left;
    int64_t right;
    if (left_den == 0 || right_den == 0 || left_num < -10000 ||
        left_num > 10000 || right_num < -10000 || right_num > 10000 ||
        left_den < -10000 || left_den > 10000 || right_den < -10000 ||
        right_den > 10000) {
        return -2;
    }
    if (left_den < 0) {
        left_num = -left_num;
        left_den = -left_den;
    }
    if (right_den < 0) {
        right_num = -right_num;
        right_den = -right_den;
    }
    left = (int64_t)left_num * (int64_t)right_den;
    right = (int64_t)right_num * (int64_t)left_den;
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    return 0;
}
