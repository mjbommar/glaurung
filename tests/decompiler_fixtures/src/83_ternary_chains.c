#include <stdint.h>

/* Nested conditional expressions. The conditional operator is right-associative
 * and yields an lvalue-free result whose type is the usual arithmetic
 * conversion of both arms, so an incorrectly widened arm changes the answer. */

__attribute__((noinline)) int32_t
classify_ladder(int32_t value) {
    return value < -100  ? -3
           : value < -10 ? -2
           : value < 0   ? -1
           : value == 0  ? 0
           : value < 10  ? 1
           : value < 100 ? 2
                         : 3;
}

__attribute__((noinline)) uint32_t
ternary_mixed_types(int32_t selector, int32_t signed_arm, uint32_t unsigned_arm) {
    /* Both arms convert to unsigned int: the signed arm is converted, not the
     * other way round. A negative signed_arm therefore wraps. */
    return selector ? (uint32_t)signed_arm : unsigned_arm;
}

__attribute__((noinline)) int32_t
nested_ternary_assignment(int32_t a, int32_t b, int32_t c, int32_t *out) {
    int32_t result;
    if (out == 0) {
        return -1;
    }
    result = (a > b) ? ((b > c) ? a - c : ((a > c) ? a - b : c - a))
                     : ((a > c) ? b - c : ((b > c) ? b - a : c - b));
    *out = result;
    return (a > b) + (b > c) + (a > c);
}
