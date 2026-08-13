#include <stdint.h>

/* In `E1 op= E2` the lvalue E1 is evaluated exactly once, which matters when
 * the subscript itself has a side effect. Compound assignment also converts
 * back to the left operand's type, so a narrow target truncates each step. */

__attribute__((noinline)) int32_t
subscript_evaluated_once(int32_t *values, int32_t count, int32_t *cursor) {
    if (values == 0 || cursor == 0 || count < 1 || count > 16) {
        return -1;
    }
    *cursor = 0;
    /* The postincrement happens once, not twice. */
    values[(*cursor)++] += 100;
    return *cursor;
}

__attribute__((noinline)) int32_t
narrow_compound_truncates(int32_t seed, int32_t steps) {
    uint8_t narrow = (uint8_t)seed;
    int32_t step;
    if (steps < 0 || steps > 16) {
        return -1;
    }
    for (step = 0; step < steps; ++step) {
        narrow += 50; /* wraps at 256 every time, not once at the end */
    }
    return (int32_t)narrow;
}

__attribute__((noinline)) int32_t
mixed_compound_operators(int32_t seed) {
    int32_t value = seed;
    value += 7;
    value *= 3;
    value ^= 0x55;
    value >>= 1;
    value |= 1;
    value -= 2;
    return value;
}
