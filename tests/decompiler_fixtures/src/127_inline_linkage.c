#include <stdint.h>

/* static inline may be emitted, inlined, or both. An address taken of a static
 * inline forces an out-of-line copy to exist, so the same source function can
 * appear zero, one or several times in the object. */

static inline int32_t scale(int32_t value, int32_t factor) {
    return (int32_t)((uint32_t)value * (uint32_t)factor);
}

static inline int32_t clamp(int32_t value, int32_t low, int32_t high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

__attribute__((noinline)) int32_t
inline_used_twice(int32_t value, int32_t factor) {
    return scale(value, factor) + scale(factor, value);
}

__attribute__((noinline)) int32_t
inline_address_taken(int32_t value, int32_t low, int32_t high) {
    /* Taking the address forces an out-of-line body to exist. */
    int32_t (*indirect)(int32_t, int32_t, int32_t) = clamp;
    return indirect(value, low, high) + clamp(value, low, high);
}

__attribute__((noinline)) int32_t
inline_in_loop(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        total += clamp(scale(values[index], 3), -100, 100);
    }
    return total;
}
