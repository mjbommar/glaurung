#include <stdint.h>

/* _Bool normalizes any nonzero value to 1 on conversion, which is a real
 * instruction sequence (test/setne), not a no-op cast. Storing into a _Bool and
 * reading it back is therefore lossy in a specific, observable way. */

__attribute__((noinline)) int32_t
bool_normalizes(int32_t value) {
    _Bool flag = (_Bool)value;
    return (int32_t)flag;
}

__attribute__((noinline)) int32_t
bool_roundtrip_mask(int32_t value) {
    /* Only bit 8 is inspected, but the result is still normalized to 0 or 1. */
    _Bool flag = (value & 0x100) != 0;
    return flag ? 1000 : 2000;
}

__attribute__((noinline)) int32_t
bool_arithmetic(int32_t a, int32_t b, int32_t c) {
    /* Relational operators yield int 0/1; summing them counts satisfied
     * predicates without any branch. */
    return (a > b) + (b > c) + (c > a) + (_Bool)(a | b | c);
}
