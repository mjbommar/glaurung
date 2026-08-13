#include <stdint.h>

/* An IOCCC-flavoured expression: comma operators, nested conditionals, compound
 * assignment, and subscript arithmetic packed into a few statements. It is
 * deliberately dense but fully defined -- every side effect is separated by a
 * sequence point. */

__attribute__((noinline)) int32_t
dense_fold(int32_t *state, int32_t count, int32_t seed) {
    int32_t i = 0;
    int32_t a = seed;
    int32_t b = 0;
    if (state == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (; i < count; a ^= (b = (a << 1) ^ i), state[i] = a, ++i) {
        a = (a & 1) ? ((a >> 1) ^ 0x5A5A) : (a >> 1);
    }
    return (i ? (state[i - 1] ^ b) : a) + (b ? 1 : 0);
}

__attribute__((noinline)) int32_t
chained_assignment(int32_t seed, int32_t *trace) {
    int32_t a;
    int32_t b;
    int32_t c;
    if (trace == 0) {
        return -1;
    }
    a = b = c = seed;          /* right-associative */
    a += b -= c *= 2;          /* c doubles, b drops, a rises */
    trace[0] = a;
    trace[1] = b;
    trace[2] = c;
    return a + b + c;
}

__attribute__((noinline)) int32_t
conditional_lvalue_select(int32_t which, int32_t *left, int32_t *right) {
    if (left == 0 || right == 0) {
        return -1;
    }
    /* The conditional selects a pointer, then the store happens through it. */
    *(which ? left : right) += 10;
    return *left * 100 + *right;
}
