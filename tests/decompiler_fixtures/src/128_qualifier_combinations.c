#include <stdint.h>

/* The qualifier binds to what precedes the const: `const int *` is a mutable
 * pointer to constant data, `int *const` is a constant pointer to mutable data.
 * They generate different code for the same-looking source. */

__attribute__((noinline)) int32_t
pointer_to_const_walks(const int32_t *values, int32_t count) {
    const int32_t *cursor = values; /* the pointer may move */
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        total += *cursor;
        cursor += 1;
    }
    return total;
}

__attribute__((noinline)) int32_t
const_pointer_writes(int32_t *const target, int32_t count) {
    int32_t index;
    if (target == 0 || count < 0 || count > 16) {
        return -1;
    }
    /* The pointer cannot move, but the pointee can change. */
    for (index = 0; index < count; ++index) {
        target[index] = index * 2;
    }
    return target[0] + count;
}

__attribute__((noinline)) int32_t
volatile_const_is_readable(int32_t seed) {
    /* A hardware-register idiom: not writable here, but re-read every time. */
    volatile const int32_t cell = seed;
    int32_t total = 0;
    total += cell;
    total += cell;
    return total;
}
