#include <stdint.h>

/* a[i] is defined as *(a + i), so i[a] is the same object. The IOCCC leans on
 * this; the point here is that the recovered code should express the addressing
 * plainly regardless of which spelling produced it. */

__attribute__((noinline)) int32_t
reversed_subscript(const int32_t *values, int32_t index, int32_t bound) {
    if (values == 0 || index < 0 || bound < 0 || bound > 16 || index >= bound) {
        return -1;
    }
    return index[values]; /* identical to values[index] */
}

__attribute__((noinline)) int32_t
mixed_subscript_sum(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        total += (index & 1) ? index[values] : values[index];
    }
    return total;
}

__attribute__((noinline)) int32_t
negative_offset_from_interior(const int32_t *values, int32_t count) {
    const int32_t *interior;
    if (values == 0 || count < 2 || count > 16) {
        return -1;
    }
    interior = values + count - 1;
    /* A negative subscript on an interior pointer is ordinary arithmetic. */
    return interior[-1] + interior[0];
}
