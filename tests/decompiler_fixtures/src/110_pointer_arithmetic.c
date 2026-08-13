#include <stdint.h>
#include <stddef.h>

/* Pointer differences are in elements, not bytes; a one-past-the-end pointer is
 * valid to form and compare but not to dereference. */

__attribute__((noinline)) int32_t
element_distance(const int32_t *values, int32_t count) {
    const int32_t *first;
    const int32_t *last;
    if (values == 0 || count < 1 || count > 16) {
        return -1;
    }
    first = values;
    last = values + count; /* one past the end: legal to form */
    return (int32_t)(ptrdiff_t)(last - first);
}

__attribute__((noinline)) int32_t
byte_versus_element_step(const int32_t *values, int32_t count) {
    const uint8_t *bytes;
    if (values == 0 || count < 1 || count > 16) {
        return -1;
    }
    bytes = (const uint8_t *)values;
    /* values + 1 advances four bytes; bytes + 1 advances one. */
    return (int32_t)(bytes[4] == (uint8_t)(values[1] & 0xFF));
}

__attribute__((noinline)) int32_t
walk_until_sentinel(const int32_t *values, int32_t count, int32_t sentinel) {
    const int32_t *cursor;
    const int32_t *end;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    end = values + count;
    for (cursor = values; cursor != end; ++cursor) {
        if (*cursor == sentinel) {
            return (int32_t)(cursor - values);
        }
    }
    return count;
}
