#include <stdint.h>

/* __builtin_expect reorders the emitted blocks without changing semantics, so
 * the hot path becomes the fallthrough and the cold path is moved out of line.
 * The two functions below are identical apart from the hint. */

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

__attribute__((noinline)) int32_t
hinted_validation(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (UNLIKELY(values == 0) || UNLIKELY(count < 0) || UNLIKELY(count > 16)) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (LIKELY(values[index] >= 0)) {
            total += values[index];
        } else {
            total -= 1;
        }
    }
    return total;
}

__attribute__((noinline)) int32_t
unhinted_validation(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (values[index] >= 0) {
            total += values[index];
        } else {
            total -= 1;
        }
    }
    return total;
}
