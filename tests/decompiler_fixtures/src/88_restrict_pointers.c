#include <stdint.h>

/* C99 `restrict` promises no aliasing, which licenses the compiler to keep
 * values in registers across stores it would otherwise have to reload. The
 * aliasing and non-aliasing variants below are deliberately identical apart
 * from the qualifier, so the generated code diverges while the source does not. */

__attribute__((noinline)) int32_t
restrict_accumulate(int32_t *restrict destination,
                    const int32_t *restrict source, int32_t count) {
    int32_t index;
    if (destination == 0 || source == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        destination[0] += source[index];
    }
    return destination[0];
}

__attribute__((noinline)) int32_t
aliasing_accumulate(int32_t *destination, const int32_t *source, int32_t count) {
    int32_t index;
    if (destination == 0 || source == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        destination[0] += source[index];
    }
    return destination[0];
}
