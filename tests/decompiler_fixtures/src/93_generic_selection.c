#include <stdint.h>

/* C11 _Generic resolves at translation time, so the emitted code contains only
 * the selected branch. The interesting recovery question is that three source
 * spellings collapse to three different widths of the same operation. */

#define WIDEN(v) _Generic((v), \
    int8_t: (int32_t)1, \
    int16_t: (int32_t)2, \
    int32_t: (int32_t)4, \
    int64_t: (int32_t)8, \
    default: (int32_t)0)

__attribute__((noinline)) int32_t generic_tag_of_int32(int32_t value) {
    return WIDEN(value) + (value != 0);
}

__attribute__((noinline)) int32_t generic_tag_of_int16(int32_t value) {
    int16_t narrow = (int16_t)value;
    return WIDEN(narrow) + (narrow != 0);
}

__attribute__((noinline)) int32_t generic_tag_of_int64(int32_t value) {
    int64_t wide = (int64_t)value;
    return WIDEN(wide) + (wide != 0);
}

__attribute__((noinline)) int32_t generic_dispatch(int32_t selector) {
    switch (selector & 3) {
    case 0:
        return generic_tag_of_int16(selector);
    case 1:
        return generic_tag_of_int32(selector);
    default:
        return generic_tag_of_int64(selector);
    }
}
