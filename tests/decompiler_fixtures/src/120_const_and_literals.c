#include <stdint.h>

/* const on the object versus const through the pointer. A `const` object with
 * a constant initializer can be folded entirely; a pointer-to-const only
 * promises this access path will not write. */

static const int32_t FOLDABLE = 41;

__attribute__((noinline)) int32_t reads_foldable_constant(void) {
    return FOLDABLE + 1;
}

__attribute__((noinline)) int32_t
pointer_to_const_still_loads(const int32_t *values, int32_t index) {
    if (values == 0 || index < 0 || index > 15) {
        return -1;
    }
    /* The pointee may change between these two loads through another path, so
     * neither load may be reused for the other. */
    return values[index] * 2;
}

__attribute__((noinline)) int32_t
const_array_of_pointers(int32_t which, int32_t fallback) {
    static const int32_t first = 7;
    static const int32_t second = 8;
    static const int32_t third = 9;
    static const int32_t *const table[3] = {&first, &second, &third};
    if (which < 0 || which > 2) {
        return fallback;
    }
    return *table[which];
}
