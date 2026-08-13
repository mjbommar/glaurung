#include <stdint.h>

/* Struct passing crosses an ABI boundary that depends on size: a two-word
 * struct travels in registers on SysV x86-64, while a larger one is passed in
 * memory with a hidden pointer. Both spellings look identical in C. */

struct Small {
    int32_t a;
    int32_t b;
};

struct Large {
    int32_t a;
    int32_t b;
    int32_t c;
    int32_t d;
    int32_t e;
};

static int32_t consume_small(struct Small value) {
    return value.a * 10 + value.b;
}

static int32_t consume_large(struct Large value) {
    return value.a + value.b + value.c + value.d + value.e;
}

__attribute__((noinline)) int32_t
pass_small_by_value(int32_t a, int32_t b) {
    struct Small value;
    value.a = a;
    value.b = b;
    return consume_small(value);
}

__attribute__((noinline)) int32_t
pass_large_by_value(int32_t seed) {
    struct Large value;
    value.a = seed;
    value.b = seed + 1;
    value.c = seed + 2;
    value.d = seed + 3;
    value.e = seed + 4;
    return consume_large(value);
}

__attribute__((noinline)) int32_t
returns_small_struct_field(int32_t a, int32_t b, int32_t which) {
    struct Small value;
    value.a = a;
    value.b = b;
    /* Returning the whole struct would cross the same boundary in reverse. */
    return which ? value.a : value.b;
}
