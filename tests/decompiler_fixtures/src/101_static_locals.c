#include <stdint.h>

/* A static local has static storage duration but block scope: the object lives
 * in .data/.bss and survives across calls, so recovering it means recognizing a
 * global that only one function names. */

__attribute__((noinline)) int32_t counter_next(int32_t increment) {
    static int32_t counter = 100;
    counter += increment;
    return counter;
}

__attribute__((noinline)) int32_t counter_reset(void) {
    static int32_t generation = 0;
    generation += 1;
    return generation;
}

__attribute__((noinline)) int32_t
static_table_lookup(int32_t index) {
    /* A read-only table with internal linkage: no relocation names it. */
    static const int32_t squares[8] = {0, 1, 4, 9, 16, 25, 36, 49};
    if (index < 0 || index > 7) {
        return -1;
    }
    return squares[index];
}
