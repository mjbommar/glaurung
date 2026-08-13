#include <stdint.h>

/* while, do/while and for with the same intent lower differently: a do/while
 * body always runs once, and a for loop with an empty condition needs an
 * internal exit. Loop rotation at -O2 makes several of these converge. */

__attribute__((noinline)) int32_t while_zero_trips(int32_t limit) {
    int32_t index = 0;
    int32_t total = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    while (index < limit) {
        total += index;
        index += 1;
    }
    return total * 10 + index;
}

__attribute__((noinline)) int32_t do_while_always_once(int32_t limit) {
    int32_t index = 0;
    int32_t total = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    do {
        total += index;
        index += 1;
    } while (index < limit);
    return total * 10 + index; /* differs from the while form at limit 0 */
}

__attribute__((noinline)) int32_t infinite_with_internal_exit(int32_t limit) {
    int32_t index = 0;
    int32_t total = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    for (;;) {
        if (index >= limit) {
            break;
        }
        total += index;
        index += 1;
    }
    return total * 10 + index;
}

__attribute__((noinline)) int32_t decrementing_loop(int32_t limit) {
    int32_t index;
    int32_t total = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    /* Counting down to zero lets the compiler test the flags from the
     * decrement itself instead of a separate comparison. */
    for (index = limit; index > 0; --index) {
        total += index;
    }
    return total * 10 + index;
}
