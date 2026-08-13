#include <stdint.h>

/* Every volatile access is an observable side effect: the compiler may not
 * merge, reorder, or elide them. Four reads of the same volatile object are
 * four loads, and a redundant store is still emitted. */

__attribute__((noinline)) int32_t
volatile_reads_are_not_merged(int32_t seed) {
    volatile int32_t cell = seed;
    int32_t total = 0;
    total += cell;
    total += cell;
    total += cell;
    total += cell;
    return total;
}

__attribute__((noinline)) int32_t
volatile_store_then_load(int32_t seed) {
    volatile int32_t cell;
    cell = seed;
    cell = seed + 1; /* not dead: volatile stores are observable */
    return cell;
}

__attribute__((noinline)) int32_t
volatile_loop_bound(int32_t limit) {
    volatile int32_t bound = limit;
    int32_t iterations = 0;
    if (limit < 0 || limit > 16) {
        return -1;
    }
    /* `bound` is reloaded on every test, so the trip count is not hoisted. */
    while (iterations < bound) {
        iterations += 1;
    }
    return iterations;
}

__attribute__((noinline)) int32_t
nonvolatile_control(int32_t seed) {
    int32_t cell = seed;
    int32_t total = 0;
    total += cell;
    total += cell;
    total += cell;
    total += cell;
    return total;
}
