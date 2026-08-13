#include <stdint.h>

/* C99 designated initializers. Unnamed members are zero-initialized and array
 * designators may appear out of order, so the initialized image does not follow
 * the textual order. (A duplicate designator would also be legal C, but both
 * compilers reject it under -Werror and this corpus does not suppress
 * warnings.) */

struct Config {
    int32_t alpha;
    int32_t beta;
    int32_t gamma;
    int32_t delta;
};

__attribute__((noinline)) int32_t
designated_struct(int32_t selector) {
    struct Config config = {.gamma = 3, .alpha = 1};
    /* beta and delta are zero. */
    switch (selector & 3) {
    case 0:
        return config.alpha;
    case 1:
        return config.beta;
    case 2:
        return config.gamma;
    default:
        return config.delta;
    }
}

__attribute__((noinline)) int32_t
designated_array_out_of_order(int32_t index) {
    /* Written [4], [1], [2]; the object is still laid out in index order, and
     * the three unnamed slots are zero. */
    static const int32_t table[6] = {[4] = 50, [1] = 10, [2] = 30};
    if (index < 0 || index > 5) {
        return -1;
    }
    return table[index];
}

__attribute__((noinline)) int32_t
designated_sum(void) {
    const int32_t sparse[8] = {[0] = 1, [3] = 4, [7] = 8};
    int32_t total = 0;
    int32_t index;
    for (index = 0; index < 8; ++index) {
        total += sparse[index];
    }
    return total;
}
