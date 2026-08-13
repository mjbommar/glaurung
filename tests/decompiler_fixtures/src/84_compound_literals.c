#include <stdint.h>

/* C99 compound literals: an unnamed object with automatic storage inside a
 * block. Its address is valid for the enclosing block only, and the object is
 * a fresh one on every evaluation. */

struct Pair {
    int32_t first;
    int32_t second;
};

static int32_t pair_span(const struct Pair *pair) {
    return pair->first - pair->second;
}

__attribute__((noinline)) int32_t
compound_literal_argument(int32_t left, int32_t right) {
    /* The literal lives until the end of this block. */
    return pair_span(&(struct Pair){left, right});
}

__attribute__((noinline)) int32_t
compound_literal_array(int32_t index) {
    if (index < 0 || index > 5) {
        return -1;
    }
    return (int32_t[]){2, 3, 5, 7, 11, 13}[index];
}

__attribute__((noinline)) int32_t
compound_literal_in_loop(int32_t count) {
    int32_t total = 0;
    int32_t step;
    if (count < 0 || count > 16) {
        return -1;
    }
    for (step = 0; step < count; ++step) {
        /* A distinct object each iteration. */
        struct Pair local = (struct Pair){step, count - step};
        total += pair_span(&local);
    }
    return total;
}
