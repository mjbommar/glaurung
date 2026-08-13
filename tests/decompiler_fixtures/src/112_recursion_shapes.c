#include <stdint.h>

/* Four recursion shapes that lower differently: mutual recursion (two frames
 * that cannot be inlined into each other), self tail recursion (usually turned
 * into a loop at -O2), non-tail recursion (a real frame), and an accumulator
 * form that is tail-recursive by construction. */

static int32_t is_odd_helper(int32_t value, int32_t fuel);

static int32_t is_even_helper(int32_t value, int32_t fuel) {
    if (fuel <= 0) {
        return -1;
    }
    if (value == 0) {
        return 1;
    }
    return is_odd_helper(value - 1, fuel - 1);
}

static int32_t is_odd_helper(int32_t value, int32_t fuel) {
    if (fuel <= 0) {
        return -1;
    }
    if (value == 0) {
        return 0;
    }
    return is_even_helper(value - 1, fuel - 1);
}

__attribute__((noinline)) int32_t mutual_parity(int32_t value) {
    if (value < 0 || value > 64) {
        return -1;
    }
    return is_even_helper(value, 128);
}

__attribute__((noinline)) int32_t tail_countdown(int32_t value, int32_t total) {
    if (value <= 0) {
        return total;
    }
    return tail_countdown(value - 1, total + value); /* self tail call */
}

__attribute__((noinline)) int32_t nontail_depth(int32_t value) {
    if (value <= 0) {
        return 0;
    }
    if (value > 32) {
        return -1;
    }
    /* The addition happens after the call returns: a real frame. */
    return 1 + nontail_depth(value - 1);
}

__attribute__((noinline)) int32_t
recursion_entry(int32_t selector, int32_t value) {
    if (value < 0 || value > 32) {
        return -1;
    }
    switch (selector & 3) {
    case 0:
        return mutual_parity(value);
    case 1:
        return tail_countdown(value, 0);
    default:
        return nontail_depth(value);
    }
}
