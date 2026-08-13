#include <stdint.h>

/* Functions the optimiser SPLITS into more than one address range.
 *
 * COVERAGE TARGET: `.text.unlikely` / `foo.cold` and `.text.part` / `foo.part`.
 * At -O2 with the right shape, GCC moves an unlikely path into a separate
 * section and Clang does the same for an outlined slow path, so one source
 * function becomes two or more disjoint ranges with only one entry symbol. The
 * corpus has never contained a function that reliably splits, so nothing checks
 * that:
 *
 *   * function discovery attributes the cold chunk to its hot parent instead of
 *     inventing a second function at `foo.cold`;
 *   * the DWARF range list's FIRST chunk is treated as the entry — sorting the
 *     chunks by address would make `foo.cold` the entry whenever the compiler
 *     placed it lower;
 *   * a `jmp` into the cold range is an intra-function edge, not a tail call.
 *
 * The split is PROVOKED, not assumed: every cold path is marked with
 * `__builtin_expect` and ends in a call the optimiser knows is expensive.
 * Whether a given compiler actually splits is checked by the harness's
 * structural lane, and the functions are correct and executable either way. */

#define SPLIT182_LIMIT 64

/* Deliberately not inlinable and deliberately unlikely to be called: this is
 * the body GCC hoists into `.text.unlikely`. */
__attribute__((noinline, cold)) static int32_t split182_report(int32_t code,
                                                               int32_t detail) {
    int32_t folded = code;
    int32_t step;
    /* Enough work that the optimiser does not simply inline it back. */
    for (step = 0; step < 4; ++step) {
        folded = folded * 31 + detail + step;
    }
    return folded;
}

/* The classic hot/cold split: one early-out guard whose body is cold. */
__attribute__((noinline)) int32_t validate_with_cold_path(int32_t value,
                                                          int32_t bound) {
    if (__builtin_expect(bound <= 0 || bound > SPLIT182_LIMIT, 0)) {
        return split182_report(-1, bound);
    }
    if (__builtin_expect(value < 0, 0)) {
        return split182_report(-2, value);
    }
    return value % bound;
}

/* Two cold exits from inside a loop, so the cold chunk has more than one
 * predecessor and cannot be modelled as a single trailing block. */
__attribute__((noinline)) int32_t scan_with_two_cold_exits(const int32_t *items,
                                                           int32_t count) {
    int32_t index;
    int32_t total = 0;
    if (items == 0) {
        return split182_report(-3, 0);
    }
    if (__builtin_expect(count < 0 || count > SPLIT182_LIMIT, 0)) {
        return split182_report(-4, count);
    }
    for (index = 0; index < count; ++index) {
        int32_t item = items[index];
        if (__builtin_expect(item == INT32_MIN, 0)) {
            return split182_report(-5, index);
        }
        if (__builtin_expect(item < 0 && total < 0, 0)) {
            return split182_report(-6, index);
        }
        total += item / 2;
    }
    return total;
}

/* The `.part` shape: a large function with one branch the optimiser can outline
 * because it is used from a single site and never falls through. Kept
 * arithmetic-only so the result is exactly comparable. */
__attribute__((noinline)) int32_t mix_with_outlinable_tail(int32_t seed,
                                                           int32_t rounds) {
    int32_t state = seed;
    int32_t round;
    if (rounds < 0 || rounds > SPLIT182_LIMIT) {
        rounds = SPLIT182_LIMIT;
    }
    for (round = 0; round < rounds; ++round) {
        state ^= state << 3;
        state ^= (int32_t)((uint32_t)state >> 5);
        state += round;
    }
    if (__builtin_expect(state == 0, 0)) {
        /* The outlinable tail: reached rarely, does a lot, returns directly. */
        int32_t recovery = seed;
        int32_t step;
        for (step = 0; step < 8; ++step) {
            recovery = recovery * 1103515245 + 12345;
            recovery ^= (int32_t)((uint32_t)recovery >> 7);
        }
        return recovery;
    }
    return state;
}

/* A cold path that is TAKEN on ordinary inputs, so the execution differential
 * exercises the split range rather than only the hot one. */
__attribute__((noinline)) int32_t always_reaches_the_cold_chunk(int32_t value) {
    if (__builtin_expect(value >= 0, 0)) {
        return split182_report(1, value);
    }
    return split182_report(2, value);
}
