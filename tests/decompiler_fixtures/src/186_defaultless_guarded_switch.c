#include <stdint.h>

/* A switch with NO `default` label, guarded by an explicit range test.
 *
 * COVERAGE TARGET: `ir::guarded_switch`. When a switch has no default, falling
 * off the end is not an error — control simply continues after the statement —
 * so the compiler emits a range check that jumps PAST the whole switch rather
 * than into a default arm. Every switch fixture in the corpus has a default,
 * which means the recovery has only ever seen the shape where the out-of-range
 * edge lands on a real block. The defaultless shape is the one where a recovery
 * that invents a default arm silently changes what the function returns for an
 * out-of-range discriminant.
 *
 * Each function makes the fall-through observable: a value is set before the
 * switch and returned after it, so "no arm ran" is a distinct answer from every
 * arm's answer. */

#define SWITCH186_LIMIT 8

/* Dense, defaultless, with a value that survives the fall-through. */
__attribute__((noinline)) int32_t dense_no_default(int32_t selector) {
    int32_t result = -1;
    switch (selector) {
    case 0:
        result = 100;
        break;
    case 1:
        result = 101;
        break;
    case 2:
        result = 102;
        break;
    case 3:
        result = 103;
        break;
    case 4:
        result = 104;
        break;
    case 5:
        result = 105;
        break;
    case 6:
        result = 106;
        break;
    case 7:
        result = 107;
        break;
    }
    return result;
}

/* Sparse and defaultless: the compiler emits a comparison ladder or a shifted
 * table, and the out-of-range edge still leaves `result` untouched. */
__attribute__((noinline)) int32_t sparse_no_default(int32_t selector) {
    int32_t result = -7;
    switch (selector) {
    case -1000:
        result = 1;
        break;
    case 0:
        result = 2;
        break;
    case 17:
        result = 3;
        break;
    case 4096:
        result = 4;
        break;
    case 1000000:
        result = 5;
        break;
    }
    return result;
}

/* Defaultless with FALL-THROUGH between arms, so the recovery cannot model each
 * case as an independent block. */
__attribute__((noinline)) int32_t fallthrough_no_default(int32_t selector) {
    int32_t accumulated = 0;
    switch (selector & 7) {
    case 0:
        accumulated += 1;
        /* fall through */
    case 1:
        accumulated += 2;
        /* fall through */
    case 2:
        accumulated += 4;
        break;
    case 5:
        accumulated += 8;
        /* fall through */
    case 6:
        accumulated += 16;
        break;
    }
    return accumulated;
}

/* Defaultless inside a loop: the out-of-range edge is a `continue`, not a
 * return, so the jump target is the loop latch rather than the epilogue. */
__attribute__((noinline)) int32_t loop_switch_no_default(const int32_t *codes,
                                                         int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (codes == 0 || count < 0 || count > SWITCH186_LIMIT) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        switch (codes[index] & 3) {
        case 0:
            total += 1;
            break;
        case 1:
            total += 10;
            break;
        case 3:
            total += 1000;
            break;
        }
        total += 1;
    }
    return total;
}

/* Every arm returns, and there is still no default — so the function's only
 * fall-through path is the one the range check takes. A recovery that turns the
 * range check into a default arm has to invent a return value here, and any
 * value it invents is wrong for some input. */
__attribute__((noinline)) int32_t returning_arms_no_default(int32_t selector) {
    switch (selector) {
    case 10:
        return 1;
    case 11:
        return 2;
    case 12:
        return 3;
    case 13:
        return 4;
    }
    return -99;
}
