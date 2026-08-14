#include <stdint.h>

/* An array subscript with a constant bias — a[i + 3] — is the shape the affine
 * index analysis is meant to recover: one object, one induction variable, one
 * fixed displacement folded into the address. `109_subscript_commutativity`
 * covers which *spelling* produced a subscript, and a negative offset from an
 * interior pointer; neither is a constant bias on the index itself.
 *
 * The last two functions are the controls. Recovering a bias is only correct if
 * it is not recovered where there is none: `value_bias_not_index` adds the same
 * constant to the loaded *value*, and `variable_bias` displaces the index by a
 * runtime argument. A pass that folds either into a fixed address bias is
 * wrong, and would otherwise look indistinguishable from success.
 *
 * Every access is bounded by an explicit source guard rather than by the
 * harness contract, so an out-of-domain argument returns -1 on both the
 * original and the recompiled side instead of reading past the buffer. */

#define BIAS_CAPACITY 16
#define FORWARD_BIAS 2

__attribute__((noinline)) int32_t
bias_forward_sum(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > BIAS_CAPACITY - FORWARD_BIAS) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        total += values[index + FORWARD_BIAS];
    }
    return total;
}

__attribute__((noinline)) int32_t
bias_backward_pair(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 1 || count > BIAS_CAPACITY) {
        return -1;
    }
    /* Two biased reads of one object per iteration: one at the cursor and one a
     * fixed element behind it. */
    for (index = 1; index < count; ++index) {
        total += values[index] - values[index - 1];
    }
    return total;
}

__attribute__((noinline)) int32_t
adjacent_difference(const int32_t *values, int32_t count, int32_t *out) {
    int32_t index;
    if (values == 0 || out == 0 || count < 1 || count > BIAS_CAPACITY) {
        return -1;
    }
    /* A biased load feeding an unbiased store: the two objects must not be
     * unified just because their cursors advance in step. */
    for (index = 0; index + 1 < count; ++index) {
        out[index] = values[index + 1] - values[index];
    }
    return count - 1;
}

__attribute__((noinline)) int32_t
value_bias_not_index(const int32_t *values, int32_t count) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > BIAS_CAPACITY) {
        return -1;
    }
    /* Control: the constant is added to the loaded value, never to the address.
     * The sum differs from `bias_forward_sum` for the same buffer. */
    for (index = 0; index < count; ++index) {
        total += values[index] + FORWARD_BIAS;
    }
    return total;
}

__attribute__((noinline)) int32_t
variable_bias(const int32_t *values, int32_t count, int32_t bias) {
    int32_t total = 0;
    int32_t index;
    if (values == 0 || count < 0 || count > BIAS_CAPACITY || bias < 0 ||
        bias > count) {
        return -1;
    }
    /* Control: the displacement is a runtime value, so no constant bias exists
     * to recover. */
    for (index = 0; index + bias < count; ++index) {
        total += values[index + bias];
    }
    return total;
}
