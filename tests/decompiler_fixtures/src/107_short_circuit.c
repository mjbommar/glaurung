#include <stdint.h>

/* && and || impose a sequence point and evaluate the right operand only when
 * needed. Counting the evaluations proves the branch was preserved rather than
 * flattened into an arithmetic combination. */

static int32_t observe(int32_t value, int32_t *counter) {
    *counter += 1;
    return value;
}

__attribute__((noinline)) int32_t
short_circuit_and(int32_t a, int32_t b, int32_t *evaluations) {
    if (evaluations == 0) {
        return -1;
    }
    *evaluations = 0;
    if (observe(a, evaluations) && observe(b, evaluations)) {
        return 1;
    }
    return 0;
}

__attribute__((noinline)) int32_t
short_circuit_or(int32_t a, int32_t b, int32_t *evaluations) {
    if (evaluations == 0) {
        return -1;
    }
    *evaluations = 0;
    if (observe(a, evaluations) || observe(b, evaluations)) {
        return 1;
    }
    return 0;
}

__attribute__((noinline)) int32_t
guarded_dereference(const int32_t *pointer, int32_t index, int32_t bound) {
    /* The classic guard: the right operand must not run when the left fails. */
    if (pointer != 0 && index >= 0 && index < bound && bound <= 16) {
        return pointer[index];
    }
    return -1;
}
