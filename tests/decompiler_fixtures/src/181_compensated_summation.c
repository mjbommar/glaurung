#include <stdint.h>

/* Kahan/Neumaier compensated summation at binary64.
 *
 * COVERAGE TARGET: `Subsd`. The corpus reaches `addsd`, `mulsd` and `divsd`
 * through 172 and 175, but nothing subtracts at binary64 — and subtraction is
 * the one scalar operation whose lowering cannot be checked by symmetry, since
 * `a - b` and `b - a` differ. Compensated summation is where a real program
 * subtracts doubles: the compensation term IS `(sum - old) - value`, and the
 * whole point of the algorithm is that this quantity is not zero.
 *
 * It is also a recovery test with teeth. The compensation is exactly the
 * rounding error the naive sum discards, so a recovery that reassociates the
 * arithmetic, keeps an intermediate at the wrong width, or swaps a subtraction's
 * operands returns the NAIVE sum — a number that is close enough to look right
 * and is bit-exactly wrong, which is what the differential compares.
 *
 * Inputs come in as `float` and widen, so the terms are exactly representable
 * and the only inexactness in the answer is the one the algorithm compensates. */

#define FP181_TERM_LIMIT 32

/* The naive sum, for the difference to be measured against. */
__attribute__((noinline)) double naive_sum_f64(const float *terms,
                                               int32_t count) {
    double total = 0.0;
    int32_t index;
    if (terms == 0 || count < 0 || count > FP181_TERM_LIMIT) {
        return 0.0;
    }
    for (index = 0; index < count; ++index) {
        total += (double)terms[index];
    }
    return total;
}

/* Kahan summation. `compensation` is carried by SUBTRACTION at binary64 and is
 * the only reason this differs from `naive_sum_f64`. */
__attribute__((noinline)) double kahan_sum_f64(const float *terms,
                                               int32_t count) {
    double total = 0.0;
    double compensation = 0.0;
    int32_t index;
    if (terms == 0 || count < 0 || count > FP181_TERM_LIMIT) {
        return 0.0;
    }
    for (index = 0; index < count; ++index) {
        double adjusted = (double)terms[index] - compensation;
        double next = total + adjusted;
        /* `(next - total)` is the part of `adjusted` that survived rounding;
         * subtracting `adjusted` leaves exactly the part that did not. Both
         * subtractions are binary64 and neither may be reassociated away. */
        compensation = (next - total) - adjusted;
        total = next;
    }
    return total;
}

/* The compensation itself, as a value: nonzero exactly when the naive sum lost
 * a digit. Returned as an integer so the verdict does not depend on how the
 * harness marshals a tiny double. */
__attribute__((noinline)) int32_t summation_disagrees(const float *terms,
                                                      int32_t count) {
    double naive = naive_sum_f64(terms, count);
    double kahan = kahan_sum_f64(terms, count);
    return (naive == kahan) ? 0 : 1;
}

/* A single compensated step, isolated. Three binary64 subtractions with no loop
 * around them, so a failure here is a lowering bug and not a loop-shape one. */
__attribute__((noinline)) double compensation_of_step(double total,
                                                      double value) {
    double next = total + value;
    return (next - total) - value;
}

/* Difference of products — the determinant shape, at binary64, where operand
 * order is observable. `a*d - b*c` and `b*c - a*d` are negatives of each other,
 * so a swapped `subsd` is caught by any input whose result is not zero. */
__attribute__((noinline)) double difference_of_products(double a, double b,
                                                        double c, double d) {
    return a * d - b * c;
}
