#include <stdint.h>

/* Bisection and Newton-Raphson on the same Q16.16 objective.  Bisection is a
 * sign-test loop with a shrinking bracket; Newton is a self-correcting
 * recurrence with a derivative guard.  Both terminate on a tolerance. */

#define ROOT_ITERATIONS 40

static int32_t root_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t root_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

static int32_t root_objective(int32_t x, int32_t target) {
    return root_mul_q16(x, x) - target;
}

__attribute__((noinline)) int32_t
bisection_sqrt(int32_t target, int32_t tolerance) {
    int32_t low = 0;
    int32_t high = 256 * 65536;
    int32_t iteration;
    if (target < 0 || tolerance <= 0) {
        return -1;
    }
    for (iteration = 0; iteration < ROOT_ITERATIONS; ++iteration) {
        int32_t middle = low + (high - low) / 2;
        int32_t value = root_objective(middle, target);
        int32_t magnitude = (value < 0) ? -value : value;
        if (magnitude <= tolerance) {
            return middle;
        }
        if (value > 0) {
            high = middle;
        } else {
            low = middle;
        }
    }
    return low + (high - low) / 2;
}

__attribute__((noinline)) int32_t
newton_sqrt(int32_t target, int32_t tolerance) {
    int32_t estimate = 65536;
    int32_t iteration;
    if (target <= 0 || tolerance <= 0) {
        return -1;
    }
    for (iteration = 0; iteration < ROOT_ITERATIONS; ++iteration) {
        int32_t value = root_objective(estimate, target);
        int32_t derivative = 2 * estimate;
        int32_t magnitude = (value < 0) ? -value : value;
        if (magnitude <= tolerance) {
            return estimate;
        }
        if (derivative == 0) {
            return -2;
        }
        estimate -= root_div_q16(value, derivative);
        if (estimate <= 0) {
            estimate = 65536;
        }
    }
    return estimate;
}
