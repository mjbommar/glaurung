#include <stdint.h>

/* One-dimensional elastic and inelastic collisions in Q16.16, plus a momentum
 * conservation residual.  All three read the same four parameters, so a
 * mis-assigned argument register is caught by comparing their results. */

static int32_t collide_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t collide_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
elastic_velocity_a(int32_t mass_a, int32_t mass_b, int32_t velocity_a,
                   int32_t velocity_b) {
    int32_t total;
    int32_t term;
    if (mass_a <= 0 || mass_b <= 0) {
        return 0;
    }
    total = mass_a + mass_b;
    term = collide_mul_q16(mass_a - mass_b, velocity_a) +
           collide_mul_q16(2 * mass_b, velocity_b);
    return collide_div_q16(term, total);
}

__attribute__((noinline)) int32_t
inelastic_velocity(int32_t mass_a, int32_t mass_b, int32_t velocity_a,
                   int32_t velocity_b) {
    int32_t momentum;
    if (mass_a <= 0 || mass_b <= 0) {
        return 0;
    }
    momentum = collide_mul_q16(mass_a, velocity_a) +
               collide_mul_q16(mass_b, velocity_b);
    return collide_div_q16(momentum, mass_a + mass_b);
}

__attribute__((noinline)) int32_t
momentum_residual(int32_t mass_a, int32_t mass_b, int32_t velocity_a,
                  int32_t velocity_b) {
    int32_t before = collide_mul_q16(mass_a, velocity_a) +
                     collide_mul_q16(mass_b, velocity_b);
    int32_t after_a = elastic_velocity_a(mass_a, mass_b, velocity_a, velocity_b);
    int32_t after_b = elastic_velocity_a(mass_b, mass_a, velocity_b, velocity_a);
    int32_t after = collide_mul_q16(mass_a, after_a) +
                    collide_mul_q16(mass_b, after_b);
    return before - after;
}
