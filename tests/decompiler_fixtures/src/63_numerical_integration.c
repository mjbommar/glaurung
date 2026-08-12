#include <stdint.h>

/* Trapezoid and Simpson quadrature of a fixed cubic in Q16.16.  Simpson's
 * alternating 4/2 weights produce a parity test inside the accumulation loop,
 * which is a small but reliable structuring probe. */

#define QUAD_STEPS_MAX 32

static int32_t quad_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t quad_cubic(int32_t x) {
    int32_t square = quad_mul_q16(x, x);
    int32_t cube = quad_mul_q16(square, x);
    return cube - quad_mul_q16(2 * 65536, square) + x;
}

__attribute__((noinline)) int32_t
trapezoid_integrate(int32_t lower, int32_t upper, int32_t steps) {
    int64_t total = 0;
    int32_t width;
    int32_t index;
    if (steps < 1 || steps > QUAD_STEPS_MAX || upper < lower) {
        return 0;
    }
    width = (upper - lower) / steps;
    for (index = 0; index <= steps; ++index) {
        int32_t sample = quad_cubic(lower + width * index);
        if (index == 0 || index == steps) {
            total += sample;
        } else {
            total += 2 * (int64_t)sample;
        }
    }
    return (int32_t)((total * (int64_t)width) / (2 * 65536));
}

__attribute__((noinline)) int32_t
simpson_integrate(int32_t lower, int32_t upper, int32_t steps) {
    int64_t total = 0;
    int32_t width;
    int32_t index;
    if (steps < 2 || steps > QUAD_STEPS_MAX || (steps % 2) != 0 ||
        upper < lower) {
        return 0;
    }
    width = (upper - lower) / steps;
    for (index = 0; index <= steps; ++index) {
        int32_t sample = quad_cubic(lower + width * index);
        if (index == 0 || index == steps) {
            total += sample;
        } else if ((index % 2) == 1) {
            total += 4 * (int64_t)sample;
        } else {
            total += 2 * (int64_t)sample;
        }
    }
    return (int32_t)((total * (int64_t)width) / (3 * 65536));
}
