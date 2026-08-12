#include <stdint.h>

/* One symplectic-Euler gravitational step for a body orbiting a fixed mass.
 * The inverse-square law needs a divide by a squared radius, so an incorrect
 * intermediate width diverges immediately rather than subtly. */

#define ORBIT_STEPS_MAX 16

static int32_t orbit_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t orbit_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
orbital_step(int32_t *position_x, int32_t *position_y, int32_t *velocity_x,
             int32_t *velocity_y, int32_t mu, int32_t timestep, int32_t steps) {
    int32_t step;
    if (position_x == 0 || position_y == 0 || velocity_x == 0 ||
        velocity_y == 0 || steps < 0 || steps > ORBIT_STEPS_MAX ||
        timestep <= 0 || timestep > 65536 || mu <= 0) {
        return -1;
    }
    for (step = 0; step < steps; ++step) {
        int32_t rx = *position_x;
        int32_t ry = *position_y;
        int32_t radius_squared =
            orbit_mul_q16(rx, rx) + orbit_mul_q16(ry, ry);
        int32_t acceleration;
        if (radius_squared <= 0) {
            return -2;
        }
        acceleration = orbit_div_q16(mu, radius_squared);
        *velocity_x -= orbit_mul_q16(orbit_mul_q16(acceleration, rx), timestep);
        *velocity_y -= orbit_mul_q16(orbit_mul_q16(acceleration, ry), timestep);
        *position_x += orbit_mul_q16(*velocity_x, timestep);
        *position_y += orbit_mul_q16(*velocity_y, timestep);
    }
    return steps;
}
