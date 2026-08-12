#include <stdint.h>

/* Ballistic trajectory in Q16.16: position and velocity integrated under
 * constant gravity, with an impact test.  Two coupled state variables update
 * per step, the classic physics-loop shape. */

#define KIN_STEPS_MAX 32
#define KIN_GRAVITY 642245 /* 9.8 m/s^2 in Q16.16 */

static int32_t kin_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

__attribute__((noinline)) int32_t
projectile_step(int32_t initial_height, int32_t initial_velocity,
                int32_t timestep, int32_t steps, int32_t *impact_step) {
    int32_t height = initial_height;
    int32_t velocity = initial_velocity;
    int32_t step;
    if (impact_step == 0 || steps < 0 || steps > KIN_STEPS_MAX ||
        timestep <= 0 || timestep > 65536) {
        return 0;
    }
    *impact_step = -1;
    for (step = 0; step < steps; ++step) {
        velocity -= kin_mul_q16(KIN_GRAVITY, timestep);
        height += kin_mul_q16(velocity, timestep);
        if (height <= 0) {
            *impact_step = step;
            height = 0;
            velocity = 0;
            break;
        }
    }
    return height;
}

__attribute__((noinline)) int32_t
kinetic_energy(int32_t mass, int32_t velocity) {
    int32_t square = kin_mul_q16(velocity, velocity);
    return kin_mul_q16(mass, square) / 2;
}
