#include <stdint.h>

/* Ideal-gas pressure, Newton's law of cooling over discrete steps, and a
 * mixing temperature.  The cooling loop is a geometric decay whose factor is
 * recomputed each step from two parameters. */

#define THERMO_STEPS_MAX 24

static int32_t thermo_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t thermo_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
ideal_gas_pressure(int32_t moles, int32_t temperature, int32_t volume) {
    int32_t gas_constant = 544807; /* 8.314 in Q16.16 */
    int32_t numerator;
    if (volume <= 0 || moles < 0 || temperature < 0) {
        return 0;
    }
    numerator = thermo_mul_q16(thermo_mul_q16(moles, gas_constant), temperature);
    return thermo_div_q16(numerator, volume);
}

__attribute__((noinline)) int32_t
newton_cooling(int32_t temperature, int32_t ambient, int32_t rate,
               int32_t steps) {
    int32_t step;
    if (steps < 0 || steps > THERMO_STEPS_MAX || rate < 0 || rate > 65536) {
        return temperature;
    }
    for (step = 0; step < steps; ++step) {
        int32_t difference = temperature - ambient;
        temperature -= thermo_mul_q16(rate, difference);
    }
    return temperature;
}

__attribute__((noinline)) int32_t
mixing_temperature(int32_t mass_a, int32_t temperature_a, int32_t mass_b,
                   int32_t temperature_b) {
    int32_t total = mass_a + mass_b;
    int32_t weighted;
    if (mass_a < 0 || mass_b < 0 || total <= 0) {
        return 0;
    }
    weighted = thermo_mul_q16(mass_a, temperature_a) +
               thermo_mul_q16(mass_b, temperature_b);
    return thermo_div_q16(weighted, total);
}
