#include <stdint.h>

/* Simple and exponential moving averages plus a population variance, all in
 * Q16.16.  Variance accumulates squares in a 64-bit total and divides once at
 * the end, a common width-narrowing failure point. */

#define SERIES_MAX 16

static int32_t stat_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

__attribute__((noinline)) int32_t
simple_moving_average(const int32_t *series, int32_t count, int32_t window,
                      int32_t *output) {
    int32_t index;
    if (series == 0 || output == 0 || count < 0 || count > SERIES_MAX ||
        window < 1 || window > SERIES_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        int64_t total = 0;
        int32_t taken = 0;
        int32_t back;
        for (back = 0; back < window && index - back >= 0; ++back) {
            total += series[index - back];
            taken += 1;
        }
        output[index] = (taken > 0) ? (int32_t)(total / taken) : 0;
    }
    return count;
}

__attribute__((noinline)) int32_t
exponential_moving_average(const int32_t *series, int32_t count, int32_t alpha) {
    int32_t average;
    int32_t index;
    if (series == 0 || count < 1 || count > SERIES_MAX || alpha < 0 ||
        alpha > 65536) {
        return 0;
    }
    average = series[0];
    for (index = 1; index < count; ++index) {
        int32_t difference = series[index] - average;
        average += stat_mul_q16(alpha, difference);
    }
    return average;
}

__attribute__((noinline)) int32_t
population_variance(const int32_t *series, int32_t count) {
    int64_t total = 0;
    int64_t squares = 0;
    int32_t mean;
    int32_t index;
    if (series == 0 || count < 1 || count > SERIES_MAX) {
        return 0;
    }
    for (index = 0; index < count; ++index) {
        total += series[index];
    }
    mean = (int32_t)(total / count);
    for (index = 0; index < count; ++index) {
        int64_t deviation = (int64_t)series[index] - (int64_t)mean;
        squares += (deviation * deviation) >> 16;
    }
    return (int32_t)(squares / count);
}
