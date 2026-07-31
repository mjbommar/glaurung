#include <limits.h>
#include <stdint.h>

__attribute__((noinline)) int32_t euler_decay_q16(int32_t initial_q16,
                                                  int32_t rate_q16,
                                                  int32_t steps) {
    int64_t state = initial_q16;
    int32_t step;
    if (steps < 0 || steps > 32) {
        return initial_q16;
    }
    for (step = 0; step < steps; ++step) {
        int64_t delta = (state * (int64_t)rate_q16) / 65536;
        state -= delta;
        if (state > INT32_MAX) {
            state = INT32_MAX;
        } else if (state < INT32_MIN) {
            state = INT32_MIN;
        }
    }
    return (int32_t)state;
}
