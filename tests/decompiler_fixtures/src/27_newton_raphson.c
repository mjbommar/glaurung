#include <stdint.h>

__attribute__((noinline)) uint32_t newton_isqrt(uint32_t value) {
    uint32_t estimate;
    int32_t iteration;
    if (value < 2u) {
        return value;
    }
    estimate = value / 2u + 1u;
    for (iteration = 0; iteration < 32; ++iteration) {
        uint32_t next = (estimate + value / estimate) / 2u;
        if (next >= estimate) {
            return estimate;
        }
        estimate = next;
    }
    return estimate;
}
