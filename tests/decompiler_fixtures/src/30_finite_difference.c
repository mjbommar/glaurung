#include <stdint.h>

__attribute__((noinline)) uint32_t heat_step_1d(int32_t *destination,
                                                const int32_t *source,
                                                int32_t n) {
    uint32_t checksum = 0;
    int32_t i;
    if (destination == 0 || source == 0 || n < 0 || n > 16) {
        return 0;
    }
    if (n > 0) {
        destination[0] = source[0];
    }
    for (i = 1; i + 1 < n; ++i) {
        int64_t weighted = (int64_t)source[i - 1] +
                           2 * (int64_t)source[i] + source[i + 1];
        destination[i] = (int32_t)(weighted / 4);
    }
    if (n > 1) {
        destination[n - 1] = source[n - 1];
    }
    for (i = 0; i < n; ++i) {
        checksum = checksum * 33u + (uint32_t)destination[i];
    }
    return checksum;
}
