#include <stdint.h>

__attribute__((noinline)) uint32_t
polynomial_eval_mod32(const uint32_t *coefficients, int32_t count, uint32_t x) {
    uint32_t result = 0;
    int32_t i;
    if (coefficients == 0 || count < 0 || count > 16) {
        return 0;
    }
    for (i = count - 1; i >= 0; --i) {
        result = result * x + coefficients[i];
    }
    return result;
}

__attribute__((noinline)) uint32_t
polynomial_derivative_mod32(const uint32_t *coefficients, int32_t count,
                            uint32_t x) {
    uint32_t result = 0;
    int32_t i;
    if (coefficients == 0 || count < 0 || count > 16) {
        return 0;
    }
    for (i = count - 1; i > 0; --i) {
        result = result * x + coefficients[i] * (uint32_t)i;
    }
    return result;
}
