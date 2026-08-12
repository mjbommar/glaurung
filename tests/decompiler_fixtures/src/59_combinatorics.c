#include <stdint.h>

/* Pascal's triangle, binomial coefficients by multiplicative recurrence, and
 * Catalan numbers.  The multiplicative binomial divides exactly at each step,
 * so an incorrectly ordered multiply/divide overflows and diverges. */

#define PASCAL_MAX 12

__attribute__((noinline)) int32_t
pascal_row(int32_t row, uint32_t *output, int32_t capacity) {
    uint32_t value = 1;
    int32_t index;
    if (output == 0 || row < 0 || row > PASCAL_MAX || capacity < row + 1 ||
        capacity > PASCAL_MAX + 1) {
        return -1;
    }
    for (index = 0; index <= row; ++index) {
        output[index] = value;
        value = value * (uint32_t)(row - index) / (uint32_t)(index + 1);
    }
    return row + 1;
}

__attribute__((noinline)) uint32_t binomial(int32_t n, int32_t k) {
    uint64_t result = 1;
    int32_t step;
    if (n < 0 || k < 0 || k > n || n > 30) {
        return 0;
    }
    if (k > n - k) {
        k = n - k;
    }
    for (step = 0; step < k; ++step) {
        result = result * (uint64_t)(n - step) / (uint64_t)(step + 1);
    }
    return (uint32_t)result;
}

__attribute__((noinline)) uint32_t catalan(int32_t n) {
    uint64_t result = 1;
    int32_t step;
    if (n < 0 || n > 16) {
        return 0;
    }
    for (step = 0; step < n; ++step) {
        result = result * (uint64_t)(2 * n - step) / (uint64_t)(step + 1);
    }
    return (uint32_t)(result / (uint64_t)(n + 1));
}
