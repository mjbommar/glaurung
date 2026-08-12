#include <stdint.h>

/* Portfolio drift and rebalancing trades.  Weights are Q16.16 fractions that
 * must sum to one; the trade vector is the signed difference against target
 * weights, written into a caller-owned buffer. */

#define PORTFOLIO_MAX 8

static int32_t folio_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
maximum_drift(const int32_t *values, const int32_t *target_weights,
              int32_t count) {
    int64_t total = 0;
    int32_t worst = 0;
    int32_t index;
    if (values == 0 || target_weights == 0 || count < 1 ||
        count > PORTFOLIO_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (values[index] < 0) {
            return -2;
        }
        total += values[index];
    }
    if (total <= 0) {
        return -3;
    }
    for (index = 0; index < count; ++index) {
        int32_t weight = folio_div_q16(values[index], (int32_t)total);
        int32_t drift = weight - target_weights[index];
        int32_t magnitude = (drift < 0) ? -drift : drift;
        if (magnitude > worst) {
            worst = magnitude;
        }
    }
    return worst;
}

__attribute__((noinline)) int32_t
rebalance_trades(const int32_t *values, const int32_t *target_weights,
                 int32_t count, int32_t *trades) {
    int64_t total = 0;
    int32_t index;
    int32_t nonzero = 0;
    if (values == 0 || target_weights == 0 || trades == 0 || count < 1 ||
        count > PORTFOLIO_MAX) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        if (values[index] < 0) {
            return -2;
        }
        total += values[index];
    }
    if (total <= 0 || total > 2147483647LL) {
        return -3;
    }
    for (index = 0; index < count; ++index) {
        int32_t desired =
            (int32_t)(((int64_t)total * (int64_t)target_weights[index]) >> 16);
        trades[index] = desired - values[index];
        if (trades[index] != 0) {
            nonzero += 1;
        }
    }
    return nonzero;
}
