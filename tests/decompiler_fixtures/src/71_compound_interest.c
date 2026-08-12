#include <stdint.h>

/* Compound growth in Q16.16 with per-period compounding, plus a future value
 * for a regular contribution stream.  The repeated multiply-accumulate is the
 * finance analogue of a stencil: small body, exact carry requirements. */

#define FIN_PERIODS_MAX 32

static int32_t fin_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

__attribute__((noinline)) int32_t
compound_balance(int32_t principal, int32_t rate_per_period, int32_t periods) {
    int32_t balance = principal;
    int32_t period;
    if (principal < 0 || rate_per_period < 0 || rate_per_period > 65536 ||
        periods < 0 || periods > FIN_PERIODS_MAX) {
        return -1;
    }
    for (period = 0; period < periods; ++period) {
        balance += fin_mul_q16(balance, rate_per_period);
    }
    return balance;
}

__attribute__((noinline)) int32_t
annuity_future_value(int32_t contribution, int32_t rate_per_period,
                     int32_t periods) {
    int32_t balance = 0;
    int32_t period;
    if (contribution < 0 || rate_per_period < 0 || rate_per_period > 65536 ||
        periods < 0 || periods > FIN_PERIODS_MAX) {
        return -1;
    }
    for (period = 0; period < periods; ++period) {
        balance += fin_mul_q16(balance, rate_per_period);
        balance += contribution;
    }
    return balance;
}
