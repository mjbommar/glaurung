#include <stdint.h>

/* A loan amortisation schedule written into caller-owned buffers: each period
 * splits a fixed payment into interest and principal, and the final period
 * absorbs the rounding remainder.  Two parallel output buffers advance with
 * one induction variable. */

#define LOAN_PERIODS_MAX 12

static int32_t loan_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

__attribute__((noinline)) int32_t
amortization_schedule(int32_t principal, int32_t rate_per_period,
                      int32_t payment, int32_t periods, int32_t *interest_out,
                      int32_t *principal_out) {
    int32_t balance = principal;
    int32_t period;
    if (interest_out == 0 || principal_out == 0 || principal < 0 ||
        rate_per_period < 0 || rate_per_period > 65536 || payment <= 0 ||
        periods < 0 || periods > LOAN_PERIODS_MAX) {
        return -1;
    }
    for (period = 0; period < periods; ++period) {
        int32_t interest = loan_mul_q16(balance, rate_per_period);
        int32_t reduction = payment - interest;
        if (reduction < 0) {
            return -2;
        }
        if (reduction > balance) {
            reduction = balance;
        }
        interest_out[period] = interest;
        principal_out[period] = reduction;
        balance -= reduction;
    }
    return balance;
}

__attribute__((noinline)) int32_t
remaining_balance(int32_t principal, int32_t rate_per_period, int32_t payment,
                  int32_t periods) {
    int32_t balance = principal;
    int32_t period;
    if (principal < 0 || rate_per_period < 0 || rate_per_period > 65536 ||
        payment <= 0 || periods < 0 || periods > LOAN_PERIODS_MAX) {
        return -1;
    }
    for (period = 0; period < periods && balance > 0; ++period) {
        int32_t interest = loan_mul_q16(balance, rate_per_period);
        int32_t reduction = payment - interest;
        if (reduction <= 0) {
            return balance;
        }
        balance -= (reduction > balance) ? balance : reduction;
    }
    return balance;
}
