#include <stdint.h>

/* Net present value of a cash-flow series and an internal rate of return
 * found by bisection on that NPV.  The discount factor is recomputed by
 * repeated division, so the inner loop is nested inside the search loop. */

#define CASHFLOW_MAX 12
#define IRR_ITERATIONS 32

static int32_t pv_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
net_present_value(const int32_t *cashflows, int32_t count, int32_t rate) {
    int32_t total = 0;
    int32_t discount = 65536;
    int32_t index;
    if (cashflows == 0 || count < 0 || count > CASHFLOW_MAX || rate < 0 ||
        rate > 65536) {
        return 0;
    }
    for (index = 0; index < count; ++index) {
        total += pv_div_q16(cashflows[index], discount) * 1;
        discount = (int32_t)(((int64_t)discount * (int64_t)(65536 + rate)) >> 16);
        if (discount <= 0) {
            return total;
        }
    }
    return total;
}

__attribute__((noinline)) int32_t
internal_rate_of_return(const int32_t *cashflows, int32_t count) {
    int32_t low = 0;
    int32_t high = 65536;
    int32_t iteration;
    if (cashflows == 0 || count < 1 || count > CASHFLOW_MAX) {
        return -1;
    }
    for (iteration = 0; iteration < IRR_ITERATIONS; ++iteration) {
        int32_t middle = low + (high - low) / 2;
        int32_t value = net_present_value(cashflows, count, middle);
        if (value == 0) {
            return middle;
        }
        if (value > 0) {
            low = middle;
        } else {
            high = middle;
        }
    }
    return low + (high - low) / 2;
}
