#include <stdint.h>

/* Minimum-coin change and the count of distinct combinations.  The sentinel
 * "unreachable" value participates in arithmetic comparisons, which is where
 * an over-eager value-range narrowing shows up. */

#define COIN_KINDS 8
#define COIN_TARGET 32
#define COIN_UNREACHABLE 1000000

__attribute__((noinline)) int32_t
min_coins(const int32_t *denominations, int32_t kinds, int32_t target) {
    int32_t best[COIN_TARGET + 1];
    int32_t amount;
    int32_t kind;
    if (denominations == 0 || kinds < 0 || kinds > COIN_KINDS || target < 0 ||
        target > COIN_TARGET) {
        return -1;
    }
    best[0] = 0;
    for (amount = 1; amount <= target; ++amount) {
        best[amount] = COIN_UNREACHABLE;
    }
    for (amount = 1; amount <= target; ++amount) {
        for (kind = 0; kind < kinds; ++kind) {
            int32_t coin = denominations[kind];
            if (coin > 0 && coin <= amount) {
                int32_t candidate = best[amount - coin];
                if (candidate != COIN_UNREACHABLE && candidate + 1 < best[amount]) {
                    best[amount] = candidate + 1;
                }
            }
        }
    }
    if (best[target] == COIN_UNREACHABLE) {
        return -2;
    }
    return best[target];
}

__attribute__((noinline)) uint32_t
count_change(const int32_t *denominations, int32_t kinds, int32_t target) {
    uint32_t ways[COIN_TARGET + 1];
    int32_t amount;
    int32_t kind;
    if (denominations == 0 || kinds < 0 || kinds > COIN_KINDS || target < 0 ||
        target > COIN_TARGET) {
        return 0;
    }
    ways[0] = 1;
    for (amount = 1; amount <= target; ++amount) {
        ways[amount] = 0;
    }
    for (kind = 0; kind < kinds; ++kind) {
        int32_t coin = denominations[kind];
        if (coin <= 0 || coin > target) {
            continue;
        }
        for (amount = coin; amount <= target; ++amount) {
            ways[amount] += ways[amount - coin];
        }
    }
    return ways[target];
}
