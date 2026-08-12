#include <stdint.h>

/* 0/1 knapsack by rolling one-dimensional capacity array, iterated in reverse
 * so each item is used at most once.  The reverse inner loop with a
 * data-dependent lower bound is a common structuring failure. */

#define KNAP_ITEMS 8
#define KNAP_CAPACITY 16

__attribute__((noinline)) int32_t
knapsack_best_value(const int32_t *weights, const int32_t *values,
                    int32_t item_count, int32_t capacity) {
    int32_t best[KNAP_CAPACITY + 1];
    int32_t item;
    int32_t room;
    if (weights == 0 || values == 0 || item_count < 0 ||
        item_count > KNAP_ITEMS || capacity < 0 || capacity > KNAP_CAPACITY) {
        return -1;
    }
    for (room = 0; room <= capacity; ++room) {
        best[room] = 0;
    }
    for (item = 0; item < item_count; ++item) {
        int32_t weight = weights[item];
        int32_t value = values[item];
        if (weight <= 0 || weight > capacity || value < 0) {
            continue;
        }
        for (room = capacity; room >= weight; --room) {
            int32_t candidate = best[room - weight] + value;
            if (candidate > best[room]) {
                best[room] = candidate;
            }
        }
    }
    return best[capacity];
}

__attribute__((noinline)) int32_t
unbounded_knapsack(const int32_t *weights, const int32_t *values,
                   int32_t item_count, int32_t capacity) {
    int32_t best[KNAP_CAPACITY + 1];
    int32_t item;
    int32_t room;
    if (weights == 0 || values == 0 || item_count < 0 ||
        item_count > KNAP_ITEMS || capacity < 0 || capacity > KNAP_CAPACITY) {
        return -1;
    }
    for (room = 0; room <= capacity; ++room) {
        best[room] = 0;
    }
    for (room = 1; room <= capacity; ++room) {
        for (item = 0; item < item_count; ++item) {
            int32_t weight = weights[item];
            int32_t value = values[item];
            if (weight > 0 && weight <= room && value >= 0) {
                int32_t candidate = best[room - weight] + value;
                if (candidate > best[room]) {
                    best[room] = candidate;
                }
            }
        }
    }
    return best[capacity];
}
