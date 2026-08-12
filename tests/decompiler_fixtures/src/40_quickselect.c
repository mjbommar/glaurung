#include <stdint.h>

/* Iterative quickselect for the k-th smallest element, plus a median helper.
 * The loop narrows [low, high] from both ends, so the recovered code must keep
 * two independent induction variables and a data-dependent exit. */

#define QSEL_MAX 16

__attribute__((noinline)) int32_t
quickselect_kth(int32_t *values, int32_t count, int32_t k) {
    int32_t low = 0;
    int32_t high;
    int32_t guard;
    if (values == 0 || count <= 0 || count > QSEL_MAX || k < 0 || k >= count) {
        return -1;
    }
    high = count - 1;
    for (guard = 0; guard < QSEL_MAX * 2 && low < high; ++guard) {
        int32_t pivot = values[high];
        int32_t boundary = low;
        int32_t scan;
        for (scan = low; scan < high; ++scan) {
            if (values[scan] <= pivot) {
                int32_t swap = values[boundary];
                values[boundary] = values[scan];
                values[scan] = swap;
                boundary += 1;
            }
        }
        values[high] = values[boundary];
        values[boundary] = pivot;
        if (boundary == k) {
            return values[boundary];
        }
        if (k < boundary) {
            high = boundary - 1;
        } else {
            low = boundary + 1;
        }
    }
    return values[low];
}

__attribute__((noinline)) int32_t
median_of_three(int32_t a, int32_t b, int32_t c) {
    if ((a >= b && a <= c) || (a <= b && a >= c)) {
        return a;
    }
    if ((b >= a && b <= c) || (b <= a && b >= c)) {
        return b;
    }
    return c;
}
