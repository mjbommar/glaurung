#include <stdint.h>

/* Genuinely recursive Lomuto quicksort with an explicit depth bound.  The rest
 * of the corpus deliberately uses explicit stacks; this fixture exists so that
 * real self-recursion, its base cases, and the recursive frame are covered. */

#define QS_MAX 16

static int32_t partition_lomuto(int32_t *values, int32_t low, int32_t high) {
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
    return boundary;
}

static void quicksort_range(int32_t *values, int32_t low, int32_t high,
                            int32_t depth) {
    if (low >= high || depth <= 0) {
        return;
    }
    {
        int32_t split = partition_lomuto(values, low, high);
        quicksort_range(values, low, split - 1, depth - 1);
        quicksort_range(values, split + 1, high, depth - 1);
    }
}

__attribute__((noinline)) int32_t
quicksort_i32(int32_t *values, int32_t count) {
    int32_t index;
    if (values == 0 || count < 0 || count > QS_MAX) {
        return -1;
    }
    quicksort_range(values, 0, count - 1, QS_MAX * 2);
    for (index = 1; index < count; ++index) {
        if (values[index - 1] > values[index]) {
            return 0;
        }
    }
    return count;
}
