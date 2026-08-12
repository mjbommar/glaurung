#include <stdint.h>

/* Insertion sort and Shell sort with the Knuth 3h+1 gap sequence.  Both are
 * inner loops whose trip count depends on the data, and Shell's outer gap loop
 * divides by three, which lowers to a multiply-high sequence at -O2. */

#define SORT_MAX 16

__attribute__((noinline)) int32_t
insertion_sort_i32(int32_t *values, int32_t count) {
    int32_t index;
    if (values == 0 || count < 0 || count > SORT_MAX) {
        return -1;
    }
    for (index = 1; index < count; ++index) {
        int32_t key = values[index];
        int32_t scan = index - 1;
        while (scan >= 0 && values[scan] > key) {
            values[scan + 1] = values[scan];
            scan -= 1;
        }
        values[scan + 1] = key;
    }
    return count;
}

__attribute__((noinline)) int32_t
shell_sort_i32(int32_t *values, int32_t count) {
    int32_t gap = 1;
    int32_t index;
    if (values == 0 || count < 0 || count > SORT_MAX) {
        return -1;
    }
    while (gap < count / 3) {
        gap = 3 * gap + 1;
    }
    while (gap >= 1) {
        for (index = gap; index < count; ++index) {
            int32_t key = values[index];
            int32_t scan = index - gap;
            while (scan >= 0 && values[scan] > key) {
                values[scan + gap] = values[scan];
                scan -= gap;
            }
            values[scan + gap] = key;
        }
        gap = gap / 3;
    }
    for (index = 1; index < count; ++index) {
        if (values[index - 1] > values[index]) {
            return 0;
        }
    }
    return count;
}
