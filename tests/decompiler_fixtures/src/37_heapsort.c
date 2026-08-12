#include <stdint.h>

/* In-place heapsort: sift-down with two child indices and a trailing swap
 * loop.  The child-index arithmetic (2i+1, 2i+2) and its bounds test are a
 * compact strength-reduction target at -O2. */

#define HS_MAX 16

static void sift_down(int32_t *values, int32_t root, int32_t count) {
    int32_t guard;
    for (guard = 0; guard < HS_MAX; ++guard) {
        int32_t left = 2 * root + 1;
        int32_t right = left + 1;
        int32_t largest = root;
        int32_t swap;
        if (left < count && values[left] > values[largest]) {
            largest = left;
        }
        if (right < count && values[right] > values[largest]) {
            largest = right;
        }
        if (largest == root) {
            return;
        }
        swap = values[root];
        values[root] = values[largest];
        values[largest] = swap;
        root = largest;
    }
}

__attribute__((noinline)) int32_t
heapsort_i32(int32_t *values, int32_t count) {
    int32_t index;
    if (values == 0 || count < 0 || count > HS_MAX) {
        return -1;
    }
    for (index = count / 2 - 1; index >= 0; --index) {
        sift_down(values, index, count);
    }
    for (index = count - 1; index > 0; --index) {
        int32_t swap = values[0];
        values[0] = values[index];
        values[index] = swap;
        sift_down(values, 0, index);
    }
    for (index = 1; index < count; ++index) {
        if (values[index - 1] > values[index]) {
            return 0;
        }
    }
    return count;
}
