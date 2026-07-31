#include <stdint.h>

__attribute__((noinline)) int32_t merge_sort_i32(int32_t *values, int32_t n) {
    int32_t temp[16];
    int32_t width;
    if (values == 0 || n < 0 || n > 16) {
        return -1;
    }
    for (width = 1; width < n; width *= 2) {
        int32_t left;
        for (left = 0; left < n; left += width * 2) {
            int32_t middle = left + width < n ? left + width : n;
            int32_t right = left + width * 2 < n ? left + width * 2 : n;
            int32_t i = left;
            int32_t j = middle;
            int32_t out = left;
            while (i < middle && j < right) {
                temp[out++] = values[i] <= values[j] ? values[i++] : values[j++];
            }
            while (i < middle) {
                temp[out++] = values[i++];
            }
            while (j < right) {
                temp[out++] = values[j++];
            }
            for (i = left; i < right; ++i) {
                values[i] = temp[i];
            }
        }
    }
    return n > 0 ? values[n / 2] : 0;
}
