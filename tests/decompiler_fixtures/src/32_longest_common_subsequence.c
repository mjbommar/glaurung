#include <stdint.h>

/* Longest common subsequence length plus a reconstructed subsequence.  The
 * reconstruction walks the table backwards and writes into a caller-owned
 * output buffer, so both the forward table stride and a reverse loop with a
 * two-variable induction must survive lowering. */

#define LCS_MAX 8
#define LCS_STRIDE (LCS_MAX + 1)

__attribute__((noinline)) int32_t
lcs_length(const uint8_t *left, int32_t left_length, const uint8_t *right,
           int32_t right_length) {
    int32_t table[LCS_STRIDE * LCS_STRIDE];
    int32_t i;
    int32_t j;
    if (left == 0 || right == 0 || left_length < 0 || right_length < 0 ||
        left_length > LCS_MAX || right_length > LCS_MAX) {
        return -1;
    }
    for (i = 0; i <= left_length; ++i) {
        for (j = 0; j <= right_length; ++j) {
            if (i == 0 || j == 0) {
                table[i * LCS_STRIDE + j] = 0;
            } else if (left[i - 1] == right[j - 1]) {
                table[i * LCS_STRIDE + j] =
                    table[(i - 1) * LCS_STRIDE + (j - 1)] + 1;
            } else {
                int32_t up = table[(i - 1) * LCS_STRIDE + j];
                int32_t back = table[i * LCS_STRIDE + (j - 1)];
                table[i * LCS_STRIDE + j] = (up >= back) ? up : back;
            }
        }
    }
    return table[left_length * LCS_STRIDE + right_length];
}

__attribute__((noinline)) int32_t
lcs_recover(const uint8_t *left, int32_t left_length, const uint8_t *right,
            int32_t right_length, uint8_t *output) {
    int32_t table[LCS_STRIDE * LCS_STRIDE];
    int32_t i;
    int32_t j;
    int32_t produced;
    int32_t head;
    if (left == 0 || right == 0 || output == 0 || left_length < 0 ||
        right_length < 0 || left_length > LCS_MAX || right_length > LCS_MAX) {
        return -1;
    }
    for (i = 0; i <= left_length; ++i) {
        for (j = 0; j <= right_length; ++j) {
            if (i == 0 || j == 0) {
                table[i * LCS_STRIDE + j] = 0;
            } else if (left[i - 1] == right[j - 1]) {
                table[i * LCS_STRIDE + j] =
                    table[(i - 1) * LCS_STRIDE + (j - 1)] + 1;
            } else {
                int32_t up = table[(i - 1) * LCS_STRIDE + j];
                int32_t back = table[i * LCS_STRIDE + (j - 1)];
                table[i * LCS_STRIDE + j] = (up >= back) ? up : back;
            }
        }
    }
    produced = 0;
    i = left_length;
    j = right_length;
    while (i > 0 && j > 0 && produced < LCS_MAX) {
        if (left[i - 1] == right[j - 1]) {
            output[produced] = left[i - 1];
            produced += 1;
            i -= 1;
            j -= 1;
        } else if (table[(i - 1) * LCS_STRIDE + j] >=
                   table[i * LCS_STRIDE + (j - 1)]) {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    for (head = 0; head < produced / 2; ++head) {
        uint8_t swap = output[head];
        output[head] = output[produced - 1 - head];
        output[produced - 1 - head] = swap;
    }
    return produced;
}
