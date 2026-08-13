#include <stdint.h>

/* Levenshtein distance over a flat (ED_MAX+1)^2 table. The classic
 * three-way minimum makes the inner body a small dependence lattice: every
 * cell reads two previous rows/columns, so a decompiler must keep the row
 * stride and the -1 offsets exact to reproduce the result. */

#define ED_MAX 8
#define ED_STRIDE (ED_MAX + 1)

__attribute__((noinline)) int32_t
edit_distance(const uint8_t *left, int32_t left_length, const uint8_t *right,
              int32_t right_length) {
    int32_t table[ED_STRIDE * ED_STRIDE];
    int32_t i;
    int32_t j;
    if (left == 0 || right == 0 || left_length < 0 || right_length < 0 ||
        left_length > ED_MAX || right_length > ED_MAX) {
        return -1;
    }
    for (i = 0; i <= left_length; ++i) {
        table[i * ED_STRIDE] = i;
    }
    for (j = 0; j <= right_length; ++j) {
        table[j] = j;
    }
    for (i = 1; i <= left_length; ++i) {
        for (j = 1; j <= right_length; ++j) {
            int32_t cost = (left[i - 1] == right[j - 1]) ? 0 : 1;
            int32_t best = table[(i - 1) * ED_STRIDE + j] + 1;
            int32_t insertion = table[i * ED_STRIDE + (j - 1)] + 1;
            int32_t substitution = table[(i - 1) * ED_STRIDE + (j - 1)] + cost;
            if (insertion < best) {
                best = insertion;
            }
            if (substitution < best) {
                best = substitution;
            }
            table[i * ED_STRIDE + j] = best;
        }
    }
    return table[left_length * ED_STRIDE + right_length];
}

__attribute__((noinline)) int32_t
hamming_distance(const uint8_t *left, const uint8_t *right, int32_t length) {
    int32_t distance = 0;
    int32_t i;
    if (left == 0 || right == 0 || length < 0 || length > ED_MAX) {
        return -1;
    }
    for (i = 0; i < length; ++i) {
        if (left[i] != right[i]) {
            distance += 1;
        }
    }
    return distance;
}
