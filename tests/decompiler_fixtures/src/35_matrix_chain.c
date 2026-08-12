#include <stdint.h>

/* Matrix-chain multiplication cost by interval dynamic programming.  The
 * triangular iteration order (length, then start, then split) yields three
 * nested loops whose bounds all depend on the enclosing induction variable. */

#define CHAIN_MAX 7
#define CHAIN_STRIDE (CHAIN_MAX + 1)
#define CHAIN_INFINITE 2000000000

__attribute__((noinline)) int32_t
matrix_chain_cost(const int32_t *dimensions, int32_t matrices) {
    int32_t cost[CHAIN_STRIDE * CHAIN_STRIDE];
    int32_t length;
    int32_t start;
    int32_t split;
    int32_t i;
    int32_t j;
    if (dimensions == 0 || matrices < 1 || matrices > CHAIN_MAX) {
        return -1;
    }
    for (i = 0; i < CHAIN_STRIDE; ++i) {
        for (j = 0; j < CHAIN_STRIDE; ++j) {
            cost[i * CHAIN_STRIDE + j] = 0;
        }
    }
    for (i = 0; i <= matrices; ++i) {
        if (dimensions[i] <= 0 || dimensions[i] > 64) {
            return -2;
        }
    }
    for (length = 2; length <= matrices; ++length) {
        for (start = 0; start + length - 1 < matrices; ++start) {
            int32_t end = start + length - 1;
            int32_t best = CHAIN_INFINITE;
            for (split = start; split < end; ++split) {
                int32_t left = cost[start * CHAIN_STRIDE + split];
                int32_t right = cost[(split + 1) * CHAIN_STRIDE + end];
                int32_t merge = dimensions[start] * dimensions[split + 1] *
                                dimensions[end + 1];
                int32_t candidate = left + right + merge;
                if (candidate < best) {
                    best = candidate;
                }
            }
            cost[start * CHAIN_STRIDE + end] = best;
        }
    }
    return cost[matrices - 1];
}
