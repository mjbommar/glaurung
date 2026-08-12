#include <stdint.h>

/* Gaussian elimination with partial pivoting on a Q16.16 augmented matrix.
 * Row swapping through an index indirection, a scaled subtract across a row,
 * and back-substitution in reverse order compose the densest 2D-indexing case
 * in the corpus. */

#define GAUSS_DIM 4

static int32_t gauss_mul_q16(int32_t left, int32_t right) {
    return (int32_t)(((int64_t)left * (int64_t)right) >> 16);
}

static int32_t gauss_div_q16(int32_t numerator, int32_t denominator) {
    if (denominator == 0) {
        return 0;
    }
    return (int32_t)(((int64_t)numerator << 16) / (int64_t)denominator);
}

__attribute__((noinline)) int32_t
gaussian_solve(int32_t *augmented, int32_t dimension, int32_t *solution) {
    int32_t pivot;
    int32_t row;
    int32_t column;
    int32_t stride;
    if (augmented == 0 || solution == 0 || dimension < 1 ||
        dimension > GAUSS_DIM) {
        return -1;
    }
    stride = dimension + 1;
    for (pivot = 0; pivot < dimension; ++pivot) {
        int32_t best = pivot;
        int32_t best_magnitude;
        for (row = pivot + 1; row < dimension; ++row) {
            int32_t candidate = augmented[row * stride + pivot];
            int32_t current = augmented[best * stride + pivot];
            int32_t candidate_magnitude = (candidate < 0) ? -candidate : candidate;
            int32_t current_magnitude = (current < 0) ? -current : current;
            if (candidate_magnitude > current_magnitude) {
                best = row;
            }
        }
        if (best != pivot) {
            for (column = 0; column < stride; ++column) {
                int32_t swap = augmented[pivot * stride + column];
                augmented[pivot * stride + column] =
                    augmented[best * stride + column];
                augmented[best * stride + column] = swap;
            }
        }
        best_magnitude = augmented[pivot * stride + pivot];
        if (best_magnitude == 0) {
            return -2;
        }
        for (row = pivot + 1; row < dimension; ++row) {
            int32_t factor =
                gauss_div_q16(augmented[row * stride + pivot], best_magnitude);
            for (column = pivot; column < stride; ++column) {
                augmented[row * stride + column] -=
                    gauss_mul_q16(factor, augmented[pivot * stride + column]);
            }
        }
    }
    for (row = dimension - 1; row >= 0; --row) {
        int32_t accumulator = augmented[row * stride + dimension];
        for (column = row + 1; column < dimension; ++column) {
            accumulator -=
                gauss_mul_q16(augmented[row * stride + column], solution[column]);
        }
        solution[row] = gauss_div_q16(accumulator, augmented[row * stride + row]);
    }
    return dimension;
}
