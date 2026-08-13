#include <stdint.h>

/* Dense integer matrix multiply, transpose, and a 3x3 determinant.  The
 * multiply is the canonical triple loop with two different strides, and the
 * determinant is a flat expression over nine indexed loads. */

#define MAT_DIM 4

__attribute__((noinline)) int32_t
matrix_multiply(const int32_t *left, const int32_t *right, int32_t *output,
                int32_t dimension) {
    int32_t row;
    int32_t column;
    int32_t inner;
    if (left == 0 || right == 0 || output == 0 || dimension < 0 ||
        dimension > MAT_DIM) {
        return -1;
    }
    for (row = 0; row < dimension; ++row) {
        for (column = 0; column < dimension; ++column) {
            int32_t sum = 0;
            for (inner = 0; inner < dimension; ++inner) {
                sum += left[row * dimension + inner] *
                       right[inner * dimension + column];
            }
            output[row * dimension + column] = sum;
        }
    }
    return dimension * dimension;
}

__attribute__((noinline)) int32_t
matrix_transpose(const int32_t *input, int32_t *output, int32_t dimension) {
    int32_t row;
    int32_t column;
    if (input == 0 || output == 0 || dimension < 0 || dimension > MAT_DIM) {
        return -1;
    }
    for (row = 0; row < dimension; ++row) {
        for (column = 0; column < dimension; ++column) {
            output[column * dimension + row] = input[row * dimension + column];
        }
    }
    return dimension * dimension;
}

__attribute__((noinline)) int32_t
determinant3(const int32_t *matrix) {
    if (matrix == 0) {
        return 0;
    }
    return matrix[0] * (matrix[4] * matrix[8] - matrix[5] * matrix[7]) -
           matrix[1] * (matrix[3] * matrix[8] - matrix[5] * matrix[6]) +
           matrix[2] * (matrix[3] * matrix[7] - matrix[4] * matrix[6]);
}
