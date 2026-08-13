#include <stdint.h>

/* A small floating-point numeric kernel over CALLER-OWNED buffers: a dot
 * product at both widths, and the 2x2 matrix operations built on it.
 *
 * This is the shape the SysV ABI stresses hardest — floating values arriving in
 * xmm0..7 while the pointers arrive in the integer registers, and a loop whose
 * accumulator lives in a register the integer corpus never made the decompiler
 * account for.  The buffers also give the differential something to compare
 * besides a return value: `matrix2_multiply` writes its result through a
 * pointer, so a recovery that computes the right numbers and stores them in the
 * wrong cells still fails.
 *
 * Every count is validated against a literal bound before it indexes anything,
 * every loop is bounded by that count, and the fixed-size matrix entry points
 * touch exactly four elements of buffers the harness allocates with sixteen. */

#define FP175_MAX_ELEMENTS 16
#define FP175_MATRIX_CELLS 4

static float fp175_dot_f32(const float *left, const float *right,
                           int32_t count) {
    float total = 0.0f;
    int32_t index;
    for (index = 0; index < count; ++index) {
        total += left[index] * right[index];
    }
    return total;
}

static int fp175_count_ok(int32_t count) {
    return count >= 0 && count <= FP175_MAX_ELEMENTS;
}

__attribute__((noinline)) float dot_product_f32(const float *left,
                                                const float *right,
                                                int32_t count) {
    if (left == 0 || right == 0 || !fp175_count_ok(count)) {
        return 0.0f;
    }
    return fp175_dot_f32(left, right, count);
}

/* The binary64 twin.  Same source, one width up: the element loads, the
 * multiply and the accumulator all change instruction, and a recovery that
 * types one from the other disagrees on any inexact input. */
__attribute__((noinline)) double dot_product_f64(const double *left,
                                                 const double *right,
                                                 int32_t count) {
    double total = 0.0;
    int32_t index;
    if (left == 0 || right == 0 || !fp175_count_ok(count)) {
        return 0.0;
    }
    for (index = 0; index < count; ++index) {
        total += left[index] * right[index];
    }
    return total;
}

/* Squares accumulated one width above the elements, so the total keeps digits a
 * binary32 accumulator drops. */
__attribute__((noinline)) double sum_of_squares_f32(const float *series,
                                                    int32_t count) {
    double total = 0.0;
    int32_t index;
    if (series == 0 || !fp175_count_ok(count)) {
        return 0.0;
    }
    for (index = 0; index < count; ++index) {
        total += (double)series[index] * (double)series[index];
    }
    return total;
}

/* Row-major 2x2: cells[0] cells[1] / cells[2] cells[3]. */
__attribute__((noinline)) float matrix2_determinant(const float *cells) {
    if (cells == 0) {
        return 0.0f;
    }
    return cells[0] * cells[3] - cells[1] * cells[2];
}

/* result = left * right, four dot products of length two.  `result` is a
 * distinct caller-owned buffer, so no cell is read after it is overwritten. */
__attribute__((noinline)) int32_t matrix2_multiply(const float *left,
                                                   const float *right,
                                                   float *result) {
    if (left == 0 || right == 0 || result == 0) {
        return -1;
    }
    result[0] = left[0] * right[0] + left[1] * right[2];
    result[1] = left[0] * right[1] + left[1] * right[3];
    result[2] = left[2] * right[0] + left[3] * right[2];
    result[3] = left[2] * right[1] + left[3] * right[3];
    return FP175_MATRIX_CELLS;
}

/* In-place scaling: the buffer mutation IS the observable, and the return value
 * only reports how many elements were touched. */
__attribute__((noinline)) int32_t scale_series_f32(float *series, int32_t count,
                                                   float factor) {
    int32_t index;
    if (series == 0 || !fp175_count_ok(count)) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        series[index] = series[index] * factor;
    }
    return count;
}
