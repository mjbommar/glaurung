#include <stdint.h>

/* A true 2D array is one object with a compound stride; an array of pointers is
 * two loads. The functions below are deliberately confusable at the source
 * level and completely different in the binary. */

#define GRID_ROWS 4
#define GRID_COLUMNS 4

__attribute__((noinline)) int32_t
sum_true_2d(const int32_t grid[GRID_ROWS][GRID_COLUMNS], int32_t rows) {
    int32_t total = 0;
    int32_t row;
    int32_t column;
    if (grid == 0 || rows < 0 || rows > GRID_ROWS) {
        return -1;
    }
    for (row = 0; row < rows; ++row) {
        for (column = 0; column < GRID_COLUMNS; ++column) {
            total += grid[row][column];
        }
    }
    return total;
}

__attribute__((noinline)) int32_t
sum_flat_with_stride(const int32_t *flat, int32_t rows, int32_t columns) {
    int32_t total = 0;
    int32_t row;
    int32_t column;
    if (flat == 0 || rows < 0 || rows > GRID_ROWS || columns < 0 ||
        columns > GRID_COLUMNS) {
        return -1;
    }
    for (row = 0; row < rows; ++row) {
        for (column = 0; column < columns; ++column) {
            total += flat[row * columns + column];
        }
    }
    return total;
}

__attribute__((noinline)) int32_t
row_decay_span(const int32_t grid[GRID_ROWS][GRID_COLUMNS], int32_t row) {
    const int32_t *decayed;
    if (grid == 0 || row < 0 || row >= GRID_ROWS) {
        return -1;
    }
    decayed = grid[row]; /* a row decays to int32_t*, not int32_t(*)[4] */
    return decayed[0] + decayed[GRID_COLUMNS - 1];
}
