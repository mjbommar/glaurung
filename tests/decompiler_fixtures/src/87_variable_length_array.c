#include <stdint.h>

/* C99 variable-length arrays. The element count is a runtime value, so the
 * frame is sized dynamically and indexing uses a runtime stride. The count is
 * hard-clamped: an unbounded VLA would be a stack-overflow hazard, not a test. */

#define VLA_LIMIT 16

__attribute__((noinline)) int32_t
vla_reverse_sum(const int32_t *input, int32_t count) {
    if (input == 0 || count < 1 || count > VLA_LIMIT) {
        return -1;
    }
    {
        int32_t scratch[count];
        int32_t index;
        int32_t total = 0;
        for (index = 0; index < count; ++index) {
            scratch[count - 1 - index] = input[index];
        }
        for (index = 0; index < count; ++index) {
            total += scratch[index] * (index + 1);
        }
        return total;
    }
}

__attribute__((noinline)) int32_t
vla_two_dimensional(int32_t rows, int32_t columns) {
    if (rows < 1 || rows > 4 || columns < 1 || columns > 4) {
        return -1;
    }
    {
        int32_t grid[rows][columns];
        int32_t row;
        int32_t column;
        int32_t total = 0;
        for (row = 0; row < rows; ++row) {
            for (column = 0; column < columns; ++column) {
                grid[row][column] = row * columns + column;
            }
        }
        for (row = 0; row < rows; ++row) {
            for (column = 0; column < columns; ++column) {
                total += grid[row][column];
            }
        }
        return total;
    }
}
