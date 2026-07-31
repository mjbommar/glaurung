#include <stdint.h>

__attribute__((noinline)) uint32_t
csr_matvec(const int32_t *row_offsets, const int32_t *column_indices,
           const int32_t *values, const int32_t *vector, uint32_t *output,
           int32_t rows, int32_t columns, int32_t nonzeros) {
    uint32_t checksum = 0;
    int32_t row;
    if (row_offsets == 0 || column_indices == 0 || values == 0 || vector == 0 ||
        output == 0 || rows < 0 || rows > 15 || columns < 0 || columns > 16 ||
        nonzeros < 0 || nonzeros > 16) {
        return 0;
    }
    for (row = 0; row < rows; ++row) {
        int32_t begin = row_offsets[row];
        int32_t end = row_offsets[row + 1];
        uint32_t sum = 0;
        int32_t position;
        if (begin < 0 || end < begin || end > nonzeros) {
            output[row] = 0;
            continue;
        }
        for (position = begin; position < end; ++position) {
            int32_t column = column_indices[position];
            if (column >= 0 && column < columns) {
                sum += (uint32_t)values[position] * (uint32_t)vector[column];
            }
        }
        output[row] = sum;
        checksum = checksum * 31u + sum;
    }
    return checksum;
}
