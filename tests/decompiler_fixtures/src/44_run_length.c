#include <stdint.h>

/* Run-length encode and decode with a bounded run counter.  Encoding emits
 * pairs, so the output index advances by two while the input index advances by
 * a data-dependent run length. */

#define RLE_MAX 16

__attribute__((noinline)) int32_t
rle_encode(const uint8_t *input, int32_t length, uint8_t *output,
           int32_t output_capacity) {
    int32_t produced = 0;
    int32_t index = 0;
    if (input == 0 || output == 0 || length < 0 || length > RLE_MAX ||
        output_capacity < 0 || output_capacity > RLE_MAX) {
        return -1;
    }
    while (index < length) {
        uint8_t symbol = input[index];
        int32_t run = 1;
        while (index + run < length && input[index + run] == symbol &&
               run < 255) {
            run += 1;
        }
        if (produced + 2 > output_capacity) {
            return -2;
        }
        output[produced] = (uint8_t)run;
        output[produced + 1] = symbol;
        produced += 2;
        index += run;
    }
    return produced;
}

__attribute__((noinline)) int32_t
rle_decode(const uint8_t *input, int32_t length, uint8_t *output,
           int32_t output_capacity) {
    int32_t produced = 0;
    int32_t index;
    if (input == 0 || output == 0 || length < 0 || length > RLE_MAX ||
        output_capacity < 0 || output_capacity > RLE_MAX || (length % 2) != 0) {
        return -1;
    }
    for (index = 0; index < length; index += 2) {
        int32_t run = (int32_t)input[index];
        uint8_t symbol = input[index + 1];
        int32_t step;
        if (produced + run > output_capacity) {
            return -2;
        }
        for (step = 0; step < run; ++step) {
            output[produced] = symbol;
            produced += 1;
        }
    }
    return produced;
}
