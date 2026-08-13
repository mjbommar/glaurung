#include <stdint.h>

/* Duff's device: a switch whose cases fall into the middle of a do/while. The
 * loop and the switch share a body, so no structuring that treats them as
 * separate regions can reproduce it. */

#define DUFF_MAX 16

__attribute__((noinline)) int32_t
duff_copy(const int32_t *source, int32_t *destination, int32_t count) {
    int32_t index = 0;
    int32_t blocks;
    if (source == 0 || destination == 0 || count < 1 || count > DUFF_MAX) {
        return -1;
    }
    blocks = (count + 7) / 8;
    switch (count % 8) {
    case 0:
        do {
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 7:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 6:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 5:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 4:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 3:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 2:
            destination[index] = source[index];
            index += 1;
            __attribute__((fallthrough));
    case 1:
            destination[index] = source[index];
            index += 1;
        } while (--blocks > 0);
    }
    return index;
}
