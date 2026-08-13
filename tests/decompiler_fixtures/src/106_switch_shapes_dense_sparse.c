#include <stdint.h>

/* Three switch shapes that lower differently: a dense contiguous range becomes
 * a jump table, a sparse one becomes a comparison tree, and a range with a
 * single outlier becomes a hybrid. */

__attribute__((noinline)) int32_t dense_switch(int32_t selector) {
    switch (selector) {
    case 0: return 11;
    case 1: return 22;
    case 2: return 33;
    case 3: return 44;
    case 4: return 55;
    case 5: return 66;
    case 6: return 77;
    case 7: return 88;
    default: return -1;
    }
}

__attribute__((noinline)) int32_t sparse_switch(int32_t selector) {
    switch (selector) {
    case -1000: return 1;
    case 7: return 2;
    case 1009: return 3;
    case 65536: return 4;
    case 1000000: return 5;
    default: return -1;
    }
}

__attribute__((noinline)) int32_t hybrid_switch(int32_t selector) {
    int32_t total = 0;
    switch (selector) {
    case 1:
    case 2:
    case 3:
        total = 10;
        break;
    case 4:
        total = 20;
        __attribute__((fallthrough));
    case 5:
        total += 5;
        break;
    case 999999:
        total = 30;
        break;
    default:
        total = -1;
        break;
    }
    return total;
}
