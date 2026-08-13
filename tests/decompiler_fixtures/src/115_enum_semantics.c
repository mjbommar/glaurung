#include <stdint.h>

/* An enum's underlying type is implementation-defined and is chosen to fit the
 * enumerators. A value outside the enumerated set is still representable, so a
 * switch over an enum needs its default arm. */

enum Small {
    SMALL_ZERO = 0,
    SMALL_ONE = 1,
    SMALL_TWO = 2
};

enum Wide {
    WIDE_LOW = -70000,
    WIDE_HIGH = 70000
};

enum Sparse {
    SPARSE_A = 1,
    SPARSE_B = 100,
    SPARSE_C = 10000
};

__attribute__((noinline)) int32_t enum_sizes(int32_t which) {
    switch (which & 3) {
    case 0:
        return (int32_t)sizeof(enum Small);
    case 1:
        return (int32_t)sizeof(enum Wide);
    default:
        return (int32_t)sizeof(enum Sparse);
    }
}

__attribute__((noinline)) int32_t enum_switch(int32_t raw) {
    enum Sparse value = (enum Sparse)raw;
    switch (value) {
    case SPARSE_A:
        return 11;
    case SPARSE_B:
        return 22;
    case SPARSE_C:
        return 33;
    default:
        return -1; /* reachable: raw need not be an enumerator */
    }
}

__attribute__((noinline)) int32_t enum_arithmetic(int32_t step) {
    enum Small value = SMALL_ZERO;
    if (step < 0 || step > 8) {
        return -1;
    }
    /* Enums participate in integer arithmetic after promotion. */
    return (int32_t)value + step * (int32_t)SMALL_TWO + (int32_t)WIDE_HIGH;
}
