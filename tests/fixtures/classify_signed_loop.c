#include <limits.h>

__attribute__((noinline)) int classify(int n) {
    if (n < 0) {
        return -1;
    }
    while (n > 100) {
        n -= 100;
    }
    return n;
}

__attribute__((noinline)) unsigned int classify_unsigned(unsigned int n) {
    if (n == 0U) {
        return UINT_MAX;
    }
    while (n > 100U) {
        n -= 100U;
    }
    return n >> 1U;
}
