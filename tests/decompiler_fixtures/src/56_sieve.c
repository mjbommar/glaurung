#include <stdint.h>

/* Sieve of Eratosthenes into a caller-owned flag array plus trial-division
 * factorisation.  The sieve's inner loop starts at p*p and strides by p, a
 * classic non-unit-stride induction variable. */

#define SIEVE_MAX 64
#define FACTOR_MAX 8

__attribute__((noinline)) int32_t
sieve_primes(uint8_t *flags, int32_t limit) {
    int32_t candidate;
    int32_t multiple;
    int32_t count = 0;
    if (flags == 0 || limit < 0 || limit > SIEVE_MAX) {
        return -1;
    }
    for (candidate = 0; candidate < limit; ++candidate) {
        flags[candidate] = 1;
    }
    if (limit > 0) {
        flags[0] = 0;
    }
    if (limit > 1) {
        flags[1] = 0;
    }
    for (candidate = 2; candidate * candidate < limit; ++candidate) {
        if (flags[candidate]) {
            for (multiple = candidate * candidate; multiple < limit;
                 multiple += candidate) {
                flags[multiple] = 0;
            }
        }
    }
    for (candidate = 0; candidate < limit; ++candidate) {
        if (flags[candidate]) {
            count += 1;
        }
    }
    return count;
}

__attribute__((noinline)) int32_t
factorize(int32_t value, int32_t *factors, int32_t capacity) {
    int32_t divisor = 2;
    int32_t produced = 0;
    if (factors == 0 || value < 2 || value > 1000000 || capacity < 1 ||
        capacity > FACTOR_MAX) {
        return -1;
    }
    while (divisor * divisor <= value && produced < capacity) {
        while ((value % divisor) == 0 && produced < capacity) {
            factors[produced] = divisor;
            produced += 1;
            value /= divisor;
        }
        divisor += 1;
    }
    if (value > 1 && produced < capacity) {
        factors[produced] = value;
        produced += 1;
    }
    return produced;
}
