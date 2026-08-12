#include <stdint.h>

/* A 32-bit xorshift, a 64-bit linear congruential generator, and rejection
 * sampling into a bounded range.  The LCG exercises 64-bit multiply lowering
 * on 32-bit targets; rejection sampling adds a data-dependent retry loop. */

#define PRNG_MAX 16

__attribute__((noinline)) uint32_t xorshift32(uint32_t state) {
    if (state == 0u) {
        state = 0x1234567u;
    }
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

__attribute__((noinline)) uint32_t lcg64_next_high(uint32_t seed) {
    uint64_t state = (uint64_t)seed * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(state >> 33);
}

__attribute__((noinline)) int32_t
bounded_sample(uint32_t seed, int32_t bound, int32_t *output, int32_t count) {
    uint32_t state = seed;
    int32_t produced = 0;
    int32_t guard = 0;
    if (output == 0 || bound < 1 || bound > 1024 || count < 0 ||
        count > PRNG_MAX) {
        return -1;
    }
    while (produced < count && guard < PRNG_MAX * 64) {
        uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % (uint32_t)bound);
        state = xorshift32(state);
        guard += 1;
        if (state > limit) {
            continue;
        }
        output[produced] = (int32_t)(state % (uint32_t)bound);
        produced += 1;
    }
    return produced;
}
