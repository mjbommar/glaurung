#include <stdint.h>

/* Counting sort over a small key domain and an LSD radix sort over 4-bit
 * digits.  Both build a prefix-sum histogram and then scatter in reverse to
 * remain stable; the scatter is an indirect write whose index is loaded. */

#define RADIX_MAX 16
#define RADIX_BUCKETS 16

__attribute__((noinline)) int32_t
counting_sort_u8(uint8_t *values, int32_t count) {
    int32_t histogram[256];
    int32_t index;
    int32_t bucket;
    int32_t out;
    if (values == 0 || count < 0 || count > RADIX_MAX) {
        return -1;
    }
    for (bucket = 0; bucket < 256; ++bucket) {
        histogram[bucket] = 0;
    }
    for (index = 0; index < count; ++index) {
        histogram[values[index]] += 1;
    }
    out = 0;
    for (bucket = 0; bucket < 256; ++bucket) {
        int32_t remaining = histogram[bucket];
        while (remaining > 0 && out < count) {
            values[out] = (uint8_t)bucket;
            out += 1;
            remaining -= 1;
        }
    }
    return count;
}

__attribute__((noinline)) int32_t
radix_sort_u32(uint32_t *values, int32_t count) {
    uint32_t scratch[RADIX_MAX];
    int32_t histogram[RADIX_BUCKETS];
    int32_t shift;
    int32_t index;
    int32_t bucket;
    if (values == 0 || count < 0 || count > RADIX_MAX) {
        return -1;
    }
    for (shift = 0; shift < 32; shift += 4) {
        int32_t running = 0;
        for (bucket = 0; bucket < RADIX_BUCKETS; ++bucket) {
            histogram[bucket] = 0;
        }
        for (index = 0; index < count; ++index) {
            histogram[(values[index] >> shift) & 0xFu] += 1;
        }
        for (bucket = 0; bucket < RADIX_BUCKETS; ++bucket) {
            int32_t occupancy = histogram[bucket];
            histogram[bucket] = running;
            running += occupancy;
        }
        for (index = 0; index < count; ++index) {
            int32_t slot = (int32_t)((values[index] >> shift) & 0xFu);
            scratch[histogram[slot]] = values[index];
            histogram[slot] += 1;
        }
        for (index = 0; index < count; ++index) {
            values[index] = scratch[index];
        }
    }
    return count;
}
