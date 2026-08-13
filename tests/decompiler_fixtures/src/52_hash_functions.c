#include <stdint.h>

/* FNV-1a, a djb2 variant, and the MurmurHash3 finalizer.  These are pure
 * multiply/xor/shift chains: with no control flow to anchor on, an incorrect
 * constant or shift width is immediately visible in the differential. */

#define HASH_MAX 16

__attribute__((noinline)) uint32_t
fnv1a_32(const uint8_t *data, int32_t length) {
    uint32_t hash = 2166136261u;
    int32_t index;
    if (data == 0 || length < 0 || length > HASH_MAX) {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        hash ^= (uint32_t)data[index];
        hash *= 16777619u;
    }
    return hash;
}

__attribute__((noinline)) uint32_t
djb2_xor(const uint8_t *data, int32_t length) {
    uint32_t hash = 5381u;
    int32_t index;
    if (data == 0 || length < 0 || length > HASH_MAX) {
        return 0;
    }
    for (index = 0; index < length; ++index) {
        hash = ((hash << 5) + hash) ^ (uint32_t)data[index];
    }
    return hash;
}

__attribute__((noinline)) uint32_t murmur3_finalize(uint32_t value) {
    value ^= value >> 16;
    value *= 0x85EBCA6Bu;
    value ^= value >> 13;
    value *= 0xC2B2AE35u;
    value ^= value >> 16;
    return value;
}
