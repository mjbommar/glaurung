#include <stdint.h>

/* RC4 key scheduling and keystream generation.  Both phases permute a
 * 256-byte state in place with two indices that wrap modulo 256, so the
 * recovered code must keep the byte-width truncation of `j` exact. */

#define RC4_MAX 16

__attribute__((noinline)) uint32_t
rc4_keystream_checksum(const uint8_t *key, int32_t key_length, int32_t rounds) {
    uint8_t state[256];
    uint32_t checksum = 0;
    int32_t index;
    uint8_t i;
    uint8_t j = 0;
    if (key == 0 || key_length < 1 || key_length > RC4_MAX || rounds < 0 ||
        rounds > 64) {
        return 0;
    }
    for (index = 0; index < 256; ++index) {
        state[index] = (uint8_t)index;
    }
    for (index = 0; index < 256; ++index) {
        uint8_t swap;
        j = (uint8_t)(j + state[index] + key[index % key_length]);
        swap = state[index];
        state[index] = state[j];
        state[j] = swap;
    }
    i = 0;
    j = 0;
    for (index = 0; index < rounds; ++index) {
        uint8_t swap;
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + state[i]);
        swap = state[i];
        state[i] = state[j];
        state[j] = swap;
        checksum = checksum * 33u + state[(uint8_t)(state[i] + state[j])];
    }
    return checksum;
}
