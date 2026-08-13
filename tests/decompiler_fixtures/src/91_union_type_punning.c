#include <stdint.h>

/* Reading a union member other than the one last stored is defined in C (it
 * reinterprets the object representation). The byte order and the trap-free
 * integer layout make this a precise test of storage-identity recovery. */

union Punner {
    uint32_t word;
    uint8_t bytes[4];
    struct {
        uint16_t low;
        uint16_t high;
    } halves;
};

__attribute__((noinline)) int32_t
pun_byte_of_word(uint32_t word, int32_t index) {
    union Punner punner;
    punner.word = word;
    if (index < 0 || index > 3) {
        return -1;
    }
    return (int32_t)punner.bytes[index];
}

__attribute__((noinline)) uint32_t
pun_halves_swapped(uint32_t word) {
    union Punner punner;
    uint16_t swap;
    punner.word = word;
    swap = punner.halves.low;
    punner.halves.low = punner.halves.high;
    punner.halves.high = swap;
    return punner.word;
}

__attribute__((noinline)) int32_t
pun_is_little_endian(void) {
    union Punner punner;
    punner.word = 1u;
    return punner.bytes[0] == 1u;
}
