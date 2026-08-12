#include <stdint.h>

/* A word-addressed bit set: population count, rank, and select.  The
 * word/bit index split (>>5, &31) and the SWAR popcount are dense bit
 * arithmetic with no control flow to lean on. */

#define BITSET_WORDS 8
#define BITSET_BITS (BITSET_WORDS * 32)

static uint32_t popcount32(uint32_t word) {
    word = word - ((word >> 1) & 0x55555555u);
    word = (word & 0x33333333u) + ((word >> 2) & 0x33333333u);
    word = (word + (word >> 4)) & 0x0F0F0F0Fu;
    return (word * 0x01010101u) >> 24;
}

__attribute__((noinline)) uint32_t
bitset_population(const uint32_t *words, int32_t word_count) {
    uint32_t total = 0;
    int32_t index;
    if (words == 0 || word_count < 0 || word_count > BITSET_WORDS) {
        return 0;
    }
    for (index = 0; index < word_count; ++index) {
        total += popcount32(words[index]);
    }
    return total;
}

__attribute__((noinline)) int32_t
bitset_rank(const uint32_t *words, int32_t word_count, int32_t position) {
    uint32_t total = 0;
    int32_t whole;
    int32_t index;
    if (words == 0 || word_count < 0 || word_count > BITSET_WORDS ||
        position < 0 || position > word_count * 32) {
        return -1;
    }
    whole = position / 32;
    for (index = 0; index < whole; ++index) {
        total += popcount32(words[index]);
    }
    if ((position % 32) != 0 && whole < word_count) {
        uint32_t mask = (1u << (uint32_t)(position % 32)) - 1u;
        total += popcount32(words[whole] & mask);
    }
    return (int32_t)total;
}

__attribute__((noinline)) int32_t
bitset_select(const uint32_t *words, int32_t word_count, int32_t ordinal) {
    int32_t seen = 0;
    int32_t index;
    if (words == 0 || word_count < 0 || word_count > BITSET_WORDS ||
        ordinal < 0) {
        return -1;
    }
    for (index = 0; index < word_count * 32; ++index) {
        uint32_t word = words[index / 32];
        if (((word >> (uint32_t)(index % 32)) & 1u) != 0u) {
            if (seen == ordinal) {
                return index;
            }
            seen += 1;
        }
    }
    return -2;
}
