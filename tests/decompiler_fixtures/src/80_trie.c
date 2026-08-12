#include <stdint.h>

/* A four-way prefix tree over a flat node array (symbols 'a'..'d').  Children
 * are indices, not pointers, so insertion allocates by bumping a cursor and
 * lookup is a chain of dependent loads -- pointer-chasing without a heap. */

#define TRIE_NODES 24
#define TRIE_FANOUT 4

__attribute__((noinline)) int32_t
trie_insert(int32_t *children, uint8_t *terminal, int32_t *cursor,
            const uint8_t *word, int32_t length) {
    int32_t node = 0;
    int32_t index;
    if (children == 0 || terminal == 0 || cursor == 0 || word == 0 ||
        length < 0 || length > 8 || *cursor < 1 || *cursor > TRIE_NODES) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        int32_t symbol = (int32_t)word[index] - 'a';
        int32_t slot;
        if (symbol < 0 || symbol >= TRIE_FANOUT) {
            return -2;
        }
        slot = node * TRIE_FANOUT + symbol;
        if (children[slot] == 0) {
            if (*cursor >= TRIE_NODES) {
                return -3;
            }
            children[slot] = *cursor;
            *cursor = *cursor + 1;
        }
        node = children[slot];
    }
    terminal[node] = 1;
    return node;
}

__attribute__((noinline)) int32_t
trie_lookup(const int32_t *children, const uint8_t *terminal,
            const uint8_t *word, int32_t length) {
    int32_t node = 0;
    int32_t index;
    if (children == 0 || terminal == 0 || word == 0 || length < 0 ||
        length > 8) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        int32_t symbol = (int32_t)word[index] - 'a';
        int32_t slot;
        if (symbol < 0 || symbol >= TRIE_FANOUT) {
            return -2;
        }
        slot = node * TRIE_FANOUT + symbol;
        if (children[slot] == 0) {
            return 0;
        }
        node = children[slot];
    }
    return terminal[node] ? 1 : 0;
}
