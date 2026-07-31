#include <stdint.h>

#define HASH_EMPTY INT32_MIN

static uint32_t hash_slot(int32_t key, int32_t capacity) {
    return ((uint32_t)key * 2654435761u) % (uint32_t)capacity;
}

__attribute__((noinline)) int32_t hash_lookup(const int32_t *keys,
                                               const int32_t *values,
                                               int32_t capacity, int32_t key) {
    uint32_t start;
    int32_t probe;
    if (keys == 0 || values == 0 || capacity <= 0 || capacity > 16 ||
        key == HASH_EMPTY) {
        return -1;
    }
    start = hash_slot(key, capacity);
    for (probe = 0; probe < capacity; ++probe) {
        uint32_t slot = (start + (uint32_t)probe) % (uint32_t)capacity;
        if (keys[slot] == HASH_EMPTY) {
            return -1;
        }
        if (keys[slot] == key) {
            return values[slot];
        }
    }
    return -1;
}

__attribute__((noinline)) int32_t hash_insert(int32_t *keys, int32_t *values,
                                               int32_t capacity, int32_t key,
                                               int32_t value) {
    uint32_t start;
    int32_t probe;
    if (keys == 0 || values == 0 || capacity <= 0 || capacity > 16 ||
        key == HASH_EMPTY) {
        return -1;
    }
    start = hash_slot(key, capacity);
    for (probe = 0; probe < capacity; ++probe) {
        uint32_t slot = (start + (uint32_t)probe) % (uint32_t)capacity;
        if (keys[slot] == HASH_EMPTY || keys[slot] == key) {
            keys[slot] = key;
            values[slot] = value;
            return (int32_t)slot;
        }
    }
    return -1;
}
