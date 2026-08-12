#include <stdint.h>

/* A fixed-capacity LRU cache built from parallel arrays with an explicit
 * recency stamp.  Lookup promotes; insertion evicts the minimum stamp.  Two
 * scans over the same arrays with different reduction operators. */

#define LRU_CAPACITY 8

__attribute__((noinline)) int32_t
lru_access(int32_t *keys, int32_t *stamps, int32_t capacity, int32_t key,
           int32_t clock, int32_t *evicted_key) {
    int32_t index;
    int32_t victim = 0;
    if (keys == 0 || stamps == 0 || evicted_key == 0 || capacity < 1 ||
        capacity > LRU_CAPACITY || clock < 0) {
        return -1;
    }
    *evicted_key = -1;
    for (index = 0; index < capacity; ++index) {
        if (keys[index] == key) {
            stamps[index] = clock;
            return 1;
        }
    }
    for (index = 0; index < capacity; ++index) {
        if (keys[index] == 0) {
            keys[index] = key;
            stamps[index] = clock;
            return 0;
        }
        if (stamps[index] < stamps[victim]) {
            victim = index;
        }
    }
    *evicted_key = keys[victim];
    keys[victim] = key;
    stamps[victim] = clock;
    return 2;
}
