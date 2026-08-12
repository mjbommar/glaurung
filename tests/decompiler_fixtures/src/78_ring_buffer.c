#include <stdint.h>

/* A power-of-two circular buffer with separate head and tail indices.  The
 * wrap is a mask rather than a modulo, and fullness is derived from the
 * unsigned difference of two monotonically increasing counters. */

#define RING_CAPACITY 8
#define RING_MASK (RING_CAPACITY - 1)

__attribute__((noinline)) int32_t
ring_push(int32_t *storage, uint32_t *head, uint32_t *tail, int32_t value) {
    if (storage == 0 || head == 0 || tail == 0) {
        return -1;
    }
    if ((*head - *tail) >= (uint32_t)RING_CAPACITY) {
        return 0;
    }
    storage[*head & (uint32_t)RING_MASK] = value;
    *head = *head + 1u;
    return 1;
}

__attribute__((noinline)) int32_t
ring_pop(int32_t *storage, uint32_t *head, uint32_t *tail, int32_t *value) {
    if (storage == 0 || head == 0 || tail == 0 || value == 0) {
        return -1;
    }
    if (*head == *tail) {
        return 0;
    }
    *value = storage[*tail & (uint32_t)RING_MASK];
    *tail = *tail + 1u;
    return 1;
}

__attribute__((noinline)) int32_t
ring_occupancy(uint32_t head, uint32_t tail) {
    uint32_t used = head - tail;
    if (used > (uint32_t)RING_CAPACITY) {
        return -1;
    }
    return (int32_t)used;
}
