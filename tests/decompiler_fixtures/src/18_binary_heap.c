#include <stdint.h>

__attribute__((noinline)) int32_t heap_push(int32_t *heap, int32_t n,
                                            int32_t capacity, int32_t value) {
    int32_t child;
    if (heap == 0 || n < 0 || capacity < 0 || capacity > 16 || n >= capacity) {
        return -1;
    }
    child = n;
    heap[child] = value;
    while (child > 0) {
        int32_t parent = (child - 1) / 2;
        int32_t tmp;
        if (heap[parent] <= heap[child]) {
            break;
        }
        tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;
        child = parent;
    }
    return n + 1;
}

__attribute__((noinline)) int32_t heap_pop(int32_t *heap, int32_t n,
                                           int32_t *removed) {
    int32_t parent = 0;
    if (heap == 0 || removed == 0 || n <= 0 || n > 16) {
        return -1;
    }
    removed[0] = heap[0];
    heap[0] = heap[n - 1];
    --n;
    for (;;) {
        int32_t left = parent * 2 + 1;
        int32_t right = left + 1;
        int32_t child;
        int32_t tmp;
        if (left >= n) {
            break;
        }
        child = (right < n && heap[right] < heap[left]) ? right : left;
        if (heap[parent] <= heap[child]) {
            break;
        }
        tmp = heap[parent];
        heap[parent] = heap[child];
        heap[child] = tmp;
        parent = child;
    }
    return n;
}
