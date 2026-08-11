#include <stddef.h>
#include <stdint.h>

struct capacity_buffer {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

static __attribute__((noinline)) size_t saturating_add(size_t left, size_t right) {
    return left <= SIZE_MAX - right ? left + right : SIZE_MAX;
}

__attribute__((visibility("default"), noinline))
int lazy_call_select(struct capacity_buffer *buffer, int value) {
    size_t new_length = saturating_add(buffer->length, 1);
    if (new_length == SIZE_MAX) {
        return -22;
    }
    if (buffer->capacity < new_length) {
        size_t new_capacity = saturating_add(buffer->capacity, 1) <= SIZE_MAX / 2
                                  ? saturating_add(buffer->capacity, 1) * 2
                                  : SIZE_MAX;
        if (new_capacity == SIZE_MAX) {
            return -22;
        }
        buffer->capacity = new_capacity;
    }
    buffer->data[buffer->length++] = (unsigned char)value;
    return 0;
}
