#include <stdint.h>
#include <stddef.h>

/* Padding is part of the object but not of any member. Copying a struct copies
 * the padding; comparing member-by-member does not. The two orderings below
 * hold identical members and differ only in size. */

struct Wasteful {
    uint8_t tag;
    int32_t value;
    uint8_t flag;
    int32_t extra;
};

struct Tight {
    int32_t value;
    int32_t extra;
    uint8_t tag;
    uint8_t flag;
};

__attribute__((noinline)) int32_t layout_size_delta(void) {
    return (int32_t)(sizeof(struct Wasteful) - sizeof(struct Tight));
}

__attribute__((noinline)) int32_t layout_offsets(int32_t which) {
    switch (which & 3) {
    case 0:
        return (int32_t)offsetof(struct Wasteful, value);
    case 1:
        return (int32_t)offsetof(struct Wasteful, extra);
    case 2:
        return (int32_t)offsetof(struct Tight, tag);
    default:
        return (int32_t)offsetof(struct Tight, flag);
    }
}

__attribute__((noinline)) int32_t
struct_assignment_copies(int32_t tag, int32_t value) {
    struct Tight source;
    struct Tight destination;
    source.value = value;
    source.extra = value * 2;
    source.tag = (uint8_t)tag;
    source.flag = (uint8_t)(tag + 1);
    destination = source; /* whole-object copy, padding included */
    return destination.value + destination.extra + (int32_t)destination.tag +
           (int32_t)destination.flag;
}
