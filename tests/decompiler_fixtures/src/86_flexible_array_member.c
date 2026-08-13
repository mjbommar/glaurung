#include <stdint.h>

/* C99 flexible array members: the trailing `int32_t items[]` contributes
 * nothing to sizeof, so the header size and the element stride must both be
 * recovered to walk the payload correctly. */

struct Packet {
    int32_t length;
    int32_t tag;
    int32_t items[];
};

__attribute__((noinline)) int32_t
flexible_header_size(void) {
    return (int32_t)sizeof(struct Packet);
}

__attribute__((noinline)) int32_t
flexible_sum(const int32_t *storage, int32_t available) {
    const struct Packet *packet;
    int32_t total = 0;
    int32_t index;
    int32_t count;
    if (storage == 0 || available < 2 || available > 16) {
        return -1;
    }
    packet = (const struct Packet *)(const void *)storage;
    count = packet->length;
    if (count < 0 || count > available - 2) {
        return -2;
    }
    for (index = 0; index < count; ++index) {
        total += packet->items[index];
    }
    return total + packet->tag;
}
