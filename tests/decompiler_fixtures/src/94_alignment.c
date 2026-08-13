#include <stdint.h>
#include <stddef.h>

/* C11 alignment: _Alignas raises a member's alignment, which inserts padding
 * that offsetof exposes. sizeof and offsetof are compile-time constants, so the
 * emitted code contains the resolved numbers and nothing else. */

struct Padded {
    uint8_t tag;
    _Alignas(16) int32_t payload;
    uint8_t trailer;
};

struct Packed {
    uint8_t tag;
    int32_t payload;
    uint8_t trailer;
};

__attribute__((noinline)) int32_t alignment_of_padded(void) {
    return (int32_t)_Alignof(struct Padded);
}

__attribute__((noinline)) int32_t offset_of_payload(int32_t which) {
    return which ? (int32_t)offsetof(struct Padded, payload)
                 : (int32_t)offsetof(struct Packed, payload);
}

__attribute__((noinline)) int32_t size_difference(void) {
    return (int32_t)(sizeof(struct Padded) - sizeof(struct Packed));
}

__attribute__((noinline)) int32_t
padded_roundtrip(int32_t tag, int32_t payload) {
    struct Padded object;
    object.tag = (uint8_t)tag;
    object.payload = payload;
    object.trailer = (uint8_t)(tag + 1);
    return object.payload + (int32_t)object.tag + (int32_t)object.trailer;
}
