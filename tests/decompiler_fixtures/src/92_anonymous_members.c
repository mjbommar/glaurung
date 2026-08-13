#include <stdint.h>

/* C11 anonymous structs and unions: members of an unnamed member are addressed
 * as if they belonged to the enclosing type, so the source names carry no
 * offset information a decompiler can lean on. */

struct Message {
    int32_t kind;
    union {
        struct {
            int32_t x;
            int32_t y;
        };
        struct {
            int32_t code;
            int32_t detail;
        };
        int32_t raw[2];
    };
};

__attribute__((noinline)) int32_t
anonymous_select(int32_t kind, int32_t first, int32_t second, int32_t which) {
    struct Message message;
    message.kind = kind;
    message.x = first;
    message.y = second;
    switch (which & 3) {
    case 0:
        return message.x + message.y;
    case 1:
        return message.code - message.detail;
    case 2:
        return message.raw[0];
    default:
        return message.raw[1];
    }
}

__attribute__((noinline)) int32_t
anonymous_overlap_proof(int32_t value) {
    struct Message message;
    message.kind = 0;
    message.code = value;
    /* `x` and `code` name the same storage. */
    return message.x == value;
}
