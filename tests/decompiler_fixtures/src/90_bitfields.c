#include <stdint.h>

/* Bitfields: a plain `int` bitfield's signedness is implementation-defined, an
 * explicitly signed 3-bit field holds -4..3, and reading one is a shift/mask
 * pair whose exact widths must survive. */

struct Flags {
    unsigned int low : 3;
    unsigned int middle : 5;
    signed int high : 4;
    unsigned int rest : 20;
};

__attribute__((noinline)) int32_t
bitfield_extract(uint32_t packed, int32_t which) {
    struct Flags flags;
    flags.low = packed & 0x7u;
    flags.middle = (packed >> 3) & 0x1Fu;
    flags.high = (int32_t)((packed >> 8) & 0xFu);
    flags.rest = (packed >> 12) & 0xFFFFFu;
    switch (which & 3) {
    case 0:
        return (int32_t)flags.low;
    case 1:
        return (int32_t)flags.middle;
    case 2:
        return (int32_t)flags.high; /* sign-extends from 4 bits */
    default:
        return (int32_t)flags.rest;
    }
}

__attribute__((noinline)) int32_t
bitfield_signed_range(int32_t value) {
    struct Flags flags;
    flags.low = 0;
    flags.middle = 0;
    flags.rest = 0;
    flags.high = value; /* truncates to 4 bits, then sign-extends on read */
    return flags.high;
}

__attribute__((noinline)) int32_t
bitfield_struct_size(void) {
    return (int32_t)sizeof(struct Flags);
}
