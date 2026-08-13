#include <stdint.h>

/* A wire codec that packs four fields of different widths into one word and
 * reads them back. The shift/mask constants are the entire specification, so an
 * off-by-one in any of them is invisible structurally and fatal behaviorally. */

#define FIELD_A_BITS 5
#define FIELD_B_BITS 7
#define FIELD_C_BITS 12
#define FIELD_D_BITS 8

__attribute__((noinline)) uint32_t
pack_fields(int32_t a, int32_t b, int32_t c, int32_t d) {
    uint32_t packed = 0;
    packed |= (uint32_t)a & ((1u << FIELD_A_BITS) - 1u);
    packed |= ((uint32_t)b & ((1u << FIELD_B_BITS) - 1u)) << FIELD_A_BITS;
    packed |= ((uint32_t)c & ((1u << FIELD_C_BITS) - 1u))
              << (FIELD_A_BITS + FIELD_B_BITS);
    packed |= ((uint32_t)d & ((1u << FIELD_D_BITS) - 1u))
              << (FIELD_A_BITS + FIELD_B_BITS + FIELD_C_BITS);
    return packed;
}

__attribute__((noinline)) int32_t
unpack_field(uint32_t packed, int32_t which) {
    switch (which & 3) {
    case 0:
        return (int32_t)(packed & ((1u << FIELD_A_BITS) - 1u));
    case 1:
        return (int32_t)((packed >> FIELD_A_BITS) &
                         ((1u << FIELD_B_BITS) - 1u));
    case 2:
        return (int32_t)((packed >> (FIELD_A_BITS + FIELD_B_BITS)) &
                         ((1u << FIELD_C_BITS) - 1u));
    default:
        return (int32_t)((packed >>
                          (FIELD_A_BITS + FIELD_B_BITS + FIELD_C_BITS)) &
                         ((1u << FIELD_D_BITS) - 1u));
    }
}

__attribute__((noinline)) int32_t
codec_roundtrip(int32_t a, int32_t b, int32_t c, int32_t d) {
    uint32_t packed = pack_fields(a, b, c, d);
    return (unpack_field(packed, 0) == (a & 31)) +
           (unpack_field(packed, 1) == (b & 127)) +
           (unpack_field(packed, 2) == (c & 4095)) +
           (unpack_field(packed, 3) == (d & 255));
}
