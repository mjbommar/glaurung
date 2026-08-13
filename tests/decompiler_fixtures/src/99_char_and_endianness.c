#include <stdint.h>

/* Plain `char` has implementation-defined signedness, so the same source reads
 * 0x80 as -128 or 128 depending on target. Both spellings are pinned here, and
 * the byte order is observed rather than assumed. */

__attribute__((noinline)) int32_t
plain_char_is_signed(void) {
    char probe = (char)0x80;
    return probe < 0;
}

__attribute__((noinline)) int32_t
char_widening(int32_t value) {
    signed char narrow = (signed char)value;
    unsigned char wide = (unsigned char)value;
    return (int32_t)narrow * 1000 + (int32_t)wide;
}

__attribute__((noinline)) uint32_t
byte_swap32(uint32_t value) {
    return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
           ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
}

__attribute__((noinline)) uint32_t
load_big_endian(const uint8_t *bytes, int32_t available) {
    if (bytes == 0 || available < 4) {
        return 0;
    }
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}
