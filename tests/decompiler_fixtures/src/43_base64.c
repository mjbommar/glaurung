#include <stdint.h>

/* Base64 encode and decode.  Three input bytes become four 6-bit groups, so
 * the shift/mask lattice crosses byte boundaries in both directions -- a
 * precise test of sub-register width tracking. */

#define B64_INPUT_MAX 12
#define B64_OUTPUT_MAX 16

static uint8_t encode_symbol(uint32_t sextet) {
    if (sextet < 26u) {
        return (uint8_t)((uint32_t)'A' + sextet);
    }
    if (sextet < 52u) {
        return (uint8_t)((uint32_t)'a' + (sextet - 26u));
    }
    if (sextet < 62u) {
        return (uint8_t)((uint32_t)'0' + (sextet - 52u));
    }
    if (sextet == 62u) {
        return (uint8_t)'+';
    }
    return (uint8_t)'/';
}

static int32_t decode_symbol(uint8_t symbol) {
    if (symbol >= (uint8_t)'A' && symbol <= (uint8_t)'Z') {
        return (int32_t)symbol - 'A';
    }
    if (symbol >= (uint8_t)'a' && symbol <= (uint8_t)'z') {
        return (int32_t)symbol - 'a' + 26;
    }
    if (symbol >= (uint8_t)'0' && symbol <= (uint8_t)'9') {
        return (int32_t)symbol - '0' + 52;
    }
    if (symbol == (uint8_t)'+') {
        return 62;
    }
    if (symbol == (uint8_t)'/') {
        return 63;
    }
    return -1;
}

__attribute__((noinline)) int32_t
base64_encode(const uint8_t *input, int32_t length, uint8_t *output) {
    int32_t produced = 0;
    int32_t index = 0;
    if (input == 0 || output == 0 || length < 0 || length > B64_INPUT_MAX) {
        return -1;
    }
    while (index < length) {
        uint32_t group = (uint32_t)input[index] << 16;
        int32_t remaining = length - index;
        if (remaining > 1) {
            group |= (uint32_t)input[index + 1] << 8;
        }
        if (remaining > 2) {
            group |= (uint32_t)input[index + 2];
        }
        output[produced] = encode_symbol((group >> 18) & 0x3Fu);
        output[produced + 1] = encode_symbol((group >> 12) & 0x3Fu);
        output[produced + 2] =
            (remaining > 1) ? encode_symbol((group >> 6) & 0x3Fu) : (uint8_t)'=';
        output[produced + 3] =
            (remaining > 2) ? encode_symbol(group & 0x3Fu) : (uint8_t)'=';
        produced += 4;
        index += 3;
    }
    return produced;
}

__attribute__((noinline)) int32_t
base64_decode(const uint8_t *input, int32_t length, uint8_t *output) {
    int32_t produced = 0;
    int32_t index;
    if (input == 0 || output == 0 || length < 0 || length > B64_OUTPUT_MAX ||
        (length % 4) != 0) {
        return -1;
    }
    for (index = 0; index < length; index += 4) {
        int32_t a = decode_symbol(input[index]);
        int32_t b = decode_symbol(input[index + 1]);
        int32_t c = decode_symbol(input[index + 2]);
        int32_t d = decode_symbol(input[index + 3]);
        uint32_t group;
        int32_t pad = 0;
        if (a < 0 || b < 0) {
            return -2;
        }
        if (c < 0) {
            c = 0;
            pad += 1;
        }
        if (d < 0) {
            d = 0;
            pad += 1;
        }
        group = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                ((uint32_t)c << 6) | (uint32_t)d;
        output[produced] = (uint8_t)((group >> 16) & 0xFFu);
        produced += 1;
        if (pad < 2) {
            output[produced] = (uint8_t)((group >> 8) & 0xFFu);
            produced += 1;
        }
        if (pad < 1) {
            output[produced] = (uint8_t)(group & 0xFFu);
            produced += 1;
        }
    }
    return produced;
}
