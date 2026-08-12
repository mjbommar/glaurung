#include <stdint.h>

/* Bounded string conversions and predicates.  Signed parsing accumulates in a
 * wider type and saturates, and the digit emitter divides by ten -- both are
 * where recovered integer widths and division idioms are visible. */

#define STR_MAX 16

__attribute__((noinline)) int32_t
parse_decimal(const uint8_t *text, int32_t length, int32_t *value) {
    int64_t accumulator = 0;
    int32_t negative = 0;
    int32_t index = 0;
    int32_t digits = 0;
    if (text == 0 || value == 0 || length < 0 || length > STR_MAX) {
        return -1;
    }
    if (index < length && (text[index] == (uint8_t)'-' ||
                           text[index] == (uint8_t)'+')) {
        negative = (text[index] == (uint8_t)'-');
        index += 1;
    }
    while (index < length && text[index] >= (uint8_t)'0' &&
           text[index] <= (uint8_t)'9') {
        accumulator = accumulator * 10 + (int64_t)(text[index] - (uint8_t)'0');
        if (accumulator > 2147483647LL) {
            return -2;
        }
        digits += 1;
        index += 1;
    }
    if (digits == 0) {
        return -3;
    }
    *value = (int32_t)(negative ? -accumulator : accumulator);
    return digits;
}

__attribute__((noinline)) int32_t
format_decimal(int32_t value, uint8_t *output, int32_t capacity) {
    uint8_t digits[12];
    uint32_t magnitude;
    int32_t count = 0;
    int32_t produced = 0;
    int32_t index;
    if (output == 0 || capacity < 1 || capacity > STR_MAX) {
        return -1;
    }
    magnitude = (value < 0) ? (uint32_t)(-(int64_t)value) : (uint32_t)value;
    do {
        digits[count] = (uint8_t)((uint32_t)'0' + (magnitude % 10u));
        magnitude /= 10u;
        count += 1;
    } while (magnitude != 0u && count < 12);
    if (value < 0) {
        if (produced >= capacity) {
            return -2;
        }
        output[produced] = (uint8_t)'-';
        produced += 1;
    }
    for (index = count - 1; index >= 0; --index) {
        if (produced >= capacity) {
            return -2;
        }
        output[produced] = digits[index];
        produced += 1;
    }
    return produced;
}

__attribute__((noinline)) int32_t
is_palindrome(const uint8_t *text, int32_t length) {
    int32_t head = 0;
    int32_t tail;
    if (text == 0 || length < 0 || length > STR_MAX) {
        return -1;
    }
    tail = length - 1;
    while (head < tail) {
        if (text[head] != text[tail]) {
            return 0;
        }
        head += 1;
        tail -= 1;
    }
    return 1;
}
