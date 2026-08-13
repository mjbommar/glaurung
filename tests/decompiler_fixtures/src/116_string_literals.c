#include <stdint.h>

/* String literals: adjacent literals concatenate at translation phase 6, the
 * terminating NUL is part of the object, and sizeof counts it while a length
 * scan does not. The literal itself lands in read-only data. */

__attribute__((noinline)) int32_t literal_size_versus_length(void) {
    static const char greeting[] = "abc" "def";
    int32_t length = 0;
    while (greeting[length] != '\0') {
        length += 1;
    }
    return (int32_t)sizeof(greeting) * 100 + length;
}

__attribute__((noinline)) int32_t literal_index(int32_t index) {
    if (index < 0 || index > 5) {
        return -1;
    }
    return (int32_t)"HELLO!"[index];
}

__attribute__((noinline)) int32_t
count_matching(const uint8_t *text, int32_t length, int32_t target) {
    static const char vowels[] = "aeiou";
    int32_t matches = 0;
    int32_t index;
    int32_t vowel;
    if (text == 0 || length < 0 || length > 16) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        for (vowel = 0; vowel < 5; ++vowel) {
            if ((int32_t)text[index] == (int32_t)(uint8_t)vowels[vowel]) {
                matches += 1;
            }
        }
    }
    return matches + (target != 0);
}

__attribute__((noinline)) int32_t escape_sequences(int32_t which) {
    static const char escapes[] = "\t\n\\\0X";
    if (which < 0 || which > 4) {
        return -1;
    }
    return (int32_t)escapes[which];
}
