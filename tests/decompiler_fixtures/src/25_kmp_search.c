#include <stdint.h>

__attribute__((noinline)) int32_t kmp_search(const uint8_t *text, int32_t n,
                                              const uint8_t *pattern,
                                              int32_t m) {
    int32_t prefix[16];
    int32_t i;
    int32_t matched = 0;
    if (text == 0 || pattern == 0 || n < 0 || n > 16 || m < 0 || m > 16) {
        return -1;
    }
    if (m == 0) {
        return 0;
    }
    prefix[0] = 0;
    for (i = 1; i < m; ++i) {
        while (matched > 0 && pattern[i] != pattern[matched]) {
            matched = prefix[matched - 1];
        }
        if (pattern[i] == pattern[matched]) {
            ++matched;
        }
        prefix[i] = matched;
    }
    matched = 0;
    for (i = 0; i < n; ++i) {
        while (matched > 0 && text[i] != pattern[matched]) {
            matched = prefix[matched - 1];
        }
        if (text[i] == pattern[matched]) {
            ++matched;
        }
        if (matched == m) {
            return i - m + 1;
        }
    }
    return -1;
}
