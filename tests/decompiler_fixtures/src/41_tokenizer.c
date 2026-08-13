#include <stdint.h>

/* A byte-level lexer driven by an explicit state variable.  Character
 * classification produces a dense switch over a small domain, and the accepted
 * token count is written through an output pointer, so both the jump table and
 * the store-through-parameter must survive. */

#define TOK_MAX 16

#define TOK_STATE_BLANK 0
#define TOK_STATE_WORD 1
#define TOK_STATE_NUMBER 2

static int32_t classify(uint8_t byte) {
    if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
        return TOK_STATE_NUMBER;
    }
    if ((byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
        (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
        byte == (uint8_t)'_') {
        return TOK_STATE_WORD;
    }
    return TOK_STATE_BLANK;
}

__attribute__((noinline)) int32_t
tokenize(const uint8_t *text, int32_t length, int32_t *word_count,
         int32_t *number_count) {
    int32_t state = TOK_STATE_BLANK;
    int32_t words = 0;
    int32_t numbers = 0;
    int32_t index;
    if (text == 0 || word_count == 0 || number_count == 0 || length < 0 ||
        length > TOK_MAX) {
        return -1;
    }
    for (index = 0; index < length; ++index) {
        int32_t next = classify(text[index]);
        if (next != state) {
            switch (next) {
            case TOK_STATE_WORD:
                words += 1;
                break;
            case TOK_STATE_NUMBER:
                numbers += 1;
                break;
            default:
                break;
            }
            state = next;
        }
    }
    *word_count = words;
    *number_count = numbers;
    return words + numbers;
}
