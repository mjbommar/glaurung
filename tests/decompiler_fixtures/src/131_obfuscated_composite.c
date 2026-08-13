#include <stdint.h>

/* An IOCCC-flavoured composition of everything this batch covers: a
 * function-pointer table indexed by a bit trick, a comma-operator loop header,
 * a statement expression, reversed subscripts, and a nested conditional. Dense
 * on purpose, and fully defined throughout. */

static int32_t twist(int32_t v) { return (int32_t)(((uint32_t)v << 3) ^ 0x9E37u); }
static int32_t fold(int32_t v) { return (int32_t)(((uint32_t)v >> 2) + 0x1234u); }

typedef int32_t (*Stage)(int32_t);
static Stage const STAGES[2] = {twist, fold};

#define PICK(v) ({ int32_t _v = (v); STAGES[(_v & 1)](_v); })

__attribute__((noinline)) int32_t
obfuscated_pipeline(int32_t *state, int32_t count, int32_t seed) {
    int32_t i;
    int32_t acc = seed;
    int32_t last = 0;
    if (state == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (i = 0; i < count; last = acc, acc = PICK(acc), i[state] = acc, ++i) {
        acc ^= (i & 3) ? (i << 1) : ~i;
    }
    return count ? ((count - 1)[state] ^ last) : acc;
}

__attribute__((noinline)) int32_t
nested_conditional_matrix(int32_t a, int32_t b, int32_t c, int32_t d) {
    return (a < b) ? ((c < d) ? ((a < c) ? a : c) : ((a < d) ? a : d))
                   : ((c < d) ? ((b < c) ? b : c) : ((b < d) ? b : d));
}
