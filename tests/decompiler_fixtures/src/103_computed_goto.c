#include <stdint.h>

/* Labels as values (a GCC extension both compilers implement): a jump table the
 * source builds explicitly. The dispatch is an indirect branch to an address
 * loaded from an array, which is exactly the shape a decompiler must not
 * mistake for a compiler-generated switch table. */

#define TOKEN_MAX 16

__attribute__((noinline)) int32_t
threaded_interpreter(const int32_t *program, int32_t length, int32_t seed) {
    static void *const targets[4] = {&&do_add, &&do_double, &&do_negate,
                                     &&do_clamp};
    int32_t accumulator = seed;
    int32_t position = 0;
    if (program == 0 || length < 0 || length > TOKEN_MAX) {
        return -1;
    }
    while (position < length) {
        int32_t opcode = program[position] & 3;
        position += 1;
        goto *targets[opcode];
    do_add:
        accumulator += position;
        continue;
    do_double:
        accumulator = (int32_t)((uint32_t)accumulator * 2u);
        continue;
    do_negate:
        accumulator = (int32_t)(0u - (uint32_t)accumulator);
        continue;
    do_clamp:
        if (accumulator > 1000) {
            accumulator = 1000;
        }
        continue;
    }
    return accumulator;
}
