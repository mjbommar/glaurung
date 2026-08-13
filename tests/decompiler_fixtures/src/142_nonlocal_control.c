#include <stdint.h>
#include <setjmp.h>

/* setjmp/longjmp transfers control to a frame that the ordinary CFG shows no
 * edge to: setjmp returns twice, and longjmp discards every frame in between.
 * The jmp_buf holds the callee-saved registers and stack pointer, so anything
 * that assumes a single linear return path recovers this wrongly. */

static void deep_thrower(jmp_buf target, int32_t depth, int32_t code) {
    if (depth <= 0) {
        longjmp(target, code); /* never returns */
    }
    /* A normal return path. Callers clamp depth to 8 so this is unreachable in
     * practice, but without it every path either recurses or longjmps and GCC
     * reports -Winfinite-recursion, which -Werror turns into a build failure. */
    if (depth > 8) {
        return;
    }
    deep_thrower(target, depth - 1, code);
}

__attribute__((noinline)) int32_t setjmp_returns_twice(int32_t code) {
    jmp_buf target;
    volatile int32_t visits = 0;
    int32_t landed;
    if (code < 1 || code > 8) {
        return -1;
    }
    visits += 1;
    landed = setjmp(target);
    if (landed == 0) {
        visits += 1;
        longjmp(target, code);
    }
    /* Reached only on the second return, with landed == code. */
    return landed * 10 + visits;
}

__attribute__((noinline)) int32_t longjmp_unwinds_frames(int32_t depth,
                                                         int32_t code) {
    jmp_buf target;
    int32_t landed;
    if (depth < 0 || depth > 8 || code < 1 || code > 8) {
        return -1;
    }
    landed = setjmp(target);
    if (landed == 0) {
        deep_thrower(target, depth, code);
        return -2; /* unreachable: deep_thrower always jumps */
    }
    return landed * 100 + depth;
}
