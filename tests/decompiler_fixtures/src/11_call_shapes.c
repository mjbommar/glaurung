/* 11_call_shapes.c
 *
 * Call-boundary fixture: what a function's *signature* means when values flow
 * through it. `06_calling_conventions.c` proves arguments arrive in the right
 * order; this file proves the recovered widths and the call result survive.
 *
 * The corpus previously had almost no function whose declared parameter width
 * mattered across a call, so a decompiler that widened, narrowed, or dropped a
 * call result kept passing. Every function here consumes a callee's return value
 * in a way that changes the answer if the width is wrong: a 64-bit product of
 * two 32-bit arguments, a byte that must wrap at 8 bits, a result compared
 * against a boundary, an accumulator fed by a call inside a loop.
 *
 * All parameters and returns are integer and all callees are external symbols,
 * so every function is differential-testable and portable across SysV x86-64,
 * Win64, x86-32 cdecl and AAPCS64. Deterministic, terminating, no libc.
 *
 * Targets review #20 (call-heavy corpus gap).
 */
#include <stdint.h>

/* --- callees ----------------------------------------------------------- */
/* Not `static`: the harness drives functions by exported symbol, and a callee
 * that is itself checked is a callee whose own recovery is proven. */

/* Widening callee: the product genuinely needs 64 bits. A caller that keeps
 * this result in 32 bits loses the high half. */
uint64_t widen_mul(uint32_t a, uint32_t b) {
    return (uint64_t)a * (uint64_t)b;
}

/* Narrowing callee: wraps at 8 bits. A caller that treats the result as 32-bit
 * sees values this function can never return. */
uint8_t wrap_byte(uint32_t x) {
    return (uint8_t)(x * 31u + 7u);
}

/* Sign-extending callee: negative results must stay negative through the ABI's
 * 64-bit return register. */
int32_t signed_step(int32_t x) {
    return x - 1000;
}

/* A callee with stack arguments under every ABI here, returning a combination
 * that changes if any argument is dropped or reordered. */
int spill_combine(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7) {
    return a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5 + 7 * a6 + 8 * a7;
}

/* --- callers ----------------------------------------------------------- */

/* The call result is 64 bits wide; folding both halves detects a caller that
 * truncated it to the 32-bit return register view. */
int call_fold_wide_result(uint32_t a, uint32_t b) {
    uint64_t r = widen_mul(a, b);
    return (int)((r >> 32) ^ (r & 0xFFFFFFFFu));
}

/* The result must wrap at 8 bits *before* it is widened: a caller that keeps
 * the callee's full 32-bit register value gets a different sum. */
int call_accumulate_bytes(uint32_t seed, int count) {
    uint32_t acc = 0;
    int n = count & 15;                 /* bounded: the verdict cannot depend on time */
    for (int i = 0; i < n; i++) {
        acc += wrap_byte(seed + (uint32_t)i);
    }
    return (int)acc;
}

/* A negative call result compared against a boundary. Zero-extending the
 * callee's 32-bit return into 64 bits makes every comparison take the wrong arm. */
int call_result_drives_branch(int32_t x) {
    int32_t r = signed_step(x);
    if (r < 0) {
        return -r;
    }
    return r + 1;
}

/* Nested calls: the inner result is an argument to the outer call, so an
 * argument/return mix-up is visible in the answer. */
int call_nested(uint32_t a, uint32_t b) {
    uint64_t r = widen_mul(wrap_byte(a), wrap_byte(b));
    return (int)(r & 0xFFFFFFFFu);
}

/* Two calls whose results are combined. A caller that reuses one call's result
 * register for both — the classic "a call defines nothing" bug — returns twice
 * the second value instead of a mix. */
int call_twice_and_combine(int32_t x, int32_t y) {
    int32_t p = signed_step(x);
    int32_t q = signed_step(y);
    return p * 3 + q;
}

/* A call result feeding a stack-argument call: the return value must survive
 * being spilled and reloaded across the argument setup. */
int call_into_spill(int a0, int a1) {
    int r = signed_step(a0);
    return spill_combine(r, a1, r + 1, a1 + 2, r + 3, a1 + 4, r + 5, a1 + 6);
}

/* A call inside a loop whose result feeds the next iteration's argument, so the
 * result cannot be hoisted, folded, or read from a stale register. */
int call_chain_in_loop(int32_t seed, int rounds) {
    int32_t v = seed;
    int n = rounds & 7;                 /* bounded */
    for (int i = 0; i < n; i++) {
        v = signed_step(v) + i;
    }
    return v;
}

/* The call result is used exactly once, as a return value. A decompiler that
 * drops the call entirely still has to produce this number. */
int call_forward_result(int32_t x) {
    return signed_step(x);
}

/* The first call's result is deliberately UNUSED. `signed_step` is pure, so an
 * optimising build is free to delete the call outright — which is the point: the
 * returned value must be the same whether the call survives or not, and nothing
 * may attribute the *second* call's result to the first. */
int call_result_unused(int32_t x) {
    signed_step(x);
    return signed_step(x + 1);
}
