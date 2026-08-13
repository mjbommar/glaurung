#include <stdint.h>

/* Instruction substitution: the second pass every obfuscator runs after
 * flattening. Each primitive arithmetic operation is replaced by a longer
 * sequence of cheaper ones that computes the same function:
 *
 *     x + y  ==  (x ^ y) + 2 * (x & y)        (sum of "carry-less add" + carries)
 *     x - y  ==  x + ~y + 1                   (two's complement definition)
 *     x ^ y  ==  (x | y) - (x & y)
 *     x & y  ==  (x + y) - (x | y)
 *     x | y  ==  (x + y) - (x & y)
 *     x * 23 ==  (x << 4) + (x << 2) + (x << 1) + x
 *
 * Every identity above is exact over the full uint32_t ring — they are not
 * approximations that happen to work for small values — so the expansions are
 * safe to apply to arbitrary fuzz input, and any deviation the differential
 * reports is the decompiler's, not the identity's.
 *
 * Why this breaks decompilers: an expression simplifier has to decide whether
 * `(x ^ y) + ((x & y) << 1)` is "really" an addition. If it declines, the
 * output is unreadable but correct; if it accepts, it must apply the rewrite
 * only where it is actually valid — the near-miss `(x ^ y) + (x & y)` is NOT
 * `x + y`, and neither is `(x ^ y) + ((x | y) << 1)`. Pattern matchers keyed on
 * shape rather than semantics fire on all three and produce a decompilation
 * that reads like clean arithmetic and computes the wrong number. Type recovery
 * is attacked at the same time: the bitwise operands look like flags/masks, so
 * a plausible-looking `unsigned flags` type is inferred for what is an integer.
 *
 * No undefined behaviour: everything is unsigned, all shift counts are literal
 * and below 32, buffer lengths are validated against a small constant bound.
 */

#define ISUB147_MAX_BYTES 16

static uint32_t isub147_add(uint32_t x, uint32_t y) {
    return (x ^ y) + ((x & y) << 1);
}

static uint32_t isub147_sub(uint32_t x, uint32_t y) {
    return isub147_add(x, isub147_add(~y, 1u));
}

static uint32_t isub147_xor(uint32_t x, uint32_t y) {
    return (x | y) - (x & y);
}

static uint32_t isub147_and(uint32_t x, uint32_t y) {
    return isub147_sub(isub147_add(x, y), x | y);
}

static uint32_t isub147_or(uint32_t x, uint32_t y) {
    return isub147_sub(isub147_add(x, y), x & y);
}

/* Plain addition, expanded twice: the outer add is itself substituted, so the
 * carry chain appears as nested xor/and/shift instead of one instruction. */
__attribute__((noinline)) uint32_t
substituted_add(uint32_t x, uint32_t y) {
    return isub147_add(isub147_add(x, y), 0u);
}

/* Subtraction routed through the two's-complement identity. Note the negation
 * itself is substituted, so no unary minus survives in the source. */
__attribute__((noinline)) uint32_t
substituted_sub(uint32_t x, uint32_t y) {
    return isub147_sub(x, y);
}

/* All three bitwise primitives expressed through their arithmetic duals, then
 * recombined. The result is `(x ^ y) ^ ((x & y) | ...)` for concrete inputs but
 * is written entirely in terms of + and -. */
__attribute__((noinline)) uint32_t
substituted_bitops(uint32_t x, uint32_t y) {
    uint32_t a = isub147_xor(x, y);
    uint32_t b = isub147_and(x, y);
    uint32_t c = isub147_or(x, y);
    return isub147_add(isub147_xor(a, b), isub147_sub(c, b));
}

/* Multiplication by a constant as a shift-add chain, with each add substituted.
 * A decompiler that recognises the shift-add ladder must recover `* 23`; one
 * that recognises it wrongly recovers a different constant, which the
 * differential separates on the very first vector. */
__attribute__((noinline)) uint32_t
substituted_multiply(uint32_t x) {
    uint32_t s4 = x << 4;
    uint32_t s2 = x << 2;
    uint32_t s1 = x << 1;
    return isub147_add(isub147_add(s4, s2), isub147_add(s1, x));
}

/* Negation with no `-` in sight. Signed extremes are safe because the whole
 * computation happens in uint32_t. */
__attribute__((noinline)) int32_t
substituted_negate(int32_t value) {
    return (int32_t)isub147_add(~(uint32_t)value, 1u);
}

/* A byte-wise checksum whose every operation is substituted, so the loop body
 * expands to roughly twenty instructions with no recognisable accumulator
 * update. `length` is validated against a small constant bound. */
__attribute__((noinline)) uint32_t
substituted_checksum(uint8_t *data, int32_t length) {
    int32_t index;
    uint32_t acc = 0x811C9DC5u;

    if (data == 0 || length < 0 || length > ISUB147_MAX_BYTES) {
        return 0u;
    }

    for (index = 0; index < length; ++index) {
        uint32_t byte = (uint32_t)data[index];
        acc = isub147_xor(acc, byte);
        acc = isub147_add(isub147_add(acc << 1, acc << 4), isub147_add(acc << 7, acc));
    }
    return isub147_sub(acc, (uint32_t)length);
}
