#include <stdint.h>

/* Mixed boolean-arithmetic (MBA): expressions that interleave a boolean algebra
 * (&, |, ^, ~) with a ring (+, -, *) over the same words. Because the two
 * structures do not distribute over each other, there is no normal form a
 * compiler's simplifier can push everything into, and rewriting requires
 * per-identity knowledge:
 *
 *     x + y  ==  (x ^ y) + 2 * (x & y)
 *     x + y  ==  (x | y) + (x & y)
 *     x + y  ==  2 * (x | y) - (x ^ y)
 *     x - y  ==  (x ^ y) - 2 * (~x & y)
 *     x | y  ==  (x & y) + (x ^ y)
 *     x & y  ==  (x | y) - (x ^ y)
 *     0      ==  (x ^ y) + 2 * (x & y) - (x | y) - (x & y)     [zero polynomial]
 *
 * Each holds for every uint32_t pair, wraparound included: they are identities
 * over Z/2^32, derived from the fact that `x + y` splits into the carry-less
 * sum `x ^ y` plus twice the carries `x & y`.
 *
 * Why this breaks decompilers: MBA is the standard defence against symbolic
 * simplification precisely because bit-blasting an MBA expression to a
 * satisfiability query is exponential in the word size, and syntactic peephole
 * rules cover only the handful of forms someone thought to encode. Two failures
 * follow. A simplifier that misses the identity emits fifteen lines of masking
 * where the program adds two numbers — technically faithful, analytically
 * useless, and it drags a bogus "this is a bitmask/flags field" type inference
 * along with it. A simplifier that over-matches applies a rule whose side
 * condition it did not check: `(x ^ y) + (x & y)` and `(x | y) + (x ^ y)` look
 * one token away from the identities above but equal neither `x + y` nor
 * `x | y`. The zero polynomial is the sharpest case: it is an additive nonce
 * that must fold away entirely, and a decompiler that folds it *almost* right
 * emits confident, readable, wrong arithmetic.
 *
 * Everything is unsigned, all shifts are by literal counts below 32, and the
 * one buffer-taking function validates its length against a small bound.
 */

#define MBA149_MAX_BYTES 16

static uint32_t mba149_add_xor_and(uint32_t x, uint32_t y) {
    return (x ^ y) + ((x & y) << 1);
}

static uint32_t mba149_add_or_and(uint32_t x, uint32_t y) {
    return (x | y) + (x & y);
}

static uint32_t mba149_add_or_xor(uint32_t x, uint32_t y) {
    return ((x | y) << 1) - (x ^ y);
}

static uint32_t mba149_sub_xor_andnot(uint32_t x, uint32_t y) {
    return (x ^ y) - (((~x) & y) << 1);
}

/* Identically zero for every input pair: (x + y) - (x | y) - (x & y). */
static uint32_t mba149_zero(uint32_t x, uint32_t y) {
    return ((x ^ y) + ((x & y) << 1)) - (x | y) - (x & y);
}

/* Three independent encodings of the same addition, combined. `divergence` is
 * zero in every execution — it is an opaque zero built out of the identities
 * disagreeing with each other, which they never do. */
__attribute__((noinline)) uint32_t
mba_add_identities(uint32_t x, uint32_t y) {
    uint32_t a = mba149_add_xor_and(x, y);
    uint32_t b = mba149_add_or_and(x, y);
    uint32_t c = mba149_add_or_xor(x, y);
    uint32_t divergence = (a ^ b) | (b ^ c);
    return (a + (c ^ 0x9E3779B9u)) ^ divergence;
}

/* Subtraction via the carry-borrow identity, then re-added through a different
 * identity: the round trip must recover `x`. */
__attribute__((noinline)) uint32_t
mba_sub_identity(uint32_t x, uint32_t y) {
    uint32_t difference = mba149_sub_xor_andnot(x, y);
    return mba149_add_or_and(difference, y) ^ difference;
}

/* An MBA zero polynomial used as an additive nonce around a real computation.
 * Correct output is `x * y + (x ^ y)`; anything else means the nonce did not
 * fold to zero. */
__attribute__((noinline)) uint32_t
mba_zero_polynomial(uint32_t x, uint32_t y) {
    uint32_t nonce = mba149_zero(x, y);
    uint32_t nonce2 = mba149_zero(y, x ^ 0xFFFFu);
    return (x * y) + (x ^ y) + nonce + (nonce2 << 3);
}

/* Branchless select written in MBA form. `flag`'s low bit picks a value; the
 * mask is built by negation and the blend by xor-and-xor, so no comparison and
 * no branch appear in the source at all. */
__attribute__((noinline)) uint32_t
mba_select(uint32_t x, uint32_t y, uint32_t flag) {
    uint32_t mask = 0u - (flag & 1u);
    uint32_t blended = x ^ ((x ^ y) & mask);
    return mba149_add_xor_and(blended, mba149_zero(x, y));
}

/* Bit-count by the classic SWAR reduction, but with every add replaced by an
 * MBA encoding. The closed form is popcount; a decompiler that recovers the
 * masks but mangles one adder returns a plausible near-popcount. */
__attribute__((noinline)) uint32_t
mba_bit_population(uint32_t value) {
    uint32_t v = value - ((value >> 1) & 0x55555555u);
    v = mba149_add_or_and(v & 0x33333333u, (v >> 2) & 0x33333333u);
    v = mba149_add_xor_and(v, v >> 4) & 0x0F0F0F0Fu;
    return (v * 0x01010101u) >> 24;
}

/* An MBA-mixed rolling hash over a caller-owned byte buffer. Each round uses a
 * different identity so no single peephole rule cleans the loop up. */
__attribute__((noinline)) uint32_t
mba_mix_buffer(uint8_t *data, int32_t length, uint32_t seed) {
    int32_t index;
    uint32_t acc = seed;

    if (data == 0 || length < 0 || length > MBA149_MAX_BYTES) {
        return 0u;
    }

    for (index = 0; index < length; ++index) {
        uint32_t byte = (uint32_t)data[index];
        acc = mba149_add_xor_and(acc, byte);
        acc = mba149_add_or_xor(acc << 3, acc >> 7);
        acc = mba149_sub_xor_andnot(acc, mba149_zero(acc, byte));
    }
    return mba149_add_or_and(acc, (uint32_t)length);
}
