#include <stdint.h>

/* Opaque predicates: conditions whose value is fixed for every possible input,
 * but which no compiler (and no decompiler) can fold, because deciding them
 * requires number theory or knowledge the translation unit does not contain.
 *
 * Two families appear here:
 *
 *   1. Arithmetic invariants — `n * (n + 1)` is always even; a square is always
 *      0 or 1 modulo 4; `(v | 1)` is always odd. Each identity survives modular
 *      reduction, so it holds for uint32_t wraparound too, not just for the
 *      mathematical integers. The compiler would have to reason about all 2^32
 *      inputs to fold the branch, so it emits both arms.
 *
 *   2. A `volatile` sentinel — a file-scope object the compiler is forbidden to
 *      constant-propagate through. It is only ever read, never written, so its
 *      value is 0 in every execution, yet every arm guarded by it must be
 *      emitted.
 *
 * Why this breaks decompilers: the recovered CFG contains large regions that
 * are provably dead at runtime but structurally live. Output looks like a
 * function with rich branching behaviour it does not have, and any dataflow
 * summary (taint, range, "which inputs reach this write") is contaminated by
 * paths that never execute. A decompiler that *does* try to simplify — folding
 * `(v | 1) & 1` to 1, say — must get the whole identity right; getting it half
 * right silently deletes the live arm and keeps the dead one, which is the
 * canonical confident-nonsense failure. The differential distinguishes the two
 * because every arm here computes a *different* value.
 *
 * All arms are memory-safe whichever way a mis-recovery branches: no arm
 * indexes outside the validated bounds, so a wrong answer is a wrong number,
 * never a crash in the harness.
 */

#define OPAQUE146_MAX_ELEMS 16

/* Never written. Reading it is an unpredictable-to-the-compiler load whose
 * runtime value is always zero. */
static volatile uint32_t opq146_sentinel = 0u;

/* `n * (n + 1)` is the product of two consecutive integers, hence even; the
 * property is preserved modulo 2^32 because 2 divides 2^32. The `else` arm can
 * never execute. */
__attribute__((noinline)) int32_t
opaque_always_true(int32_t value) {
    uint32_t v = (uint32_t)value;
    if (((v * (v + 1u)) & 1u) == 0u) {
        return (int32_t)(v * 3u + 1u);
    }
    return (int32_t)(v ^ 0xDEADBEEFu);
}

/* Squares are congruent to 0 or 1 modulo 4, and `& 3` of the truncated product
 * equals the true residue because 4 divides 2^32. The `alternative` arm is
 * therefore unreachable for every pair of inputs. */
__attribute__((noinline)) int32_t
opaque_square_residue(int32_t value, int32_t alternative) {
    uint32_t v = (uint32_t)value;
    uint32_t square = v * v;
    uint32_t residue = square & 3u;
    if (residue == 2u || residue == 3u) {
        return (int32_t)((uint32_t)alternative ^ residue);
    }
    return (int32_t)((square >> 2) + residue);
}

/* A branchless opaque select. `mask` is 0 in every execution, so the result is
 * always `x`, but the compiler must materialise the full blend because the
 * sentinel is volatile. Recovering this as `return a;` is correct; recovering
 * it as `return b;` is the failure mode. */
__attribute__((noinline)) int32_t
opaque_volatile_select(int32_t a, int32_t b) {
    uint32_t gate = opq146_sentinel;
    uint32_t mask = 0u - (gate & 1u);
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    return (int32_t)(x ^ ((x ^ y) & mask));
}

/* An opaque predicate re-evaluated on loop-carried data: the product of two odd
 * numbers is odd, so the `else` arm never runs even though its operand changes
 * every iteration. Both arms write in bounds. */
__attribute__((noinline)) int32_t
opaque_loop_filter(int32_t *buffer, int32_t count) {
    int32_t index;
    uint32_t hits = 0u;

    if (buffer == 0 || count < 0 || count > OPAQUE146_MAX_ELEMS) {
        return -1;
    }

    for (index = 0; index < count; ++index) {
        uint32_t odd = (uint32_t)buffer[index] | 1u;
        if (((odd * odd) & 1u) == 1u) {
            buffer[index] = (int32_t)(odd + 1u);
            hits += 1u;
        } else {
            buffer[index] = 0;
        }
    }
    return (int32_t)hits;
}

/* A two-way opaque predicate: the condition genuinely depends on the input, but
 * both arms compute the same value by different routes. A decompiler is free to
 * keep either arm; it must not mix them, and it must not claim the function has
 * two behaviours. */
__attribute__((noinline)) int32_t
opaque_two_way_join(int32_t value, int32_t addend) {
    uint32_t v = (uint32_t)value;
    uint32_t k = (uint32_t)addend;
    if ((v & 1u) == 0u) {
        return (int32_t)((v ^ k) + ((v & k) << 1));
    }
    return (int32_t)((v | k) + (v & k));
}

/* The sentinel drives an index. Even under a total mis-recovery of the volatile
 * load the index stays inside the buffer: it is masked to 0..7 and then reduced
 * modulo a validated positive count. */
__attribute__((noinline)) int32_t
opaque_guarded_store(int32_t *buffer, int32_t count, int32_t value) {
    uint32_t gate = opq146_sentinel;
    int32_t index;

    if (buffer == 0 || count <= 0 || count > OPAQUE146_MAX_ELEMS) {
        return -1;
    }

    index = (int32_t)(gate & 7u) % count;
    buffer[index] = (int32_t)((uint32_t)value + 1u);
    return buffer[0];
}
