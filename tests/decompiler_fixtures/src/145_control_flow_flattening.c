#include <stdint.h>

/* Control-flow flattening: the shape produced by every commodity obfuscator
 * (OLLVM's `-fla`, VMProtect's dispatcher, most packers' unpack stubs).
 *
 * Every structured region — the loop, the if/else ladder, the early exit — is
 * dissolved into basic blocks that no longer dominate each other. What remains
 * is a single `while` around a `switch` on a state variable, plus assignments
 * to that variable at the end of each block. The original edges live only in
 * the DATA the dispatcher reads, not in the CFG.
 *
 * Why this breaks decompilers: interval/structural analysis sees one loop with
 * N successors and no natural nesting, so it emits `while (1) { switch (state)
 * { ... } }` verbatim — syntactically valid, semantically faithful, and
 * completely useless to an analyst. Worse, a structurer that tries to be clever
 * often *invents* nesting that isn't there, producing confident nonsense: a
 * `for` loop whose body is only reachable on one of the three state edges.
 * The differential catches exactly that class of over-eager restructuring,
 * because a wrong edge changes the answer even though the text looks plausible.
 *
 * Everything here is fully defined: all arithmetic that can overflow runs
 * through uint32_t, every buffer index is bounded by a validated count, and
 * the dispatcher carries a step budget so the loop terminates for any input.
 */

#define FLAT145_S_ENTRY 0
#define FLAT145_S_TEST 1
#define FLAT145_S_BODY 2
#define FLAT145_S_ARM_A 3
#define FLAT145_S_ARM_B 4
#define FLAT145_S_NEXT 5
#define FLAT145_S_DONE 6

#define FLAT145_MAX_ELEMS 16
#define FLAT145_MAX_STEPS 256

/* A flattened `for (i = 0; i < count; ++i)` whose body is a flattened
 * `if (odd) ... else ...`. Six states replace two structured constructs. */
__attribute__((noinline)) int32_t
flattened_accumulate(int32_t *values, int32_t count, int32_t seed) {
    int32_t state = FLAT145_S_ENTRY;
    int32_t index = 0;
    int32_t steps;
    uint32_t acc = 0u;

    if (values == 0 || count < 0 || count > FLAT145_MAX_ELEMS) {
        return -1;
    }

    for (steps = 0; steps < FLAT145_MAX_STEPS && state != FLAT145_S_DONE; ++steps) {
        switch (state) {
        case FLAT145_S_ENTRY:
            acc = (uint32_t)seed;
            index = 0;
            state = FLAT145_S_TEST;
            break;
        case FLAT145_S_TEST:
            state = (index < count) ? FLAT145_S_BODY : FLAT145_S_DONE;
            break;
        case FLAT145_S_BODY:
            state = (values[index] & 1) ? FLAT145_S_ARM_A : FLAT145_S_ARM_B;
            break;
        case FLAT145_S_ARM_A:
            acc = acc * 3u + (uint32_t)values[index];
            state = FLAT145_S_NEXT;
            break;
        case FLAT145_S_ARM_B:
            acc ^= (uint32_t)values[index] << 1;
            state = FLAT145_S_NEXT;
            break;
        case FLAT145_S_NEXT:
            index += 1;
            state = FLAT145_S_TEST;
            break;
        default:
            state = FLAT145_S_DONE;
            break;
        }
    }
    return (int32_t)(acc ^ (uint32_t)index);
}

/* A flattened loop with an early exit: the `found` edge jumps straight to the
 * terminal state, so the dispatcher has two distinct predecessors of DONE. A
 * structurer that folds both into one tail loses the break. */
__attribute__((noinline)) int32_t
flattened_search(int32_t *haystack, int32_t count, int32_t needle) {
    int32_t state = FLAT145_S_ENTRY;
    int32_t index = 0;
    int32_t found = -1;
    int32_t steps;

    if (haystack == 0 || count < 0 || count > FLAT145_MAX_ELEMS) {
        return -2;
    }

    for (steps = 0; steps < FLAT145_MAX_STEPS && state != FLAT145_S_DONE; ++steps) {
        switch (state) {
        case FLAT145_S_ENTRY:
            index = 0;
            found = -1;
            state = FLAT145_S_TEST;
            break;
        case FLAT145_S_TEST:
            state = (index < count) ? FLAT145_S_BODY : FLAT145_S_DONE;
            break;
        case FLAT145_S_BODY:
            state = (haystack[index] == needle) ? FLAT145_S_ARM_A : FLAT145_S_NEXT;
            break;
        case FLAT145_S_ARM_A:
            found = index;
            state = FLAT145_S_DONE;
            break;
        case FLAT145_S_NEXT:
            index += 1;
            state = FLAT145_S_TEST;
            break;
        default:
            state = FLAT145_S_DONE;
            break;
        }
    }
    return found;
}

/* Euclid's algorithm flattened. The natural loop is a three-state cycle; the
 * guard that keeps `%` defined lives in a different state from the `%` itself,
 * so a decompiler that reorders the states introduces a division by zero that
 * the original never performs. */
__attribute__((noinline)) uint32_t
flattened_gcd(uint32_t left, uint32_t right) {
    uint32_t a = left;
    uint32_t b = right;
    uint32_t rem = 0u;
    int32_t state = FLAT145_S_TEST;
    int32_t steps;

    for (steps = 0; steps < FLAT145_MAX_STEPS && state != FLAT145_S_DONE; ++steps) {
        switch (state) {
        case FLAT145_S_TEST:
            state = (b == 0u) ? FLAT145_S_DONE : FLAT145_S_BODY;
            break;
        case FLAT145_S_BODY:
            rem = a % b;
            state = FLAT145_S_NEXT;
            break;
        case FLAT145_S_NEXT:
            a = b;
            b = rem;
            state = FLAT145_S_TEST;
            break;
        default:
            state = FLAT145_S_DONE;
            break;
        }
    }
    return a;
}

/* A flattened if/else-if/else ladder with no loop at all in the source: the
 * dispatcher is pure control-flow noise. The case labels are deliberately not
 * in execution order, which is what a real obfuscator's randomised state
 * numbering produces. */
__attribute__((noinline)) int32_t
flattened_classify(int32_t x, int32_t y) {
    int32_t state = FLAT145_S_ENTRY;
    int32_t result = 0;
    int32_t steps;

    for (steps = 0; steps < 32 && state != FLAT145_S_DONE; ++steps) {
        switch (state) {
        case FLAT145_S_ENTRY:
            state = (x < y) ? FLAT145_S_ARM_A : FLAT145_S_TEST;
            break;
        case FLAT145_S_NEXT:
            result = (y < 0) ? 2 : 1;
            state = FLAT145_S_DONE;
            break;
        case FLAT145_S_ARM_A:
            result = (x < 0) ? -2 : -1;
            state = FLAT145_S_DONE;
            break;
        case FLAT145_S_TEST:
            state = (x == y) ? FLAT145_S_ARM_B : FLAT145_S_NEXT;
            break;
        case FLAT145_S_ARM_B:
            result = 0;
            state = FLAT145_S_DONE;
            break;
        default:
            state = FLAT145_S_DONE;
            break;
        }
    }
    return result * 10 + steps;
}
