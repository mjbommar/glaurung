#include <stdint.h>

/* The whole adversarial stack at once — which is how real obfuscated code
 * arrives, because the passes compose:
 *
 *   * control-flow flattening (145): a dispatcher loop over a state variable,
 *   * opaque predicates (146): guards that are constant at runtime but not at
 *     compile time, including a `volatile` sentinel,
 *   * instruction substitution (147) and MBA (149): every add/sub/xor rewritten
 *     into mixed boolean-arithmetic form,
 *   * dispatch obfuscation (148): the dispatcher's successor comes from a table
 *     and the per-state operation from a function-pointer table.
 *
 * Why the combination is worse than the sum: each pass individually leaves one
 * recovery handle intact, and the next pass removes it. Flattening alone leaves
 * readable state constants — until the successor is a table load. A jump table
 * alone can be resolved by range analysis on the index — until the index is an
 * MBA expression that the range analysis cannot narrow. An MBA expression alone
 * can be attacked by symbolic simplification — until it is spread across
 * dispatcher states so no single basic block contains a whole identity.
 *
 * This is where "confident nonsense" is generated in practice: with no handle
 * left, a decompiler that keeps guessing produces structured, well-typed,
 * named output that is wrong about the loop trip count, the operation applied,
 * and the branch taken, all at once. Only an execution differential separates
 * that from the truth, which is the point of this corpus.
 *
 * Fully defined for every input: unsigned arithmetic throughout, literal shift
 * counts below 32, all indices masked to their table size, all buffer bounds
 * validated against small constants, and every dispatcher carrying a step
 * budget so it terminates.
 */

#define COMP150_S_ENTRY 0
#define COMP150_S_TEST 1
#define COMP150_S_MIX 2
#define COMP150_S_GUARD 3
#define COMP150_S_STORE 4
#define COMP150_S_STEP 5
#define COMP150_S_DONE 6

#define COMP150_MAX_ELEMS 16
#define COMP150_MAX_BYTES 16
#define COMP150_MAX_ROUNDS 4
#define COMP150_MAX_STEPS 512
#define COMP150_OPS 4

/* Never written; reads always yield zero but the compiler cannot know it. */
static volatile uint32_t comp150_sentinel = 0u;

static uint32_t comp150_add(uint32_t x, uint32_t y) {
    return (x ^ y) + ((x & y) << 1);
}

static uint32_t comp150_sub(uint32_t x, uint32_t y) {
    return (x ^ y) - (((~x) & y) << 1);
}

static uint32_t comp150_xor(uint32_t x, uint32_t y) {
    return (x | y) - (x & y);
}

/* Identically zero for every input pair. */
static uint32_t comp150_nonce(uint32_t x, uint32_t y) {
    return comp150_add(x, y) - (x | y) - (x & y);
}

static uint32_t comp150_op_mix(uint32_t a, uint32_t b) {
    return comp150_add(a, comp150_xor(b, 0x2545F491u));
}

static uint32_t comp150_op_fold(uint32_t a, uint32_t b) {
    return comp150_sub(a, (b << 3) | (b >> 29));
}

static uint32_t comp150_op_scatter(uint32_t a, uint32_t b) {
    return comp150_xor((a << 5) ^ (a >> 11), b);
}

static uint32_t comp150_op_seal(uint32_t a, uint32_t b) {
    return comp150_add(a * 0x9E3779B1u, comp150_nonce(a, b));
}

typedef uint32_t (*comp150_stage)(uint32_t, uint32_t);

static comp150_stage const COMP150_STAGES[COMP150_OPS] = {
    comp150_op_mix,
    comp150_op_fold,
    comp150_op_scatter,
    comp150_op_seal,
};

/* State -> successor when the guard is taken, and the operation slot per state.
 * The dispatcher's edges therefore live in .rodata, not in the code. */
static const uint8_t COMP150_SLOT_MAP[8] = {1, 3, 0, 2, 2, 0, 3, 1};
static const uint8_t COMP150_STIR_MAP[8] = {6, 4, 7, 5, 1, 3, 0, 2};

/* Flattened loop, table-selected operation per element, opaque guard choosing
 * between two live arms, MBA arithmetic in every state. */
__attribute__((noinline)) int32_t
obfuscated_transform(int32_t *values, int32_t count, int32_t seed) {
    int32_t state = COMP150_S_ENTRY;
    int32_t index = 0;
    int32_t steps;
    uint32_t acc = 0u;
    uint32_t current = 0u;

    if (values == 0 || count < 0 || count > COMP150_MAX_ELEMS) {
        return -1;
    }

    for (steps = 0; steps < COMP150_MAX_STEPS && state != COMP150_S_DONE; ++steps) {
        switch (state) {
        case COMP150_S_ENTRY:
            acc = (uint32_t)seed ^ comp150_sentinel;
            index = 0;
            state = COMP150_S_TEST;
            break;
        case COMP150_S_TEST:
            state = (index < count) ? COMP150_S_MIX : COMP150_S_DONE;
            break;
        case COMP150_S_MIX: {
            uint32_t slot = (uint32_t)COMP150_SLOT_MAP[(uint32_t)index & 7u];
            current = COMP150_STAGES[slot & (uint32_t)(COMP150_OPS - 1)](
                acc, (uint32_t)values[index]);
            state = COMP150_S_GUARD;
            break;
        }
        case COMP150_S_GUARD:
            /* `n * (n + 1)` is always even, so the first arm always runs; the
             * second is structurally live and dynamically dead. */
            if (((current * (current + 1u)) & 1u) == 0u) {
                acc = comp150_add(current, comp150_nonce(acc, current));
            } else {
                acc = comp150_sub(current, 0x1234u);
            }
            state = COMP150_S_STORE;
            break;
        case COMP150_S_STORE:
            values[index] = (int32_t)acc;
            state = COMP150_S_STEP;
            break;
        case COMP150_S_STEP:
            index += 1;
            state = COMP150_S_TEST;
            break;
        default:
            state = COMP150_S_DONE;
            break;
        }
    }
    return (int32_t)comp150_xor(acc, (uint32_t)index);
}

/* Nested obfuscation: a bounded outer round loop wrapped around a flattened
 * inner walk whose successor comes from a stir table and whose accumulator
 * update is MBA. Both bounds are validated. */
__attribute__((noinline)) uint32_t
obfuscated_digest(uint8_t *data, int32_t length, int32_t rounds) {
    int32_t round;
    uint32_t acc = 0x811C9DC5u;
    uint32_t cursor = 0u;

    if (data == 0 || length < 0 || length > COMP150_MAX_BYTES) {
        return 0u;
    }
    if (rounds < 0 || rounds > COMP150_MAX_ROUNDS) {
        return 0u;
    }

    for (round = 0; round < rounds; ++round) {
        int32_t state = COMP150_S_TEST;
        int32_t index = 0;
        int32_t steps;

        for (steps = 0; steps < COMP150_MAX_STEPS && state != COMP150_S_DONE; ++steps) {
            switch (state) {
            case COMP150_S_TEST:
                state = (index < length) ? COMP150_S_MIX : COMP150_S_DONE;
                break;
            case COMP150_S_MIX: {
                uint32_t byte = (uint32_t)data[index];
                uint32_t slot = (uint32_t)COMP150_SLOT_MAP[cursor & 7u];
                acc = COMP150_STAGES[slot & (uint32_t)(COMP150_OPS - 1)](acc, byte);
                cursor = (uint32_t)COMP150_STIR_MAP[cursor & 7u];
                state = COMP150_S_STEP;
                break;
            }
            case COMP150_S_STEP:
                index += 1;
                state = COMP150_S_TEST;
                break;
            default:
                state = COMP150_S_DONE;
                break;
            }
        }
        acc = comp150_xor(acc, comp150_add((uint32_t)round, comp150_nonce(acc, cursor)));
    }
    return comp150_add(acc, (uint32_t)length);
}

/* No loop, no buffer: a chain of opaque predicates whose (constant) outcomes
 * select table entries, with MBA arithmetic between them. The whole function is
 * a fixed sequence of three stages dressed up as input-dependent branching. */
__attribute__((noinline)) int32_t
obfuscated_predicate_chain(int32_t a, int32_t b, int32_t c) {
    uint32_t x = (uint32_t)a;
    uint32_t y = (uint32_t)b;
    uint32_t z = (uint32_t)c;
    uint32_t gate = comp150_sentinel;
    uint32_t first;
    uint32_t second;
    uint32_t slot;

    /* A square is 0 or 1 modulo 4, so the second arm is unreachable. */
    if (((x * x) & 3u) < 2u) {
        first = comp150_add(x, comp150_nonce(y, z));
    } else {
        first = comp150_sub(x, y);
    }

    /* `(v | 1)` is odd, so the first arm always runs. */
    slot = ((y | 1u) & 1u) ? (uint32_t)COMP150_SLOT_MAP[first & 7u]
                           : (uint32_t)COMP150_STIR_MAP[first & 7u];
    second = COMP150_STAGES[slot & (uint32_t)(COMP150_OPS - 1)](first, y);

    /* The sentinel is always zero, so the blend always yields `second`. */
    second = second ^ ((second ^ z) & (0u - (gate & 1u)));
    return (int32_t)comp150_xor(second, comp150_add(z, gate));
}
