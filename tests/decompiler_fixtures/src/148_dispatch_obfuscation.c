#include <stdint.h>

/* Jump-table and dispatch obfuscation: the control-flow edge is a value in a
 * table, not a branch in the code.
 *
 * Four variants appear here. A function-pointer table reached through an index
 * that is itself a table lookup, so the callee cannot be resolved without
 * constant-folding two loads. A `switch` whose selector is permuted by a byte
 * map, so the case labels in the binary bear no relation to the caller's
 * opcode. An indirect call whose index is produced by arithmetic and then
 * masked into range. And a state walk that chases a next-index table, which is
 * a jump table used as a linked list.
 *
 * Why this breaks decompilers: recovering an indirect call requires proving
 * what the target set is. Given `TABLE[MAP[op & 7] & 3](a, b)` a decompiler
 * either (a) gives up and prints a call through a variable, losing every
 * callee's name and signature, or (b) guesses. Guessing is the dangerous
 * outcome: emitting a direct call to whichever entry happened to be first, or
 * to a "most likely" target, produces output that compiles, type-checks, reads
 * naturally, and computes the wrong function for seven of the eight opcodes.
 * The permuted `switch` attacks the same weakness from the other side — the
 * jump-table reconstruction is correct but the case *labels* are meaningless
 * unless the permutation is carried through, so a decompiler that recovers the
 * table but drops the map produces a beautifully structured wrong program.
 *
 * Safety: every index is masked to the table's size before use, every count is
 * validated against a small constant bound, and no arithmetic can overflow a
 * signed type (all of it runs through uint32_t).
 */

#define JT148_TABLE_SIZE 4
#define JT148_MAP_SIZE 8
#define JT148_MAX_ELEMS 16

static int32_t jt148_op_add(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a + (uint32_t)b);
}

static int32_t jt148_op_sub(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a - (uint32_t)b);
}

static int32_t jt148_op_xor(int32_t a, int32_t b) {
    return (int32_t)((uint32_t)a ^ (uint32_t)b);
}

static int32_t jt148_op_pick(int32_t a, int32_t b) {
    return (a < b) ? a : b;
}

typedef int32_t (*jt148_handler)(int32_t, int32_t);

static jt148_handler const JT148_HANDLERS[JT148_TABLE_SIZE] = {
    jt148_op_add,
    jt148_op_sub,
    jt148_op_xor,
    jt148_op_pick,
};

/* Opcode -> handler slot. Deliberately not the identity, and not monotone. */
static const uint8_t JT148_SLOT_MAP[JT148_MAP_SIZE] = {2, 0, 3, 1, 1, 3, 0, 2};

/* Selector -> case label. The inverse permutation of what an analyst expects. */
static const uint8_t JT148_CASE_MAP[JT148_MAP_SIZE] = {5, 3, 7, 1, 6, 0, 4, 2};

/* State -> next state. A jump table used as a successor list. */
static const uint8_t JT148_NEXT_MAP[JT148_MAP_SIZE] = {3, 5, 7, 2, 0, 6, 1, 4};

/* Two dependent loads before the call: the callee is only knowable by folding
 * both tables. */
__attribute__((noinline)) int32_t
obfuscated_dispatch(int32_t op, int32_t a, int32_t b) {
    uint32_t slot = (uint32_t)op & (uint32_t)(JT148_MAP_SIZE - 1);
    uint32_t index = (uint32_t)JT148_SLOT_MAP[slot] & (uint32_t)(JT148_TABLE_SIZE - 1);
    return JT148_HANDLERS[index](a, b);
}

/* The index is computed rather than loaded, then masked into range. Masking is
 * what makes this memory-safe for every input while keeping the target
 * genuinely input-dependent. */
__attribute__((noinline)) int32_t
computed_index_dispatch(int32_t base, int32_t delta) {
    uint32_t mixed = (uint32_t)base * 3u + (uint32_t)delta;
    uint32_t index = (mixed ^ (mixed >> 5)) & (uint32_t)(JT148_TABLE_SIZE - 1);
    return JT148_HANDLERS[index](base, delta);
}

/* A dense switch reached through a permutation table. The compiler emits a real
 * jump table for the switch; the permutation sits in .rodata in front of it. */
__attribute__((noinline)) int32_t
permuted_switch(int32_t selector, int32_t value) {
    uint32_t key = (uint32_t)JT148_CASE_MAP[(uint32_t)selector & (uint32_t)(JT148_MAP_SIZE - 1)];
    uint32_t v = (uint32_t)value;

    switch (key) {
    case 0u:
        return (int32_t)(v + 1u);
    case 1u:
        return (int32_t)(v * 2u);
    case 2u:
        return (int32_t)(v ^ 0x5A5Au);
    case 3u:
        return (int32_t)(v >> 1);
    case 4u:
        return (int32_t)(v - 7u);
    case 5u:
        return (int32_t)(v & 0xFFu);
    case 6u:
        return (int32_t)(v | 0x100u);
    case 7u:
        return (int32_t)(0u - v);
    default:
        return 0;
    }
}

/* Chasing the successor table: each iteration's control decision is a load from
 * .rodata, so the walk's trajectory is data, not code. Bounded by a validated
 * count and by the table mask. */
__attribute__((noinline)) int32_t
chained_table_walk(int32_t *out, int32_t count, int32_t start) {
    uint32_t state = (uint32_t)start & (uint32_t)(JT148_MAP_SIZE - 1);
    uint32_t acc = 0u;
    int32_t index;

    if (out == 0 || count < 0 || count > JT148_MAX_ELEMS) {
        return -1;
    }

    for (index = 0; index < count; ++index) {
        uint32_t slot = (uint32_t)JT148_SLOT_MAP[state] & (uint32_t)(JT148_TABLE_SIZE - 1);
        acc = (uint32_t)JT148_HANDLERS[slot]((int32_t)acc, (int32_t)state);
        out[index] = (int32_t)acc;
        state = (uint32_t)JT148_NEXT_MAP[state] & (uint32_t)(JT148_MAP_SIZE - 1);
    }
    return (int32_t)(acc ^ state);
}
