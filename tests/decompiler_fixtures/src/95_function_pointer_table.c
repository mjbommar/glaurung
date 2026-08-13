#include <stdint.h>

/* An array of function pointers is an indirect call whose target is a loaded
 * value, not a relocation. Recovering the dispatch means recovering the table's
 * contents, its stride, and the bounds check that guards it. */

static int32_t op_add(int32_t a, int32_t b) { return (int32_t)((uint32_t)a + (uint32_t)b); }
static int32_t op_sub(int32_t a, int32_t b) { return (int32_t)((uint32_t)a - (uint32_t)b); }
static int32_t op_and(int32_t a, int32_t b) { return a & b; }
static int32_t op_xor(int32_t a, int32_t b) { return a ^ b; }
static int32_t op_max(int32_t a, int32_t b) { return a > b ? a : b; }

typedef int32_t (*BinaryOp)(int32_t, int32_t);

static BinaryOp const OPERATIONS[5] = {op_add, op_sub, op_and, op_xor, op_max};

__attribute__((noinline)) int32_t
dispatch_operation(int32_t which, int32_t a, int32_t b) {
    if (which < 0 || which >= 5) {
        return -1;
    }
    return OPERATIONS[which](a, b);
}

__attribute__((noinline)) int32_t
fold_operations(const int32_t *selectors, int32_t count, int32_t seed) {
    int32_t accumulator = seed;
    int32_t index;
    if (selectors == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (index = 0; index < count; ++index) {
        int32_t which = selectors[index];
        if (which < 0 || which >= 5) {
            continue;
        }
        accumulator = OPERATIONS[which](accumulator, index + 1);
    }
    return accumulator;
}
