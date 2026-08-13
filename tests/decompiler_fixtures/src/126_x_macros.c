#include <stdint.h>

/* X-macros: one list expanded into several different constructs. The source
 * has a single point of truth, but the binary contains a table, a switch and a
 * sum with no trace of the macro that generated them. */

#define OPCODE_LIST(X) \
    X(NOP, 0, 1)       \
    X(INC, 1, 2)       \
    X(DEC, 2, 3)       \
    X(SHL, 3, 5)       \
    X(NEG, 4, 8)

#define AS_ENUM(name, value, weight) OPCODE_##name = (value),
enum Opcode { OPCODE_LIST(AS_ENUM) OPCODE_COUNT = 5 };
#undef AS_ENUM

#define AS_WEIGHT(name, value, weight) [value] = (weight),
static const int32_t OPCODE_WEIGHTS[5] = {OPCODE_LIST(AS_WEIGHT)};
#undef AS_WEIGHT

__attribute__((noinline)) int32_t opcode_weight(int32_t opcode) {
    if (opcode < 0 || opcode >= (int32_t)OPCODE_COUNT) {
        return -1;
    }
    return OPCODE_WEIGHTS[opcode];
}

__attribute__((noinline)) int32_t apply_opcode(int32_t opcode, int32_t value) {
    switch (opcode) {
#define AS_CASE(name, value_, weight) case OPCODE_##name:
        AS_CASE(NOP, 0, 1)
        return value;
        AS_CASE(INC, 1, 2)
        return (int32_t)((uint32_t)value + 1u);
        AS_CASE(DEC, 2, 3)
        return (int32_t)((uint32_t)value - 1u);
        AS_CASE(SHL, 3, 5)
        return (int32_t)((uint32_t)value << 1);
        AS_CASE(NEG, 4, 8)
        return (int32_t)(0u - (uint32_t)value);
#undef AS_CASE
    default:
        return -1;
    }
}

__attribute__((noinline)) int32_t total_weight(void) {
    int32_t total = 0;
#define AS_SUM(name, value, weight) total += (weight);
    OPCODE_LIST(AS_SUM)
#undef AS_SUM
    return total;
}
