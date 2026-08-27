#include <stdint.h>

/* A `switch` whose selector is 64 bits wide, with case labels above 2^32.
 *
 * WHY THE WIDTH MATTERS. Every part of dispatch recovery is 32-bit-shaped by
 * habit: the guard that proves a range bound reads a 32-bit compare, the table
 * index is a 32-bit register, and `DispatchTracker::bounded` maps a register to
 * a `u64` bound that is nevertheless only ever ESTABLISHED from a 32-bit
 * comparison. A 64-bit selector changes three things at once — the compare is
 * against a wide immediate (often itself from a literal pool), the index must
 * be truncated before it can address a table, and a case label above 2^32
 * cannot be a table offset at all, so the compiler must emit a comparison tree
 * for the high labels and may emit a table for a dense low cluster.
 *
 * That mixture — a tree over clusters, with a table inside one cluster — is the
 * shape where a recogniser that assumes "one dispatch per switch" loses the
 * arms it did not expect.
 *
 * Every existing switch fixture is 32-bit: `04_switch_shapes`,
 * `106_switch_shapes_dense_sparse`, `154_wide_switch` (wide in ARM COUNT, not
 * in selector width), `186_defaultless_guarded_switch`,
 * `204_adjacent_dispatch_tables`. None declares a `uint64_t` selector, and none
 * has a label that does not fit in 32 bits.
 *
 * `115_enum_semantics` covers the underlying type of an enum, which is a
 * different question: an enum's constants are small.
 */

/* Dense 64-bit labels in the low range: a table is legal here, and the selector
 * must be truncated to index it. */
__attribute__((noinline)) int32_t wide_selector_dense(uint64_t op) {
    switch (op) {
    case 0:  return 10;
    case 1:  return 11;
    case 2:  return 12;
    case 3:  return 13;
    case 4:  return 14;
    case 5:  return 15;
    case 6:  return 16;
    case 7:  return 17;
    default: return -1;
    }
}

/* Labels ABOVE 2^32: no table can address these, so every target emits
 * comparisons against wide constants. */
__attribute__((noinline)) int32_t wide_selector_high_labels(uint64_t op) {
    switch (op) {
    case 0x100000000ull: return 20;
    case 0x100000001ull: return 21;
    case 0x200000000ull: return 22;
    case 0xFFFFFFFFFFFFFFFFull: return 23;
    default: return -1;
    }
}

/* A dense low cluster AND high labels in one switch — a comparison tree whose
 * leaves include a jump table. */
__attribute__((noinline)) int32_t wide_selector_mixed(uint64_t op) {
    switch (op) {
    case 0:  return 30;
    case 1:  return 31;
    case 2:  return 32;
    case 3:  return 33;
    case 4:  return 34;
    case 5:  return 35;
    case 0x100000000ull: return 36;
    case 0x8000000000000000ull: return 37;
    default: return -1;
    }
}

/* A SIGNED 64-bit selector with negative labels, so the guard is a signed
 * comparison and an unsigned range proof would be wrong. */
__attribute__((noinline)) int32_t signed_wide_selector(int64_t op) {
    switch (op) {
    case -3: return 40;
    case -2: return 41;
    case -1: return 42;
    case  0: return 43;
    case  1: return 44;
    case  2: return 45;
    default: return -1;
    }
}

/* CONTROL: the identical dense switch with a 32-bit selector. It must recover
 * at least as well as the 64-bit version; if the wide one regresses and this
 * does not, the width is the cause. */
__attribute__((noinline)) int32_t narrow_selector_control(uint32_t op) {
    switch (op) {
    case 0:  return 10;
    case 1:  return 11;
    case 2:  return 12;
    case 3:  return 13;
    case 4:  return 14;
    case 5:  return 15;
    case 6:  return 16;
    case 7:  return 17;
    default: return -1;
    }
}
