/* Several guard-free `switch` dispatches in ONE translation unit, so their jump
 * tables land ADJACENT in `.rodata`.
 *
 * WHY THIS SHAPE HAS ITS OWN FIXTURE. `analysis::jump_table::
 * discover_jump_tables` recovers a table by taking the LONGEST run of section
 * words that decode to executable addresses. That rule has no end marker: when
 * a second table begins immediately after the first, the scan runs straight
 * through the boundary and reports one table of `N1 + N2 + ...` entries. The
 * over-read entries are table 2's offsets read relative to table 1's base, so
 * they resolve to `T_j - 4*N1` — addresses that are still inside `.text` and
 * therefore still pass `in_exec_regions`, which is why nothing downstream
 * rejects them.
 *
 * `cfg::discover_function` has exactly one defence against that: a dispatch
 * whose index carries no range check is attached SPECULATIVELY
 * (`TentativeDispatchEdges::needs_bound_proof`), and a whole-CFG must-dataflow
 * fixed point then has to prove a prefix, after which
 * `trim_unproven_dispatch_edges` deletes the rest. Both halves of that only
 * matter when the over-read actually happens, and it only happens when two
 * tables abut. `148_dispatch_obfuscation` has a single permuted switch, so its
 * table is the last thing in its `.rodata` neighbourhood and the scan stops on
 * its own; measured over the whole corpus at gcc/clang x O0/O1/O2 (1,107
 * binaries) the bound-proof path fires 8 times and the trim fires ZERO times.
 * This file is the missing input: it makes the tables abut on purpose.
 *
 * Each selector goes through a byte permutation table, which is what stops the
 * compiler emitting its own `cmp key, N; ja default` range check — a value
 * loaded from a `uint8_t` array is already provably in `[0, 255]` and, after
 * the compiler propagates the table contents, in `[0, 7]`. That is what makes
 * the dispatch guard-free, and a guard-free dispatch is the only kind that
 * reaches the bound-proof path at all.
 *
 * The permutations are deliberately not the identity and not monotone, so a
 * recovery that reconstructs the table but drops the mapping produces a
 * well-structured program that computes the wrong case for every selector.
 *
 * Safety: every index is masked to the map's size before the load, every map
 * entry is less than the number of cases, and all arithmetic runs through
 * `uint32_t`, so no input can overflow a signed type or read out of bounds.
 */

#include <stdint.h>

#define ADT204_MAP_SIZE 8u

/* Three distinct permutations of 0..7. Distinct so that a decompiler cannot
 * satisfy all three switches with one recovered mapping. */
static const uint8_t ADT204_MAP_A[ADT204_MAP_SIZE] = {5, 3, 7, 1, 6, 0, 4, 2};
static const uint8_t ADT204_MAP_B[ADT204_MAP_SIZE] = {2, 6, 0, 4, 1, 7, 3, 5};
static const uint8_t ADT204_MAP_C[ADT204_MAP_SIZE] = {7, 1, 5, 3, 0, 6, 2, 4};

/* First of the three abutting tables. Its scan is the one that runs off the
 * end into the other two. */
__attribute__((noinline)) int32_t adt204_switch_a(int32_t selector, int32_t value) {
    uint32_t key = ADT204_MAP_A[(uint32_t)selector & (ADT204_MAP_SIZE - 1u)];
    uint32_t v = (uint32_t)value;

    switch (key) {
    case 0u:
        return (int32_t)(v + 1u);
    case 1u:
        return (int32_t)(v * 2u);
    case 2u:
        return (int32_t)(v ^ 0x5a5au);
    case 3u:
        return (int32_t)(v >> 1);
    case 4u:
        return (int32_t)(v - 7u);
    case 5u:
        return (int32_t)(v & 0xffu);
    case 6u:
        return (int32_t)(v | 0x100u);
    default:
        return (int32_t)(0u - v);
    }
}

/* Second table. Its entries are what the first table's over-read misreads. */
__attribute__((noinline)) int32_t adt204_switch_b(int32_t selector, int32_t value) {
    uint32_t key = ADT204_MAP_B[(uint32_t)selector & (ADT204_MAP_SIZE - 1u)];
    uint32_t v = (uint32_t)value;

    switch (key) {
    case 0u:
        return (int32_t)(v + 11u);
    case 1u:
        return (int32_t)(v * 3u);
    case 2u:
        return (int32_t)(v ^ 0x1234u);
    case 3u:
        return (int32_t)(v >> 2);
    case 4u:
        return (int32_t)(v - 17u);
    case 5u:
        return (int32_t)(v & 0xfffu);
    case 6u:
        return (int32_t)(v | 0x200u);
    default:
        return (int32_t)(1u - v);
    }
}

/* Third table, so the over-read has to cross two boundaries rather than one.
 * Two boundaries matter: a trim that keeps "everything up to the first
 * discontinuity" and a trim that keeps a proven prefix behave identically with
 * one boundary and differently with two. */
__attribute__((noinline)) int32_t adt204_switch_c(int32_t selector, int32_t value) {
    uint32_t key = ADT204_MAP_C[(uint32_t)selector & (ADT204_MAP_SIZE - 1u)];
    uint32_t v = (uint32_t)value;

    switch (key) {
    case 0u:
        return (int32_t)(v + 21u);
    case 1u:
        return (int32_t)(v * 5u);
    case 2u:
        return (int32_t)(v ^ 0x4321u);
    case 3u:
        return (int32_t)(v >> 3);
    case 4u:
        return (int32_t)(v - 27u);
    case 5u:
        return (int32_t)(v & 0xffffu);
    case 6u:
        return (int32_t)(v | 0x400u);
    default:
        return (int32_t)(2u - v);
    }
}

/* Same case bodies as `adt204_switch_a`, but the selector is range-checked in
 * the source rather than through a permutation table. Its role is lane
 * dependent, and that is the useful part.
 *
 * At gcc it is the NEGATIVE CONTROL: gcc emits `cmp sel,7; ja default` with the
 * dispatch on the fall-through, which is the one edge polarity
 * `cfg::ctrl_flow::guard_bound_reaches_fallthrough` models, so the switch
 * resolves and a change that breaks this function damaged ordinary guarded
 * switches rather than the speculative path it was aimed at.
 *
 * At clang it is a SECOND POSITIVE, for a different reason than the three
 * above: clang reaches the dispatch on the TAKEN edge of a `jb`, and the taken
 * edge of a below/below-or-equal branch is not modelled at all — only the
 * fall-through of `ja`/`jae` is. Same source, same guard, opposite branch
 * polarity, and the bound is lost. That asymmetry is why a dispatch block with
 * several `jbe` predecessors (measured in `/usr/bin/3cpio` at 0x2f4bf,
 * `/usr/bin/aarch64-linux-gnu-ld.bfd` at 0x18119 and
 * `/usr/bin/aarch64-linux-gnu-objdump` at 0x20c21) currently gets its bound
 * from ONE predecessor's fall-through and nothing from the others. */
__attribute__((noinline)) int32_t adt204_guarded_control(int32_t selector, int32_t value) {
    uint32_t v = (uint32_t)value;

    if (selector < 0 || selector > 7) {
        return -1;
    }
    switch ((uint32_t)selector) {
    case 0u:
        return (int32_t)(v + 1u);
    case 1u:
        return (int32_t)(v * 2u);
    case 2u:
        return (int32_t)(v ^ 0x5a5au);
    case 3u:
        return (int32_t)(v >> 1);
    case 4u:
        return (int32_t)(v - 7u);
    case 5u:
        return (int32_t)(v & 0xffu);
    case 6u:
        return (int32_t)(v | 0x100u);
    default:
        return (int32_t)(0u - v);
    }
}

/* Drives all three abutting dispatches from one selector, so a recovery that
 * loses the arms of only the FIRST table (the one the scan over-reads from)
 * still produces an observably different result. */
__attribute__((noinline)) int32_t adt204_chained(int32_t selector, int32_t value) {
    int32_t a = adt204_switch_a(selector, value);
    int32_t b = adt204_switch_b(selector, a);
    int32_t c = adt204_switch_c(selector, b);
    return (int32_t)((uint32_t)c ^ (uint32_t)a);
}
