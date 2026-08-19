#include <stdint.h>

/* Bit SCANS and bit COUNTS are two instruction families, not one spelling of
 * another, and until 2026-08-19 the corpus reached them almost by accident.
 *
 * x86 `bsf`/`bsr` report the INDEX of a set bit and leave the destination
 * untouched when the source is zero; `tzcnt`/`lzcnt` report a COUNT and answer
 * the operand's width there. GCC compiles `__builtin_ctz` to the `TZCNT`
 * encoding at every optimisation level -- it is `rep bsf`, which a pre-BMI part
 * executes as `bsf` -- so an ordinary build of the most ordinary bit idiom in C
 * contains an instruction whose zero case differs from the one this decompiler
 * had a lowering for. The only lane that reached it was one arm of a switch in
 * `144_inline_asm`, at 32 bits; nothing reached it at 64 bits, nothing reached
 * the set/clear/toggle family at all, and nothing anywhere reached `not` on a
 * byte view.
 *
 * Every function here is total: the zero cases are spelled out and every shift
 * count is masked, so the recompiled C has no undefined behaviour to disagree
 * with the original about.
 *
 * The controls are the point. A count lowered as if it were the opposite scan,
 * or a `btr` whose mask never got complemented, produces C that compiles, runs,
 * and returns a plausible number -- so each operation is paired with the
 * neighbour it would be confused with, and the two disagree on almost every
 * input. */

/* --- counts: trailing and leading, 32 and 64 bits --- */

__attribute__((noinline)) int32_t bsc202_ctz32(uint32_t value) {
    return (value == 0u) ? 32 : (int32_t)__builtin_ctz(value);
}

/* The control for `bsc202_ctz32`. Leading and trailing counts agree only on 0
 * and on the values with exactly one bit set at index 0 or 31, so a lowering
 * that confused them is visible on essentially every vector. */
__attribute__((noinline)) int32_t bsc202_clz32(uint32_t value) {
    return (value == 0u) ? 32 : (int32_t)__builtin_clz(value);
}

__attribute__((noinline)) int32_t bsc202_ctz64(uint64_t value) {
    return (value == 0u) ? 64 : (int32_t)__builtin_ctzll(value);
}

__attribute__((noinline)) int32_t bsc202_clz64(uint64_t value) {
    return (value == 0u) ? 64 : (int32_t)__builtin_clzll(value);
}

/* The count is a count, not an index: `ctz` and `31 - clz` are the same number
 * only for a single-bit operand. Returning both from one function makes a
 * lowering that reached for the bit-scan identity disagree here while both of
 * the two above still looked right. */
__attribute__((noinline)) int32_t bsc202_count_and_index(uint32_t value) {
    int32_t trailing;
    int32_t highest;

    if (value == 0u) {
        return -1;
    }
    trailing = (int32_t)__builtin_ctz(value);
    highest = 31 - (int32_t)__builtin_clz(value);
    return (highest * 64) + trailing;
}

/* --- set / clear / toggle: the bit-modify family --- */

__attribute__((noinline)) uint32_t bsc202_set_bit(uint32_t word, int32_t index) {
    return word | (1u << (index & 31));
}

/* The control for `bsc202_set_bit`. If the clearing mask is not complemented,
 * this returns exactly what setting returns. */
__attribute__((noinline)) uint32_t bsc202_clear_bit(uint32_t word,
                                                    int32_t index) {
    return word & ~(1u << (index & 31));
}

__attribute__((noinline)) uint32_t bsc202_toggle_bit(uint32_t word,
                                                     int32_t index) {
    return word ^ (1u << (index & 31));
}

/* Both polarities of the same write, chosen at run time. This is the shape
 * clang -O2 compiles to `bts` into a copy, `btr` into the original, and a
 * `cmov` to pick one: while both writes were invisible the two arms of that
 * select were the same expression and the bit was written at NEITHER polarity,
 * which no single-polarity test above can detect. */
__attribute__((noinline)) uint32_t bsc202_assign_bit(uint32_t word,
                                                     int32_t index,
                                                     int32_t bit) {
    uint32_t mask = 1u << (index & 31);

    if (bit != 0) {
        return word | mask;
    }
    return word & ~mask;
}

/* The same shape over a whole word, so the select runs many times with a
 * carried result rather than once at a return. */
__attribute__((noinline)) uint32_t bsc202_scatter_bits(uint32_t word,
                                                       uint32_t bits) {
    int32_t i;

    for (i = 0; i < 16; i++) {
        uint32_t mask = 1u << (i & 31);

        if (((bits >> (i & 31)) & 1u) != 0u) {
            word |= mask;
        } else {
            word &= ~mask;
        }
    }
    return word;
}

/* `7 - (at & 7)`, which compilers spell `not` on a BYTE view followed by
 * `and $7`. A byte register is not canonicalised to its 64-bit parent, so a
 * complement written to the byte name alone is a definition nothing reads and
 * the reflection silently disappears — leaving `at & 7`, which differs from the
 * correct answer for every input. */
__attribute__((noinline)) int32_t bsc202_reflect_in_byte(int32_t at) {
    return 7 - (at & 7);
}

/* The reflection where it actually occurs: addressing a bit inside a byte
 * buffer most-significant-bit first. */
__attribute__((noinline)) uint32_t bsc202_msb_first_bit(uint32_t word,
                                                        int32_t at) {
    int32_t shift = 7 - (at & 7);

    return (word >> shift) & 1u;
}
