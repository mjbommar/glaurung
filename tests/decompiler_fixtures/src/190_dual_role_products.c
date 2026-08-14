#include <stdint.h>

/* Two logically distinct values produced by ONE machine operation.
 *
 * `value_split` and `call_result_split` exist to keep such values apart. When
 * they alias, the recovered C is still plausible and still compiles — it simply
 * uses one value where the machine used two. A fixture that returns only one of
 * the pair cannot see this: `02_integer_widths` already covers a widening
 * multiply, but every one of its functions consumes a single half, so a
 * decompiler that conflated the halves would still pass it.
 *
 * Division is the portable form of the shape. On x86-64 a single `div` writes
 * the quotient to `rax` and the remainder to `rdx` — one instruction, two
 * architectural outputs, both live. AArch64 spells it `udiv` then `msub`, which
 * is the same dependency with a different shape, and it is the case the
 * dual-role splitters were written for. Using division rather than `__int128`
 * also keeps every lane in play: the `__int128` functions in `02_integer_widths`
 * force i386 and armv7 to declare the whole fixture unsupported.
 *
 * Each function keeps its pair in the caller's own scratch buffer, so the
 * differential observes the two values directly rather than inferring them from
 * one combined result, and combines them with DISTINCT coefficients, so
 * substituting one for the other moves the return value instead of cancelling.
 *
 * `dp190_quotient_only` is the control: the remainder is genuinely dead there,
 * so a decompiler must still eliminate it. Without that, this fixture would be
 * satisfied by one that simply never eliminates anything. */

#define DP190_SLOT_FIRST 0
#define DP190_SLOT_SECOND 1
#define DP190_SLOT_WITNESS 2

/* One `div`: quotient and remainder are both live and play different roles. */
__attribute__((noinline)) uint32_t dp190_div_and_rem(uint32_t *scratch, uint32_t a,
                                                     uint32_t b) {
    uint32_t quotient;
    uint32_t remainder;
    if (scratch == 0 || b == 0) {
        return 0xFFFFFFFFu;
    }
    quotient = a / b;
    remainder = a % b;
    scratch[DP190_SLOT_FIRST] = quotient;
    scratch[DP190_SLOT_SECOND] = remainder;
    /* Distinct coefficients: aliasing the two outputs changes this, where
     * `quotient + remainder` would hide a swap. */
    return quotient * 3u + remainder;
}

/* Signed `idiv`. Truncation is toward zero and the remainder takes the sign of
 * the dividend, so a swap is observable in the sign as well as the magnitude. */
__attribute__((noinline)) int32_t dp190_sdiv_and_rem(int32_t *scratch, int32_t a,
                                                     int32_t b) {
    int32_t quotient;
    int32_t remainder;
    if (scratch == 0 || b == 0) {
        return -1;
    }
    /* INT32_MIN / -1 traps on x86; the original and the recovery would both
     * fault, which is not the property under test. */
    if (a == (-2147483647 - 1) && b == -1) {
        return -2;
    }
    quotient = a / b;
    remainder = a % b;
    scratch[DP190_SLOT_FIRST] = quotient;
    scratch[DP190_SLOT_SECOND] = remainder;
    return quotient * 3 + remainder;
}

/* Widening multiply with BOTH halves live. On i386 this is one `mul` writing
 * `edx:eax`; elsewhere it is a wide multiply plus a shift. Either way the two
 * halves are distinct values that must not collapse into one. */
__attribute__((noinline)) uint32_t dp190_mul_both_halves(uint32_t *scratch, uint32_t a,
                                                         uint32_t b) {
    uint64_t product;
    uint32_t low;
    uint32_t high;
    if (scratch == 0) {
        return 0xFFFFFFFFu;
    }
    product = (uint64_t)a * (uint64_t)b;
    low = (uint32_t)product;
    high = (uint32_t)(product >> 32);
    scratch[DP190_SLOT_FIRST] = low;
    scratch[DP190_SLOT_SECOND] = high;
    return high * 5u + low;
}

/* The pair crosses a branch, so the two values must stay distinct through a
 * join rather than only within one straight-line block. */
__attribute__((noinline)) uint32_t dp190_pair_across_join(uint32_t *scratch, uint32_t a,
                                                          uint32_t b, uint32_t flag) {
    uint32_t quotient;
    uint32_t remainder;
    uint32_t chosen;
    if (scratch == 0 || b == 0) {
        return 0xFFFFFFFFu;
    }
    quotient = a / b;
    remainder = a % b;
    if (flag) {
        chosen = quotient * 7u + remainder;
    } else {
        chosen = remainder * 7u + quotient;
    }
    scratch[DP190_SLOT_FIRST] = quotient;
    scratch[DP190_SLOT_SECOND] = remainder;
    scratch[DP190_SLOT_WITNESS] = chosen;
    return chosen;
}

/* CONTROL: only the quotient is used, so the remainder really is dead and must
 * still be eliminated. A decompiler that keeps every architectural output alive
 * to pass the functions above must not pass this one for free. */
__attribute__((noinline)) uint32_t dp190_quotient_only(uint32_t *scratch, uint32_t a,
                                                       uint32_t b) {
    uint32_t quotient;
    if (scratch == 0 || b == 0) {
        return 0xFFFFFFFFu;
    }
    quotient = a / b;
    scratch[DP190_SLOT_FIRST] = quotient;
    return quotient * 3u;
}
