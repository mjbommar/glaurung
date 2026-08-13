#include <stdint.h>

/* Signed division at 8 and 16 bits.
 *
 * COVERAGE TARGET: `Cbw` and `Cwd`. x86 divides through a register PAIR, and
 * the pair is built by a sign-extension instruction chosen for the operand
 * width: `cbw` (al -> ax) before `idiv r/m8`, `cwd` (ax -> dx:ax) before `idiv
 * r/m16`, `cdq`/`cqo` at 32 and 64. The corpus divides only at 32 and 64 bits,
 * so `cbw` and `cwd` are never lifted — and getting them wrong is invisible on
 * non-negative inputs, because zero-extension and sign-extension agree there.
 *
 * Every function is therefore exercised with negative dividends, and every
 * divisor is guarded: `x / 0` is undefined, and so is `INT_MIN / -1` at every
 * width, including the promoted `int` the sub-word operands become. */

__attribute__((noinline)) int32_t divide_signed_bytes(int32_t left,
                                                      int32_t right) {
    int8_t dividend = (int8_t)left;
    int8_t divisor = (int8_t)right;
    if (divisor == 0) {
        return 0;
    }
    /* `INT8_MIN / -1` is 128, which is not an `int8_t`; the promotion to `int`
     * makes it defined, and the cast back is what x86 computes in `al`. */
    if (dividend == INT8_MIN && divisor == -1) {
        return INT8_MIN;
    }
    return (int32_t)(int8_t)(dividend / divisor);
}

__attribute__((noinline)) int32_t remainder_signed_bytes(int32_t left,
                                                         int32_t right) {
    int8_t dividend = (int8_t)left;
    int8_t divisor = (int8_t)right;
    if (divisor == 0) {
        return 0;
    }
    if (dividend == INT8_MIN && divisor == -1) {
        return 0;
    }
    /* C truncates toward zero, so the remainder carries the DIVIDEND's sign —
     * the fact a zero-extending recovery gets wrong for every negative input. */
    return (int32_t)(int8_t)(dividend % divisor);
}

__attribute__((noinline)) int32_t divide_signed_shorts(int32_t left,
                                                       int32_t right) {
    int16_t dividend = (int16_t)left;
    int16_t divisor = (int16_t)right;
    if (divisor == 0) {
        return 0;
    }
    if (dividend == INT16_MIN && divisor == -1) {
        return INT16_MIN;
    }
    return (int32_t)(int16_t)(dividend / divisor);
}

__attribute__((noinline)) int32_t remainder_signed_shorts(int32_t left,
                                                          int32_t right) {
    int16_t dividend = (int16_t)left;
    int16_t divisor = (int16_t)right;
    if (divisor == 0) {
        return 0;
    }
    if (dividend == INT16_MIN && divisor == -1) {
        return 0;
    }
    return (int32_t)(int16_t)(dividend % divisor);
}

/* The unsigned siblings, which use `xor ah,ah` / `xor dx,dx` instead of
 * `cbw` / `cwd`. Present so a recovery that sign-extends everything is caught
 * as surely as one that zero-extends everything. */
__attribute__((noinline)) int32_t divide_unsigned_bytes(int32_t left,
                                                        int32_t right) {
    uint8_t dividend = (uint8_t)left;
    uint8_t divisor = (uint8_t)right;
    if (divisor == 0u) {
        return 0;
    }
    return (int32_t)(uint8_t)(dividend / divisor);
}

__attribute__((noinline)) int32_t divide_unsigned_shorts(int32_t left,
                                                         int32_t right) {
    uint16_t dividend = (uint16_t)left;
    uint16_t divisor = (uint16_t)right;
    if (divisor == 0u) {
        return 0;
    }
    return (int32_t)(uint16_t)(dividend / divisor);
}

/* Division by a CONSTANT at sub-word width: the compiler replaces the divide
 * with a multiply-high and a shift, and the correction step for a negative
 * dividend is where a mis-recovered sign extension shows up as an off-by-one. */
__attribute__((noinline)) int32_t divide_short_by_seven(int32_t value) {
    int16_t dividend = (int16_t)value;
    return (int32_t)(int16_t)(dividend / 7);
}
