#include <stdint.h>
#include <string.h>

/* Floating-point comparison and classification.
 *
 * Two things here are invisible to an integer corpus.  First, a float compare
 * has FOUR outcomes, not three: `<`, `>`, `==` and UNORDERED, the last of which
 * makes every one of the first three false at once.  On x86 that is the parity
 * flag, and a recovery that lowers `ucomiss` as if it were `cmp` produces code
 * that is right on ordered inputs and wrong on unordered ones.  Second, zero
 * has a sign: `-0.0 == 0.0` is true while their bit patterns differ, so a
 * recovery that folds one into the other is invisible to a value comparison and
 * caught immediately by a bitwise one.
 *
 * The NaN is BUILT FROM ITS BIT PATTERN rather than by dividing zero by zero.
 * A bit pattern is exact and unconditionally defined; `0.0/0.0` is defined only
 * through Annex F, and a fixture should not depend on an annex to be free of
 * undefined behaviour.  Its payload is taken from the input so the value is not
 * a compile-time constant and the comparison is really performed. */

#define FP174_QUIET_NAN_BITS 0x7FC00000u
#define FP174_SIGN_MASK 0x80000000u
#define FP174_EXPONENT_MASK 0x7F800000u
#define FP174_MANTISSA_MASK 0x007FFFFFu

/* Class codes returned by `classify_binary32`. */
#define FP174_CLASS_ZERO 0
#define FP174_CLASS_SUBNORMAL 1
#define FP174_CLASS_NORMAL 2
#define FP174_CLASS_INFINITE 3
#define FP174_CLASS_NAN 4

_Static_assert(sizeof(float) == sizeof(uint32_t), "binary32 is four bytes");

/* `memcpy` rather than a union or a cast: it is the one spelling that is
 * defined regardless of the aliasing rules the optimiser is applying, and both
 * compilers turn a four-byte copy into a single register move. */
static uint32_t fp174_float_bits(float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof bits);
    return bits;
}

static float fp174_bits_to_float(uint32_t bits) {
    float value;
    memcpy(&value, &bits, sizeof value);
    return value;
}

/* -1 / 0 / 1 as usual, and 2 for the fourth outcome an integer compare does not
 * have.  Reachable only when an operand is a NaN, which arithmetic inside a
 * caller can produce from finite inputs. */
__attribute__((noinline)) int32_t ordered_compare_binary32(float left,
                                                           float right) {
    if (left < right) {
        return -1;
    }
    if (left > right) {
        return 1;
    }
    if (left == right) {
        return 0;
    }
    return 2;
}

/* Every relational operator against a quiet NaN, as a bitmask.  The answer is
 * always 8 (`!=` alone is true), so any other value from either side is a
 * mis-lowered unordered compare rather than a disagreement about arithmetic. */
__attribute__((noinline)) int32_t unordered_compare_flags(float value) {
    uint32_t payload = fp174_float_bits(value) & FP174_MANTISSA_MASK;
    float nan_value = fp174_bits_to_float(FP174_QUIET_NAN_BITS | payload);
    int32_t flags = 0;
    if (value < nan_value) {
        flags |= 1;
    }
    if (value > nan_value) {
        flags |= 2;
    }
    if (value == nan_value) {
        flags |= 4;
    }
    if (value != nan_value) {
        flags |= 8;
    }
    if (value <= nan_value) {
        flags |= 16;
    }
    if (value >= nan_value) {
        flags |= 32;
    }
    return flags;
}

/* The sign bit itself, which is the only way to tell -0.0 from 0.0. */
__attribute__((noinline)) int32_t sign_bit_of_binary32(float value) {
    return (int32_t)((fp174_float_bits(value) & FP174_SIGN_MASK) >> 31);
}

/* Negation is a sign-bit flip, not a subtraction from zero: `-(0.0f)` is
 * `-0.0f`, while `0.0f - 0.0f` is `+0.0f`.  The bit-exact return comparison is
 * what makes the difference observable. */
__attribute__((noinline)) float negate_binary32(float value) {
    return -value;
}

__attribute__((noinline)) float absolute_binary32(float value) {
    return fp174_bits_to_float(fp174_float_bits(value) & ~FP174_SIGN_MASK);
}

__attribute__((noinline)) int32_t classify_binary32(float value) {
    uint32_t bits = fp174_float_bits(value);
    uint32_t exponent = bits & FP174_EXPONENT_MASK;
    uint32_t mantissa = bits & FP174_MANTISSA_MASK;
    if (exponent == FP174_EXPONENT_MASK) {
        return (mantissa != 0u) ? FP174_CLASS_NAN : FP174_CLASS_INFINITE;
    }
    if (exponent == 0u) {
        return (mantissa != 0u) ? FP174_CLASS_SUBNORMAL : FP174_CLASS_ZERO;
    }
    return FP174_CLASS_NORMAL;
}

/* A signed zero the harness cannot hand in directly: multiplying by zero keeps
 * the operand's sign, so a negative input yields -0.0 and a positive one +0.0,
 * and the two are `==` but not identical.  An infinite input yields a NaN
 * instead, which the guard rejects with -1. */
__attribute__((noinline)) int32_t zero_sign_from_product(float value) {
    float product = value * 0.0f;
    if (!(product == 0.0f)) {
        return -1;
    }
    return (fp174_float_bits(product) == fp174_float_bits(0.0f)) ? 0 : 1;
}
