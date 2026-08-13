#include <stdint.h>

/* Conversions in both directions between integers and IEEE binary32/binary64.
 *
 * Float-to-integer TRUNCATES TOWARD ZERO — `-2.75` becomes `-2`, not `-3` — and
 * is UNDEFINED when the value does not fit the destination, so every function
 * here range-checks before converting.  The predicate is spelled `!(in range)`
 * rather than `out of range` so that a NaN, which compares false against
 * everything, takes the reject path instead of falling through it.
 *
 * The reverse direction is exact for small magnitudes and ROUNDS for large
 * ones: `(float)INT32_MAX` is 2147483648.0f, one above the value it came from.
 * `int32_round_trip_delta` measures precisely that, which is why a recovery
 * that drops the conversion, or performs it at the wrong width, cannot fake it.
 */

#define FP173_INT32_LIMIT 2147483648.0f          /* 2^31, exact in binary32 */
#define FP173_UINT32_LIMIT 4294967296.0f         /* 2^32, exact in binary32 */
#define FP173_INT64_LIMIT 9223372036854775808.0  /* 2^63, exact in binary64 */
#define FP173_ROUND_LIMIT 1000000.0f

/* Shared by the two binary32 -> int32 paths so both reject identically. */
static int fp173_in_int32_range(float value) {
    return value >= -FP173_INT32_LIMIT && value < FP173_INT32_LIMIT;
}

__attribute__((noinline)) int32_t truncate_toward_zero(float value) {
    if (!fp173_in_int32_range(value)) {
        return 0;
    }
    return (int32_t)value;
}

__attribute__((noinline)) int64_t truncate_double_to_i64(double value) {
    if (!(value >= -FP173_INT64_LIMIT && value < FP173_INT64_LIMIT)) {
        return 0;
    }
    return (int64_t)value;
}

/* Unsigned truncation is a different instruction sequence from the signed one
 * (the destination has no sign bit to borrow), and a recovery that types the
 * result signed disagrees for everything above 2^31. */
__attribute__((noinline)) uint32_t truncate_to_unsigned(float value) {
    if (!(value >= 0.0f && value < FP173_UINT32_LIMIT)) {
        return 0u;
    }
    return (uint32_t)value;
}

/* Rounding half away from zero, built out of truncation.  Bounded well inside
 * the int32 range so the `+/- 0.5f` cannot push the value out of it. */
__attribute__((noinline)) int32_t round_half_away_from_zero(float value) {
    if (!(value >= -FP173_ROUND_LIMIT && value <= FP173_ROUND_LIMIT)) {
        return 0;
    }
    return (int32_t)(value >= 0.0f ? value + 0.5f : value - 0.5f);
}

__attribute__((noinline)) float widen_int_to_float(int32_t value) {
    return (float)value;
}

__attribute__((noinline)) double widen_long_to_double(int64_t value) {
    return (double)value;
}

/* How far one int32 -> binary32 -> int32 round trip moved the value.  The
 * subtraction is performed at 64 bits: the two operands are within 128 of each
 * other, but computing the difference in `int32_t` would still be reasoning
 * about overflow that does not need to exist. */
__attribute__((noinline)) int32_t int32_round_trip_delta(int32_t value) {
    float widened = (float)value;
    if (!fp173_in_int32_range(widened)) {
        return 0;
    }
    return (int32_t)((int64_t)(int32_t)widened - (int64_t)value);
}
