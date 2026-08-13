#include <stdint.h>

/* IEEE binary32 against binary64: the SAME expression at two widths.
 *
 * Every numeric fixture before this one is Q16.16 fixed point, because the
 * execution differential rejected floating point at signature recovery.  So
 * nothing in the corpus ever made the decompiler recover an xmm operand, a
 * `float` that is not a `double`, or the widening the ABI inserts between them.
 *
 * These functions are deliberately paired: `single_precision_horner` and
 * `double_precision_horner` are character-for-character the same arithmetic,
 * and a recovery that types every floating value as a `double` (or reuses one
 * width's constant pool for the other) produces identical C for both — which
 * the bit-exact return comparison then catches on the very first inexact input.
 *
 * Overflow to an infinity is an IEEE result, not undefined behaviour, so it is
 * left to happen.  NARROWING is different: converting a double whose magnitude
 * exceeds the float range is undefined, so it is range-checked first. */

/* Largest finite binary32, spelled as the exact binary64 value it widens to. */
#define FP172_FLOAT_MAX 3.4028234663852886e38

/* Every loop below is bounded by this literal, and the count that indexes it is
 * validated before use. */
#define FP172_TERM_LIMIT 16

static float fp172_horner_f32(float x, float a, float b) {
    return (a * x + b) * x + a;
}

static double fp172_horner_f64(double x, double a, double b) {
    return (a * x + b) * x + a;
}

__attribute__((noinline)) float single_precision_horner(float x, float a,
                                                        float b) {
    return fp172_horner_f32(x, a, b);
}

__attribute__((noinline)) double double_precision_horner(double x, double a,
                                                         double b) {
    return fp172_horner_f64(x, a, b);
}

/* One multiply performed at binary64 and delivered at binary32.  The guard is
 * written as `!(in range)` so a NaN intermediate — which `inf * 0` can produce
 * from in-range inputs — also takes the reject path instead of being narrowed.
 */
__attribute__((noinline)) float narrow_after_double_math(float left,
                                                         float right) {
    double product = (double)left * (double)right;
    double scaled = product / 3.0;
    if (!(scaled >= -FP172_FLOAT_MAX && scaled <= FP172_FLOAT_MAX)) {
        return 0.0f;
    }
    return (float)scaled;
}

/* Divide by three and multiply back.  Inexact in both formats, but by different
 * amounts, so the answer depends on the width the intermediate was kept at —
 * the one property a width-collapsing recovery cannot reproduce. */
__attribute__((noinline)) int32_t width_disagreement(float value) {
    float at_float = value / 3.0f * 3.0f;
    double at_double = (double)value / 3.0 * 3.0;
    return ((double)at_float == at_double) ? 0 : 1;
}

/* A halving series accumulated at the ELEMENT width. */
__attribute__((noinline)) float accumulate_narrow(float seed, int32_t count) {
    float total = 0.0f;
    float step = seed;
    int32_t index;
    if (count < 0 || count > FP172_TERM_LIMIT) {
        return 0.0f;
    }
    for (index = 0; index < count; ++index) {
        total += step;
        step = step * 0.5f;
    }
    return total;
}

/* The same series accumulated one width UP.  The terms are binary32 and the
 * total is binary64, so the two functions disagree exactly where the narrow
 * accumulator loses a digit — an accumulator whose width was mis-recovered is
 * visible here and nowhere else. */
__attribute__((noinline)) double accumulate_wide(float seed, int32_t count) {
    double total = 0.0;
    float step = seed;
    int32_t index;
    if (count < 0 || count > FP172_TERM_LIMIT) {
        return 0.0;
    }
    for (index = 0; index < count; ++index) {
        total += (double)step;
        step = step * 0.5f;
    }
    return total;
}
