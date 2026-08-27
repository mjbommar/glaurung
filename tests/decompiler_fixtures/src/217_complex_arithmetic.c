#include <stdint.h>

/* `_Complex` — a C type with its own ABI class, its own register pairing, and
 * no coverage anywhere in this corpus.
 *
 * WHY IT IS NOT JUST TWO FLOATS. Under SysV a `float _Complex` is a single
 * eightbyte of class SSE (both halves in one xmm register), while a
 * `double _Complex` is TWO eightbytes and returns in `xmm0:xmm1`. On AArch64 a
 * complex value is a homogeneous float aggregate and goes in `v0`/`v1`. On
 * ARM32 hard-float it is a VFP register pair. Every one of those is a distinct
 * classification path, and each is the path a decompiler gets wrong by treating
 * the value as a struct of two scalars — which compiles, and returns garbage in
 * the high half.
 *
 * Multiplication is the shape that exposes it: `(a+bi)(c+di)` reads all four
 * components and writes two, so a recovery that loses the pairing produces an
 * answer that is wrong in one half only. That is exactly the failure a
 * single-value return check cannot see, which is why every function here folds
 * BOTH halves into its integer result.
 *
 * `197_homogeneous_float_aggregates` covers HFAs built from a struct;
 * `172_float_double_widths` covers scalar float widths;
 * `188_vector_transport` covers 128-bit vector moves. None of them uses
 * `_Complex`, so none exercises the compiler's complex-specific lowering
 * (`__mulsc3`-style helper calls at -O0 on some targets, inline sequences at
 * -O2) or the ABI class it selects.
 *
 * Every constant is an exact binary fraction and every result is scaled to an
 * integer, so the answers are identical whether the target computes in 32-bit,
 * 64-bit or 80-bit intermediate precision.
 */

/* Complex multiply, both halves folded into the result. */
__attribute__((noinline)) int64_t complex_multiply(int32_t ar, int32_t ai,
                                                    int32_t br, int32_t bi) {
    double _Complex a = (double)ar + (double)ai * (double _Complex){0.0 + 1.0i};
    double _Complex b = (double)br + (double)bi * (double _Complex){0.0 + 1.0i};
    double _Complex p = a * b;
    return (int64_t)(__real__ p) * 1000 + (int64_t)(__imag__ p);
}

/* Addition and conjugation: cheaper lowering, still a paired value. */
__attribute__((noinline)) int64_t complex_add_conj(int32_t ar, int32_t ai,
                                                    int32_t br, int32_t bi) {
    double _Complex a = (double)ar + (double)ai * 1.0i;
    double _Complex b = (double)br + (double)bi * 1.0i;
    double _Complex s = a + ~b; /* ~ is conjugation on complex */
    return (int64_t)(__real__ s) * 1000 + (int64_t)(__imag__ s);
}

/* `float _Complex` — one eightbyte on x86-64, a different class from the
 * double form above. */
__attribute__((noinline)) int64_t complex_float_multiply(int32_t ar,
                                                          int32_t ai,
                                                          int32_t br,
                                                          int32_t bi) {
    float _Complex a = (float)ar + (float)ai * 1.0if;
    float _Complex b = (float)br + (float)bi * 1.0if;
    float _Complex p = a * b;
    return (int64_t)(__real__ p) * 1000 + (int64_t)(__imag__ p);
}

/* A complex value passed THROUGH a call boundary and returned, so the argument
 * and return classifications are both exercised rather than only the local
 * arithmetic. */
static double _Complex scale_complex(double _Complex v, double factor) {
    return v * factor;
}

__attribute__((noinline)) int64_t complex_through_call(int32_t ar, int32_t ai,
                                                       int32_t factor) {
    double _Complex a = (double)ar + (double)ai * 1.0i;
    double _Complex s = scale_complex(a, (double)(factor & 7) + 0.5);
    return (int64_t)(__real__ s * 2.0) * 1000 + (int64_t)(__imag__ s * 2.0);
}

/* An array of complex values summed in a loop: a stride of two doubles, which
 * an object model must see as one element rather than two. */
__attribute__((noinline)) int64_t complex_array_sum(const int32_t *pairs,
                                                     int32_t count) {
    double _Complex total = 0.0 + 0.0i;
    if (pairs == 0 || count < 0 || count > 8) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        total += (double)(pairs[i] & 0xff) + (double)((pairs[i] >> 8) & 0xff) * 1.0i;
    }
    return (int64_t)(__real__ total) * 1000 + (int64_t)(__imag__ total);
}

/* CONTROL: the same arithmetic on a struct of two doubles, which is an
 * ordinary aggregate rather than a complex. If this passes and the complex
 * versions fail, the ABI class is the cause and not the float arithmetic. */
struct two_doubles {
    double re;
    double im;
};

__attribute__((noinline)) int64_t struct_pair_control(int32_t ar, int32_t ai,
                                                       int32_t br, int32_t bi) {
    struct two_doubles a = {(double)ar, (double)ai};
    struct two_doubles b = {(double)br, (double)bi};
    struct two_doubles p = {a.re * b.re - a.im * b.im,
                            a.re * b.im + a.im * b.re};
    return (int64_t)p.re * 1000 + (int64_t)p.im;
}
