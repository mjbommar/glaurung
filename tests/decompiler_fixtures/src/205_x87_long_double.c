#include <stdint.h>

/* `long double` is the only portable way to reach x87 from C on x86-64, and
 * x87 is where this decompiler's unmodelled-instruction hole actually lives.
 *
 * A census of the 158 x86-64 binaries in the frozen DecBench sample-set found
 * 89,363 instructions that the lifter declines to model AND that declare no
 * register write -- 99.997% of them x87 (`fstp` alone is 89,258, in 25 of the
 * binaries), and 12 of the 158 scored target functions contain one. An
 * instruction lifted to `Op::Unknown` / `Op::opaque` reports no definition to
 * `use_def::defs_uses`, so `ssa::write_regs` places no phi and never bumps the
 * destination's version: the value that was live BEFORE the instruction flows
 * past it into every later reader. Worse, a destination nothing defines is
 * read as an incoming argument, so the recovered prototype grows parameters
 * the function never had.
 *
 * Before this file the fixture corpus had no `long double` anywhere, so none of
 * that was covered. Every function here returns an INTEGER derived from the
 * computation, because the harness diffs executed results and a printed
 * `long double` is neither portable nor exactly comparable. Every constant is
 * an exact binary fraction, so the answers do not depend on whether the target
 * evaluates in 80-bit (x86-64 x87), 128-bit (AArch64) or 64-bit (ARM32)
 * precision -- only on the arithmetic being carried out at all.
 */

/* A running sum in extended precision. On x86-64 this is fld/faddp/fstp; a
 * stale-value bug returns the accumulator's PREVIOUS state rather than the
 * sum. */
__attribute__((noinline)) int64_t x87_accumulate(int32_t count) {
    long double total = 0.0L;
    if (count < 0) {
        return -1;
    }
    if (count > 64) {
        count = 64;
    }
    for (int32_t i = 0; i < count; i++) {
        total += (long double)i * 0.25L;
    }
    return (int64_t)(total * 4.0L);
}

/* A product chain: fmul/fmulp, and one fdiv. Exact halves keep the result
 * representable in every long double format. */
__attribute__((noinline)) int64_t x87_product_chain(int32_t count) {
    long double product = 1.0L;
    if (count < 0 || count > 20) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        product *= 1.5L;
    }
    product /= 0.5L;
    return (int64_t)(product * 1024.0L);
}

/* Comparison and sign manipulation: fcom/fucomi, fchs, fabs. The classify
 * result is a small integer so an incorrect compare is a visible diff rather
 * than a rounding difference. */
__attribute__((noinline)) int32_t x87_compare_classify(int32_t left,
                                                       int32_t right) {
    long double a = (long double)left * 0.5L;
    long double b = (long double)right * 0.25L;
    long double negated = -a;
    int32_t code = 0;
    if (a > b) {
        code |= 1;
    }
    if (a == b) {
        code |= 2;
    }
    if (negated < b) {
        code |= 4;
    }
    if (a != 0.0L && b != 0.0L) {
        code |= 8;
    }
    return code;
}

/* Width mixing: float -> long double -> double -> integer. On x86-64 this is
 * the fld/fstp traffic that dominates the census, and it is where a dropped
 * destination write turns one width's value into another's. */
__attribute__((noinline)) int64_t x87_mixed_widths(int32_t seed) {
    float narrow = (float)(seed & 0xff) * 0.5f;
    long double wide = (long double)narrow + 0.125L;
    double middle = (double)(wide * 8.0L);
    long double back = (long double)middle - 1.0L;
    return (int64_t)(back * 2.0L);
}

/* Several live extended-precision values at once. On x86-64 the x87 register
 * stack is only eight deep and the compiler spills with fstp, so this is the
 * shape that produces the most stack traffic per source line. */
__attribute__((noinline)) int64_t x87_many_live_values(int32_t seed) {
    long double a = (long double)(seed & 7) + 0.5L;
    long double b = a * 2.0L;
    long double c = b + 0.25L;
    long double d = c * a;
    long double e = d - b;
    long double f = e + c;
    long double g = f * 0.5L;
    long double h = g + d;
    return (int64_t)((a + b + c + d + e + f + g + h) * 16.0L);
}
