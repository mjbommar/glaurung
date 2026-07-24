/* 01_conditional_polarity.c
 *
 * Branch-polarity fixture. Every function is a pure integer function whose each
 * reachable branch returns a UNIQUE constant, so an execution-differential test
 * (original vs. recompiled decompilation) detects a swapped taken/fallthrough
 * edge or an inverted condition the moment any input reaches the wrong arm.
 *
 * Targets review P0 #1 (conditional-edge polarity). Keep every function pure
 * (no globals, no memory) and deterministic in its integer arguments.
 */
#include <stdint.h>

/* Signed comparison ladder. a<b, a>b, a==b each return a distinct value. */
int cmp_signed(int a, int b) {
    if (a < b) return 11;
    if (a > b) return 22;
    return 33;
}

/* Unsigned comparison — polarity AND signedness must be preserved. For
 * a=-1 (0xFFFFFFFF) and b=1, unsigned makes a>b, so this must NOT match the
 * signed version. */
int cmp_unsigned(unsigned a, unsigned b) {
    if (a < b) return 44;
    if (a > b) return 55;
    return 66;
}

/* Early return: the `then` arm exits, the fallthrough continues. */
int early_return(int x) {
    if (x < 0) return 77;
    return 88;
}

/* Inverted early return via `>=`. */
int early_return_ge(int x) {
    if (x >= 100) return 111;
    return 222;
}

/* Nested if with distinct returns in every leaf. */
int nested(int x, int y) {
    if (x != 0) {
        if (y != 0)
            return 1;
        else
            return 2;
    }
    return 3;
}

/* if / else if / else — a comparison tree. */
int elseif(int x) {
    if (x < 0)
        return -1;
    else if (x == 0)
        return 0;
    else if (x < 10)
        return 5;
    else
        return 100;
}

/* Ternary. */
int ternary(int x) {
    return x > 5 ? 1000 : 2000;
}

/* Nested ternary. */
int ternary_nested(int x) {
    return x < 0 ? 10 : (x == 0 ? 20 : 30);
}

/* Short-circuit AND: body runs only when BOTH hold. Distinct return catches a
 * mis-structured `&&` (e.g. treating it as `&`, or the wrong join). */
int sc_and(int x, int y) {
    if (x > 0 && y > 0)
        return 1234;
    return 4321;
}

/* Short-circuit OR. */
int sc_or(int x, int y) {
    if (x > 0 || y > 0)
        return 5678;
    return 8765;
}

/* Combined: (a && b) || c — three-way short circuit with a unique constant. */
int sc_mixed(int a, int b, int c) {
    if ((a > 0 && b > 0) || c > 0)
        return 9;
    return 90;
}

/* A guard that returns early on the *taken* branch of a forward conditional
 * (jl/jle) — the exact shape that inverts if arm order is chosen by block
 * index rather than the taken edge. */
int classify(int a, int b) {
    if (a > b) return a - b;
    if (a < b) return b - a;
    return 0;
}
