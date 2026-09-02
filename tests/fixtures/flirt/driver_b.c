/* Driver B: links the same libmathlib.a non-PIE, behind enough of its own
 * code that the archive members land at different addresses than in driver A,
 * and calls a different subset so a different set of relocations resolves.
 */
#include <stdio.h>
#include "mathlib.h"

/* Filler with results the optimiser cannot fold away, purely to push the
 * archive's text to a different address than driver A puts it at. */
static int shift_a(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += i * 3;
    }
    return s;
}

static int shift_b(int n) {
    int s = 1;
    for (int i = 1; i <= n; i++) {
        s = s * 2 + i;
    }
    return s;
}

static int shift_c(int n) {
    int s = n;
    int steps = 0;
    while (s > 1 && steps < 1000) {
        s = (s & 1) ? 3 * s + 1 : s / 2;
        steps++;
    }
    return steps;
}

int main(int argc, char **argv) {
    MathPoint p1 = {0.0, 0.0};
    MathPoint p2 = {3.0, 4.0};
    int values[] = {1, 7, 3};
    (void)argv;
    printf("%d\n", shift_a(argc + 10));
    printf("%d\n", shift_b(argc + 5));
    printf("%d\n", shift_c(argc + 27));
    printf("%lld\n", mathlib_factorial(10));
    printf("%d\n", mathlib_fibonacci(20));
    printf("%.1f\n", mathlib_point_distance(&p1, &p2));
    printf("%d\n", mathlib_array_max(values, 3));
    printf("%d\n", mathlib_gcd(48, 18));
    printf("%d\n", mathlib_add(2, 3));
    return 0;
}
