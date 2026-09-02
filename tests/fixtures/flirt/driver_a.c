/* Driver A: links libmathlib.a as a PIE, calling a handful of entry points.
 *
 * The point of having two drivers is that the archive's code must land at a
 * different address, in a different order, with different resolved call and
 * data displacements in each one. A signature that matches in both is a
 * signature that survived relinking; that is the whole property
 * tests/flirt_signature_matching.rs exists to check.
 */
#include <stdio.h>
#include "mathlib.h"

int main(void) {
    int values[] = {3, 1, 4, 1, 5, 9, 2, 6};
    printf("%s\n", mathlib_version());
    printf("%d\n", mathlib_add(2, 3));
    printf("%d\n", mathlib_gcd(48, 18));
    printf("%d\n", mathlib_array_sum(values, 8));
    printf("%d\n", mathlib_is_prime(97));
    return 0;
}
