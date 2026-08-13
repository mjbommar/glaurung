#include <stdint.h>

/* Balance a two-reactant, two-product reaction by brute-force search over
 * small integer coefficients, then reduce them by their greatest common
 * divisor.  Four nested bounded loops with an early exit on the first
 * conserving assignment. */

#define BALANCE_LIMIT 8
#define BALANCE_ELEMENTS 4

static int32_t balance_gcd(int32_t a, int32_t b) {
    int32_t guard;
    for (guard = 0; guard < 32 && b != 0; ++guard) {
        int32_t remainder = a % b;
        a = b;
        b = remainder;
    }
    return (a == 0) ? 1 : a;
}

__attribute__((noinline)) int32_t
balance_reaction(const int32_t *reactant_a, const int32_t *reactant_b,
                 const int32_t *product_a, const int32_t *product_b,
                 int32_t elements, int32_t *coefficients) {
    int32_t ca;
    int32_t cb;
    int32_t cc;
    int32_t cd;
    if (reactant_a == 0 || reactant_b == 0 || product_a == 0 ||
        product_b == 0 || coefficients == 0 || elements < 1 ||
        elements > BALANCE_ELEMENTS) {
        return -1;
    }
    for (ca = 1; ca <= BALANCE_LIMIT; ++ca) {
        for (cb = 1; cb <= BALANCE_LIMIT; ++cb) {
            for (cc = 1; cc <= BALANCE_LIMIT; ++cc) {
                for (cd = 1; cd <= BALANCE_LIMIT; ++cd) {
                    int32_t element;
                    int32_t conserved = 1;
                    for (element = 0; element < elements; ++element) {
                        int32_t left = ca * reactant_a[element] +
                                       cb * reactant_b[element];
                        int32_t right = cc * product_a[element] +
                                        cd * product_b[element];
                        if (left != right) {
                            conserved = 0;
                            break;
                        }
                    }
                    if (conserved) {
                        int32_t divisor = balance_gcd(balance_gcd(ca, cb),
                                                      balance_gcd(cc, cd));
                        coefficients[0] = ca / divisor;
                        coefficients[1] = cb / divisor;
                        coefficients[2] = cc / divisor;
                        coefficients[3] = cd / divisor;
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
