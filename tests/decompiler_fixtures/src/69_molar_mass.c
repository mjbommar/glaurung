#include <stdint.h>

/* A chemical-formula parser: element symbols with optional multi-digit counts,
 * looked up in a small table, accumulated as centi-atomic-mass units.  Parsing
 * plus table lookup plus accumulation in one pass. */

#define FORMULA_MAX 16

static int32_t element_mass_centi(uint8_t first, uint8_t second) {
    if (first == (uint8_t)'H' && second == 0) {
        return 101;
    }
    if (first == (uint8_t)'C' && second == 0) {
        return 1201;
    }
    if (first == (uint8_t)'N' && second == 0) {
        return 1401;
    }
    if (first == (uint8_t)'O' && second == 0) {
        return 1600;
    }
    if (first == (uint8_t)'S' && second == 0) {
        return 3207;
    }
    if (first == (uint8_t)'N' && second == (uint8_t)'a') {
        return 2299;
    }
    if (first == (uint8_t)'C' && second == (uint8_t)'l') {
        return 3545;
    }
    if (first == (uint8_t)'F' && second == (uint8_t)'e') {
        return 5585;
    }
    return -1;
}

__attribute__((noinline)) int32_t
molar_mass_centi(const uint8_t *formula, int32_t length) {
    int32_t total = 0;
    int32_t index = 0;
    if (formula == 0 || length < 0 || length > FORMULA_MAX) {
        return -1;
    }
    while (index < length) {
        uint8_t first = formula[index];
        uint8_t second = 0;
        int32_t count = 0;
        int32_t mass;
        if (first < (uint8_t)'A' || first > (uint8_t)'Z') {
            return -2;
        }
        index += 1;
        if (index < length && formula[index] >= (uint8_t)'a' &&
            formula[index] <= (uint8_t)'z') {
            second = formula[index];
            index += 1;
        }
        mass = element_mass_centi(first, second);
        if (mass < 0) {
            return -3;
        }
        while (index < length && formula[index] >= (uint8_t)'0' &&
               formula[index] <= (uint8_t)'9') {
            count = count * 10 + (int32_t)(formula[index] - (uint8_t)'0');
            if (count > 99) {
                return -4;
            }
            index += 1;
        }
        if (count == 0) {
            count = 1;
        }
        total += mass * count;
    }
    return total;
}
