#include <stdint.h>

/* Multi-limb unsigned arithmetic over base 2^16 limbs.  Carry propagation
 * across limbs is the whole point: a lost carry or a truncated intermediate is
 * invisible in structure but fatal in the differential. */

#define LIMB_MAX 8
#define LIMB_BASE 65536u

__attribute__((noinline)) int32_t
bignum_add(const uint32_t *left, int32_t left_limbs, const uint32_t *right,
           int32_t right_limbs, uint32_t *output, int32_t capacity) {
    uint32_t carry = 0;
    int32_t index;
    int32_t limbs;
    if (left == 0 || right == 0 || output == 0 || left_limbs < 0 ||
        right_limbs < 0 || left_limbs > LIMB_MAX || right_limbs > LIMB_MAX ||
        capacity < 1 || capacity > LIMB_MAX) {
        return -1;
    }
    limbs = (left_limbs > right_limbs) ? left_limbs : right_limbs;
    if (limbs > capacity) {
        return -2;
    }
    for (index = 0; index < limbs; ++index) {
        uint32_t a = (index < left_limbs) ? (left[index] % LIMB_BASE) : 0u;
        uint32_t b = (index < right_limbs) ? (right[index] % LIMB_BASE) : 0u;
        uint32_t sum = a + b + carry;
        output[index] = sum % LIMB_BASE;
        carry = sum / LIMB_BASE;
    }
    if (carry != 0u && limbs < capacity) {
        output[limbs] = carry;
        limbs += 1;
    }
    return limbs;
}

__attribute__((noinline)) int32_t
bignum_mul_small(const uint32_t *value, int32_t limbs, uint32_t multiplier,
                 uint32_t *output, int32_t capacity) {
    uint32_t carry = 0;
    int32_t index;
    int32_t produced;
    if (value == 0 || output == 0 || limbs < 0 || limbs > LIMB_MAX ||
        capacity < 1 || capacity > LIMB_MAX || multiplier >= LIMB_BASE) {
        return -1;
    }
    if (limbs > capacity) {
        return -2;
    }
    for (index = 0; index < limbs; ++index) {
        uint32_t product = (value[index] % LIMB_BASE) * multiplier + carry;
        output[index] = product % LIMB_BASE;
        carry = product / LIMB_BASE;
    }
    produced = limbs;
    while (carry != 0u && produced < capacity) {
        output[produced] = carry % LIMB_BASE;
        carry /= LIMB_BASE;
        produced += 1;
    }
    return produced;
}
