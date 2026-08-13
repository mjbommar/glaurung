#include <stdint.h>

/* Integer promotion and the usual arithmetic conversions. Everything narrower
 * than int promotes to int before arithmetic, so uint8_t * uint8_t is computed
 * in int and can exceed 255 without wrapping. */

__attribute__((noinline)) int32_t
promote_narrow_product(int32_t left, int32_t right) {
    uint8_t a = (uint8_t)left;
    uint8_t b = (uint8_t)right;
    /* Promoted to int: 200 * 200 is 40000, not 64. */
    return a * b;
}

__attribute__((noinline)) int32_t
promote_then_truncate(int32_t left, int32_t right) {
    uint8_t a = (uint8_t)left;
    uint8_t b = (uint8_t)right;
    return (int32_t)(uint8_t)(a * b);
}

__attribute__((noinline)) int32_t
short_promotion_sign(int32_t value) {
    int16_t narrow = (int16_t)value;
    /* Promotes to int, keeping the sign; the addition happens in int. */
    return narrow + 1;
}

__attribute__((noinline)) uint32_t
unsigned_conversion_rank(int32_t signed_value, uint32_t unsigned_value) {
    /* The signed operand converts to unsigned: the comparison is unsigned. */
    return ((uint32_t)signed_value < unsigned_value) ? 1u : 0u;
}
