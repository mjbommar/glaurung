#include <stdint.h>
#include <string.h>

/* A FLOATING VALUE STORED THROUGH INTEGER-TYPED STORAGE, and the reverse.
 *
 * `movss %xmm0, -0x10(%rbp)` copies four bytes. The recovered destination type
 * comes from the ACCESS WIDTH, so it is `int`, and a renderer that reconciles
 * an `int` destination with a `float` source by inserting a cast emits
 * `*(int *)(&local[0]) = (float)(...)` — which is C's arithmetic conversion
 * (C23 6.3.1.4, truncation toward zero). `1.5f` is then written as `1` rather
 * than `0x3FC00000`, and every byte of the destination is wrong immediately,
 * before anything downstream reads it.
 *
 * The corpus already contained this shape in `195`, `197` and `198` — but only
 * inside AGGREGATE-RETURNING helpers, which `exec_class` refuses, so all twelve
 * occurrences were recorded `structural` and none was ever executed. It also
 * contained it in `174`'s `fp174_float_bits`, which is a LOCAL symbol with no
 * baseline row of its own. So the defect had no lane that could report it: no
 * function in the corpus both exhibits the shape and is directly executed.
 * Every function here is `int32_t`-returning and scalar-argument, so every one
 * of them is.
 *
 * THE NEGATIVE CONTROLS ARE THE POINT. A reinterpretation is right here and
 * wrong for `cvttss2si`, and the two are one instruction apart. `f201_*_values`
 * do the same arithmetic on the same values and TRUNCATE, so a recovery that
 * satisfies the positives by never converting fails exactly there; and
 * `f201_scalar_control` has no floating point at all, so a recovery that broke
 * ordinary integer stores while fixing these is separable from one that did not.
 *
 * `memcpy` rather than a union or a pointer cast: it is the one spelling
 * defined under every aliasing rule, and both compilers turn a four- or
 * eight-byte copy into a single register move. Every value is a small integer
 * converted to `float`/`double`, so it is exactly representable in both widths
 * and the differential compares exact values rather than rounding artifacts. */

#define F201_SLOTS 2

/* ---- positives: a float's BITS reach an integer destination ---------------- */

/* The reported shape at binary32. At `-O0` both compilers emit
 * `cvtsi2ss ... ; movss %xmm0, -N(%rbp)` for each slot and then read the same
 * bytes back with an integer `mov`. The exponent fields are the part a
 * truncating conversion destroys: `(float)(seed + 1)` for a small `seed` has
 * bits around 0x4000_0000 and a value around 1, so the two disagree in every
 * bit that this function returns. */
__attribute__((noinline)) int32_t f201_f32_slot_bits(int32_t seed) {
    float slots[F201_SLOTS];
    uint32_t words[F201_SLOTS];
    slots[0] = (float)(seed + 1);
    slots[1] = (float)(seed * 2 + 3);
    memcpy(words, slots, sizeof words);
    /* Distinct coefficients, so recovering the right total from permuted or
     * duplicated slots is caught rather than passing by luck. */
    return (int32_t)((words[0] >> 23) * 3u + (words[1] >> 20) * 5u);
}

/* The same at binary64, which is a different instruction (`movsd`), a different
 * access width, and a different recovered pointee (`long`, not `int`). */
__attribute__((noinline)) int32_t f201_f64_slot_bits(int32_t seed) {
    double slots[F201_SLOTS];
    uint64_t words[F201_SLOTS];
    slots[0] = (double)(seed + 1);
    slots[1] = (double)(seed * 2 + 3);
    memcpy(words, slots, sizeof words);
    return (int32_t)((uint32_t)(words[0] >> 52) * 3u + (uint32_t)(words[1] >> 48) * 5u);
}

/* The single-value form, with no array indexing between the store and the read.
 * This is `174`'s `fp174_float_bits` promoted to an exported, executable
 * function: the whole body is one `movss` to the frame and one `mov` back. */
__attribute__((noinline)) int32_t f201_f32_single_bits(int32_t seed) {
    float value = (float)(seed * 4 + 1);
    uint32_t word;
    memcpy(&word, &value, sizeof word);
    return (int32_t)(word >> 16);
}

/* Through a CALLER-OWNED pointer rather than a frame slot, so the destination
 * is not a promoted local and the store cannot be recovered as a plain
 * variable assignment. */
__attribute__((noinline)) int32_t f201_store_through_pointer(int32_t *out, int32_t seed) {
    float value = (float)(seed + 7);
    if (out == 0) {
        return -1;
    }
    memcpy(out, &value, sizeof *out);
    return (int32_t)(((uint32_t)*out) >> 21);
}

/* ---- the mirror: an integer bit pattern read back as a float --------------- */

/* `word` is built with a pinned exponent field, so `value` is finite, normal
 * and inside [8, 16) for every input the harness can draw — the multiply and
 * the truncation below are therefore defined for all of them, and a NaN or an
 * out-of-range conversion can never be reached. */
__attribute__((noinline)) int32_t f201_word_to_value(int32_t seed) {
    uint32_t word = 0x41000000u | (((uint32_t)seed & 0x7Fu) << 8);
    float value;
    memcpy(&value, &word, sizeof value);
    return (int32_t)(value * 256.0f);
}

/* ---- negative controls: conversions that must stay conversions ------------- */

/* THE FIRST NEGATIVE. Identical storage, identical arithmetic, but the slots
 * are read as NUMBERS. `cvttss2si` truncates toward zero, and a recovery that
 * reinterpreted every float reaching an integer destination would return the
 * exponent fields here instead of the values — off by seven orders of
 * magnitude, not by a rounding step. Bounded well inside the int32 range so no
 * conversion is undefined. */
__attribute__((noinline)) int32_t f201_f32_slot_values(int32_t seed) {
    float slots[F201_SLOTS];
    slots[0] = (float)(seed + 1) / 2.0f;
    slots[1] = (float)(seed * 2 + 3) / 4.0f;
    return (int32_t)slots[0] * 3 + (int32_t)slots[1] * 5;
}

/* THE SECOND NEGATIVE, at binary64 and through a `memcpy` of the FLOAT — the
 * copy is a bit move, the read that follows is a conversion, and both happen in
 * one function. A recovery that decides "this buffer holds bits" or "this
 * buffer holds numbers" once per object rather than once per access is wrong
 * here whichever way it decides. */
__attribute__((noinline)) int32_t f201_f64_copy_then_convert(int32_t seed) {
    double value = (double)(seed * 3 + 1) / 8.0;
    double copy;
    memcpy(&copy, &value, sizeof copy);
    return (int32_t)copy * 7;
}

/* THE THIRD NEGATIVE: the same buffer traffic with no floating point anywhere,
 * so a recovery that damaged ordinary integer stores while fixing the positives
 * fails here and only here. */
__attribute__((noinline)) int32_t f201_scalar_control(int32_t seed) {
    int32_t slots[F201_SLOTS];
    uint32_t words[F201_SLOTS];
    slots[0] = seed + 1;
    slots[1] = seed * 2 + 3;
    memcpy(words, slots, sizeof words);
    return (int32_t)(words[0] * 3u + words[1] * 5u);
}
