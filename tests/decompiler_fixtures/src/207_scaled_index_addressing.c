#include <stdint.h>

/* An index register SCALED by the element width, at every stride the machine
 * encodes, plus the controls that prove the scale is read rather than assumed.
 *
 * THE DEFECT THIS EXISTS FOR. Capstone carries an ARM/AArch64 shift on the
 * OPERAND (`ArmOperand::shift`), not inside the memory-operand struct
 * (`ArmOpMem`), so a reader that inspects only the mem struct sees `[base,
 * index]` where the encoding says `[base, index, lsl #2]`. Both of our ARM arms
 * did exactly that — `let scale = None` — for as long as they existed. Every
 * effective address in the analysis layer was therefore `base + index` instead
 * of `base + index * 2^n`: for `lsl #2`, wrong by a factor of four, silently,
 * with no diagnostic anywhere. `analysis::dispatch`, `analysis::xrefs` and the
 * memory-bound guards all consume that field.
 *
 * It survived because the ARM lifter compensates locally (`lift_arm32::
 * scaled_memop` re-derives the shift from the instruction), so the DECOMPILED C
 * was right while the analysis was wrong — which is invisible to a fixture that
 * only diffs execution. That is why the assertions here are about the recovered
 * subscript arithmetic on every architecture, and why the fixture spans all
 * three element widths rather than testing one.
 *
 * NOT COVERED BY `109_subscript_commutativity` (which spelling produced a
 * subscript), `110_pointer_arithmetic` (pointer displacement), or
 * `187_constant_bias_index` (a constant added to the index). None of those vary
 * the ELEMENT WIDTH, which is the only thing that changes the encoded scale.
 *
 * The last two functions are the controls. `byte_stride_unscaled` indexes a
 * byte array, where the scale is 1 and no shift is encoded at all — a reader
 * that fabricated a scale would break it. `shift_as_value` shifts the loaded
 * VALUE rather than the index, which must not be folded into an address.
 */

__attribute__((noinline)) int32_t word_stride_sum(const int32_t *values,
                                                  int32_t count) {
    int32_t total = 0;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    /* 4-byte elements: `lsl #2` on ARM/AArch64, `(,%r,4)` on x86. */
    for (int32_t i = 0; i < count; i++) {
        total += values[i];
    }
    return total;
}

__attribute__((noinline)) int64_t quad_stride_sum(const int64_t *values,
                                                  int32_t count) {
    int64_t total = 0;
    if (values == 0 || count < 0 || count > 16) {
        return -1;
    }
    /* 8-byte elements: `lsl #3` / `(,%r,8)`. */
    for (int32_t i = 0; i < count; i++) {
        total += values[i];
    }
    return total;
}

/* One scaled load at a computed index, with no loop, so the addressing mode is
 * the entire function body and nothing can hide it. */
__attribute__((noinline)) int32_t word_at_index(const int32_t *values,
                                                int32_t index) {
    if (values == 0 || index < 0 || index > 15) {
        return -1;
    }
    return values[index] + 7;
}

/* A scaled STORE, so the write path is covered as well as the read path. */
__attribute__((noinline)) int32_t word_store_at_index(int32_t *values,
                                                      int32_t index,
                                                      int32_t value) {
    if (values == 0 || index < 0 || index > 15) {
        return -1;
    }
    values[index] = value * 3;
    return values[index];
}

/* CONTROL: byte elements. Scale is 1 and no shift is encoded; a fabricated
 * scale changes the answer. */
__attribute__((noinline)) int32_t byte_stride_unscaled(const uint8_t *bytes,
                                                       int32_t count) {
    int32_t total = 0;
    if (bytes == 0 || count < 0 || count > 16) {
        return -1;
    }
    for (int32_t i = 0; i < count; i++) {
        total += (int32_t)bytes[i];
    }
    return total;
}

/* CONTROL: the shift is applied to the loaded VALUE, not to the index. Folding
 * it into an address scale would be wrong in a way that still compiles and
 * still looks plausible. */
__attribute__((noinline)) int32_t shift_as_value(const int32_t *values,
                                                 int32_t index) {
    if (values == 0 || index < 0 || index > 15) {
        return -1;
    }
    return values[index] << 2;
}
