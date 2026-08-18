#include <stdint.h>

/* RETURN VALUES NARROWER THAN A REGISTER.
 *
 * A census of every function definition in this corpus (900 of them, across
 * `.c`, `.cpp` and `.rs`) found that the returned type is a full machine word
 * almost everywhere:
 *
 *   int32_t / int / uint32_t / i32     704 definitions
 *   double / float                      22
 *   64-bit (long, int64_t, uint64_t)    14
 *   uint8_t                              2   (11_call_shapes:wrap_byte,
 *                                             43_base64:encode_symbol)
 *   uint16_t                             1   (07_packet_parser:read_be16,
 *                                             not a REQUIRED function)
 *   int8_t, int16_t, char, _Bool         0
 *
 * So the corpus asks "what happens when only the low 8 or 16 bits of the result
 * register are architecturally meaningful?" exactly twice, never in the SIGNED
 * direction, and never for `_Bool`. That is the shape this fixture adds.
 *
 * Why it is a distinct question from a narrow LOCAL (which `02_integer_widths`
 * already covers): a narrow local is a value the compiler may keep in any width
 * it likes, while a narrow return is an ABI contract about `al`/`ax` — the
 * high bits of `eax` are dead, so `movsbl`/`movzwl` around the return are the
 * only thing that distinguishes `int8_t f()` from `int32_t f()` in the machine
 * code. A decompiler that models every result as a 32-bit register produces C
 * that compiles and that agrees on every input whose value happens to fit.
 *
 * Each positive case therefore narrows and then does arithmetic that the
 * narrowing CHANGES, so the low bits differ rather than only the dead high
 * ones: signed division after truncation is not truncation after division.
 *
 * THREE NEGATIVE CONTROLS, each aimed at a different wrong generalisation:
 *
 *   `nrw194_i32_control`      computes the same expression as `nrw194_i8_divide`
 *                             at full width. A recovery that narrows every
 *                             return satisfies the positives and fails here.
 *   `nrw194_u8_value_control` has the same BODY as `nrw194_u8_mix` — the value
 *                             is narrowed to 8 bits — but returns `int32_t`.
 *                             It separates "models the return width" from
 *                             "models the value width"; conflating the two
 *                             passes every other case in this file.
 *   `nrw194_bool_wide_control` spells `nrw194_bool_and`'s boolean normalisation
 *                             out explicitly with `!= 0` and returns `int32_t`,
 *                             so the `_Bool` case is measuring the CONVERSION
 *                             and not the arithmetic around it.
 *
 * Every function is a pure function of its integer arguments: no memory, no
 * I/O, no undefined behaviour. Intermediate products are formed in `uint32_t`
 * so the boundary sweep's `INT_MIN`/`INT_MAX` vectors cannot overflow a signed
 * multiply, and every divisor is a nonzero constant.
 *
 * ONE DELIBERATE CROSS-ARCHITECTURE ARTIFACT: plain `char` is SIGNED on x86 and
 * x86-64 and UNSIGNED on both ARM targets, so `nrw194_char_divide` has a
 * genuinely different DWARF return type in an AArch64/ARMv7 build than in the
 * host reference. `diff_decompile.abi_incomparable` should decline those two
 * lanes with `incomparable` rather than compare a truncation against a
 * zero-extension and call the difference a lifter bug. That refusal is part of
 * what this fixture is for; the i386 lane shares x86's signed `char` and must
 * stay comparable. */

/* --- signed narrow returns ------------------------------------------------ */

/* int8_t: truncate to 8 bits, THEN divide. `x = 300` narrows to 44 and returns
 * 22; dividing first and truncating afterwards returns 106. The two disagree in
 * the low byte, which is the only byte the ABI defines. */
__attribute__((noinline)) int8_t nrw194_i8_divide(int32_t x) {
    int8_t narrowed = (int8_t)((uint32_t)x * 3u);
    return (int8_t)(narrowed / 2);
}

/* int16_t: the same question one width up, where a 16-bit truncation is a
 * different instruction (`movswl` rather than `movsbl`). */
__attribute__((noinline)) int16_t nrw194_i16_divide(int32_t x) {
    int16_t narrowed = (int16_t)((uint32_t)x * 5u);
    return (int16_t)(narrowed / 7);
}

/* --- unsigned narrow returns ---------------------------------------------- */

/* uint8_t: division and a logical shift of a ZERO-extended byte. Reading the
 * same bits as signed makes `narrowed >> 5` an arithmetic shift and changes the
 * answer for every input with bit 7 set. */
__attribute__((noinline)) uint8_t nrw194_u8_mix(int32_t x) {
    uint8_t narrowed = (uint8_t)x;
    return (uint8_t)(narrowed / 3u + (uint32_t)(narrowed >> 5));
}

/* uint16_t: the same, one width up. */
__attribute__((noinline)) uint16_t nrw194_u16_mix(int32_t x) {
    uint16_t narrowed = (uint16_t)x;
    return (uint16_t)(narrowed / 9u + (uint32_t)(narrowed >> 11));
}

/* --- plain `char`, whose signedness is a property of the TARGET ------------ */

/* Signed on x86/x86-64, unsigned on AArch64 and ARMv7. The host lanes divide a
 * sign-extended byte; a naive cross-architecture comparison would divide a
 * zero-extended one and blame the lifter. See the header note. */
__attribute__((noinline)) char nrw194_char_divide(int32_t x) {
    char narrowed = (char)x;
    return (char)(narrowed / 2);
}

/* --- _Bool, where the ABI value is NORMALISED and not merely truncated ----- */

/* `(x & 0x100)` is 0 or 256; converting it to `_Bool` is `test`/`setne`, so the
 * returned byte is 0 or 1. A recovery that keeps the raw mask returns 0 for
 * EVERY input, because 256's low byte is zero — the one case where the dead
 * high bits are what carried the answer. */
__attribute__((noinline)) _Bool nrw194_bool_bit(int32_t x) {
    return (_Bool)(x & 0x100);
}

/* Two `_Bool` conversions combined with a bitwise AND. Both operands must be
 * normalised to 0/1 first: `4 & 8` is 0, so a recovery that ANDs the raw masks
 * answers 0 where the original answers 1. */
__attribute__((noinline)) _Bool nrw194_bool_and(int32_t x, int32_t y) {
    _Bool a = (_Bool)(x & 4);
    _Bool b = (_Bool)(y & 8);
    return (_Bool)(a & b);
}

/* --- CONTROLS ------------------------------------------------------------- */

/* CONTROL: `nrw194_i8_divide`'s expression at FULL width. A decompiler that
 * applies a narrowing to every return fails exactly here. */
__attribute__((noinline)) int32_t nrw194_i32_control(int32_t x) {
    int32_t wide = (int32_t)((uint32_t)x * 3u);
    return wide / 2;
}

/* CONTROL: `nrw194_u8_mix`'s BODY, returned at full width. The value is narrow
 * and the result is not, so conflating the two is visible here and nowhere
 * else in this file. */
__attribute__((noinline)) int32_t nrw194_u8_value_control(int32_t x) {
    uint8_t narrowed = (uint8_t)x;
    return (int32_t)(narrowed / 3u + (uint32_t)(narrowed >> 5));
}

/* CONTROL: `nrw194_bool_and` with the normalisation written out by hand and an
 * `int32_t` result. If this passes while `nrw194_bool_and` fails, the defect is
 * in the `_Bool` return conversion rather than in the surrounding arithmetic. */
__attribute__((noinline)) int32_t nrw194_bool_wide_control(int32_t x, int32_t y) {
    int32_t a = (x & 4) != 0;
    int32_t b = (y & 8) != 0;
    return a & b;
}
