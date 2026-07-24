/* 02_integer_widths.c
 *
 * Integer width / signedness fixture. Every function is a pure integer function
 * whose result depends on the EXACT bit width and signedness of the operations
 * a correct decompilation must recover. A width- or sign-broken lowering
 * (dropped 32-bit zero-extension, `>>` on the wrong signedness, a missing
 * truncation mask, a sign-extend where a zero-extend belonged) sends the return
 * value to a different constant, which an execution-differential test catches.
 *
 * Targets review #2 (integer width & sign). Keep every function pure (no
 * globals, no memory beyond passed-in pointers, no libc) and deterministic in
 * its integer arguments. Every function returns an int that differs between a
 * correct and a width-broken lowering.
 */
#include <stdint.h>

/* --- round-trips through each unsigned width --------------------------- */

/* uint8_t round-trip: value must survive an 8-bit store/load, i.e. be masked
 * to the low byte. A decompiler that widens the temporary loses the & 0xFF. */
int rt_u8(unsigned x) {
    uint8_t v = (uint8_t)x;
    return (int)v;                 /* == x & 0xFF */
}

/* uint16_t round-trip. */
int rt_u16(unsigned x) {
    uint16_t v = (uint16_t)x;
    return (int)v;                 /* == x & 0xFFFF */
}

/* uint32_t round-trip: return the full 32-bit value as a signed int. */
int rt_u32(unsigned x) {
    uint32_t v = (uint32_t)x;
    return (int)v;
}

/* uint64_t round-trip: pack a value into 64 bits, fold the halves back to an
 * int. If the high 32 bits are dropped the fold changes. */
int rt_u64(unsigned x) {
    uint64_t v = ((uint64_t)x << 20) | (uint64_t)x;
    return (int)((v >> 20) ^ (v & 0xFFFFFF));
}

/* --- sign extension ---------------------------------------------------- */

/* Return an int8_t param as int: the top bit must sign-extend. For x=0xFF the
 * result is -1, not 255. A zero-extend here is the classic bug. */
int sext_i8(int x) {
    int8_t v = (int8_t)x;
    return (int)v;
}

/* Sign-extend a 16-bit quantity. */
int sext_i16(int x) {
    int16_t v = (int16_t)x;
    return (int)v;
}

/* --- zero extension of architecture-defined 32-bit writes -------------- */

/* Write a 32-bit value into a 64-bit register: on x86-64 a 32-bit write
 * zero-extends the full 64-bit register. Compute in 64 bits and mask so the
 * value is unambiguous; a lowering that treats the write as sign-extending or
 * leaves the high bits dirty produces a different masked result. */
int zext_u32_to_u64(uint32_t x) {
    uint64_t r = x;                /* zero-extended by definition */
    r += 0x100000000ULL;           /* deposit into the high word */
    return (int)(r >> 32);         /* == 1 for every x if zero-extended */
}

/* A 32-bit subtract that underflows: the borrow must NOT propagate into a
 * 64-bit register. (a - b) as uint32_t wraps mod 2^32; widened math would not. */
int wrap_sub_u32(uint32_t a, uint32_t b) {
    uint32_t r = a - b;
    return (int)(r >> 24);         /* top byte of the wrapped difference */
}

/* --- truncation -------------------------------------------------------- */

/* Truncate to a byte. */
int trunc_u8(unsigned x) {
    return (uint8_t)x;             /* low 8 bits, zero-extended to int */
}

/* Truncate to a halfword after an arithmetic op that overflows 16 bits. */
int trunc_u16_after_mul(unsigned x) {
    uint16_t v = (uint16_t)(x * 3u);
    return (int)v;
}

/* --- partial-word write / deposit -------------------------------------- */

/* Overwrite only the low byte of a word, keep the upper three bytes. A
 * decompiler that clobbers the whole word instead of doing a byte deposit
 * returns a different value. */
int deposit_low_byte(unsigned x, unsigned b) {
    uint32_t v = (uint32_t)x;
    v = (v & 0xFFFFFF00u) | (b & 0xFFu);
    return (int)v;
}

/* Deposit into the second byte lane [15:8]. */
int deposit_byte1(unsigned x, unsigned b) {
    uint32_t v = (uint32_t)x;
    v = (v & 0xFFFF00FFu) | ((b & 0xFFu) << 8);
    return (int)v;
}

/* --- byte extraction --------------------------------------------------- */

/* Extract byte lane 1: (x >> 8) & 0xFF. */
int extract_byte1(unsigned x) {
    return (int)((x >> 8) & 0xFFu);
}

/* Extract byte lane 3 (top byte of a 32-bit word). */
int extract_byte3(unsigned x) {
    return (int)((x >> 24) & 0xFFu);
}

/* --- hi<<32 | lo reconstruction ---------------------------------------- */

/* Reassemble a 64-bit value from two 32-bit halves, then fold to an int. If
 * `hi` is not shifted into the true high word (e.g. shifted in 32-bit math and
 * lost) the fold differs. */
int reconstruct_64(uint32_t hi, uint32_t lo) {
    uint64_t v = ((uint64_t)hi << 32) | (uint64_t)lo;
    return (int)((v >> 32) - (v & 0xFFFFFFFFu));
}

/* --- signed vs unsigned right shift (MUST differ for negatives) -------- */

/* Arithmetic right shift on a signed int: sign bit replicates. For x<0 the
 * result stays negative. */
int sar_signed(int x) {
    return x >> 4;
}

/* Logical right shift on an unsigned: zero fill. For the SAME negative bit
 * pattern this must NOT equal sar_signed — that divergence is the whole point. */
int shr_unsigned(unsigned x) {
    return (int)(x >> 4);
}

/* Right shift after casting a negative int to unsigned: forces the logical
 * (zero-fill) form even though the source looks signed. */
int shr_via_cast(int x) {
    return (int)(((unsigned)x) >> 1);
}

/* --- overflow-sensitive add / mul -------------------------------------- */

/* 32-bit signed add that is allowed to wrap: the result is only correct if the
 * add is performed at 32 bits. Computed through uint32_t to keep it defined. */
int add_wrap32(int a, int b) {
    uint32_t r = (uint32_t)a + (uint32_t)b;
    return (int)r;
}

/* 32-bit multiply that discards the high product. If the decompiler promotes to
 * a 64-bit multiply and keeps the high bits, the masked result changes. */
int mul_wrap32(unsigned a, unsigned b) {
    uint32_t r = a * b;
    return (int)(r & 0x7FFFFFFF);
}

/* Widening multiply: the product genuinely needs 64 bits; folding it back
 * exercises the high half that a 32-bit-only lowering would drop. */
int mul_widen(uint32_t a, uint32_t b) {
    uint64_t r = (uint64_t)a * (uint64_t)b;
    return (int)((r >> 32) ^ (r & 0xFFFFFFFFu));
}

/* --- rotates written in portable C ------------------------------------- */

/* Rotate-left by a fixed amount, 32-bit. The (x >> (32-n)) half must use
 * 32-bit unsigned semantics; a wrong width leaks or loses bits. */
int rotl32_7(uint32_t x) {
    uint32_t r = (x << 7) | (x >> (32 - 7));
    return (int)r;
}

/* Rotate-right by a variable amount masked to 5 bits. */
int rotr32(uint32_t x, unsigned n) {
    n &= 31u;
    uint32_t r = (x >> n) | (x << ((32 - n) & 31));
    return (int)r;
}

/* 16-bit rotate: the wrap distance is 16, and the intermediate must be masked
 * to 16 bits or the two halves collide. */
int rotl16_3(unsigned x) {
    uint16_t v = (uint16_t)x;
    uint16_t r = (uint16_t)((v << 3) | (v >> (16 - 3)));
    return (int)r;
}
