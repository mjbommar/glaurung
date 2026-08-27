#include <stdint.h>

/* Constants too large to encode in an instruction, which ARM must therefore
 * fetch from a LITERAL POOL — a block of data placed inside `.text`, addressed
 * PC-relatively, and interleaved with the code that reads it.
 *
 * WHY IT IS A DECOMPILER PROBLEM. A literal pool is data in an executable
 * section, sitting between functions or even between basic blocks of one
 * function. Three separate things have to get it right: the linear sweep must
 * not decode pool words as instructions (they disassemble perfectly well as
 * garbage); function discovery must not seed a function at a pool word that
 * happens to look like a prologue; and the lifter must FOLD the load, because
 * `ldr r0, [pc, #24]` reads a value that is fully known at lift time and
 * leaving it as a memory read of an undefined register loses the constant.
 *
 * We do fold it — `lift_arm32` resolves `[pc, #imm]` through `ctx.literal` and
 * emits `Op::Assign` with the word — and there is no fixture behind that path.
 * The Thumb-2 encoding rounds `pc` DOWN to a 4-byte boundary while A32 does
 * not, so the same source exercises two different address computations, and an
 * off-by-four reads the neighbouring word and produces a confidently wrong
 * constant.
 *
 * `120_const_and_literals` covers constants as a C-level concept (const
 * qualification, string literals, enum constants). It does not force a pool:
 * its values are small enough to encode inline. `116_string_literals` covers
 * `.rodata` addressing, which is a relocation, not a PC-relative fetch.
 *
 * The constants below are chosen to be unencodable as ARM immediates (which
 * must be an 8-bit value rotated by an even amount), so every target must
 * either build them with a multi-instruction sequence or fetch them from a
 * pool. Several functions are placed so a pool must land between them.
 */

/* A single unencodable constant. */
__attribute__((noinline)) uint32_t wide_constant_mix(uint32_t seed) {
    return (seed ^ 0x5A3C7E19u) + 0x12345678u;
}

/* Enough distinct wide constants that the pool cannot be folded into the
 * instruction stream, and must be emitted as a block. */
__attribute__((noinline)) uint32_t many_wide_constants(uint32_t seed) {
    uint32_t acc = seed;
    acc ^= 0xDEADBEEFu;
    acc += 0xCAFEBABEu;
    acc ^= 0x8BADF00Du;
    acc += 0xFEEDFACEu;
    acc ^= 0x0BADC0DEu;
    acc += 0x1BADB002u;
    return acc;
}

/* 64-bit constants: two pool words each on a 32-bit target. */
__attribute__((noinline)) uint64_t wide_64bit_constants(uint64_t seed) {
    uint64_t acc = seed;
    acc ^= 0x0123456789ABCDEFull;
    acc += 0xFEDCBA9876543210ull;
    return acc;
}

/* A long function whose constants are used near the END, so the assembler must
 * place a pool in the middle of the function rather than after it — the case
 * where pool words are interleaved with basic blocks. */
__attribute__((noinline)) uint32_t pool_inside_function(uint32_t seed,
                                                        int32_t count) {
    uint32_t acc = seed;
    if (count < 0 || count > 32) {
        return 0xFFFFFFFFu;
    }
    for (int32_t i = 0; i < count; i++) {
        acc = (acc << 1) ^ (acc >> 31);
        acc += (uint32_t)i;
        acc ^= (acc >> 7);
        acc += (acc << 3);
        acc ^= (acc >> 17);
    }
    acc ^= 0xA5A5F0F0u;
    acc += 0x3C3C0F0Fu;
    return acc;
}

/* Constants that ARE encodable as ARM immediates, so no pool is emitted. The
 * control: if these fail, the defect is in constant handling generally. */
__attribute__((noinline)) uint32_t encodable_constants(uint32_t seed) {
    uint32_t acc = seed;
    acc ^= 0xFFu;
    acc += 0x1000u;
    acc ^= 0x00FF0000u;
    return acc;
}

/* A wide constant used as a COMPARISON bound rather than as an operand, so the
 * folded value has to reach a predicate rather than an arithmetic result. */
__attribute__((noinline)) int32_t compare_against_pool(uint32_t value) {
    if (value > 0x7EDCBA98u) {
        return 1;
    }
    if (value < 0x1234ABCDu) {
        return 2;
    }
    return 3;
}
