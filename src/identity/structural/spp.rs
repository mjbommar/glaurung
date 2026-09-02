//! The Small Primes Product over normalized mnemonics.
//!
//! Dullien and Rolles, "Graph-based Comparison of Executable Objects" (SSTIC
//! 2005), section 3: map each mnemonic to a distinct small odd prime through a
//! function `tau`, and take the product of `tau(m)` over the instructions of a
//! block or function, modulo `2^64`. Diaphora ships the same idea as the
//! `mnemonics_spp` column; BinDiff's `prime signature matching` pass is the
//! weaker *sum* of Goedel numbers, which fits a word but loses the
//! multiplicative structure.
//!
//! What the product buys is an **order-independent multiset identity**.
//! Multiplication commutes, so an instruction scheduler that reorders a block
//! without changing which instructions are in it leaves the SPP alone; and
//! because the primes are distinct, two equal products mean the two multisets
//! of mnemonics agree (up to the modular reduction, whose collision bound the
//! paper derives). Adding or removing a single instruction changes it.
//!
//! # Normalized mnemonic
//!
//! The mnemonic text comes from whichever backend decoded the instruction --
//! `iced` for x86 and x86-64, `capstone` for ARM, AArch64, MIPS, PowerPC and
//! RISC-V (see `crate::disasm::registry`) -- so "the mnemonic" is not one
//! vocabulary. [`normalize_mnemonic`] applies three rules, in order:
//!
//! 1. **Lowercase and trim.** Both backends already emit lowercase; this is
//!    belt and braces for a caller supplying its own text.
//! 2. **Truncate at the first `.`.** Capstone puts the data-type suffix of a
//!    NEON/VFP instruction there (`vneg.f64`, `add.4s`), and RISC-V pseudo-ops
//!    use it too. The lane arrangement is carried by the operands, not by the
//!    operation, and folding it in would make an `f32` and an `f64` form of the
//!    same instruction two different primes.
//! 3. **Strip one trailing ARM condition suffix, but only when the remaining
//!    stem is itself a known mnemonic.** Capstone renders a predicated A32
//!    instruction as `addne`, `bleq`, `movmi`. Stripping unconditionally would
//!    mangle every mnemonic that happens to end in two condition letters --
//!    x86's `cmovle` would become `cmov`, `setle` would become `set` -- so the
//!    strip is gated twice: the whole name is looked up first and returned
//!    as-is when it is listed (`cmovle` and `setle` both are), and only then is
//!    a suffix removed, and only onto a stem that is itself listed. `addne` is
//!    stripped because `addne` is not in the table and `add` is. The gate makes
//!    the rule total and decidable from the table alone.
//!
//! Nothing is done about the `s` flag-setting suffix (`adds`, `subs`): it is a
//! real semantic difference (it writes the condition flags) and the ARM
//! assembler treats it as a different instruction.
//!
//! # The prime table
//!
//! [`KNOWN_MNEMONICS`] is a fixed list. **Its order is the scheme.** Entry `i`
//! maps to the `i`-th odd prime (3, 5, 7, 11, ...), so inserting a name in the
//! middle renumbers everything after it and invalidates every stored SPP.
//! Append only, and treat an append as a scheme version bump.
//!
//! A mnemonic that is not in the table -- an AVX-512 form, a vendor extension,
//! an architecture we grew support for after this list was written -- is mapped
//! into a fixed overflow window of [`OVERFLOW_SLOTS`] further primes, indexed
//! by a FNV-1a hash of the normalized text. Two unlisted mnemonics can
//! therefore collide onto one prime. That is a deliberate trade: the
//! alternative is an unbounded table that changes shape whenever a decoder
//! learns a new opcode, which would be a silent scheme change. The consequence
//! is bounded -- a collision can only make two different functions look alike,
//! never make one function look different from itself -- and the SPP is one
//! term in the ranking blend, not an identity on its own.

use std::sync::OnceLock;

/// Number of overflow primes reserved for mnemonics not in [`KNOWN_MNEMONICS`].
pub const OVERFLOW_SLOTS: usize = 1024;

/// ARM condition-code suffixes, longest first so `hs`/`lo` cannot shadow a
/// shorter match. Checked by [`normalize_mnemonic`] rule 3.
const ARM_CONDITIONS: [&str; 17] = [
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    "al",
];

/// The mnemonic-to-prime table. Position is the scheme; append only.
///
/// Covers the operations that carry the bulk of the instruction mass in the
/// architectures `crate::disasm::registry` can decode: x86/x86-64 integer, SSE
/// and x87; A32/T32 and AArch64; RISC-V RV32/64 I, M and A; MIPS; PowerPC. It
/// is deliberately not exhaustive -- see the overflow window in the module
/// docs.
pub const KNOWN_MNEMONICS: &[&str] = &[
    // --- x86 / x86-64 data movement ---
    "mov",
    "movabs",
    "movzx",
    "movsx",
    "movsxd",
    "lea",
    "push",
    "pop",
    "xchg",
    "cwde",
    "cdq",
    "cdqe",
    "cqo",
    // --- x86 / x86-64 arithmetic and logic ---
    "add",
    "adc",
    "sub",
    "sbb",
    "mul",
    "imul",
    "div",
    "idiv",
    "neg",
    "inc",
    "dec",
    "and",
    "or",
    "xor",
    "not",
    "shl",
    "shr",
    "sar",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "shld",
    "shrd",
    "bt",
    "bts",
    "btr",
    "btc",
    "bsf",
    "bsr",
    "popcnt",
    "tzcnt",
    "lzcnt",
    "bswap",
    // --- x86 / x86-64 comparison and control ---
    "cmp",
    "test",
    "sete",
    "setne",
    "setl",
    "setle",
    "setg",
    "setge",
    "setb",
    "setbe",
    "seta",
    "setae",
    "sets",
    "setns",
    "jmp",
    "je",
    "jne",
    "jl",
    "jle",
    "jg",
    "jge",
    "jb",
    "jbe",
    "ja",
    "jae",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jnp",
    "jecxz",
    "jrcxz",
    "loop",
    "call",
    "ret",
    "leave",
    "enter",
    "int",
    "int3",
    "syscall",
    "sysenter",
    "iret",
    "hlt",
    "nop",
    "ud2",
    "endbr32",
    "endbr64",
    "cpuid",
    "rdtsc",
    "xgetbv",
    // --- x86 string / flags ---
    "movsb",
    "movsw",
    "movsd",
    "movsq",
    "stosb",
    "stosw",
    "stosd",
    "stosq",
    "lodsb",
    "lodsd",
    "scasb",
    "cmpsb",
    "cld",
    "std",
    "clc",
    "stc",
    "cmc",
    "pushf",
    "popf",
    "pushfq",
    "popfq",
    "sahf",
    "lahf",
    "cmpxchg",
    "xadd",
    "cmovne",
    "cmove",
    "cmovl",
    "cmovle",
    "cmovg",
    "cmovge",
    "cmovb",
    "cmovbe",
    "cmova",
    "cmovae",
    "cmovs",
    "cmovns",
    // --- x86 SSE / AVX (the forms that dominate compiled code) ---
    "movss",
    "movaps",
    "movups",
    "movdqa",
    "movdqu",
    "movq",
    "movd",
    "addss",
    "addsd",
    "subss",
    "subsd",
    "mulss",
    "mulsd",
    "divss",
    "divsd",
    "sqrtss",
    "sqrtsd",
    "ucomiss",
    "ucomisd",
    "comiss",
    "comisd",
    "cvtsi2ss",
    "cvtsi2sd",
    "cvttss2si",
    "cvttsd2si",
    "cvtss2sd",
    "cvtsd2ss",
    "pxor",
    "por",
    "pand",
    "pcmpeqb",
    "pcmpeqd",
    "punpcklbw",
    "pshufd",
    "pmovmskb",
    "xorps",
    "xorpd",
    "andps",
    "andpd",
    "unpcklps",
    "vzeroupper",
    // --- x87 ---
    "fld",
    "fstp",
    "fst",
    "fild",
    "fistp",
    "fadd",
    "fsub",
    "fmul",
    "fdiv",
    "fchs",
    "fabs",
    "fcom",
    "fcomp",
    "fucomi",
    "fucomip",
    "fnstcw",
    "fldcw",
    "fxch",
    "fnstsw",
    // --- ARM A32 / T32 ---
    "b",
    "bl",
    "bx",
    "blx",
    "cbz",
    "cbnz",
    "ldr",
    "ldrb",
    "ldrh",
    "ldrsb",
    "ldrsh",
    "ldm",
    "ldmia",
    "ldp",
    "str",
    "strb",
    "strh",
    "stm",
    "stmdb",
    "stp",
    "rsb",
    "rsc",
    "mvn",
    "bic",
    "orr",
    "orn",
    "sbc",
    "eor",
    "tst",
    "teq",
    "cmn",
    "mla",
    "mls",
    "umull",
    "smull",
    "umlal",
    "smlal",
    "sdiv",
    "udiv",
    "lsl",
    "lsr",
    "asr",
    "rrx",
    "uxtb",
    "uxth",
    "sxtb",
    "sxth",
    "rev",
    "rev16",
    "clz",
    "it",
    "svc",
    "mrs",
    "msr",
    "dmb",
    "dsb",
    "isb",
    "wfi",
    "wfe",
    "pld",
    // --- AArch64 ---
    "adr",
    "adrp",
    "movz",
    "movk",
    "movn",
    "ldur",
    "stur",
    "ldrsw",
    "ldaxr",
    "stlxr",
    "ldxr",
    "stxr",
    "cas",
    "casal",
    "tbz",
    "tbnz",
    "csel",
    "csinc",
    "csinv",
    "csneg",
    "cset",
    "csetm",
    "ccmp",
    "ccmn",
    "madd",
    "msub",
    "smaddl",
    "umaddl",
    "smulh",
    "umulh",
    "sbfiz",
    "ubfiz",
    "sbfx",
    "ubfx",
    "bfi",
    "bfxil",
    "extr",
    "ands",
    "eon",
    "sxtw",
    "uxtw",
    "brk",
    "hint",
    "fmov",
    "fcmp",
    "fcvt",
    "scvtf",
    "ucvtf",
    "fcvtzs",
    "fcvtzu",
    // --- RISC-V ---
    "addi",
    "addiw",
    "addw",
    "subw",
    "slli",
    "srli",
    "srai",
    "slt",
    "slti",
    "sltu",
    "sltiu",
    "andi",
    "ori",
    "xori",
    "lui",
    "auipc",
    "jal",
    "jalr",
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "lb",
    "lh",
    "lw",
    "ld",
    "lbu",
    "lhu",
    "lwu",
    "sb",
    "sh",
    "sw",
    "sd",
    "mulh",
    "mulhu",
    "mulhsu",
    "rem",
    "remu",
    "divu",
    "ecall",
    "ebreak",
    "fence",
    "amoadd",
    "amoswap",
    "lr",
    "sc",
    // --- MIPS ---
    "addu",
    "addiu",
    "subu",
    "sll",
    "srl",
    "sra",
    "sllv",
    "srlv",
    "srav",
    "beqz",
    "bnez",
    "bgez",
    "bltz",
    "j",
    "jr",
    "mfhi",
    "mflo",
    "mthi",
    "mtlo",
    "multu",
    // --- PowerPC ---
    "addis",
    "stw",
    "stwu",
    "lwz",
    "lwzu",
    "mflr",
    "mtlr",
    "mtctr",
    "bctr",
    "bctrl",
    "blr",
    "cmpw",
    "cmpwi",
    "cmplw",
    "cmplwi",
    "rlwinm",
    "rldicl",
    "srawi",
    "subf",
    "mulld",
    "divd",
];

/// The `n`-th odd prime, 0-indexed: `prime_at(0) == 3`, `prime_at(1) == 5`.
///
/// The whole sequence is built once, on first use, by trial division and
/// cached. `2` is skipped because Dullien and Rolles specify *odd* primes: an
/// even factor would make the low bit of the product carry information about
/// the mnemonic count rather than the mnemonic set.
fn prime_at(n: usize) -> u64 {
    static PRIMES: OnceLock<Vec<u64>> = OnceLock::new();
    let primes = PRIMES.get_or_init(|| {
        let wanted = KNOWN_MNEMONICS.len() + OVERFLOW_SLOTS;
        let mut out: Vec<u64> = Vec::with_capacity(wanted);
        let mut candidate: u64 = 3;
        while out.len() < wanted {
            if out
                .iter()
                .take_while(|p| *p * *p <= candidate)
                .all(|p| candidate % *p != 0)
            {
                out.push(candidate);
            }
            candidate += 2;
        }
        out
    });
    primes[n % primes.len()]
}

/// FNV-1a over the bytes of `s`. Fixed, seedless and therefore reproducible
/// across processes -- unlike `DefaultHasher`, whose `RandomState` is not.
fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Normalize one decoded mnemonic. See the module docs for the three rules.
pub fn normalize_mnemonic(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    let stem = match lowered.find('.') {
        Some(i) => &lowered[..i],
        None => &lowered[..],
    };
    if is_known(stem) {
        return stem.to_string();
    }
    for cc in ARM_CONDITIONS {
        if let Some(base) = stem.strip_suffix(cc) {
            if !base.is_empty() && is_known(base) {
                return base.to_string();
            }
        }
    }
    stem.to_string()
}

/// Is `m` in [`KNOWN_MNEMONICS`]?
fn is_known(m: &str) -> bool {
    known_index(m).is_some()
}

/// Position of `m` in [`KNOWN_MNEMONICS`], which is its prime index.
fn known_index(m: &str) -> Option<usize> {
    KNOWN_MNEMONICS.iter().position(|k| *k == m)
}

/// The prime `tau(m)` for one raw mnemonic.
///
/// Normalizes first, then looks up. An unlisted mnemonic lands in the overflow
/// window at `KNOWN_MNEMONICS.len() + (fnv1a64(name) % OVERFLOW_SLOTS)`.
pub fn mnemonic_prime(raw: &str) -> u64 {
    let m = normalize_mnemonic(raw);
    match known_index(&m) {
        Some(i) => prime_at(i),
        None => prime_at(KNOWN_MNEMONICS.len() + (fnv1a64(&m) as usize) % OVERFLOW_SLOTS),
    }
}

/// The Small Primes Product over `mnemonics`, modulo `2^64`.
///
/// The empty sequence gives 1, the empty product -- not 0, which would be
/// indistinguishable from a product that happened to reduce to zero (it cannot:
/// every factor is odd, so the product is odd, so it is never zero mod 2^64).
/// That the SPP of any non-empty function is odd is a cheap invariant a caller
/// can assert on.
pub fn mnemonic_spp<'a, I: IntoIterator<Item = &'a str>>(mnemonics: I) -> u64 {
    let mut product: u64 = 1;
    for m in mnemonics {
        product = product.wrapping_mul(mnemonic_prime(m));
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_primes_are_the_odd_ones() {
        assert_eq!(prime_at(0), 3);
        assert_eq!(prime_at(1), 5);
        assert_eq!(prime_at(2), 7);
        assert_eq!(prime_at(3), 11);
        assert_eq!(prime_at(4), 13);
        assert_eq!(prime_at(5), 17);
    }

    #[test]
    fn the_table_has_no_duplicates() {
        let mut sorted: Vec<&str> = KNOWN_MNEMONICS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(
            before,
            sorted.len(),
            "KNOWN_MNEMONICS must map each name to exactly one prime"
        );
    }

    #[test]
    fn distinct_known_mnemonics_get_distinct_primes() {
        let mut primes: Vec<u64> = KNOWN_MNEMONICS.iter().map(|m| mnemonic_prime(m)).collect();
        let before = primes.len();
        primes.sort_unstable();
        primes.dedup();
        assert_eq!(before, primes.len());
    }

    #[test]
    fn normalization_lowercases_and_truncates_at_a_dot() {
        assert_eq!(normalize_mnemonic("MOV"), "mov");
        assert_eq!(normalize_mnemonic("  add  "), "add");
        assert_eq!(normalize_mnemonic("vneg.f64"), "vneg");
        assert_eq!(normalize_mnemonic("add.4s"), "add");
    }

    #[test]
    fn normalization_strips_an_arm_condition_only_onto_a_known_stem() {
        assert_eq!(normalize_mnemonic("addne"), "add");
        assert_eq!(normalize_mnemonic("moveq"), "mov");
        assert_eq!(normalize_mnemonic("bleq"), "bl");
        // `bls` is itself unlisted, and stripping `ls` gives `b`, which IS
        // listed -- so the rule fires. Documented, and the alternative (adding
        // every predicated form to the table) is what the rule exists to avoid.
        assert_eq!(normalize_mnemonic("bls"), "b");
        // A stem that is not in the table is left whole rather than mangled.
        assert_eq!(normalize_mnemonic("zzzne"), "zzzne");
    }

    #[test]
    fn spp_is_order_independent() {
        let a = mnemonic_spp(["mov", "add", "cmp", "je"]);
        let b = mnemonic_spp(["je", "cmp", "add", "mov"]);
        let c = mnemonic_spp(["cmp", "mov", "je", "add"]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn spp_is_deterministic_across_calls() {
        let a = mnemonic_spp(["push", "mov", "sub", "call", "leave", "ret"]);
        let b = mnemonic_spp(["push", "mov", "sub", "call", "leave", "ret"]);
        assert_eq!(a, b);
    }

    #[test]
    fn spp_counts_multiplicity() {
        assert_ne!(mnemonic_spp(["mov"]), mnemonic_spp(["mov", "mov"]));
    }

    #[test]
    fn spp_of_nothing_is_the_empty_product() {
        let none: [&str; 0] = [];
        assert_eq!(mnemonic_spp(none), 1);
    }

    #[test]
    fn spp_is_always_odd() {
        assert_eq!(mnemonic_spp(["mov", "add", "wibble", "zzz"]) % 2, 1);
    }

    #[test]
    fn unlisted_mnemonics_are_stable_but_may_share_a_slot() {
        let a = mnemonic_prime("vpternlogd");
        let b = mnemonic_prime("vpternlogd");
        assert_eq!(a, b, "an unlisted mnemonic must still be deterministic");
        assert_ne!(a, 0);
    }

    #[test]
    fn a_changed_instruction_changes_the_product() {
        let before = mnemonic_spp(["mov", "add", "ret"]);
        let after = mnemonic_spp(["mov", "sub", "ret"]);
        assert_ne!(before, after);
    }
}
