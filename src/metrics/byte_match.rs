//! DecBench's `byte_match` metric --- the disassembly, normalization, diff and
//! score halves of it.
//!
//! `byte_match` asks a blunt question: recompile the decompiled C, disassemble
//! the result and the original function, and see how much of the assembly
//! survives. The reference implementation is
//! `decbench/metrics/byte_match.py` in the DecBench checkout, and everything
//! here is a transcription of it rather than an improvement on it. Where the
//! reference does something that looks wrong, this module does the same wrong
//! thing and says so in a comment, because parity is the point: a number that
//! is *better* than DecBench's is a number that cannot be compared to
//! DecBench's.
//!
//! # What is here, and what deliberately is not
//!
//! The component inventory (`docs/design/static-c-analysis/implementation-inventory.md`
//! section 6) splits the metric into eight pieces, B-1 through B-8. This module
//! implements the four that need no compiler in the loop:
//!
//! * **B-5**, [`disassemble_lines`] --- capstone with detail on, `nop` dropped
//!   as alignment padding.
//! * **B-6**, [`normalize_operands`] --- blanking the operand values that a
//!   relink would move.
//! * **B-7**, [`diff_lines`] --- line interning plus Myers O(ND) with the
//!   middle-snake bisect.
//! * **B-8**, [`score_lines`] --- `shared / (a_only + shared + b_only)`, and
//!   the absolute changed-line count beside it.
//!
//! **The metric is not finished.** B-1 (format and architecture detection),
//! B-2 (producer-flag recovery from `DW_AT_producer`), B-3 (function byte
//! extraction, including the ARM Thumb bit on `STT_FUNC` symbol values) and
//! B-4 (the compilability fixup fixpoint --- an `XL` transcription of 207
//! prototypes and 177 helper macros driven by compiler diagnostics) are all
//! absent. Those four need a recompiler in the loop and are separable from
//! these; nothing in this module should be read as "Glaurung computes
//! `byte_match`". What it computes is the comparison, given two byte strings
//! someone else produced.
//!
//! # Two places the reference is surprising
//!
//! * **The register digit is collateral damage.** [`normalize_operands`]
//!   blanks *every* numeric token in a branch operand, not just the target,
//!   because the reference's `_HEX_TOKEN` is an unanchored `#?-?(?:0x[0-9a-fA-F]+|\d+)`.
//!   So `jmp r8` normalizes to `jmp rX` and `cbz w0, #0x100` to `cbz wX, X`.
//!   That is measured reference behaviour, not a transcription slip --- see
//!   the citations on [`tests::normalize_matches_reference_edge_cases`].
//! * **Mnemonic membership is exact string equality.** ARM Thumb wide
//!   encodings print as `b.w` / `bl.w` / `beq.w`, which are not in the
//!   50-element set, so their branch targets are *not* blanked and every Thumb
//!   wide branch counts as a mismatch between a linked original and an
//!   unlinked recompile. Reproduced faithfully; noted on [`BRANCH_MNEMONICS`].
//!
//! # What a do-nothing decompiler scores, measured
//!
//! `docs/design/metrics-research/` audited GED and found its headline
//! saturated by trivial functions: a backend emitting `int f(void){return 0;}`
//! for every function is 27.24% GED-perfect, above Ghidra. `type_match` was
//! asked the same question and answered 73.5%. `byte_match` is a Jaccard, so
//! it deserved the same interrogation, and the answer is different in kind.
//!
//! Corpus: the 5,753 x86-64 functions of `tests/decompiler_fixtures/build/`
//! and `samples/`, normalized by [`disassemble_lines`], scored against real
//! `gcc -O0`/`-O2` objects built from five do-nothing bodies (`void f(void){}`,
//! `int f(void){return 0;}`, `long f(long a){return a;}`, a single call, a
//! trivial loop) with the reference `_compute_jaccard_similarity`:
//!
//! | null body | mean | median | perfect (== 1.0) |
//! |---|---|---|---|
//! | `void f(void){}` `-O2` | 8.10% | 1.92% | 7 (0.40% of `-O2` functions) |
//! | `int f(void){return 0;}` `-O2` | 7.26% | 2.61% | 0 (0.00%) |
//! | `int f(void){return 0;}` `-O0` | 12.10% | 6.45% | 0 (0.00%) |
//! | best of all ten stubs, per function | 15.65% | 10.64% | **11 (0.19%)** |
//!
//! **0.19%, against GED's 27.24% and `type_match`'s 73.5%.** The denominator
//! is not flattering here, and the reason is structural: this is a Jaccard over
//! a *diff*, not over a set, so the denominator is `|a| + |b| - shared` and
//! grows with the original function's length. A three-line answer against a
//! sixty-line function is capped at 3/60 however right those three lines are.
//! GED's denominator saturates because a one-node CFG has no structure left to
//! be wrong about; this one cannot.
//!
//! Two calibrations that say what the number means:
//!
//! * **A null decompilation scores the same as an unrelated real function.**
//!   4,000 random pairs of *different real functions* from the same corpus:
//!   mean 6.17%, median 3.80%, 0.08% perfect. The stubs' 6-8% at `-O2` is the
//!   noise floor, not partial credit --- the metric gives nothing away for
//!   merely being plausible C.
//! * **Toolchain identity dominates decompiler quality.** The *same source
//!   function* compiled `gcc -O2` versus `clang -O2` scores mean 29.83%,
//!   median 20.51%, and **0.00% perfect** (n=127); `gcc -O0` versus `gcc -O2`
//!   scores 15.07% with 1.83% perfect (n=109). Since DecBench ranks by
//!   `perfect_percentage` --- `MetricResult.compute_aggregates` counts
//!   `v == perfect_value` and `scoreboard.py` ranks on it --- a perfectly
//!   correct decompilation recompiled with a slightly different toolchain
//!   contributes exactly as much to the ranking as a null one. That is the
//!   failure mode here, and it is the mirror image of GED's: not a headline
//!   saturated *high* by trivial functions but one saturated *low* by anything
//!   that is not a byte-exact toolchain reproduction, which leaves the
//!   surviving signal concentrated in the functions that are trivially
//!   reproducible. 151 of the 5,753 (2.6%) normalize to exactly `["ret"]`, and
//!   324 (5.6%) to two lines or fewer.
//!
//! B-4 is not implemented, so none of this measures a *recompile*; it measures
//! the comparison the recompile feeds. The `gcc -O2` versus `clang -O2` row is
//! the closest available proxy for "correct decompilation, imperfect
//! toolchain", and it is the row that should be read before anyone quotes a
//! `byte_match` number as a decompiler ranking.
//!
//! # A non-answer is a value, and the bound that makes it one
//!
//! [`diff_lines`] and [`score_lines`] return `Option`. `None` is an
//! abstention --- "not measurable", which leaves the denominator uniformly for
//! every decompiler --- and never a disguised `0.0`. It happens above
//! [`MAX_DIFF_LINES`], and if the diff driver ever exhausts its expansion
//! budget.
//!
//! That bound is not decoration. While mutation-testing this module, a
//! deliberately broken parity arm in [`bisect`] returned a split point that did
//! not shrink the problem; the explicit work stack pushed the same task back on
//! every iteration; the `Vec` doubling asked for 5 GiB and the kernel OOM
//! killer took the whole session with it, on a six-line-by-six-line input.
//! [`split_makes_progress`] is the structural fix and the budget is the second
//! line, so that the worst a malformed or adversarial listing can cost is an
//! abstention.
//!
//! # Determinism
//!
//! Every function here is pure and total over its inputs. The one map is a
//! [`BTreeMap`] used to intern lines, and its iteration never reaches output.
//! The reference's one source of nondeterminism --- `diff_match_patch`'s
//! `Diff_Timeout = 1.0` wall-clock deadline, which makes `diff_bisect` bail to
//! a degenerate all-delete/all-insert answer and score `0.0` --- is
//! deliberately **not** reproduced. See [`diff_lines`] for the measurement
//! that justifies dropping it.

use std::collections::BTreeMap;

use capstone::{Arch, Capstone, Mode};
use once_cell::sync::Lazy;
use regex::Regex;

/// Anything that can stop [`disassemble_lines`] before it produces a listing.
///
/// A dedicated error rather than `Option` because "capstone would not open for
/// this architecture" and "these bytes decode to nothing" are different facts,
/// and the caller that turns a listing into a score has to distinguish an
/// abstention from a zero (the tri-state rule in
/// `docs/design/static-c-analysis/implementation-inventory.md` K-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteMatchError {
    /// Capstone refused to construct a decoder for this architecture/mode
    /// pair. Carries capstone's own message.
    CapstoneOpen(String),
    /// Capstone accepted the decoder but failed on the buffer itself.
    CapstoneDisasm(String),
}

impl std::fmt::Display for ByteMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ByteMatchError::CapstoneOpen(m) => write!(f, "capstone open failed: {m}"),
            ByteMatchError::CapstoneDisasm(m) => write!(f, "capstone disassembly failed: {m}"),
        }
    }
}

impl std::error::Error for ByteMatchError {}

/// The capstone `(arch, mode)` pair `byte_match` disassembles with.
///
/// This mirrors `decbench.utils.binfmt.capstone_arch_mode` exactly, and it is
/// deliberately a closed five-member enum rather than a pair of raw capstone
/// constants: the reference selects the AL-zeroing peephole by comparing the
/// *tuple* against `(CS_ARCH_X86, CS_MODE_64)`, so the target has to be a value
/// that can be compared for equality, not a bag of mode bits.
///
/// Note what is absent. The reference passes no endianness flag and no extra
/// mode, so neither does this --- in particular **not** `ExtraMode::V8`, which
/// `crate::disasm::capstone` enables for ARM. That flag changes which ARM
/// encodings decode, so enabling it here would silently produce listings the
/// reference never produced. This is also why this module opens its own
/// capstone handle instead of reusing `CapstoneDisassembler`: that type is
/// tuned for Glaurung's own CFG recovery (V8, an MClass fallback decoder) and
/// its `Instruction` discards the printed operand text that B-6 normalizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AsmTarget {
    /// `(CS_ARCH_X86, CS_MODE_32)`
    X86_32,
    /// `(CS_ARCH_X86, CS_MODE_64)` --- the only target the AL-zeroing peephole
    /// applies to.
    X86_64,
    /// `(CS_ARCH_ARM, CS_MODE_ARM)`
    Arm,
    /// `(CS_ARCH_ARM, CS_MODE_THUMB)` --- selected from the Thumb bit of the
    /// `STT_FUNC` symbol value, which is B-3's job and not this module's.
    ArmThumb,
    /// `(CS_ARCH_ARM64, CS_MODE_ARM)`
    Arm64,
}

impl AsmTarget {
    /// The capstone C constants this target corresponds to, as
    /// `(CS_ARCH_*, CS_MODE_*)`.
    ///
    /// Exposed so that a differential harness can address the same cell the
    /// Python reference recorded, which stores those two integers verbatim.
    pub fn capstone_ids(self) -> (u32, u32) {
        match self {
            // CS_ARCH_X86 = 3, CS_ARCH_ARM = 0, CS_ARCH_ARM64 = 1.
            // CS_MODE_ARM = 0, CS_MODE_32 = 4, CS_MODE_64 = 8, CS_MODE_THUMB = 16.
            AsmTarget::X86_32 => (3, 4),
            AsmTarget::X86_64 => (3, 8),
            AsmTarget::Arm => (0, 0),
            AsmTarget::ArmThumb => (0, 16),
            AsmTarget::Arm64 => (1, 0),
        }
    }

    /// The target for a pair of capstone C constants, or `None` for a pair
    /// `binfmt.capstone_arch_mode` never returns.
    ///
    /// The inverse of [`AsmTarget::capstone_ids`], and the entry point a
    /// differential harness uses to replay a recorded cell.
    pub fn from_capstone_ids(arch: u32, mode: u32) -> Option<Self> {
        match (arch, mode) {
            (3, 4) => Some(AsmTarget::X86_32),
            (3, 8) => Some(AsmTarget::X86_64),
            (0, 0) => Some(AsmTarget::Arm),
            (0, 16) => Some(AsmTarget::ArmThumb),
            (1, 0) => Some(AsmTarget::Arm64),
            _ => None,
        }
    }

    fn open(self) -> Result<Capstone, ByteMatchError> {
        let (arch, mode) = match self {
            AsmTarget::X86_32 => (Arch::X86, Mode::Mode32),
            AsmTarget::X86_64 => (Arch::X86, Mode::Mode64),
            AsmTarget::Arm => (Arch::ARM, Mode::Arm),
            AsmTarget::ArmThumb => (Arch::ARM, Mode::Thumb),
            AsmTarget::Arm64 => (Arch::ARM64, Mode::Arm),
        };
        let mut cs = Capstone::new_raw(arch, mode, std::iter::empty(), None)
            .map_err(|e| ByteMatchError::CapstoneOpen(e.to_string()))?;
        // The reference sets `cs.detail = True`. Capstone's own operand
        // printer does not consult the detail record, so this changes nothing
        // about the text we read --- but the reference sets it, so we set it,
        // and any future divergence in capstone's printer stays a divergence
        // we inherit rather than one we introduced.
        cs.set_detail(true)
            .map_err(|e| ByteMatchError::CapstoneOpen(e.to_string()))?;
        Ok(cs)
    }
}

/// The 50 mnemonics whose operand is a code address.
///
/// After single-function recompilation that target is layout- and
/// linker-dependent: the original is linked at its real virtual address, the
/// recompiled object is unlinked and based at zero, so identical control flow
/// would otherwise count as 50 mismatches. Verbatim from `_BRANCH_MNEMONICS`
/// in the reference, in the reference's order.
///
/// **Exact string equality, deliberately.** ARM Thumb wide encodings print as
/// `b.w`, `bl.w`, `beq.w`; IT-block forms print as `addeq`, `moveq`. None of
/// those are members, so none of their operands are blanked. That costs the
/// metric real accuracy on Thumb targets --- `b.w #0x450` differs between a
/// linked original and an unlinked recompile every single time --- and it is
/// reproduced rather than fixed, because widening the set changes every score
/// DecBench has ever recorded.
pub static BRANCH_MNEMONICS: &[&str] = &[
    "call", "jmp", "loop", "loope", "loopne", "jecxz", "jrcxz", "je", "jne", "jz", "jnz", "jg",
    "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jc", "jnc", "js", "jns", "jo", "jno", "jp",
    "jnp", "jpe", "jpo", "jcxz", "b", "bl", "blx", "bx", "beq", "bne", "bcs", "bcc", "bmi", "bpl",
    "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble", "cbz", "cbnz",
];

/// The mnemonics whose *immediate* is PC-relative even without brackets.
///
/// AArch64 `adrp`/`adr` materialize a page address into a register; the value
/// is a link-time constant, so it is blanked unconditionally --- unlike the
/// branch set, `adrp` is normalized even when its operand contains a `[`.
/// Verbatim from `_PC_REL_MNEMONICS`.
pub static PC_REL_MNEMONICS: &[&str] = &["adrp", "adr"];

/// Any numeric token: an optional `#`, an optional `-`, then hex or decimal.
///
/// Unanchored and untethered to a word boundary, exactly as in the reference.
/// That is what makes `jmp r8` become `jmp rX`: the `8` is a numeric token as
/// far as this pattern is concerned. Reproduced, not corrected.
static HEX_TOKEN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"#?-?(?:0x[0-9a-fA-F]+|\d+)").expect("HEX_TOKEN is a compile-time constant")
});

/// A PC-relative memory operand, with the displacement **optional**.
///
/// The optionality is load-bearing and is called out in the inventory: an
/// unlinked object has a zero relocation slot, which capstone prints as a bare
/// `[rip]`. Without the `?` the linked side would rewrite to `[rip+X]` and the
/// unlinked side would stay `[rip]`, so every PC-relative instruction in the
/// function would count as changed. Verbatim from `_PC_REL_MEM`.
static PC_REL_MEM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\[(rip|pc)(?:\s*[+\-,]\s*#?-?(?:0x[0-9a-fA-F]+|\d+))?\]")
        .expect("PC_REL_MEM is a compile-time constant")
});

/// B-6. Replace layout- and linker-dependent operand values with `X`.
///
/// Two rules, applied in this order and in this order only, because the second
/// tests the output of the first:
///
/// 1. Every `[rip±d]` / `[pc, #d]` --- displacement optional --- becomes
///    `[rip+X]` / `[pc+X]`. Note that the replacement is a literal, so the
///    spacing capstone printed (`[rip + 0x2e75]`) is *not* preserved.
/// 2. If the mnemonic is `adrp`/`adr`, **or** it is a branch mnemonic and the
///    operand no longer contains a `[`, every numeric token becomes `X`.
///
/// The `[` test happens after rule 1, so `call qword ptr [rip + 0x4e562]`
/// keeps its `qword ptr` and stops at `[rip+X]`, while `call 0x10f9` collapses
/// to `X`. That asymmetry is the reference's, and it is the reason an indirect
/// call through the GOT and a direct call do not normalize the same way.
///
/// Testing `op_str` instead of `rewritten` there would be indistinguishable,
/// and deliberately so: `PC_REL_MEM`'s replacement is `[$1+X]`, which contains
/// exactly one `[` for the one it consumed, so the rewrite never adds or
/// removes a bracket and the two tests agree on every input. A mutation
/// swapping them survives the whole suite for that reason --- it is an
/// equivalent mutant, not a hole. Order is still written the reference's way,
/// because a future change to the replacement string would make it matter.
pub fn normalize_operands(mnemonic: &str, op_str: &str) -> String {
    let rewritten = PC_REL_MEM.replace_all(op_str, "[${1}+X]");
    let blank_immediates = PC_REL_MNEMONICS.contains(&mnemonic)
        || (BRANCH_MNEMONICS.contains(&mnemonic) && !rewritten.contains('['));
    if blank_immediates {
        HEX_TOKEN.replace_all(&rewritten, "X").into_owned()
    } else {
        rewritten.into_owned()
    }
}

/// B-5. Disassemble `data` at `address` into normalized assembly lines.
///
/// Each surviving instruction becomes `"{mnemonic} {normalized operands}"`
/// with the whole string trimmed, so an operandless instruction is just
/// `"ret"`. Two filters run over the listing:
///
/// * **`nop` is dropped**, single- and multi-byte alike (capstone reports
///   `nop dword ptr [rax]` for the `0f 1f 40 00` form, so the mnemonic test
///   catches padding of every width). It is alignment, and alignment is a
///   property of where a function landed rather than of what it computes.
/// * **A zeroed `al` immediately before a `call` is dropped, on
///   [`AsmTarget::X86_64`] only.** `xor eax, eax` before a variadic call
///   records that a prototype was in scope, which for a recompile is the
///   harness's scaffolding rather than the decompiler's logic. Off every other
///   target, where the same instruction is a real argument.
///
/// The peephole reads the *pre-filter* listing when it looks ahead, matching
/// the reference's single list comprehension: three `xor eax, eax` in a row
/// before a `call` lose only the last one, not all three.
///
/// Decoding stops at the first byte capstone cannot decode, which is capstone's
/// own `cs_disasm` behaviour and the reference's too --- a truncated listing,
/// not an error.
pub fn disassemble_lines(
    data: &[u8],
    address: u64,
    target: AsmTarget,
) -> Result<Vec<String>, ByteMatchError> {
    let cs = target.open()?;
    let insns = cs
        .disasm_all(data, address)
        .map_err(|e| ByteMatchError::CapstoneDisasm(e.to_string()))?;

    let mut lines: Vec<String> = Vec::new();
    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap_or("");
        if mnemonic == "nop" {
            continue;
        }
        let op_str = insn.op_str().unwrap_or("");
        let normalized = normalize_operands(mnemonic, op_str);
        lines.push(format!("{mnemonic} {normalized}").trim().to_string());
    }

    if target == AsmTarget::X86_64 {
        let filtered: Vec<String> = lines
            .iter()
            .enumerate()
            .filter(|(i, line)| {
                let is_al_zero = line.as_str() == "mov eax, 0" || line.as_str() == "xor eax, eax";
                let next_is_call = lines
                    .get(i + 1)
                    .is_some_and(|next| next.starts_with("call "));
                !(is_al_zero && next_is_call)
            })
            .map(|(_, line)| line.clone())
            .collect();
        return Ok(filtered);
    }

    Ok(lines)
}

/// One side of a diff hunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffOp {
    /// Present in `a` only --- a line the recompile lost.
    Delete,
    /// Present in both.
    Equal,
    /// Present in `b` only --- a line the recompile invented.
    Insert,
}

/// A run of consecutive lines sharing one [`DiffOp`].
///
/// Only the length is carried, not the lines: B-8 needs counts, and keeping
/// the text would double the memory of a diff over a 4,500-line function for
/// no consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffChunk {
    /// Which side this run belongs to.
    pub op: DiffOp,
    /// How many lines are in the run. Never zero.
    pub len: usize,
}

/// The three totals a `byte_match` score is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LineDiff {
    /// Lines only in the original listing.
    pub a_only: usize,
    /// Lines common to both listings.
    pub shared: usize,
    /// Lines only in the recompiled listing.
    pub b_only: usize,
}

impl LineDiff {
    /// The reference's `changed_lines`: the absolute number of assembly lines
    /// that differ, which the DecBench report surfaces on its "distance" view
    /// beside the ratio.
    pub fn changed(self) -> usize {
        self.a_only + self.b_only
    }

    /// Roll a chunk list up into totals.
    fn from_chunks(chunks: &[DiffChunk]) -> Self {
        let mut d = LineDiff::default();
        for c in chunks {
            match c.op {
                DiffOp::Delete => d.a_only += c.len,
                DiffOp::Equal => d.shared += c.len,
                DiffOp::Insert => d.b_only += c.len,
            }
        }
        d
    }
}

/// A `byte_match` comparison of two assembly listings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ByteMatchScore {
    /// `shared / (a_only + shared + b_only)`, in `[0, 1]`, higher is better.
    pub similarity: f64,
    /// `a_only + b_only`.
    pub changed_lines: usize,
    /// The totals the ratio came from.
    pub diff: LineDiff,
}

/// The largest pair of listings [`diff_lines`] will diff, in total lines.
///
/// A bound, not a quality knob, and the reason it exists is an incident: while
/// mutation-testing this module a deliberately broken middle snake returned a
/// split point that did not shrink the problem, [`diff_lines`]' work stack grew
/// on every iteration, and the resulting 5 GiB allocation took the machine's
/// OOM killer with it. [`split_makes_progress`] is the structural fix; this cap
/// and the expansion budget beside it are the belt and braces, so that a
/// malformed listing costs an abstention rather than a box.
///
/// The value is measured rather than picked. Across the 6,400 real functions of
/// `tests/decompiler_fixtures/build/` and `samples/`, the largest normalized
/// listing is 4,540 lines (`151_wide_branch_ladder-gcc-O2.so::big151_branch_ladder`),
/// the 99.9th percentile is 2,074, and the largest *pair* that corpus can form
/// is 8,307 lines. 16,384 is roughly twice that, so nothing real abstains,
/// while the worst case Myers can reach at the cap --- two listings with
/// nothing in common --- is about `16_384^2 / 2` inner steps, which is a
/// fraction of a second even in a debug build.
///
/// Above it, [`diff_lines`] and [`score_lines`] return `None`. That is
/// [`crate::metrics`]' rule and `tree_distance`'s
/// [`crate::metrics::tree_distance::MAX_SKELETON_NODES`] pattern: an
/// abstention leaves the denominator uniformly for everyone, while a cheaper
/// fallback value would be a silent wrong answer.
pub const MAX_DIFF_LINES: usize = 16_384;

/// Whether a middle-snake split point actually shrinks the problem.
///
/// [`bisect`] returns the point `(x, y)` at which an optimal edit path crosses,
/// and `compute` turns it into the two subproblems `a[..x] / b[..y]` and
/// `a[x..] / b[y..]`. Exactly two split points fail to make progress: `(0, 0)`
/// makes the *second* subproblem identical to its parent, and `(n, m)` makes
/// the *first* identical to its parent. Either one is an infinite loop in an
/// explicit-stack driver --- one task popped, two pushed, one of them the same
/// task again --- and the stack, not the recursion depth, is what grows.
///
/// Myers' theorem says a correct middle snake never returns either. This
/// function exists because "the algorithm is correct" is not a runtime
/// guarantee: a transcription error in the parity arm of [`bisect`] produced
/// exactly `(0, 0)` and the driver allocated until the kernel intervened. The
/// guard turns that class of bug into a wrong-but-bounded answer.
fn split_makes_progress(x: usize, y: usize, n: usize, m: usize) -> bool {
    !((x == 0 && y == 0) || (x == n && y == m))
}

/// Score two normalized assembly listings (component B-8).
///
/// The three degenerate cases are the reference's, and the first of them is
/// the one worth staring at: **two empty listings score a perfect 1.0.** An
/// original function that disassembles to nothing and a recompile that
/// disassembles to nothing agree completely, by this definition. That is
/// `_compute_jaccard_similarity`'s first branch and it is reproduced here.
///
/// * both empty --- `1.0`, zero changed lines
/// * exactly one empty --- `0.0`, and every line of the other side changed
/// * otherwise --- the diff ratio
///
/// The denominator is `|a| + |b| - shared`, not `max(|a|, |b|)`, so a short
/// answer against a long function is punished by its shortness as well as by
/// its wrongness. That is what stops this metric from having GED's
/// trivial-function problem; the measured null baseline is in the module's
/// test notes.
///
/// Returns `None` --- an abstention, not a zero --- when the pair is larger
/// than [`MAX_DIFF_LINES`] or when [`diff_lines`] exhausts its work budget.
/// The two empty-listing branches are decided before the cap, because they
/// need no diff at all.
///
/// Note that the reference *pipeline* never reaches either empty branch:
/// `_compute_uncached` guards the call with `if original_asm and
/// recompiled_asm` and otherwise falls back to a positional byte comparison
/// (`matching / max_len` over the raw function bytes). That fallback belongs to
/// B-3's output and is not implemented here; these two branches reproduce
/// `_compute_jaccard_similarity` as a *function*, which is what a caller who
/// already holds two listings gets.
pub fn score_lines<S: AsRef<str>, T: AsRef<str>>(a: &[S], b: &[T]) -> Option<ByteMatchScore> {
    if a.is_empty() && b.is_empty() {
        return Some(ByteMatchScore {
            similarity: 1.0,
            changed_lines: 0,
            diff: LineDiff::default(),
        });
    }
    if a.is_empty() || b.is_empty() {
        return Some(ByteMatchScore {
            similarity: 0.0,
            changed_lines: a.len() + b.len(),
            diff: LineDiff {
                a_only: a.len(),
                shared: 0,
                b_only: b.len(),
            },
        });
    }

    let diff = LineDiff::from_chunks(&diff_lines(a, b)?);
    let total = diff.a_only + diff.shared + diff.b_only;
    if total == 0 {
        return Some(ByteMatchScore {
            similarity: 1.0,
            changed_lines: 0,
            diff,
        });
    }
    Some(ByteMatchScore {
        similarity: diff.shared as f64 / total as f64,
        changed_lines: diff.changed(),
        diff,
    })
}

/// Diff two listings line by line and return the hunk list (component B-7).
///
/// # What this reproduces, and what it drops
///
/// The reference runs `diff_match_patch`: `diff_linesToChars` interns each
/// distinct line as one character, `diff_main(..., checklines=False)` diffs the
/// interned strings, `diff_charsToLines` maps back. This is that pipeline with
/// `u32` line ids instead of Unicode scalars (which also removes the
/// reference's 1,114,111-distinct-line ceiling), and with `diff_main`'s control
/// flow transcribed: common-prefix and common-suffix trimming, the
/// empty-side shortcut, the substring shortcut, the length-one shortcut, then
/// the middle-snake bisect.
///
/// Two things from `diff_match_patch` are deliberately absent, and both come
/// from the same place --- `Diff_Timeout`:
///
/// * **The wall-clock deadline.** `diff_bisect` abandons the search when a
///   one-second timer expires and returns "delete everything, insert
///   everything", which scores `0.0`. That makes a recorded `byte_match` value
///   a property of the recording machine's speed, and it is landmine 1 of the
///   component inventory. Not reproduced: this diff always runs to completion.
/// * **`diff_halfMatch`.** The reference gates it on `Diff_Timeout > 0` with
///   the comment "don't risk returning a non-optimal diff if we have unlimited
///   time", so dropping the deadline drops the heuristic by the reference's
///   own rule. Without it the result is an optimal Myers diff, and `shared` is
///   exactly the length of the longest common subsequence.
///
/// That is a behavioural change, so it was measured rather than assumed. Over
/// 4,400 randomly paired real function listings plus 657 same-function
/// pairs across `-O0`/`-O2` and gcc/clang, plus 400 pairs shaped to provoke
/// `diff_halfMatch`, `diff_match_patch` at its default `Diff_Timeout = 1.0`
/// produced *the same* `(a_only, shared, b_only)` triple as the timeout-free
/// path in every case, and both matched the LCS-derived triple in every case.
/// See `tests::shared_equals_lcs_on_real_listings`.
///
/// `diff_cleanupMerge` is also absent: it coalesces adjacent same-op hunks and
/// factors shared prefixes out of adjacent delete/insert pairs. The first is
/// done here directly (see `push_chunk`); the second cannot fire on an optimal
/// diff, and neither changes the per-op totals B-8 reads.
///
/// # Why it is iterative
///
/// `diff_bisect` splits and recurses on both halves, and the input is
/// attacker-controlled binary content. The split point can be arbitrarily
/// unbalanced --- a listing shaped so that every split peels one line off the
/// front recurses once per line --- so a 200,000-line listing would be a stack
/// overflow, not a slow answer. The recursion is therefore an explicit
/// `Vec<Task>` work stack: a `Diff` task expands into the hunks it can decide
/// plus the subproblems it cannot, pushed in reverse so the stack pops them
/// left to right and the output stays in document order.
///
/// # Bounded, because an unbounded diff took a machine down
///
/// Returns `None` rather than working without limit in two cases:
///
/// * the two listings together exceed [`MAX_DIFF_LINES`];
/// * the driver expands more subproblems than [`expansion_budget`] allows,
///   which can only happen if [`bisect`] returns a split that
///   [`split_makes_progress`] should already have rejected.
///
/// The second is defence in depth against the specific failure that motivated
/// both: a broken middle snake returned `(0, 0)`, every expansion pushed the
/// same task back onto the work stack, and the `Vec` doubling asked the kernel
/// for 5 GiB. The guard makes non-termination impossible; the budget makes a
/// guard bug an abstention instead of an outage.
pub fn diff_lines<S: AsRef<str>, T: AsRef<str>>(a: &[S], b: &[T]) -> Option<Vec<DiffChunk>> {
    if a.len().saturating_add(b.len()) > MAX_DIFF_LINES {
        return None;
    }
    let (ia, ib) = intern(a, b);
    diff_interned(&ia, &ib)
}

/// How many subproblem expansions a diff of `n + m` lines may take.
///
/// Every expansion either decides its subproblem outright or splits it into two
/// strictly smaller ones ([`split_makes_progress`]), so the expansion tree is a
/// binary tree whose leaves are disjoint sub-ranges: at most `2 * (n + m) + 1`
/// nodes. Four times that plus a constant is generous by a factor the corpus
/// never approaches, and exceeding it means the progress guard has been
/// defeated.
///
/// It follows that removing this budget on its own changes no observable
/// behaviour, and a mutation that does so survives the suite --- the guard
/// keeps it out of reach. The pair has to be read together: the guard is what
/// makes the loop terminate, and the budget is what makes a *failure of the
/// guard* a returned `None` and a red test rather than an allocation the
/// kernel has to stop. Removing both together hangs, which is exactly the
/// state this module was in when it took a machine down.
fn expansion_budget(n: usize, m: usize) -> usize {
    n.saturating_add(m).saturating_mul(4).saturating_add(64)
}

/// Intern both listings into `u32` line ids.
///
/// Ids start at 1, mirroring `diff_linesToChars`' deliberately blank slot 0.
/// The map is a [`BTreeMap`] and ids are assigned in order of first appearance
/// --- `a` left to right, then `b` --- so the interning is a pure function of
/// the inputs and two runs produce byte-identical ids.
fn intern<S: AsRef<str>, T: AsRef<str>>(a: &[S], b: &[T]) -> (Vec<u32>, Vec<u32>) {
    // The keys borrow from `a` and `b`, which outlive the map.
    let mut ids: BTreeMap<&str, u32> = BTreeMap::new();
    let mut next: u32 = 1;
    let mut ia = Vec::with_capacity(a.len());
    for line in a {
        let s: &str = line.as_ref();
        let id = *ids.entry(s).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        ia.push(id);
    }
    let mut ib = Vec::with_capacity(b.len());
    for line in b {
        let s: &str = line.as_ref();
        let id = *ids.entry(s).or_insert_with(|| {
            let id = next;
            next += 1;
            id
        });
        ib.push(id);
    }
    (ia, ib)
}

/// One item of the explicit work stack that replaces `diff_main`'s recursion.
#[derive(Debug, Clone, Copy)]
enum Task {
    /// A subproblem: half-open index ranges into the two interned listings.
    Diff {
        a: (usize, usize),
        b: (usize, usize),
    },
    /// A decided run of lines. Emitted in document order.
    Emit(DiffOp, usize),
}

/// Append a run, coalescing with the previous run when it has the same op.
///
/// This is the only part of `diff_cleanupMerge` that matters here: without it
/// the substring and prefix/suffix shortcuts would emit `Equal(3), Equal(7)`
/// where `diff_match_patch` emits `Equal(10)`. Totals are unaffected either
/// way; hunk lists are not, and a hunk list is a public value.
fn push_chunk(out: &mut Vec<DiffChunk>, op: DiffOp, len: usize) {
    if len == 0 {
        return;
    }
    if let Some(last) = out.last_mut() {
        if last.op == op {
            last.len += len;
            return;
        }
    }
    out.push(DiffChunk { op, len });
}

/// The middle-snake source the driver uses, as a plain function pointer.
///
/// In production this is always [`bisect`]. It is a parameter so that
/// `tests::driver_terminates_on_a_non_progressing_split` can hand the driver a
/// deliberately degenerate splitter --- the exact `(0, 0)` a broken parity arm
/// produced --- and prove that the driver stays bounded and still returns a
/// diff that reconstructs both inputs. A property that cannot be provoked
/// cannot be tested, and this one took a machine down.
type SplitFn = fn(&[u32], &[u32]) -> Option<(usize, usize)>;

fn diff_interned(a: &[u32], b: &[u32]) -> Option<Vec<DiffChunk>> {
    diff_interned_with(a, b, bisect)
}

/// The iterative driver: pop tasks, expand subproblems, emit decided runs.
fn diff_interned_with(a: &[u32], b: &[u32], split: SplitFn) -> Option<Vec<DiffChunk>> {
    let mut out: Vec<DiffChunk> = Vec::new();
    let mut stack: Vec<Task> = vec![Task::Diff {
        a: (0, a.len()),
        b: (0, b.len()),
    }];
    // Reused between expansions so a deep diff does not allocate per node.
    let mut produced: Vec<Task> = Vec::new();
    let mut budget = expansion_budget(a.len(), b.len());

    while let Some(task) = stack.pop() {
        match task {
            Task::Emit(op, len) => push_chunk(&mut out, op, len),
            Task::Diff { a: ar, b: br } => {
                budget = budget.checked_sub(1)?;
                produced.clear();
                expand(a, b, ar, br, split, &mut produced);
                // Push in reverse so the stack pops them front to back.
                while let Some(t) = produced.pop() {
                    stack.push(t);
                }
            }
        }
    }
    Some(out)
}

/// `diff_main` for one subproblem: trim the common ends, then `compute`.
fn expand(
    a: &[u32],
    b: &[u32],
    ar: (usize, usize),
    br: (usize, usize),
    split: SplitFn,
    out: &mut Vec<Task>,
) {
    let sa = &a[ar.0..ar.1];
    let sb = &b[br.0..br.1];

    if sa == sb {
        out.push(Task::Emit(DiffOp::Equal, sa.len()));
        return;
    }

    let prefix = common_prefix(sa, sb);
    let suffix = common_suffix(&sa[prefix..], &sb[prefix..]);
    let mid_a = (ar.0 + prefix, ar.1 - suffix);
    let mid_b = (br.0 + prefix, br.1 - suffix);

    if prefix > 0 {
        out.push(Task::Emit(DiffOp::Equal, prefix));
    }
    compute(a, b, mid_a, mid_b, split, out);
    if suffix > 0 {
        out.push(Task::Emit(DiffOp::Equal, suffix));
    }
}

/// `diff_compute`: the shortcut ladder, then the bisect.
fn compute(
    a: &[u32],
    b: &[u32],
    ar: (usize, usize),
    br: (usize, usize),
    split: SplitFn,
    out: &mut Vec<Task>,
) {
    let sa = &a[ar.0..ar.1];
    let sb = &b[br.0..br.1];

    if sa.is_empty() {
        out.push(Task::Emit(DiffOp::Insert, sb.len()));
        return;
    }
    if sb.is_empty() {
        out.push(Task::Emit(DiffOp::Delete, sa.len()));
        return;
    }

    // The shorter side inside the longer one: the whole diff is then the
    // longer side's two remainders. Optimal, and it is what keeps a
    // pure-insertion diff from entering the bisect at all.
    let (long, short) = if sa.len() > sb.len() {
        (sa, sb)
    } else {
        (sb, sa)
    };
    if let Some(i) = find_subslice(long, short) {
        // Equal lengths cannot reach here: `long.find(short)` succeeding with
        // equal lengths means the sides are equal, and `expand` returned
        // already. So `sa.len() < sb.len()` decides the direction unambiguously.
        let op = if sa.len() < sb.len() {
            DiffOp::Insert
        } else {
            DiffOp::Delete
        };
        out.push(Task::Emit(op, i));
        out.push(Task::Emit(DiffOp::Equal, short.len()));
        out.push(Task::Emit(op, long.len() - i - short.len()));
        return;
    }
    if short.len() == 1 {
        // A single line that is not in the other side shares nothing with it.
        out.push(Task::Emit(DiffOp::Delete, sa.len()));
        out.push(Task::Emit(DiffOp::Insert, sb.len()));
        return;
    }

    // `diff_halfMatch` would sit here in the reference. See `diff_lines`.

    match split(sa, sb).filter(|&(x, y)| split_makes_progress(x, y, sa.len(), sb.len())) {
        Some((x, y)) => {
            out.push(Task::Diff {
                a: (ar.0, ar.0 + x),
                b: (br.0, br.0 + y),
            });
            out.push(Task::Diff {
                a: (ar.0 + x, ar.1),
                b: (br.0 + y, br.1),
            });
        }
        None => {
            // Unreachable for the inputs `compute` allows (both sides at least
            // two lines, so `max_d >= 2`) and for a correct middle snake, and
            // the same degenerate answer the reference gives when its deadline
            // expires. Reaching it means either the search exhausted `max_d`
            // or the split point made no progress; both are wrong answers, and
            // both are *bounded* wrong answers, which is the point.
            out.push(Task::Emit(DiffOp::Delete, sa.len()));
            out.push(Task::Emit(DiffOp::Insert, sb.len()));
        }
    }
}

fn common_prefix(a: &[u32], b: &[u32]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i < n && a[i] == b[i] {
        i += 1;
    }
    i
}

/// The length of the shared tail, trimmed before `compute` sees the problem.
///
/// A speed optimization from `diff_main`, not a semantic step: both with and
/// without it the diff is optimal, so the `(a_only, shared, b_only)` totals
/// B-8 reads are identical either way. A mutation that skips it survives the
/// suite, and that is a limitation worth stating rather than papering over ---
/// the hunk *list* is not pinned against `diff_match_patch`, only the totals
/// are, because the reference's `diff_cleanupMerge` normalizes its hunks
/// differently from `push_chunk` and Myers' optimal path is not unique.
fn common_suffix(a: &[u32], b: &[u32]) -> usize {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i < n && a[a.len() - 1 - i] == b[b.len() - 1 - i] {
        i += 1;
    }
    i
}

/// The first index at which `needle` occurs in `haystack`, or `None`.
///
/// The reference reaches Python's `str.find` here. This is the naive scan with
/// a first-element guard, which is what the input sizes justify: the largest
/// function in the fixture corpus normalizes to 4,540 lines, and the scan only
/// runs when neither side is empty and the shorter one is not already trimmed
/// away by the common prefix and suffix.
fn find_subslice(haystack: &[u32], needle: &[u32]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    for start in 0..=(haystack.len() - needle.len()) {
        if haystack[start] == first && &haystack[start..start + needle.len()] == needle {
            return Some(start);
        }
    }
    None
}

/// Myers' middle snake: the split point where an optimal edit path crosses.
///
/// A direct transcription of `diff_match_patch`'s `diff_bisect`, minus the
/// deadline check. Forward paths advance in `v1` and reverse paths in `v2`;
/// when a forward path on diagonal `k1` reaches or passes the reverse path on
/// the mirrored diagonal (or the reverse case, chosen by the parity of
/// `delta`), that meeting point is returned as `(x, y)`.
///
/// `k1start`/`k1end`/`k2start`/`k2end` shrink the diagonal band once a path
/// runs off an edge of the grid; they are the reference's, and without them
/// the loop reads `v` entries that were never written.
///
/// Returns `None` only if the search exhausts `max_d` without meeting, which
/// Myers' theorem says cannot happen, or if the inputs are too short to index
/// the `v` arrays (`max_d < 2`) --- both callers' guards already exclude that.
fn bisect(a: &[u32], b: &[u32]) -> Option<(usize, usize)> {
    let n = a.len() as i64;
    let m = b.len() as i64;
    let max_d = (n + m + 1) / 2;
    if max_d < 2 {
        // `v_offset + 1` would be out of the `2 * max_d` array.
        return None;
    }
    let v_offset = max_d;
    let v_len = (2 * max_d) as usize;
    let mut v1 = vec![-1i64; v_len];
    let mut v2 = vec![-1i64; v_len];
    v1[(v_offset + 1) as usize] = 0;
    v2[(v_offset + 1) as usize] = 0;
    let delta = n - m;
    // When the total edit distance is odd the forward path is the one that can
    // overlap a reverse path; when it is even, the reverse path is.
    let front = delta % 2 != 0;
    let (mut k1start, mut k1end, mut k2start, mut k2end) = (0i64, 0i64, 0i64, 0i64);

    for d in 0..max_d {
        // Forward.
        let mut k1 = -d + k1start;
        while k1 <= d - k1end {
            let ko = (v_offset + k1) as usize;
            let mut x1 = if k1 == -d || (k1 != d && v1[ko - 1] < v1[ko + 1]) {
                v1[ko + 1]
            } else {
                v1[ko - 1] + 1
            };
            let mut y1 = x1 - k1;
            while x1 < n && y1 < m && a[x1 as usize] == b[y1 as usize] {
                x1 += 1;
                y1 += 1;
            }
            v1[ko] = x1;
            if x1 > n {
                k1end += 2;
            } else if y1 > m {
                k1start += 2;
            } else if front {
                let k2o = v_offset + delta - k1;
                if k2o >= 0 && k2o < v_len as i64 && v2[k2o as usize] != -1 {
                    let x2 = n - v2[k2o as usize];
                    if x1 >= x2 {
                        return Some((x1 as usize, y1 as usize));
                    }
                }
            }
            k1 += 2;
        }

        // Reverse, walking in from the bottom-right corner.
        let mut k2 = -d + k2start;
        while k2 <= d - k2end {
            let ko = (v_offset + k2) as usize;
            let mut x2 = if k2 == -d || (k2 != d && v2[ko - 1] < v2[ko + 1]) {
                v2[ko + 1]
            } else {
                v2[ko - 1] + 1
            };
            let mut y2 = x2 - k2;
            while x2 < n && y2 < m && a[(n - x2 - 1) as usize] == b[(m - y2 - 1) as usize] {
                x2 += 1;
                y2 += 1;
            }
            v2[ko] = x2;
            if x2 > n {
                k2end += 2;
            } else if y2 > m {
                k2start += 2;
            } else if !front {
                let k1o = v_offset + delta - k2;
                if k1o >= 0 && k1o < v_len as i64 && v1[k1o as usize] != -1 {
                    let x1 = v1[k1o as usize];
                    let y1 = v_offset + x1 - k1o;
                    // Mirror the reverse coordinate into the top-left frame.
                    let x2_mirrored = n - x2;
                    if x1 >= x2_mirrored {
                        return Some((x1 as usize, y1 as usize));
                    }
                }
            }
            k2 += 2;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Provenance of every expectation in this file.
    //
    // All reference outputs below were produced by running the DecBench
    // reference directly:
    //
    //   $DECBENCH/.venv/bin/python -c "
    //     from decbench.metrics.byte_match import _normalize_operands,
    //         _disassemble_bytes, _compute_jaccard_similarity"
    //
    // against `decbench` at the checkout in ~/.cache/glaurung/decbench-full,
    // with capstone 5.0.9 (core 5.0.1280) and diff_match_patch 20241021.
    //
    // Byte strings named `<file>::<func>` were extracted with
    // `decbench.utils.binfmt.function_bytes` from a real binary in this
    // repository; the path is given at each one. Byte strings not so named are
    // real x86-64 encodings assembled for a specific reference behaviour, and
    // the expectation is still the reference's own output for those bytes.
    // ---------------------------------------------------------------------

    /// The set is 50 members, as the inventory's B-6 row states, and every
    /// member is distinct. A duplicate would go unnoticed in a `&[&str]`.
    #[test]
    fn branch_mnemonic_set_is_the_reference_fifty() {
        assert_eq!(BRANCH_MNEMONICS.len(), 50);
        let unique: std::collections::BTreeSet<&str> = BRANCH_MNEMONICS.iter().copied().collect();
        assert_eq!(unique.len(), 50);
        assert_eq!(PC_REL_MNEMONICS.len(), 2);
        // Spot-check the extremes of the reference's literal, so a truncated
        // transcription cannot pass.
        assert_eq!(BRANCH_MNEMONICS[0], "call");
        assert_eq!(BRANCH_MNEMONICS[49], "cbnz");
        assert!(BRANCH_MNEMONICS.contains(&"jcxz"));
        assert!(BRANCH_MNEMONICS.contains(&"jrcxz"));
        assert!(BRANCH_MNEMONICS.contains(&"loopne"));
        // And the ones a "sensible" set would include but this one does not.
        assert!(!BRANCH_MNEMONICS.contains(&"b.w"));
        assert!(!BRANCH_MNEMONICS.contains(&"ret"));
        assert!(!BRANCH_MNEMONICS.contains(&"adrp"));
    }

    /// Every row is `_normalize_operands(mnemonic, op_str)` run against the
    /// reference. The odd-looking ones are the point of the table.
    #[test]
    fn normalize_matches_reference_edge_cases() {
        // (mnemonic, op_str, reference output)
        let cases: &[(&str, &str, &str)] = &[
            // Direct branch targets collapse entirely.
            ("call", "0x1234", "X"),
            ("jne", "0x1234", "X"),
            ("jmp", "0x1230", "X"),
            ("b", "#0x860", "X"),
            ("b", "#-0x10", "X"),
            ("bl", "#0x810", "X"),
            ("beq", "#0x1144", "X"),
            ("bhi", "#0xdca", "X"),
            // Register operands of branch mnemonics lose their digits, because
            // `_HEX_TOKEN` is not word-anchored. `call rax` survives only
            // because "rax" happens to contain no digit.
            ("call", "rax", "rax"),
            ("jmp", "rsi", "rsi"),
            ("jmp", "r8", "rX"),
            ("call", "r12", "rX"),
            ("blx", "r3", "rX"),
            ("bx", "lr", "lr"),
            ("cbz", "x0, #0xa44", "xX, X"),
            ("cbz", "w0, #0x100", "wX, X"),
            ("cbnz", "x0, #0x1448", "xX, X"),
            ("bne", "r0, r1, #0x8", "rX, rX, X"),
            // `adrp`/`adr` are blanked with no bracket test at all. The last
            // two rows are the discriminator: a branch mnemonic with a `[` in
            // its operand keeps its numbers, and a PC-relative mnemonic with a
            // `[` in its operand does NOT. Folding the two arms into one
            // `(PC_REL || BRANCH) && !contains('[')` --- which reads as a
            // simplification --- changes these and nothing else in this table.
            ("adrp", "x0, #0x11000", "xX, X"),
            ("adr", "x1, #0x20", "xX, X"),
            ("adrp", "x0, [x1]", "xX, [xX]"),
            ("adr", "x1, [sp, #8]", "xX, [sp, X]"),
            // A branch whose operand still holds a `[` after the PC-relative
            // rewrite keeps everything else.
            ("call", "qword ptr [rip + 0x4e562]", "qword ptr [rip+X]"),
            ("jmp", "qword ptr [rip + 0x4e900]", "qword ptr [rip+X]"),
            ("jmp", "qword ptr [r8 + 8]", "qword ptr [r8 + 8]"),
            // PC-relative memory: the displacement is optional, negative
            // displacements normalize to `+X`, and the printed spacing is lost.
            ("lea", "rax, [rip + 0x2e75]", "rax, [rip+X]"),
            ("lea", "rax, [rip]", "rax, [rip+X]"),
            (
                "mov",
                "rax, qword ptr [rip - 0x10]",
                "rax, qword ptr [rip+X]",
            ),
            ("ldr", "r2, [pc, #0xdc]", "r2, [pc+X]"),
            ("ldr", "r1, [pc]", "r1, [pc+X]"),
            ("ldr.w", "lr, [pc, #0x8c]", "lr, [pc+X]"),
            // A non-branch keeps its second operand next to the rewritten one.
            (
                "cmp",
                "qword ptr [rip + 0x34856], 0",
                "qword ptr [rip+X], 0",
            ),
            (
                "test",
                "byte ptr [rip + 0x117333], 1",
                "byte ptr [rip+X], 1",
            ),
            (
                "xchg",
                "byte ptr [rip + 0x33d64], al",
                "byte ptr [rip+X], al",
            ),
            // Not a branch mnemonic, so nothing happens.
            ("mov", "eax, 0", "eax, 0"),
            ("str", "x0, [sp, #8]", "x0, [sp, #8]"),
            ("mov", "x29, #0", "x29, #0"),
            // Thumb wide encodings are NOT in the set, so their targets leak.
            ("b.w", "#0x450", "#0x450"),
            ("bl.w", "#0x450", "#0x450"),
        ];
        for (mnemonic, op_str, expected) in cases {
            assert_eq!(
                &normalize_operands(mnemonic, op_str),
                expected,
                "normalize_operands({mnemonic:?}, {op_str:?})"
            );
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex literal has an odd length");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex literal"))
            .collect()
    }

    /// `tests/decompiler_fixtures/build/167_rust_trait_objects-rustc-O2.so`,
    /// symbol `_ZN64_$LT$std..path..StripPrefixError...3fmt...E` at 0x2c890.
    /// Expectation is `_disassemble_bytes(bytes, 0x2c890, (CS_ARCH_X86, CS_MODE_64))`.
    #[test]
    fn disassembles_real_x86_64_function_like_the_reference() {
        let bytes = hex(
            "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000\
             4889c7ff1529b7020059c3",
        );
        let lines = disassemble_lines(&bytes, 0x2c890, AsmTarget::X86_64).expect("x86-64 decode");
        assert_eq!(
            lines,
            vec![
                "push rax",
                "mov rax, rsi",
                "mov qword ptr [rsp], rdi",
                "lea rsi, [rip+X]",
                "lea r8, [rip+X]",
                "mov rcx, rsp",
                "mov edx, 0x10",
                "mov rdi, rax",
                "call qword ptr [rip+X]",
                "pop rcx",
                "ret",
            ]
        );
    }

    /// `samples/binaries/platforms/linux/amd64/cross/arm64/c2_demo-arm64-gcc`,
    /// symbol `call_weak_fn` at 0xa34. Reference call:
    /// `_disassemble_bytes(bytes, 0xa34, (CS_ARCH_ARM64, CS_MODE_ARM))`.
    ///
    /// Carries `adrp` (blanked with no bracket test) and `cbz` (whose register
    /// digit is blanked as collateral) in one listing.
    #[test]
    fn disassembles_real_aarch64_function_like_the_reference() {
        let bytes = hex("800000b000f047f9400000b488ffff17c0035fd6");
        let lines = disassemble_lines(&bytes, 0xa34, AsmTarget::Arm64).expect("aarch64 decode");
        assert_eq!(
            lines,
            vec![
                "adrp xX, X",
                "ldr x0, [x0, #0xfe0]",
                "cbz xX, X",
                "b X",
                "ret",
            ]
        );
    }

    /// `samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc`,
    /// symbol `print_sum` at 0x5c4 (an `STT_FUNC` whose symbol value has bit 0
    /// set, hence Thumb). Reference call:
    /// `_disassemble_bytes(bytes, 0x5c4, (CS_ARCH_ARM, CS_MODE_THUMB))`.
    ///
    /// The `b.w #0x450` line is the reference defect this module reproduces:
    /// a Thumb wide branch keeps its absolute target because `b.w` is not a
    /// member of the 50-element set. If a future change "fixes" that, this
    /// assertion is what says the change left parity.
    #[test]
    fn disassembles_real_arm_thumb_function_like_the_reference() {
        let bytes = hex("0249024601207944fff740bfba000000");
        let lines = disassemble_lines(&bytes, 0x5c4, AsmTarget::ArmThumb).expect("thumb decode");
        assert_eq!(
            lines,
            vec![
                "ldr r1, [pc+X]",
                "mov r2, r0",
                "movs r0, #1",
                "add r1, pc",
                "b.w #0x450",
                "lsls r2, r7, #2",
                "movs r0, r0",
            ]
        );
    }

    /// Multi-byte `nop` padding (`0f 1f 40 00`, `66 0f 1f 44 00 00`) prints
    /// with the mnemonic `nop`, so the reference's mnemonic test drops it at
    /// every width. Raw capstone on these bytes is
    /// `push rbp / mov qword ptr [rip], rax / nop dword ptr [rax] / pop rbp /
    /// nop word ptr [rax + rax] / ret`; the reference returns the four
    /// non-`nop` lines. The bare `[rip]` here is the unlinked-object form the
    /// inventory calls out.
    #[test]
    fn nop_padding_is_dropped_at_every_width() {
        let bytes = hex("55488905000000000f1f40005d660f1f440000c3");
        let lines = disassemble_lines(&bytes, 0x1000, AsmTarget::X86_64).expect("x86-64 decode");
        assert_eq!(
            lines,
            vec!["push rbp", "mov qword ptr [rip+X], rax", "pop rbp", "ret",]
        );
    }

    /// The AL-zeroing peephole, on x86-64 only, with lookahead into the
    /// unfiltered listing.
    ///
    /// Every expectation is `_disassemble_bytes(bytes, 0, arch_mode)` for both
    /// arch modes. `31c0` is `xor eax, eax`, `b800000000` is `mov eax, 0`,
    /// `e800000000` is `call` to the next instruction, `c3` is `ret`.
    #[test]
    fn al_zeroing_peephole_matches_the_reference() {
        // xor eax, eax ; call ; ret  -> the xor goes.
        let one = hex("31c0e800000000c3");
        assert_eq!(
            disassemble_lines(&one, 0, AsmTarget::X86_64).expect("decode"),
            vec!["call X", "ret"]
        );
        // mov eax, 0 ; call ; ret  -> the mov goes too.
        let two = hex("b800000000e800000000c3");
        assert_eq!(
            disassemble_lines(&two, 0, AsmTarget::X86_64).expect("decode"),
            vec!["call X", "ret"]
        );
        // xor ; xor ; call ; ret -> ONLY the second goes. The filter looks
        // ahead in the original list, so the first xor's successor is the
        // second xor, not the call. A fixpoint implementation would drop both
        // and this assertion is what catches that.
        let three = hex("31c031c0e800000000c3");
        assert_eq!(
            disassemble_lines(&three, 0, AsmTarget::X86_64).expect("decode"),
            vec!["xor eax, eax", "call X", "ret"]
        );
        // No following call: nothing is dropped.
        let four = hex("31c0c3");
        assert_eq!(
            disassemble_lines(&four, 0, AsmTarget::X86_64).expect("decode"),
            vec!["xor eax, eax", "ret"]
        );
        // Same bytes in 32-bit mode: the peephole is off, so the xor stays.
        assert_eq!(
            disassemble_lines(&one, 0, AsmTarget::X86_32).expect("decode"),
            vec!["xor eax, eax", "call X", "ret"]
        );
        assert_eq!(
            disassemble_lines(&two, 0, AsmTarget::X86_32).expect("decode"),
            vec!["mov eax, 0", "call X", "ret"]
        );
    }

    #[test]
    fn capstone_ids_round_trip() {
        for t in [
            AsmTarget::X86_32,
            AsmTarget::X86_64,
            AsmTarget::Arm,
            AsmTarget::ArmThumb,
            AsmTarget::Arm64,
        ] {
            let (a, m) = t.capstone_ids();
            assert_eq!(AsmTarget::from_capstone_ids(a, m), Some(t));
        }
        // A pair `binfmt.capstone_arch_mode` never returns.
        assert_eq!(AsmTarget::from_capstone_ids(1, 16), None);
    }

    /// A textbook LCS by dynamic programming, used only to check the diff.
    ///
    /// Independent of the Myers implementation on purpose: if both were the
    /// same algorithm the agreement would prove nothing.
    fn lcs_len(a: &[&str], b: &[&str]) -> usize {
        let mut prev = vec![0usize; b.len() + 1];
        let mut cur = vec![0usize; b.len() + 1];
        for x in a {
            cur[0] = 0;
            for (j, y) in b.iter().enumerate() {
                cur[j + 1] = if x == y {
                    prev[j] + 1
                } else {
                    prev[j + 1].max(cur[j])
                };
            }
            std::mem::swap(&mut prev, &mut cur);
        }
        prev[b.len()]
    }

    /// The two listings from the real fixture functions above, plus stubs,
    /// diffed. `shared` must be the LCS length and the two "only" counts must
    /// be the leftovers --- which is the definition of an optimal diff, and
    /// therefore the property that says the bisect is right.
    #[test]
    fn shared_equals_lcs_on_real_listings() {
        // `167_rust_trait_objects-rustc-O2.so :: StripPrefixError::fmt`.
        let a = disassemble_lines(
            &hex(
                "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000\
                 4889c7ff1529b7020059c3",
            ),
            0x2c890,
            AsmTarget::X86_64,
        )
        .expect("decode");
        // `167_rust_trait_objects-rustc-O2.so :: core::panicking::assert_failed`
        // at 0x6710, from the same binary.
        let b = disassemble_lines(
            &hex(
                "4883ec184989f148897c2408488d05cd1304004889442410488d05b1fe04\
                 0048890424488d1586fe0400488d742408488d4c2410bf010000004989d0\
                 ff15861605000f0b",
            ),
            0x6710,
            AsmTarget::X86_64,
        )
        .expect("decode");
        // `gcc -O2 -c -fno-builtin -w` on `int f(void){return 0;}`, .text of
        // the object: f3 0f 1e fa 31 c0 c3.
        let stub = disassemble_lines(&hex("f30f1efa31c0c3"), 0, AsmTarget::X86_64).expect("decode");

        for (x, y) in [(&a, &b), (&a, &stub), (&b, &stub), (&a, &a)] {
            let xs: Vec<&str> = x.iter().map(String::as_str).collect();
            let ys: Vec<&str> = y.iter().map(String::as_str).collect();
            let d = LineDiff::from_chunks(&diff_lines(x, y).expect("under the cap"));
            let l = lcs_len(&xs, &ys);
            assert_eq!(d.shared, l, "shared must equal LCS for {xs:?} vs {ys:?}");
            assert_eq!(d.a_only, x.len() - l);
            assert_eq!(d.b_only, y.len() - l);
        }
    }

    /// `_compute_jaccard_similarity` on the same real listings, run against
    /// the reference. `a` is 11 lines, `b` is 14, `stub` is 3.
    ///
    /// Reference results (capstone 5.0.9, diff_match_patch 20241021), read off
    /// `_compute_jaccard_similarity` and the `diff_main` hunk list directly:
    ///   a  vs b     -> 1/24 = 0.041666666666666664, (a_only 10, shared 1, b_only 13), changed 23
    ///   a  vs stub  -> 1/13 = 0.07692307692307693,  (a_only 10, shared 1, b_only 2),  changed 12
    ///   b  vs stub  -> 0.0,                          (a_only 14, shared 0, b_only 3),  changed 17
    ///   a  vs a     -> 1.0,                          (a_only 0,  shared 11, b_only 0), changed 0
    ///
    /// The single shared line between `a` and `b` is `call qword ptr [rip+X]`
    /// --- two unrelated functions from the same binary share one normalized
    /// line, which is what the 6.2% null baseline in the session notes is made
    /// of.
    #[test]
    fn score_matches_the_reference_on_real_listings() {
        let a = disassemble_lines(
            &hex(
                "504889f048893c24488d3541ae01004c8d05da9a02004889e1ba10000000\
                 4889c7ff1529b7020059c3",
            ),
            0x2c890,
            AsmTarget::X86_64,
        )
        .expect("decode");
        let b = disassemble_lines(
            &hex(
                "4883ec184989f148897c2408488d05cd1304004889442410488d05b1fe04\
                 0048890424488d1586fe0400488d742408488d4c2410bf010000004989d0\
                 ff15861605000f0b",
            ),
            0x6710,
            AsmTarget::X86_64,
        )
        .expect("decode");
        let stub = disassemble_lines(&hex("f30f1efa31c0c3"), 0, AsmTarget::X86_64).expect("decode");
        assert_eq!(a.len(), 11);
        assert_eq!(b.len(), 14);
        assert_eq!(stub.len(), 3);

        let ab = score_lines(&a, &b).expect("under the cap");
        assert_eq!(
            ab.diff,
            LineDiff {
                a_only: 10,
                shared: 1,
                b_only: 13
            }
        );
        assert_eq!(ab.changed_lines, 23);
        assert!((ab.similarity - 1.0 / 24.0).abs() < 1e-12, "{ab:?}");

        let astub = score_lines(&a, &stub).expect("under the cap");
        assert_eq!(
            astub.diff,
            LineDiff {
                a_only: 10,
                shared: 1,
                b_only: 2
            }
        );
        assert_eq!(astub.changed_lines, 12);
        assert!((astub.similarity - 1.0 / 13.0).abs() < 1e-12, "{astub:?}");

        let bstub = score_lines(&b, &stub).expect("under the cap");
        assert_eq!(
            bstub.diff,
            LineDiff {
                a_only: 14,
                shared: 0,
                b_only: 3
            }
        );
        assert_eq!(bstub.changed_lines, 17);
        assert_eq!(bstub.similarity, 0.0);

        let aa = score_lines(&a, &a).expect("under the cap");
        assert_eq!(aa.similarity, 1.0);
        assert_eq!(aa.changed_lines, 0);
        assert_eq!(
            aa.diff,
            LineDiff {
                a_only: 0,
                shared: 11,
                b_only: 0
            }
        );
    }

    /// The three degenerate branches of `_compute_jaccard_similarity`,
    /// including the one that hands a perfect score to two empty listings.
    #[test]
    fn degenerate_listings_match_the_reference() {
        let empty: Vec<String> = Vec::new();
        // Reference: _compute_jaccard_similarity([], []) == (1.0, 0)
        let both = score_lines(&empty, &empty).expect("no diff needed");
        assert_eq!(both.similarity, 1.0);
        assert_eq!(both.changed_lines, 0);

        // Reference: _compute_jaccard_similarity([], ['endbr64','xor eax, eax','ret'])
        //            == (0.0, 3)
        let three = vec![
            "endbr64".to_string(),
            "xor eax, eax".to_string(),
            "ret".to_string(),
        ];
        let one_side = score_lines(&empty, &three).expect("no diff needed");
        assert_eq!(one_side.similarity, 0.0);
        assert_eq!(one_side.changed_lines, 3);
        let other_side = score_lines(&three, &empty).expect("no diff needed");
        assert_eq!(other_side.similarity, 0.0);
        assert_eq!(other_side.changed_lines, 3);
    }

    /// Duplicate lines are common in assembly (`ret`, `pop rbx`), and an
    /// interning bug that collapsed them would inflate `shared`. This is the
    /// smallest case where a set-Jaccard and a diff-Jaccard disagree: as sets
    /// the two sides are identical (similarity 1.0); as sequences the LCS is
    /// 2, so the score is 2/4.
    #[test]
    fn repeated_lines_are_counted_as_a_sequence_not_a_set() {
        let a = vec!["ret".to_string(), "ret".to_string(), "ret".to_string()];
        let b = vec!["ret".to_string(), "ret".to_string()];
        let s = score_lines(&a, &b).expect("under the cap");
        assert_eq!(
            s.diff,
            LineDiff {
                a_only: 1,
                shared: 2,
                b_only: 0
            }
        );
        assert!((s.similarity - 2.0 / 3.0).abs() < 1e-12);

        let x = vec!["a".to_string(), "b".to_string()];
        let y = vec!["b".to_string(), "a".to_string()];
        let t = score_lines(&x, &y).expect("under the cap");
        assert_eq!(t.diff.shared, 1);
        assert!((t.similarity - 1.0 / 3.0).abs() < 1e-12);
    }

    /// `push_chunk` is the whole of `diff_cleanupMerge` that this module keeps:
    /// adjacent runs of the same op become one hunk, and a zero-length run is
    /// never emitted.
    ///
    /// Tested directly rather than through a diff, because whether a *diff*
    /// happens to produce two adjacent same-op runs depends on where the bisect
    /// splits --- so a diff-level test of this property passes for the wrong
    /// reason. The shortcuts in `compute` emit `(op, i)`, `(Equal, len)`,
    /// `(op, tail)` triples where `i` or `tail` is routinely zero, and
    /// `expand` brackets every subproblem with its trimmed prefix and suffix,
    /// so both branches here are exercised on real listings.
    #[test]
    fn push_chunk_coalesces_and_drops_empty_runs() {
        let mut out: Vec<DiffChunk> = Vec::new();
        push_chunk(&mut out, DiffOp::Equal, 3);
        push_chunk(&mut out, DiffOp::Equal, 7);
        assert_eq!(
            out,
            vec![DiffChunk {
                op: DiffOp::Equal,
                len: 10
            }]
        );
        // A zero-length run is dropped, and does not break the run it sits in.
        push_chunk(&mut out, DiffOp::Delete, 0);
        push_chunk(&mut out, DiffOp::Equal, 2);
        assert_eq!(
            out,
            vec![DiffChunk {
                op: DiffOp::Equal,
                len: 12
            }]
        );
        // A different op starts a new hunk.
        push_chunk(&mut out, DiffOp::Delete, 1);
        push_chunk(&mut out, DiffOp::Insert, 4);
        push_chunk(&mut out, DiffOp::Insert, 1);
        assert_eq!(
            out,
            vec![
                DiffChunk {
                    op: DiffOp::Equal,
                    len: 12
                },
                DiffChunk {
                    op: DiffOp::Delete,
                    len: 1
                },
                DiffChunk {
                    op: DiffOp::Insert,
                    len: 5
                },
            ]
        );
        // Nothing is ever emitted for an empty first run.
        let mut empty: Vec<DiffChunk> = Vec::new();
        push_chunk(&mut empty, DiffOp::Equal, 0);
        assert!(empty.is_empty());
    }

    /// A helper the termination tests reuse: a hunk list must reconstruct both
    /// inputs exactly, in order, with no zero-length hunk.
    fn assert_hunks_reconstruct(chunks: &[DiffChunk], a: &[String], b: &[String]) {
        let (mut ai, mut bi) = (0usize, 0usize);
        for c in chunks {
            assert_ne!(c.len, 0, "a zero-length hunk must never be emitted");
            match c.op {
                DiffOp::Delete => ai += c.len,
                DiffOp::Insert => bi += c.len,
                DiffOp::Equal => {
                    assert_eq!(a[ai..ai + c.len], b[bi..bi + c.len]);
                    ai += c.len;
                    bi += c.len;
                }
            }
        }
        assert_eq!(ai, a.len(), "hunks must consume all of a");
        assert_eq!(bi, b.len(), "hunks must consume all of b");
    }

    /// A middle snake that always reports the crossing at the very start.
    ///
    /// This is not a hypothetical: it is what a broken parity arm in [`bisect`]
    /// actually returned. `(0, 0)` makes the *second* subproblem identical to
    /// its parent, so an explicit-stack driver pops one task and pushes the
    /// same one back forever --- the stack grows, not the recursion depth, and
    /// on a six-line-by-six-line input the `Vec` doubling asked the kernel for
    /// 5 GiB and was OOM-killed.
    fn split_at_start(_a: &[u32], _b: &[u32]) -> Option<(usize, usize)> {
        Some((0, 0))
    }

    /// The mirror image: the crossing at the very end, which makes the *first*
    /// subproblem identical to its parent.
    fn split_at_end(a: &[u32], b: &[u32]) -> Option<(usize, usize)> {
        Some((a.len(), b.len()))
    }

    /// The incident test. Drive the diff with a middle snake that makes no
    /// progress and require it to (a) come back at all, (b) come back with a
    /// hunk list that reconstructs both inputs, and (c) not fall back on the
    /// expansion budget to do it.
    ///
    /// The input is the exact fixture that OOM-killed the machine ---
    /// `["p","q","r","s","t","u"]` against `["q","r","z","t","u","v"]`, six
    /// lines by six --- plus larger and asymmetric shapes, because a guard that
    /// only handles the reported case is not a fix.
    ///
    /// **Reverting `split_makes_progress` must make this fail, not hang.**
    /// That is what the expansion budget in [`diff_interned_with`] buys: with
    /// the guard gone the driver runs out of budget and returns `None`, and
    /// `expect` below turns that into a clean failure instead of an outage.
    /// Verified by mutation: deleting the `.filter(...)` in `compute` fails
    /// this test at the `expect` on both degenerate splitters.
    #[test]
    fn driver_terminates_on_a_non_progressing_split() {
        let cases: [(Vec<String>, Vec<String>); 4] = [
            // The six-by-six fixture from the incident.
            (
                ["p", "q", "r", "s", "t", "u"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                ["q", "r", "z", "t", "u", "v"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
            // Asymmetric, so `delta` is odd and the other parity arm runs.
            (
                ["a", "b", "c"].iter().map(|s| s.to_string()).collect(),
                ["b", "c", "d", "e"].iter().map(|s| s.to_string()).collect(),
            ),
            // Nothing in common, both sides long enough to reach the bisect.
            (
                (0..64).map(|i| format!("mov eax, {i}")).collect(),
                (0..48).map(|i| format!("mov ebx, {i}")).collect(),
            ),
            // Heavily repeated lines, which is what assembly actually looks
            // like and where a split point is most likely to be degenerate.
            (
                (0..80).map(|i| format!("l{}", i % 3)).collect(),
                (0..80).map(|i| format!("l{}", i % 5)).collect(),
            ),
        ];

        for (a, b) in &cases {
            let (ia, ib) = intern(a, b);
            for (name, split) in [
                ("split_at_start", split_at_start as SplitFn),
                ("split_at_end", split_at_end as SplitFn),
            ] {
                let chunks = diff_interned_with(&ia, &ib, split).unwrap_or_else(|| {
                    panic!(
                        "the {name} splitter exhausted the expansion budget on a \
                         {}x{} input: the progress guard is gone",
                        a.len(),
                        b.len()
                    )
                });
                assert_hunks_reconstruct(&chunks, a, b);
                // Bounded output, not merely finite: a driver that made no
                // progress but happened to stop would still fail this.
                assert!(
                    chunks.len() <= a.len() + b.len(),
                    "{name} produced {} hunks for {}+{} lines",
                    chunks.len(),
                    a.len(),
                    b.len()
                );
            }
            // And the real middle snake on the same inputs is not just bounded
            // but optimal, so the guard cannot be firing in production.
            let real = diff_interned_with(&ia, &ib, bisect).expect("real bisect makes progress");
            assert_hunks_reconstruct(&real, a, b);
            let d = LineDiff::from_chunks(&real);
            let av: Vec<&str> = a.iter().map(String::as_str).collect();
            let bv: Vec<&str> = b.iter().map(String::as_str).collect();
            assert_eq!(d.shared, lcs_len(&av, &bv));
        }
    }

    /// The guard itself, in isolation: exactly the two split points that make a
    /// subproblem equal to its parent are rejected, and nothing else is.
    ///
    /// A separate test from the driver one on purpose. If someone weakens the
    /// predicate to `x != 0 || y != 0` --- which looks equivalent and is not,
    /// because it lets `(n, m)` through --- the driver test catches it via
    /// `split_at_end` and this one says why.
    #[test]
    fn progress_guard_rejects_exactly_the_two_degenerate_splits() {
        assert!(!split_makes_progress(0, 0, 6, 6));
        assert!(!split_makes_progress(6, 6, 6, 6));
        assert!(!split_makes_progress(0, 0, 3, 4));
        assert!(!split_makes_progress(3, 4, 3, 4));
        // Everything that does shrink both children is allowed through.
        assert!(split_makes_progress(3, 3, 6, 6));
        assert!(split_makes_progress(0, 1, 6, 6));
        assert!(split_makes_progress(1, 0, 6, 6));
        assert!(split_makes_progress(6, 5, 6, 6));
        assert!(split_makes_progress(5, 6, 6, 6));
        // A zero-length side: `(0, 0)` is still the parent, and the only split.
        assert!(!split_makes_progress(0, 0, 0, 0));
    }

    /// Above [`MAX_DIFF_LINES`] the diff abstains rather than working without
    /// limit, and an abstention is `None` and never a `0.0` in disguise.
    ///
    /// The cap is the safety net behind the progress guard, not the fix; the
    /// guard is what makes the loop terminate. This test pins the net.
    #[test]
    fn oversized_listings_abstain_rather_than_grinding() {
        let big: Vec<String> = (0..MAX_DIFF_LINES)
            .map(|i| format!("mov eax, {i}"))
            .collect();
        let one = vec!["ret".to_string()];
        assert_eq!(big.len() + one.len(), MAX_DIFF_LINES + 1);
        assert!(diff_lines(&big, &one).is_none());
        assert!(score_lines(&big, &one).is_none());
        // Exactly at the cap it still answers.
        let at_cap: Vec<String> = (0..MAX_DIFF_LINES - 1)
            .map(|i| format!("mov eax, {i}"))
            .collect();
        assert_eq!(at_cap.len() + one.len(), MAX_DIFF_LINES);
        assert!(diff_lines(&at_cap, &one).is_some());
        // An empty side is decided before the cap, because it needs no diff.
        let empty: Vec<String> = Vec::new();
        let s = score_lines(&big, &empty).expect("no diff needed");
        assert_eq!(s.similarity, 0.0);
        assert_eq!(s.changed_lines, MAX_DIFF_LINES);
    }

    /// The bisect is the recursive part of the reference; a listing shaped so
    /// that each split peels a single line would blow a call stack. 6,000
    /// lines a side with nothing in common is well past any thread's frame
    /// budget for a per-line recursion, and it must simply return.
    ///
    /// Sized to stay under [`MAX_DIFF_LINES`] and to stay cheap in a debug
    /// build; depth, not size, is what this is testing.
    #[test]
    fn deep_diff_does_not_overflow_the_stack() {
        let a: Vec<String> = (0..6_000).map(|i| format!("mov eax, {i}")).collect();
        let b: Vec<String> = (0..6_000).map(|i| format!("mov ebx, {i}")).collect();
        let s = score_lines(&a, &b).expect("under the cap");
        assert_eq!(s.diff.shared, 0);
        assert_eq!(s.diff.a_only, 6_000);
        assert_eq!(s.diff.b_only, 6_000);
        assert_eq!(s.similarity, 0.0);

        // And an interleaved shape, where the optimal path zig-zags rather
        // than running down one diagonal.
        let c: Vec<String> = (0..2_000).map(|i| format!("l{}", i % 97)).collect();
        let d: Vec<String> = (0..2_000).map(|i| format!("l{}", (i * 7) % 97)).collect();
        let t = score_lines(&c, &d).expect("under the cap");
        let cs: Vec<&str> = c.iter().map(String::as_str).collect();
        let ds: Vec<&str> = d.iter().map(String::as_str).collect();
        assert_eq!(t.diff.shared, lcs_len(&cs, &ds));
    }

    /// REQ-OUT-3: run it twice, get the same bytes. The interning map is the
    /// only place order could leak.
    #[test]
    fn diff_is_deterministic_across_runs() {
        let a = disassemble_lines(
            &hex(
                "4883ec184989f148897c2408488d05cd1304004889442410488d05b1fe04\
                 0048890424488d1586fe0400488d742408488d4c2410bf010000004989d0\
                 ff15861605000f0b",
            ),
            0x6710,
            AsmTarget::X86_64,
        )
        .expect("decode");
        let b = disassemble_lines(&hex("f30f1efa31c0c3"), 0, AsmTarget::X86_64).expect("decode");
        let first = diff_lines(&a, &b).expect("under the cap");
        for _ in 0..8 {
            assert_eq!(diff_lines(&a, &b).expect("under the cap"), first);
        }
    }

    /// Hunks come back in document order and their lengths add up to both
    /// input lengths --- the invariant that would break if the explicit work
    /// stack pushed subproblems in the wrong order.
    #[test]
    fn hunks_reconstruct_both_inputs_in_order() {
        let a: Vec<String> = ["p", "q", "r", "s", "t", "u"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let b: Vec<String> = ["q", "r", "z", "t", "u", "v"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let chunks = diff_lines(&a, &b).expect("under the cap");
        let (mut ai, mut bi) = (0usize, 0usize);
        for c in &chunks {
            match c.op {
                DiffOp::Delete => ai += c.len,
                DiffOp::Insert => bi += c.len,
                DiffOp::Equal => {
                    // An Equal hunk must be equal on both sides.
                    assert_eq!(a[ai..ai + c.len], b[bi..bi + c.len]);
                    ai += c.len;
                    bi += c.len;
                }
            }
            assert_ne!(c.len, 0, "a zero-length hunk must never be emitted");
        }
        assert_eq!(ai, a.len());
        assert_eq!(bi, b.len());
        // No two adjacent hunks share an op: push_chunk coalesces.
        for w in chunks.windows(2) {
            assert_ne!(w[0].op, w[1].op);
        }
    }

    /// A truncated buffer stops the listing rather than failing, matching
    /// capstone's `cs_disasm` and the reference's generator.
    #[test]
    fn undecodable_tail_truncates_rather_than_errors() {
        // `push rbp` (55), then 0xff 0xff which x86-64 cannot decode.
        let lines = disassemble_lines(&hex("55ffff"), 0x1000, AsmTarget::X86_64).expect("decode");
        assert_eq!(lines, vec!["push rbp"]);
        // Nothing decodable at all is an empty listing, not an error --- and
        // `score_lines` then hands it the 0.0 branch, not the 1.0 one.
        let none = disassemble_lines(&hex("ffff"), 0x1000, AsmTarget::X86_64).expect("decode");
        assert!(none.is_empty());
        assert_eq!(
            score_lines(&none, &lines)
                .expect("no diff needed")
                .similarity,
            0.0
        );
    }

    /// The corpus-scale differential for B-7 and B-8: our diff counts and
    /// score against `diff_match_patch`'s, on pairs of the *recorded reference
    /// listings* rather than on our own disassembly, so a capstone printer
    /// difference cannot contaminate the diff comparison.
    ///
    /// Point `GLAURUNG_BYTE_MATCH_ORACLE` at the cell file and
    /// `GLAURUNG_BYTE_MATCH_SCORE_ORACLE` at a JSON array of
    /// `{"i": <cell index>, "j": <cell index>, "a_only": .., "shared": ..,
    /// "b_only": .., "similarity": .., "changed": ..}` recorded from
    /// `diff_main(..., checklines=False)` and `_compute_jaccard_similarity`.
    ///
    /// This is the evidence that dropping `Diff_Timeout` (and with it
    /// `diff_halfMatch`) does not move the metric --- see [`diff_lines`].
    ///
    /// **Demand switch**, same as the listing differential:
    /// `GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED=1` turns a missing oracle into a
    /// failure instead of a silent pass.
    #[test]
    fn score_oracle_differential_against_diff_match_patch() {
        let required = std::env::var("GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED")
            .map(|v| v == "1")
            .unwrap_or(false);
        let (Ok(cells_path), Ok(pairs_path)) = (
            std::env::var("GLAURUNG_BYTE_MATCH_ORACLE"),
            std::env::var("GLAURUNG_BYTE_MATCH_SCORE_ORACLE"),
        ) else {
            assert!(
                !required,
                "GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED=1 but the oracle paths are unset"
            );
            return;
        };
        let cells: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&cells_path).expect("cells readable"))
                .expect("cells are a JSON array");
        let listings: Vec<Vec<String>> = cells
            .iter()
            .map(|c| {
                c["lines"]
                    .as_array()
                    .expect("lines")
                    .iter()
                    .map(|v| v.as_str().expect("line").to_string())
                    .collect()
            })
            .collect();
        let pairs: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(&pairs_path).expect("pairs readable"))
                .expect("pairs are a JSON array");
        assert!(!pairs.is_empty(), "score oracle has no pairs");

        let mut lines_diffed = 0usize;
        let mut deadline_bails = 0usize;
        let mut deadline_lines_recovered = 0usize;
        for p in &pairs {
            let i = p["i"].as_u64().expect("i") as usize;
            let j = p["j"].as_u64().expect("j") as usize;
            let a = &listings[i];
            let b = &listings[j];
            lines_diffed += a.len() + b.len();
            let recorded = LineDiff {
                a_only: p["a_only"].as_u64().expect("a_only") as usize,
                shared: p["shared"].as_u64().expect("shared") as usize,
                b_only: p["b_only"].as_u64().expect("b_only") as usize,
            };
            // The same pair re-run with `Diff_Timeout = 0`, which is the
            // semantics this module implements.
            let untimed = LineDiff {
                a_only: p["t0_a_only"].as_u64().expect("t0_a_only") as usize,
                shared: p["t0_shared"].as_u64().expect("t0_shared") as usize,
                b_only: p["t0_b_only"].as_u64().expect("t0_b_only") as usize,
            };
            let got = score_lines(a, b).expect("corpus listings are under the cap");

            // The load-bearing assertion: we reproduce `diff_match_patch`
            // exactly, once its wall-clock deadline is off.
            assert_eq!(
                got.diff,
                untimed,
                "diff counts for cells {i} vs {j} ({} lines vs {} lines)",
                a.len(),
                b.len()
            );

            if recorded == untimed {
                // Where the deadline did not fire, the recorded score is also
                // ours, to the last bit.
                assert_eq!(
                    got.changed_lines,
                    p["changed"].as_u64().expect("changed") as usize,
                    "changed_lines for cells {i} vs {j}"
                );
                let ref_sim = p["similarity"].as_f64().expect("similarity");
                assert!(
                    (got.similarity - ref_sim).abs() < 1e-12,
                    "similarity for cells {i} vs {j}: {} vs {ref_sim}",
                    got.similarity
                );
            } else {
                // Landmine 1 caught in the act. `diff_bisect` abandoned the
                // search on its one-second timer, so the recorded triple is a
                // property of the recording machine's speed. It can only lose
                // shared lines, never gain them.
                assert!(
                    recorded.shared < untimed.shared,
                    "a deadline bail can only lose shared lines: cells {i} vs {j}, \
                     recorded {recorded:?}, untimed {untimed:?}"
                );
                deadline_bails += 1;
                deadline_lines_recovered += untimed.shared - recorded.shared;
            }
        }
        eprintln!(
            "byte_match score differential: {} pairs, {lines_diffed} lines diffed, \
             every pair equal to diff_match_patch with Diff_Timeout=0; \
             {deadline_bails} of them had the reference's 1s deadline fire, \
             costing it {deadline_lines_recovered} shared lines",
            pairs.len()
        );
    }

    /// The two ways capstone core 5.0.0 (what `capstone-sys` 0.16.0 vendors)
    /// prints an instruction differently from capstone core 5.0.7 (what
    /// DecBench's virtualenv has).
    ///
    /// Both are *printer aliases*: the decode agrees, the text does not. They
    /// are enumerated rather than tolerated by a fuzzy comparison, because an
    /// operand-normalization bug also shows up as "one line is different" and
    /// must not hide behind a version excuse.
    ///
    /// 1. **The CET `NOTRACK` prefix.** `3e ff e0` decodes as an indirect jump
    ///    with a `0x3e` prefix. 5.0.0 prints `jmp rax`; 5.0.7 folds the prefix
    ///    into the mnemonic as `notrack jmp rax`. This matters beyond the text:
    ///    `notrack jmp` is not a member of [`BRANCH_MNEMONICS`], so on the
    ///    newer capstone the operand of a NOTRACK indirect jump is not
    ///    normalized either. It is 16 of the 23 differing cells in the fixture
    ///    corpus, all of them gcc `-fcf-protection` switch dispatches.
    /// 2. **The AArch64 `orr Xd, xzr, #imm` bitmask-immediate alias.**
    ///    `b2 7d e7 e2` prints as `orr x2, xzr, #0x1ffffffffffffff8` on 5.0.0
    ///    and as `mov x2, #0x1ffffffffffffff8` on 5.0.7.
    fn known_capstone_printer_delta(ours: &str, reference: &str) -> bool {
        if let Some(rest) = reference.strip_prefix("notrack ") {
            if rest == ours {
                return true;
            }
        }
        if let (Some(orr), Some(mov)) = (ours.strip_prefix("orr "), reference.strip_prefix("mov "))
        {
            let mut parts = orr.splitn(3, ", ");
            if let (Some(rd), Some(zr), Some(imm)) = (parts.next(), parts.next(), parts.next()) {
                if (zr == "xzr" || zr == "wzr") && mov == format!("{rd}, {imm}") {
                    return true;
                }
            }
        }
        false
    }

    /// The classifier must accept exactly the two recorded aliases and nothing
    /// else --- in particular it must not accept a normalization difference,
    /// which is the failure it would otherwise mask.
    #[test]
    fn capstone_printer_delta_classifier_is_narrow() {
        assert!(known_capstone_printer_delta("jmp rax", "notrack jmp rax"));
        assert!(known_capstone_printer_delta(
            "orr x2, xzr, #0x1ffffffffffffff8",
            "mov x2, #0x1ffffffffffffff8"
        ));
        // Direction matters: we never print `notrack`, the reference does.
        assert!(!known_capstone_printer_delta("notrack jmp rax", "jmp rax"));
        // A different register, or a different immediate, is a real mismatch.
        assert!(!known_capstone_printer_delta(
            "orr x2, xzr, #0x1ffffffffffffff8",
            "mov x3, #0x1ffffffffffffff8"
        ));
        assert!(!known_capstone_printer_delta(
            "orr x2, x3, #1",
            "mov x2, #1"
        ));
        // The mistakes this module could actually make.
        assert!(!known_capstone_printer_delta("call 0x1234", "call X"));
        assert!(!known_capstone_printer_delta(
            "lea rax, [rip + 0x10]",
            "lea rax, [rip+X]"
        ));
        assert!(!known_capstone_printer_delta("jmp r8", "jmp rX"));
        assert!(!known_capstone_printer_delta("ret", "ret "));
    }

    /// The corpus-scale differential against recorded reference output.
    ///
    /// Point `GLAURUNG_BYTE_MATCH_ORACLE` at a JSON array of cells, each
    /// `{"bytes": <hex>, "addr": <int>, "cs_arch": <int>, "cs_mode": <int>,
    /// "lines": [<reference _disassemble_bytes output>]}`, and this asserts
    /// line-for-line equality on every one. The generator lives outside the
    /// repository because it needs the DecBench checkout's virtualenv; the
    /// procedure is recorded in the session report.
    ///
    /// **Demand switch.** With no env var this test is a no-op, and a
    /// silently-skipped test is indistinguishable from a passing one. Set
    /// `GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED=1` to make its absence a failure,
    /// which is what a parity gate should do.
    ///
    /// **The capstone versions are not the same, and cannot be made the
    /// same from inside this module.** `capstone-sys` 0.16.0 vendors capstone
    /// core 5.0.0 (`CS_API_MAJOR 5`, `CS_VERSION_EXTRA 0` in its bundled
    /// `capstone.h`); DecBench's virtualenv has the `capstone` 5.0.7 wheel,
    /// whose core reports `(5, 0, 1280)`. Two of the newer printer's aliases
    /// therefore appear in the recorded oracle and not in our listing, and
    /// they are enumerated in [`known_capstone_printer_delta`] rather than
    /// waved away: any *other* difference fails this test.
    #[test]
    fn oracle_differential_against_recorded_reference_listings() {
        let path = std::env::var("GLAURUNG_BYTE_MATCH_ORACLE").ok();
        let required = std::env::var("GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED")
            .map(|v| v == "1")
            .unwrap_or(false);
        let Some(path) = path else {
            assert!(
                !required,
                "GLAURUNG_BYTE_MATCH_ORACLE_REQUIRED=1 but GLAURUNG_BYTE_MATCH_ORACLE is unset"
            );
            return;
        };
        let text = std::fs::read_to_string(&path).expect("oracle file is readable");
        let cells: Vec<serde_json::Value> =
            serde_json::from_str(&text).expect("oracle file is a JSON array");
        assert!(!cells.is_empty(), "oracle file has no cells");

        let mut checked = 0usize;
        let mut version_delta = 0usize;
        let mut unexplained = 0usize;
        let mut reported = 0usize;
        for cell in &cells {
            let arch = cell["cs_arch"].as_u64().expect("cs_arch") as u32;
            let mode = cell["cs_mode"].as_u64().expect("cs_mode") as u32;
            let Some(target) = AsmTarget::from_capstone_ids(arch, mode) else {
                continue;
            };
            let bytes = hex(cell["bytes"].as_str().expect("bytes"));
            let addr = cell["addr"].as_u64().expect("addr");
            let expected: Vec<String> = cell["lines"]
                .as_array()
                .expect("lines")
                .iter()
                .map(|v| v.as_str().expect("line").to_string())
                .collect();
            let got = disassemble_lines(&bytes, addr, target).expect("decode");
            checked += 1;
            if got == expected {
                continue;
            }
            let all_explained = got.len() == expected.len()
                && got
                    .iter()
                    .zip(expected.iter())
                    .all(|(g, e)| g == e || known_capstone_printer_delta(g, e));
            if all_explained {
                version_delta += 1;
                continue;
            }
            unexplained += 1;
            if reported < 20 {
                reported += 1;
                let first = got
                    .iter()
                    .zip(expected.iter())
                    .position(|(g, e)| g != e)
                    .unwrap_or(got.len().min(expected.len()));
                eprintln!(
                    "UNEXPLAINED {} :: {} at line {first}: ours {:?} vs reference {:?}",
                    cell["file"].as_str().unwrap_or("?"),
                    cell["func"].as_str().unwrap_or("?"),
                    got.get(first),
                    expected.get(first),
                );
            }
        }
        assert!(checked > 0, "oracle file matched no supported target");
        eprintln!(
            "byte_match oracle differential: {checked} cells checked, \
             {version_delta} differing only by a known capstone printer alias, \
             {unexplained} unexplained"
        );
        assert_eq!(
            unexplained, 0,
            "{unexplained} of {checked} cells diverged for a reason that is not a \
             known capstone version difference"
        );
    }
}
