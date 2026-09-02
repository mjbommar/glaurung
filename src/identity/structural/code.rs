//! The instruction-level half of a structural signature.
//!
//! The CFG shape in [`super::graph`] says nothing about what the blocks *do*,
//! and BinDiff's own matcher does not rely on shape alone: its `prime signature
//! matching` and `string references` passes both read the instruction stream.
//! This module re-decodes each basic block of a discovered function and
//! collects everything a signature carries about that stream: the Small Primes
//! Product, the instruction count, the call degree split into direct and
//! indirect, the rare-constant multiset, and the string-reference count.
//!
//! # Why re-decode
//!
//! `analysis::cfg` returns `Function` values whose `BasicBlock`s carry an
//! address range and an instruction *count*, not the instructions. Holding
//! every decoded instruction for every function of a 100 MB binary is the cost
//! discovery is deliberately not paying, so a consumer that wants the stream
//! decodes it again. Decoding is bounded by the block ranges discovery already
//! established, so this walk cannot run away the way a fresh linear sweep can.
//!
//! # What is masked
//!
//! Two things are dropped on purpose, both because they move on a relink and
//! would otherwise make an unchanged function read as changed:
//!
//! * **Branch and call targets.** Every operand of a control-transfer
//!   instruction is skipped for constant collection. A direct `call` to a
//!   function one byte further along is the same call.
//! * **Anything that resolves to an address in this image.** An immediate or
//!   displacement that maps to a file offset is a pointer, not a value, so it
//!   is excluded from the rare-constant multiset even when it is large.
//!
//! What is kept is what the survey's mask/keep list keeps: an order-insensitive
//! operation multiset, small constants folded into the SPP through the
//! mnemonic, large non-address constants as a sorted multiset, and the count of
//! distinct string addresses the function refers to.

use std::collections::BTreeSet;

use crate::analysis::entry::{detect_entry, va_to_code_file_offset, va_to_file_offset};
use crate::core::binary::Arch;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::core::function::{Function, FunctionFlags};
use crate::core::instruction::{Instruction, OperandKind};
use crate::disasm::registry;

use super::spp;

/// Smallest absolute immediate that counts as a "rare" constant.
///
/// FunctionSimSearch keeps "large immediates"; Diaphora keeps the whole
/// `constants` set and relies on rarity gating downstream. 0x1000 is the
/// threshold used here: below it sit loop bounds, structure offsets, `errno`
/// values and every small arithmetic constant, all of which repeat across
/// thousands of functions and carry no identity. Above it, a constant is
/// usually a magic number, a hash seed, a mask or a size -- the values CodeCMR
/// found unusually productive.
pub const RARE_CONSTANT_MIN: u64 = 0x1000;

/// Cap on how many rare constants one signature stores.
///
/// A jump-table-heavy or crypto function can name hundreds; storing all of them
/// makes the row unbounded for no ranking benefit, because the Jaccard term
/// saturates long before that. The *smallest* values are kept (the multiset is
/// sorted first), so the cut is deterministic rather than decode-order
/// dependent.
pub const RARE_CONSTANT_CAP: usize = 64;

/// Minimum printable run that makes a referenced address a "string reference".
pub const MIN_STRING_LEN: usize = 4;

/// How far past a candidate address to look for the terminating NUL.
const MAX_STRING_SCAN: usize = 512;

/// The instruction-stream facts a [`super::StructuralSignature`] carries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeFacts {
    /// Instructions decoded across every basic block of the function.
    pub instructions: u32,
    /// Small Primes Product over the normalized mnemonics. See [`super::spp`].
    pub mnemonic_spp: u64,
    /// Calls whose target is an immediate in the instruction.
    pub calls_out_direct: u32,
    /// Calls through a register or a memory operand.
    pub calls_out_indirect: u32,
    /// Large non-address constants, ascending, with multiplicity, capped at
    /// [`RARE_CONSTANT_CAP`].
    pub rare_constants: Vec<u64>,
    /// Distinct referenced addresses that hold a NUL-terminated printable run.
    pub string_refs: u32,
}

impl CodeFacts {
    /// The facts of a function with no decodable body: an empty product, no
    /// instructions, no references. Distinguishable from a decode failure only
    /// by the caller, which is why [`code_facts`] returns `None` for the
    /// latter.
    pub fn empty() -> Self {
        Self {
            instructions: 0,
            mnemonic_spp: 1,
            calls_out_direct: 0,
            calls_out_indirect: 0,
            rare_constants: Vec::new(),
            string_refs: 0,
        }
    }
}

/// A decoded image: the file bytes plus the architecture they are in.
///
/// Built once per binary with [`ImageCode::new`] and reused across every
/// function, because selecting a disassembler backend and re-parsing the
/// container headers per function is the whole cost of this pass.
pub struct ImageCode<'a> {
    data: &'a [u8],
    arch: Arch,
    /// The one decoder, reused across every function.
    ///
    /// A `RefCell` because [`ImageCode::facts`] takes `&self` -- a caller
    /// iterating functions should not need a mutable handle -- and the only
    /// thing it mutates is the backend's Thumb-mode bit, which is per
    /// function. There is no aliasing hazard: the borrow lives entirely inside
    /// one `facts` call and nothing re-enters.
    backend: std::cell::RefCell<registry::Backend>,
}

impl<'a> ImageCode<'a> {
    /// Detect the architecture of `data` and hold it for per-function decoding.
    ///
    /// `None` when the container is unrecognised or names an architecture no
    /// backend in `crate::disasm::registry` can decode. Returning `None` rather
    /// than an empty result keeps "we could not read this" distinct from "this
    /// function has no instructions".
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let info = detect_entry(data)?;
        let arch = info.arch;
        if arch == Arch::Unknown {
            return None;
        }
        // Build the decoder now, once, so a caller learns immediately that this
        // architecture has no backend rather than getting zero instructions for
        // every function -- and so that a 6,000-function binary pays for
        // backend construction once instead of 6,000 times.
        let backend = registry::for_arch(Architecture::from(arch), info.endianness)?;
        Some(Self {
            data,
            arch,
            backend: std::cell::RefCell::new(backend),
        })
    }

    /// The architecture the image was detected as.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Decode one function's blocks and collect its [`CodeFacts`].
    ///
    /// Always `Some`: the decoder was built in [`ImageCode::new`], so there is
    /// no per-function failure mode left. A function whose blocks all fail to
    /// resolve to file offsets comes back as [`CodeFacts::empty`], which is the
    /// honest answer -- the shape is known, the stream is not. The `Option`
    /// stays in the signature because it is what callers already branch on and
    /// because a future backend that can fail per function would need it back.
    pub fn facts(&self, func: &Function) -> Option<CodeFacts> {
        let mut backend = self.backend.borrow_mut();
        // ARM function symbols carry the Thumb state in bit 0 of their address;
        // discovery has already resolved it into a flag, and decoding A32 over
        // a T32 body produces garbage mnemonics rather than an error.
        let _ = backend.set_thumb_mode(func.flags & FunctionFlags::IS_THUMB);

        let mut mnemonics: Vec<String> = Vec::new();
        let mut facts = CodeFacts::empty();
        let mut constants: Vec<u64> = Vec::new();
        let mut string_targets: BTreeSet<u64> = BTreeSet::new();

        // Blocks in ascending address order so the walk is reproducible even
        // though none of the outputs depend on order.
        let mut blocks: Vec<(u64, u64)> = func
            .basic_blocks
            .iter()
            .map(|b| (b.start_address.value, b.end_address.value))
            .collect();
        blocks.sort_unstable();
        blocks.dedup();

        for (start, end) in blocks {
            if end <= start {
                continue;
            }
            let Some(base_off) = va_to_code_file_offset(self.data, start) else {
                continue;
            };
            let span = (end - start) as usize;
            let mut cursor = 0usize;
            while cursor < span {
                let off = base_off + cursor;
                if off >= self.data.len() {
                    break;
                }
                let addr = match crate::core::address::Address::new(
                    crate::core::address::AddressKind::VA,
                    start + cursor as u64,
                    if self.arch.is_64_bit() { 64 } else { 32 },
                    None,
                    None,
                ) {
                    Ok(a) => a,
                    Err(_) => break,
                };
                let window_end = (off + 16).min(self.data.len());
                let Ok(insn) = backend.disassemble_instruction(&addr, &self.data[off..window_end])
                else {
                    break;
                };
                let len = insn.length as usize;
                if len == 0 {
                    break;
                }
                facts.instructions = facts.instructions.saturating_add(1);
                self.absorb(
                    &insn,
                    &mut mnemonics,
                    &mut facts,
                    &mut constants,
                    &mut string_targets,
                );
                cursor += len;
            }
        }

        constants.sort_unstable();
        constants.truncate(RARE_CONSTANT_CAP);
        facts.rare_constants = constants;
        facts.string_refs = string_targets.len() as u32;
        facts.mnemonic_spp = spp::mnemonic_spp(mnemonics.iter().map(|s| s.as_str()));
        Some(facts)
    }

    /// Fold one decoded instruction into the running facts.
    fn absorb(
        &self,
        insn: &Instruction,
        mnemonics: &mut Vec<String>,
        facts: &mut CodeFacts,
        constants: &mut Vec<u64>,
        string_targets: &mut BTreeSet<u64>,
    ) {
        let normalized = spp::normalize_mnemonic(&insn.mnemonic);
        let control = is_control_transfer(&normalized);

        if is_call(&normalized) {
            let direct = insn
                .operands
                .iter()
                .any(|o| o.kind == OperandKind::Immediate);
            if direct {
                facts.calls_out_direct = facts.calls_out_direct.saturating_add(1);
            } else {
                facts.calls_out_indirect = facts.calls_out_indirect.saturating_add(1);
            }
        }

        for op in &insn.operands {
            match op.kind {
                OperandKind::Immediate => {
                    let Some(v) = op.immediate else { continue };
                    // A branch or call target is an address, not a value.
                    if control {
                        continue;
                    }
                    let bits = v as u64;
                    if v.unsigned_abs() < RARE_CONSTANT_MIN {
                        continue;
                    }
                    if let Some(off) = va_to_file_offset(self.data, bits) {
                        // Address-like: masked from the constant multiset, but
                        // it is exactly the operand that names a string.
                        if self.looks_like_string(off) {
                            string_targets.insert(bits);
                        }
                        continue;
                    }
                    constants.push(bits);
                }
                OperandKind::Memory => {
                    // x86-64 RIP-relative addressing: iced resolves the
                    // displacement to the absolute target, which is how a
                    // string literal is referenced in position-independent
                    // code. Other bases are frame or heap addressing and carry
                    // no image address.
                    let is_pc_relative = op
                        .base
                        .as_deref()
                        .is_some_and(|b| b == "rip" || b == "eip" || b == "pc");
                    if !is_pc_relative {
                        continue;
                    }
                    let Some(disp) = op.displacement else {
                        continue;
                    };
                    let target = disp as u64;
                    if let Some(off) = va_to_file_offset(self.data, target) {
                        if self.looks_like_string(off) {
                            string_targets.insert(target);
                        }
                    }
                }
                _ => {}
            }
        }

        mnemonics.push(normalized);
    }

    /// Does a NUL-terminated printable run of at least [`MIN_STRING_LEN`] bytes
    /// start at file offset `off`?
    ///
    /// Deliberately narrow. It is not a string extractor -- `crate::strings` is
    /// -- it is a yes/no test on one address, and it is asked once per
    /// referenced address, so it must be cheap and must not follow pointers.
    fn looks_like_string(&self, off: usize) -> bool {
        let end = (off + MAX_STRING_SCAN).min(self.data.len());
        if off >= end {
            return false;
        }
        let mut n = 0usize;
        for b in &self.data[off..end] {
            match b {
                0 => return n >= MIN_STRING_LEN,
                0x20..=0x7e | b'\t' | b'\n' | b'\r' => n += 1,
                _ => return false,
            }
        }
        false
    }
}

/// Is this normalized mnemonic a call?
///
/// The list is the call opcode of each architecture the registry decodes:
/// x86 `call`, ARM `bl`/`blx`, AArch64 `bl`/`blr`, RISC-V `jal`/`jalr`,
/// PowerPC `bl`/`bctrl`, MIPS `jal`/`jalr`. `jal`/`jalr` with a zero link
/// register are really jumps, but the operand encoding is not available here
/// and counting them as calls is the same choice `analysis::call_semantics`
/// makes.
fn is_call(m: &str) -> bool {
    matches!(
        m,
        "call" | "bl" | "blx" | "blr" | "jal" | "jalr" | "bctrl" | "bctr" | "callq"
    )
}

/// Is this normalized mnemonic a control transfer whose operands are addresses?
fn is_control_transfer(m: &str) -> bool {
    if is_call(m) {
        return true;
    }
    if m.starts_with('j') || m.starts_with('b') {
        // `bt`, `bts`, `bsf`, `bswap`, `bic` and friends are not branches.
        return !matches!(
            m,
            "bt" | "bts" | "btr" | "btc" | "bsf" | "bsr" | "bswap" | "bic" | "bfi" | "bfxil"
        );
    }
    matches!(
        m,
        "ret" | "retn" | "iret" | "loop" | "cbz" | "cbnz" | "tbz" | "tbnz" | "svc" | "syscall"
    )
}

/// Compute code facts directly from a function's own byte range, without a
/// surrounding container image to mask constants against.
///
/// [`ImageCode::facts`] needs the whole image because it excludes any
/// immediate that resolves to an address inside it and detects string
/// references by reading bytes at that address. A caller holding only a
/// function's own bytes -- `tests/identity_retrieval`'s `FunctionSample`,
/// which carries a discovered CFG and a byte slice but not the surrounding
/// container -- cannot do either, so this keeps every non-branch immediate at
/// or above [`RARE_CONSTANT_MIN`] and always reports zero string references.
/// Call and branch targets are still excluded, via the same mnemonic table
/// [`ImageCode::facts`] uses, so cross-build address churn does not pollute
/// the constant multiset; the only cost is [`CodeFacts::string_refs`], which
/// [`super::ranking_similarity`] does not read.
///
/// `blocks` is a list of `(start_va, end_va)` pairs; `base_va` is the address
/// `bytes[0]` corresponds to. A decode failure or an out-of-range block ends
/// that block's walk early -- the same recovery `ImageCode::facts` uses -- so
/// the return is always a real (if partial) answer, never a failure.
///
/// `backend` is a caller-supplied, already-built decoder rather than an
/// `(Architecture, Endianness)` pair this function would build one from:
/// [`registry::for_arch`] constructs a fresh `Backend` (a real cost on the
/// Capstone-backed architectures), and a caller scoring a corpus of many
/// functions in the same architecture -- the identity-retrieval harness's use
/// case -- should build it once and reuse it, the same discipline
/// [`ImageCode`] uses within one image.
pub fn code_facts_from_function_bytes(
    bytes: &[u8],
    base_va: u64,
    blocks: &[(u64, u64)],
    backend: &mut registry::Backend,
) -> CodeFacts {
    let mut mnemonics: Vec<String> = Vec::new();
    let mut facts = CodeFacts::empty();
    let mut constants: Vec<u64> = Vec::new();

    let mut ranges: Vec<(u64, u64)> = blocks.to_vec();
    ranges.sort_unstable();
    ranges.dedup();

    let addr_bits = backend.architecture().address_bits();

    for (start, end) in ranges {
        if end <= start || start < base_va {
            continue;
        }
        let mut pc = start;
        while pc < end {
            let off = (pc - base_va) as usize;
            if off >= bytes.len() {
                break;
            }
            let window_end = (off + 16).min(bytes.len());
            let Ok(addr) = crate::core::address::Address::new(
                crate::core::address::AddressKind::VA,
                pc,
                addr_bits,
                None,
                None,
            ) else {
                break;
            };
            let Ok(insn) = backend.disassemble_instruction(&addr, &bytes[off..window_end]) else {
                break;
            };
            let len = insn.length as usize;
            if len == 0 {
                break;
            }
            facts.instructions = facts.instructions.saturating_add(1);

            let normalized = spp::normalize_mnemonic(&insn.mnemonic);
            let control = is_control_transfer(&normalized);
            if is_call(&normalized) {
                let direct = insn
                    .operands
                    .iter()
                    .any(|o| o.kind == OperandKind::Immediate);
                if direct {
                    facts.calls_out_direct = facts.calls_out_direct.saturating_add(1);
                } else {
                    facts.calls_out_indirect = facts.calls_out_indirect.saturating_add(1);
                }
            }
            if !control {
                for op in &insn.operands {
                    if op.kind == OperandKind::Immediate {
                        if let Some(v) = op.immediate {
                            if v.unsigned_abs() >= RARE_CONSTANT_MIN {
                                constants.push(v as u64);
                            }
                        }
                    }
                }
            }
            mnemonics.push(normalized);
            pc += len as u64;
        }
    }

    constants.sort_unstable();
    constants.truncate(RARE_CONSTANT_CAP);
    facts.rare_constants = constants;
    facts.mnemonic_spp = spp::mnemonic_spp(mnemonics.iter().map(|s| s.as_str()));
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_mnemonics_are_recognised_per_architecture() {
        for m in ["call", "bl", "blx", "blr", "jal", "jalr", "bctrl"] {
            assert!(is_call(m), "{m} should be a call");
        }
        for m in ["mov", "add", "ret", "jmp", "b"] {
            assert!(!is_call(m), "{m} should not be a call");
        }
    }

    #[test]
    fn bit_test_opcodes_are_not_branches() {
        for m in ["bt", "bts", "btr", "btc", "bsf", "bsr", "bswap", "bic"] {
            assert!(!is_control_transfer(m), "{m} is not a branch");
        }
        for m in ["jmp", "je", "jne", "b", "beq", "bne", "call", "ret"] {
            assert!(is_control_transfer(m), "{m} is a control transfer");
        }
    }

    #[test]
    fn empty_facts_have_the_empty_product() {
        let f = CodeFacts::empty();
        assert_eq!(f.mnemonic_spp, 1);
        assert_eq!(f.instructions, 0);
        assert!(f.rare_constants.is_empty());
    }

    /// `code_facts_from_function_bytes` decodes `mov eax, 0x12345678; ret`
    /// (`b8 78 56 34 12 c3`) with no image and no `Function` -- the exact
    /// surface the identity-retrieval harness's `FunctionSample` offers.
    #[test]
    fn facts_from_function_bytes_decode_without_an_image() {
        let mut backend = registry::for_arch(
            Architecture::X86_64,
            crate::core::binary::Endianness::Little,
        )
        .expect("x86-64 always has a backend");
        let bytes = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let facts =
            code_facts_from_function_bytes(&bytes, 0x1000, &[(0x1000, 0x1006)], &mut backend);
        assert_eq!(facts.instructions, 2);
        assert_eq!(facts.calls_out_direct, 0);
        assert_eq!(facts.calls_out_indirect, 0);
        assert_eq!(facts.rare_constants, vec![0x1234_5678]);
        assert_ne!(
            facts.mnemonic_spp, 1,
            "two real mnemonics, not the empty product"
        );
    }

    /// The whole point of taking `&mut Backend` rather than building one
    /// internally: the same backend, reused across two different functions'
    /// worth of bytes, must not leak state between the calls (a stale Thumb
    /// bit, a half-finished decode) and must decode the second call exactly
    /// as if it had a fresh backend.
    #[test]
    fn a_shared_backend_decodes_two_functions_independently() {
        let mut backend = registry::for_arch(
            Architecture::X86_64,
            crate::core::binary::Endianness::Little,
        )
        .expect("x86-64 always has a backend");

        let mov_ret = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let first =
            code_facts_from_function_bytes(&mov_ret, 0x1000, &[(0x1000, 0x1006)], &mut backend);

        let nop_ret = [0x90, 0xc3];
        let second =
            code_facts_from_function_bytes(&nop_ret, 0x2000, &[(0x2000, 0x2002)], &mut backend);

        assert_eq!(first.instructions, 2);
        assert_eq!(second.instructions, 2);
        assert!(second.rare_constants.is_empty());
        assert_ne!(
            first.mnemonic_spp, second.mnemonic_spp,
            "different instruction streams must not share a product"
        );

        // Re-running the first bytes through the same, now-reused backend
        // must reproduce the first call exactly.
        let first_again =
            code_facts_from_function_bytes(&mov_ret, 0x1000, &[(0x1000, 0x1006)], &mut backend);
        assert_eq!(first, first_again);
    }
}
