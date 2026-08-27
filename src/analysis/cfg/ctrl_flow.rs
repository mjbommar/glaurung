//! What a mnemonic does to control flow.
//!
//! One question, answered per architecture: given a decoded instruction, does
//! it branch, call or return, does it keep its lexical fallthrough, and where
//! does it go. The linear sweep in [`super::discover_function`] asks nothing
//! else of an instruction's opcode, and every answer it gets comes from here.
//!
//! - [`classify_ctrl_flow`] is the primary: `(is_branch, is_call, is_ret)` for
//!   x86/x86-64, ARM32/Thumb-2, AArch64, MIPS, RISC-V and PowerPC.
//! - [`is_unconditional_branch_mnemonic`] says whether the fallthrough edge
//!   survives the branch; getting it wrong spills the sweep into the literal
//!   pool or the next function.
//! - [`immediate_target`] and [`memory_operand_va`] read the destination off
//!   the operands -- the direct and the slot-indirect form respectively.
//! - The ARM-specific predicates ([`arm_pop_writes_pc`],
//!   [`arm_defined_register`], and the private `is_arm_cond_branch` /
//!   `is_arm_cond_bx`) resolve the cases the mnemonic alone cannot: a `pop`
//!   that writes `pc` is a return, and Capstone marks every ARM operand as a
//!   read, so definitions must be modelled here.
//! - [`guard_bound_reaches_fallthrough`] and [`is_code_padding_terminator`]
//!   are the two smaller opcode questions the sweep and the jump-table sizer
//!   ask: does this conditional branch's fallthrough carry the compare's range
//!   bound, and is this opcode inter-function padding.
//!
//! What stays in the parent, because the call graph says so: the image and
//! pointer lookups `indexed_file_offset`, `indexed_code_offset`,
//! `read_pointer_at_va` and `indirect_memory_target` sit physically between
//! this module's two source ranges. `indirect_memory_target` *calls*
//! [`memory_operand_va`], which makes the contiguous range look right, but they
//! answer "what is at this address in the image", not "what does this opcode
//! do" -- and `read_pointer_at_va` calls the parent's `pe_va_to_file_off`, so
//! taking them would cost a widening for nothing.
//!
//! The two test modules below are this module's own. Two further tests of
//! [`is_code_padding_terminator`] and [`memory_operand_va`] live in
//! `super::scan::prologue_gate_tests`, where they gate the byte-level scans
//! that call them; they reach these functions through the parent's `use`.

use crate::core::binary::Arch as BArch;
use crate::core::instruction::Instruction;

/// True when `m` is an ARM condition-suffixed branch (`bne`, `beq`, `bhi`, …):
/// a `b` followed by exactly one of the 16 ARM condition codes. Excludes
/// non-branch `b*` mnemonics such as `bl`, `bx`, `bic`, `bkpt`, `bfi`.
fn is_arm_cond_branch(m: &str) -> bool {
    let Some(cc) = m.strip_prefix('b') else {
        return false;
    };
    matches!(
        cc,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
    )
}

/// True when `m` is an A32 condition-suffixed register branch (`bxeq`,
/// `bxne`, ...). When the operand is `lr` this is a conditional return, but
/// either operand shape ends the current block and retains lexical fallthrough.
fn is_arm_cond_bx(m: &str) -> bool {
    let Some(cc) = m.strip_prefix("bx") else {
        return false;
    };
    matches!(
        cc,
        "eq" | "ne"
            | "cs"
            | "hs"
            | "cc"
            | "lo"
            | "mi"
            | "pl"
            | "vs"
            | "vc"
            | "hi"
            | "ls"
            | "ge"
            | "lt"
            | "gt"
            | "le"
    )
}

/// True when `ins` is an ARM `pop`/`ldm*` that writes `pc` — i.e. a function
/// return. Resolved on operands because the mnemonic alone (`pop`) does not say
/// whether the register list includes `pc`.
pub(super) fn arm_pop_writes_pc(ins: &Instruction) -> bool {
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    if m == "pop" || m.starts_with("ldm") {
        return ins
            .operands
            .iter()
            .any(|o| o.register.as_deref() == Some("pc"));
    }
    // GCC commonly spells a one-register Thumb pop as the post-indexed load
    // `ldr.w pc, [sp], #4`.  Capstone reports it as `ldr`, not `pop`, so the
    // destination and stack base must participate in control-flow recovery.
    if m == "ldr" {
        return ins.operands.first().and_then(|o| o.register.as_deref()) == Some("pc")
            && ins.operands.get(1).and_then(|o| o.base.as_deref()) == Some("sp");
    }
    false
}

/// Whether this ARM instruction is a jump-table dispatch that loads `pc` from
/// an indexed table: `ldr pc, [rBase, rIdx, lsl #2]`.
///
/// `classify_ctrl_flow` sees only the mnemonic, and `ldr` is overwhelmingly an
/// ordinary load, so this shape reached the block walker unclassified: the
/// linear sweep decoded the table's address words as instructions and walked on
/// into whatever followed. That is the ARM analogue of the `tbb`/`tbh` gap
/// recorded above, and it is how every one of the 321 table dispatches in the
/// frozen DecBench sample-set lost its arms.
///
/// The test is deliberately narrow. An **index register is required**, which
/// excludes both the `ldr pc, [sp], #4` one-register pop (a return, recognised
/// by [`arm_pop_writes_pc`]) and the `ldr pc, [pc, #imm]` literal-pool veneer.
/// The mnemonic must be exactly `ldr` after the width suffix, so a predicated
/// `ldrhi pc, …` — which does fall through — is not swept up.
pub(super) fn arm_ldr_pc_table_dispatch(ins: &Instruction) -> bool {
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    if m != "ldr" {
        return false;
    }
    if ins.operands.first().and_then(|o| o.register.as_deref()) != Some("pc") {
        return false;
    }
    ins.operands.iter().any(|operand| {
        matches!(operand.kind, crate::core::instruction::OperandKind::Memory)
            && operand.index.is_some()
            && operand
                .base
                .as_deref()
                .is_some_and(|base| !base.eq_ignore_ascii_case("sp"))
    })
}

/// The register an ARM32 instruction defines, for a caller that must model
/// definitions itself.
///
/// Capstone's ARM detail marks every operand `Access::Read`, so
/// `DispatchTracker::observe` — which finds definitions through `Access::Write`
/// on operand 0 — sees no ARM write at all. Without this, a range bound proved
/// by `cmp` would survive an intervening `sub.w r5, r5, #0x3000`, and the
/// dispatch would size its table from a value that no longer exists.
///
/// The recognised set is the mnemonics that do NOT write operand 0: comparisons,
/// stores, and the `it` block prefix. Everything else is treated as a
/// definition, so an unmodelled instruction costs a resolution rather than
/// producing a table sized from a stale bound.
pub(super) fn arm_defined_register(ins: &Instruction) -> Option<&str> {
    let lower = ins.mnemonic.to_ascii_lowercase();
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower);
    // `cmp`/`cmn`/`tst`/`teq` read both operands; `str*`/`stm*`/`push` read the
    // register and write memory; `it*` carries only a condition. Prefix matching
    // covers the condition-suffixed and flag-setting spellings (`cmpne`,
    // `strbeq`, `stmia`) in one rule.
    if m.starts_with("cmp")
        || m.starts_with("cmn")
        || m.starts_with("tst")
        || m.starts_with("teq")
        || m.starts_with("str")
        || m.starts_with("stm")
        || m.starts_with("push")
        || m.starts_with("it")
    {
        return None;
    }
    ins.operands.first()?.register.as_deref()
}

/// Does this conditional branch's FALLTHROUGH edge carry the range bound its
/// block's last comparison established?
///
/// Only the unsigned "above" forms qualify: `cmp idx, N` followed by "branch
/// away when idx > N" leaves `idx <= N` on the fallthrough, which is exactly the
/// jump table's entry count minus one. A signed test is a different construct
/// and proves nothing about an unsigned table index.
pub(super) fn guard_bound_reaches_fallthrough(mnemonic: &str, arch: BArch) -> bool {
    let lower = mnemonic.to_ascii_lowercase();
    match arch {
        BArch::X86 | BArch::X86_64 => matches!(lower.as_str(), "ja" | "jae" | "jnbe" | "jnb"),
        // Thumb-2's `cmp idx, #N; bhi.w default; tbb/tbh [pc, idx]`. `bhi` alone,
        // because it is the only form whose in-range edge admits exactly `[0, N]`
        // — and it is what GCC and Clang emit for every table branch measured
        // here (three sites in `tests/decompiler_fixtures`, two in betaflight).
        BArch::ARM => {
            lower
                .strip_suffix(".w")
                .or_else(|| lower.strip_suffix(".n"))
                .unwrap_or(&lower)
                == "bhi"
        }
        _ => false,
    }
}

pub(super) fn classify_ctrl_flow(mnemonic: &str, arch: BArch) -> (bool, bool, bool) {
    let lower = mnemonic.to_ascii_lowercase();
    // Strip the Thumb-2 `.w`/`.n` width qualifier so `bne.w`, `bl.w`, `b.w`
    // classify the same as their base mnemonics.
    let m = lower
        .strip_suffix(".w")
        .or_else(|| lower.strip_suffix(".n"))
        .unwrap_or(&lower)
        .to_string();
    // returns (is_branch, is_call, is_ret)
    match arch {
        BArch::X86 | BArch::X86_64 => {
            if m == "ret" || m == "retq" {
                return (false, false, true);
            }
            if m == "call" {
                return (false, true, false);
            }
            if m.starts_with('j') {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::ARM => {
            // ARM32/Thumb-2. Returns are `bx lr` / `pop {…,pc}` (the pc-list
            // case is resolved operand-aware in the caller); `bx`/`bxns` end a
            // block either way. Calls are `bl`/`blx`. Branches are `b`, the
            // condition-suffixed `b<cond>` (bne/beq/…), and Thumb `cbz`/`cbnz`.
            if m == "bx" || m == "bxns" || m == "ret" {
                return (false, false, true);
            }
            if m == "bl" || m == "blx" {
                return (false, true, false);
            }
            // `tbb`/`tbh` are the Thumb-2 table branches. They ARE the switch
            // dispatch, and they are unconditional: control never falls through
            // to the byte after them, because that byte is the first entry of
            // the table they read. Leaving them unclassified made the linear
            // sweep decode the whole table as instructions and then walk into
            // the default arm, so a 240-case switch produced no cases at all.
            if m == "b"
                || m == "b.w"
                || m == "cbz"
                || m == "cbnz"
                || m == "tbb"
                || m == "tbh"
                || is_arm_cond_branch(&m)
                || is_arm_cond_bx(&m)
            {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::AArch64 => {
            // Returns, including ARMv8.3 pointer-authenticated returns
            // (RETAA/RETAB) that a PAC-hardened Pixel binary emits instead of
            // a plain RET at every function epilogue.
            if m == "ret" || m == "retaa" || m == "retab" {
                return (false, false, true);
            }
            // Calls: direct BL plus register-indirect BLR and its
            // pointer-authenticated forms (BLRAA/BLRAAZ/BLRAB/BLRABZ).
            if m == "bl"
                || m == "blr"
                || m == "blraa"
                || m == "blraaz"
                || m == "blrab"
                || m == "blrabz"
            {
                return (false, true, false);
            }
            // Unconditional and conditional branches. BR and its authenticated
            // variants (BRAA/BRAAZ/BRAB/BRABZ) are register-indirect branches —
            // typically tail calls or jump tables; without them the linear
            // sweep would run straight through a tail call into unrelated code.
            if m == "b"
                || m == "br"
                || m == "braa"
                || m == "braaz"
                || m == "brab"
                || m == "brabz"
                || m.starts_with("b.")
                || m == "cbz"
                || m == "cbnz"
                || m == "tbz"
                || m == "tbnz"
            {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::MIPS | BArch::MIPS64 => {
            if m == "jal" {
                return (false, true, false);
            }
            if m == "jr" {
                return (true, false, false);
            } // jr ra acts like return often; treat as branch
            if m == "j" || m.starts_with("b") {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::RISCV | BArch::RISCV64 => {
            if m == "jal" {
                return (false, true, false);
            }
            if m == "jalr" {
                return (false, true, false);
            } // often indirect call
            if m.starts_with('b') {
                return (true, false, false);
            }
            (false, false, false)
        }
        BArch::PPC | BArch::PPC64 => {
            if m == "bl" {
                return (false, true, false);
            }
            if m.starts_with('b') {
                return (true, false, false);
            }
            (false, false, false)
        }
        _ => (false, false, false),
    }
}

/// Whether a branch mnemonic is unconditional (no fallthrough edge).
///
/// Conditional branches (`b.<cond>`, `cbz`/`cbnz`, `tbz`/`tbnz`, x86 `j<cc>`)
/// must still queue their fallthrough successor; unconditional ones must not,
/// or the sweep spills into the literal pool / next function that follows a
/// tail call.
pub(super) fn is_unconditional_branch_mnemonic(mnemonic: &str, arch: BArch) -> bool {
    let m = mnemonic.to_ascii_lowercase();
    match arch {
        BArch::ARM | BArch::AArch64 => matches!(
            m.as_str(),
            // `b.w` is the Thumb-2 wide unconditional branch; `tbb`/`tbh` are
            // the Thumb-2 table branches, whose lexical successor is their own
            // table rather than a fallthrough arm.
            "b" | "b.w" | "br" | "braa" | "braaz" | "brab" | "brabz" | "tbb" | "tbh"
        ),
        BArch::X86 | BArch::X86_64 => m == "jmp",
        // Preserve the historical (arch-agnostic) semantics for the remaining
        // architectures so this refactor is behaviour-preserving for them.
        _ => m == "jmp" || m == "b",
    }
}

pub(super) fn immediate_target(ins: &Instruction) -> Option<u64> {
    // Branch destinations are the final immediate operand. Most control-flow
    // instructions have only one, but AArch64 TBZ/TBNZ spell both a tested bit
    // index and the destination as immediates (`tbnz w0,#31,target`). Taking the
    // first queues address 31 and leaves the real cold block undiscovered.
    ins.operands
        .iter()
        .filter_map(|op| op.immediate)
        .next_back()
        .map(|v| v as u64)
}

pub(super) fn memory_operand_va(ins: &Instruction) -> Option<u64> {
    ins.operands.iter().find_map(|op| {
        let disp = op.displacement?;
        if disp < 0 {
            return None;
        }
        if op.base.as_deref() == Some("rip") || op.base.is_none() {
            Some(disp as u64)
        } else {
            None
        }
    })
}

pub(super) fn is_code_padding_terminator(mnemonic: &str, arch: BArch) -> bool {
    if !(arch == BArch::X86 || arch == BArch::X86_64) {
        return false;
    }
    matches!(mnemonic.to_ascii_lowercase().as_str(), "int3" | "ud2")
}

#[cfg(test)]
mod aarch64_ctrl_flow_tests {
    use super::{classify_ctrl_flow, immediate_target, is_unconditional_branch_mnemonic, BArch};
    use crate::core::address::{Address, AddressKind};
    use crate::core::instruction::{Access, Instruction, Operand};

    fn class(m: &str) -> (bool, bool, bool) {
        classify_ctrl_flow(m, BArch::AArch64)
    }

    #[test]
    fn pac_authenticated_returns_are_returns() {
        // Plain and pointer-authenticated epilogue returns.
        for m in ["ret", "retaa", "retab"] {
            assert_eq!(class(m), (false, false, true), "{m} should be a return");
        }
    }

    #[test]
    fn authenticated_indirect_calls_are_calls() {
        for m in ["bl", "blr", "blraa", "blraaz", "blrab", "blrabz"] {
            assert_eq!(class(m), (false, true, false), "{m} should be a call");
        }
    }

    #[test]
    fn register_indirect_branches_are_unconditional_branches() {
        // BR and its authenticated variants: previously unclassified, so the
        // sweep ran past a tail call into unrelated bytes.
        for m in ["br", "braa", "braaz", "brab", "brabz"] {
            assert_eq!(class(m), (true, false, false), "{m} should be a branch");
            assert!(
                is_unconditional_branch_mnemonic(m, BArch::AArch64),
                "{m} must not add a fallthrough edge"
            );
        }
    }

    #[test]
    fn conditional_branches_keep_fallthrough() {
        for m in ["b.eq", "b.ne", "cbz", "cbnz", "tbz", "tbnz"] {
            assert_eq!(class(m), (true, false, false), "{m} is a branch");
            assert!(
                !is_unconditional_branch_mnemonic(m, BArch::AArch64),
                "{m} is conditional and must keep its fallthrough"
            );
        }
        // Plain unconditional B has no fallthrough.
        assert!(is_unconditional_branch_mnemonic("b", BArch::AArch64));
    }

    #[test]
    fn test_bit_branch_uses_its_last_immediate_as_the_target() {
        let instruction = Instruction::new(
            Address::new(AddressKind::VA, 0x1028, 64, None, None).unwrap(),
            0x3700_0060u32.to_le_bytes().to_vec(),
            "tbnz".to_string(),
            vec![
                Operand::register("w0".to_string(), 32, Access::Read),
                Operand::immediate(31, 8),
                Operand::immediate(0x1034, 64),
            ],
            4,
            "aarch64".to_string(),
            None,
            None,
            None,
            None,
        );

        assert_eq!(immediate_target(&instruction), Some(0x1034));
    }

    #[test]
    fn landing_pads_and_pac_signing_are_not_terminators() {
        // BTI and PAC-sign instructions are ordinary (non-control-flow) ops;
        // they must not split or end a basic block.
        for m in ["bti", "paciasp", "pacibsp", "autiasp", "autibsp", "nop"] {
            assert_eq!(class(m), (false, false, false), "{m} is not control flow");
        }
    }
}

#[cfg(test)]
mod arm32_ctrl_flow_tests {
    use super::{arm_pop_writes_pc, classify_ctrl_flow, is_unconditional_branch_mnemonic, BArch};
    use crate::core::address::{Address, AddressKind};
    use crate::core::binary::Endianness;
    use crate::core::disassembler::{Architecture, Disassembler};
    use crate::disasm::capstone::CapstoneDisassembler;

    #[test]
    fn real_thumb_postindexed_pc_load_is_a_return() {
        // `ldr.w pc, [sp], #4` from the real DecBench `write_power_mode`
        // epilogue.  GCC uses this encoding for a one-register pop.
        let mut backend =
            CapstoneDisassembler::new(Architecture::ARM, Endianness::Little).expect("ARM backend");
        backend.set_thumb_mode(true).expect("Thumb mode");
        let address = Address::new(AddressKind::VA, 0x801da76, 32, None, None).expect("address");
        let instruction = backend
            .disassemble_instruction(&address, &[0x5d, 0xf8, 0x04, 0xfb])
            .expect("decode real epilogue");
        assert!(
            arm_pop_writes_pc(&instruction),
            "decoded epilogue must terminate the CFG: {instruction:#?}"
        );
    }

    #[test]
    fn a32_conditional_bx_ends_the_block_but_keeps_fallthrough() {
        // A32 encodes conditional returns as `bx<cc> lr`.  Treating `bxeq` as
        // an ordinary instruction lets the lexical fallthrough execute even
        // when the return condition is true; treating it as an unconditional
        // return loses the false path.  It is therefore a conditional branch
        // for CFG construction.
        assert_eq!(classify_ctrl_flow("bxeq", BArch::ARM), (true, false, false));
        assert!(!is_unconditional_branch_mnemonic("bxeq", BArch::ARM));
    }
}
