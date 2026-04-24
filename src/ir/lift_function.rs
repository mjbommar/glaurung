//! Bridge between CFG-discovered `Function`s and LLIR.
//!
//! The CFG pass in `crate::analysis::cfg` already enumerates every basic
//! block's VA range. This module lifts each block's raw bytes through
//! `lift_x86::lift_bytes` and assembles an `LlirFunction`.
//!
//! Only x86 and x86-64 are supported today (the only ISA the lifter covers);
//! other architectures return `None` so callers can handle the unsupported
//! case explicitly rather than receive a silently-incomplete result.

use crate::analysis::entry::va_to_file_offset;
use crate::core::binary::Arch;
use crate::core::function::Function;
use crate::ir::{lift_arm64, lift_x86};
use crate::ir::types::*;

/// Lift a byte window into LLIR using the appropriate per-arch lifter.
fn lift_window(bytes: &[u8], start_va: u64, arch: Arch) -> Vec<LlirInstr> {
    match arch {
        Arch::X86 => lift_x86::lift_bytes(bytes, start_va, 32),
        Arch::X86_64 => lift_x86::lift_bytes(bytes, start_va, 64),
        Arch::AArch64 => lift_arm64::lift_bytes(bytes, start_va),
        _ => Vec::new(),
    }
}

/// Returns true when an LLIR lifter exists for the given architecture.
pub fn supports_arch(arch: Arch) -> bool {
    matches!(arch, Arch::X86 | Arch::X86_64 | Arch::AArch64)
}

/// Lift every basic block of `func` from `data` into LLIR blocks.
///
/// Returns `None` when the architecture has no LLIR lifter yet.
/// Individual blocks whose bytes cannot be located (e.g. VA outside any
/// mapped segment) are skipped silently; the function's other blocks still
/// produce LLIR.
pub fn lift_function_from_bytes(
    data: &[u8],
    func: &Function,
    arch: Arch,
) -> Option<LlirFunction> {
    if !supports_arch(arch) {
        return None;
    }

    let mut blocks: Vec<LlirBlock> = Vec::with_capacity(func.basic_blocks.len());

    for bb in &func.basic_blocks {
        let start = bb.start_address.value;
        let end = bb.end_address.value;
        if end <= start {
            continue;
        }
        let Some(foff) = va_to_file_offset(data, start) else {
            continue;
        };
        let size = (end - start) as usize;
        let end_off = foff.saturating_add(size).min(data.len());
        if foff >= end_off {
            continue;
        }
        let window = &data[foff..end_off];
        let instrs = lift_window(window, start, arch);

        // Successors are the CFG successor block starts, which we can recover
        // from bb.successor_ids by finding the corresponding BasicBlock.
        let mut succs: Vec<u64> = Vec::new();
        for sid in &bb.successor_ids {
            if let Some(target) = func
                .basic_blocks
                .iter()
                .find(|b| &b.id == sid)
                .map(|b| b.start_address.value)
            {
                succs.push(target);
            }
        }

        blocks.push(LlirBlock {
            start_va: start,
            end_va: end,
            instrs,
            succs,
        });
    }

    if blocks.is_empty() {
        return None;
    }

    // Sort deterministically by VA for stable consumers.
    blocks.sort_by_key(|b| b.start_va);

    Some(LlirFunction {
        entry_va: func.entry_point.value,
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use std::path::Path;

    #[test]
    fn lifts_hello_gcc_entry_function() {
        // Real-binary end-to-end: discover functions via cfg, lift the one
        // containing the entry VA, and check that we got sensible LLIR.
        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            eprintln!("sample missing: {}", path.display());
            return;
        }
        let data = std::fs::read(path).expect("read sample");
        let budgets = Budgets {
            max_functions: 8,
            max_blocks: 256,
            max_instructions: 4000,
            timeout_ms: 500,
        };
        let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
        assert!(!funcs.is_empty(), "cfg produced no functions");

        // Lift the first function (entry).
        let f = &funcs[0];
        let lf = lift_function_from_bytes(&data, f, Arch::X86_64)
            .expect("lift function");
        assert_eq!(lf.entry_va, f.entry_point.value);
        assert!(!lf.blocks.is_empty(), "lifted function has no blocks");
        // Every block's start VA must match a block in the source function.
        let src_starts: std::collections::HashSet<u64> =
            f.basic_blocks.iter().map(|b| b.start_address.value).collect();
        for b in &lf.blocks {
            assert!(
                src_starts.contains(&b.start_va),
                "block start 0x{:x} not in source function",
                b.start_va
            );
            assert!(!b.instrs.is_empty(), "empty LLIR block at 0x{:x}", b.start_va);
        }
        // Entry's block should terminate in some recognised control-flow op.
        // A real compiler-emitted function body nearly always ends with ret,
        // call, jmp, or a conditional jump.
        let entry_block = lf
            .blocks
            .iter()
            .find(|b| b.start_va == lf.entry_va)
            .expect("entry block lifted");
        let last = entry_block.instrs.last().expect("entry block has instrs");
        assert!(
            matches!(
                &last.op,
                Op::Return | Op::Call { .. } | Op::Jump { .. } | Op::CondJump { .. } | Op::Unknown { .. }
            ),
            "unexpected terminator at 0x{:x}: {:?}",
            last.va,
            last.op
        );
    }

    #[test]
    fn returns_none_for_unsupported_arch() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::function::{Function, FunctionKind};
        let entry = Address::new(AddressKind::VA, 0, 64, None, None).unwrap();
        let f = Function::new("f".into(), entry, FunctionKind::Normal).unwrap();
        assert!(lift_function_from_bytes(&[0u8; 0], &f, Arch::ARM).is_none());
        assert!(lift_function_from_bytes(&[0u8; 0], &f, Arch::MIPS64).is_none());
        assert!(lift_function_from_bytes(&[0u8; 0], &f, Arch::RISCV64).is_none());
    }

    #[test]
    fn supports_arch_enumerates_lifters() {
        assert!(supports_arch(Arch::X86));
        assert!(supports_arch(Arch::X86_64));
        assert!(supports_arch(Arch::AArch64));
        assert!(!supports_arch(Arch::ARM));
        assert!(!supports_arch(Arch::MIPS));
    }

    #[test]
    fn lifts_hello_arm64_entry_function() {
        let path = Path::new(
            "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        );
        if !path.exists() {
            eprintln!("sample missing: {}", path.display());
            return;
        }
        let data = std::fs::read(path).expect("read sample");
        let budgets = Budgets {
            max_functions: 8,
            max_blocks: 256,
            max_instructions: 4000,
            timeout_ms: 500,
        };
        let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
        assert!(!funcs.is_empty(), "cfg produced no functions for arm64");
        let f = &funcs[0];
        let lf = lift_function_from_bytes(&data, f, Arch::AArch64)
            .expect("lift arm64 function");
        assert_eq!(lf.entry_va, f.entry_point.value);
        assert!(!lf.blocks.is_empty(), "no blocks lifted");
        // At least one block's instr list must be non-empty and contain a
        // recognised op kind.
        assert!(lf
            .blocks
            .iter()
            .any(|b| b.instrs.iter().any(|i| !matches!(&i.op, Op::Unknown { .. }))));
    }
}
