//! Cross-reference helpers (MVP).
//!
//! This module provides minimal routines to compute code→data xrefs by scanning
//! discovered instructions for immediate operands that fall within known data
//! sections. It is intentionally conservative and budgeted.
//!
//! Two entry points live here today:
//! * [`code_to_data_xrefs`] — operates on decoded machine instructions and
//!   includes an AArch64 ADRP+X reconstruction pass.
//! * [`llir_to_data_xrefs`] — operates on an already-lifted [`LlirFunction`]
//!   and picks up `Op::Assign { src: Value::Addr(..) }` / `Op::Load`/`Op::Store`
//!   with absolute-address memory operands. This path is more faithful for
//!   RIP-relative LEAs on x86-64 because the lifter already resolves them.

use crate::analysis::aarch64_literals;
use crate::core::address::{Address, AddressKind};
use crate::core::instruction::Instruction;
use crate::ir::types::{LlirFunction, MemOp, Op, Value};

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: Address,
    pub to: Address,
}

fn in_ranges(v: u64, ranges: &[(u64, u64)]) -> bool {
    ranges.iter().any(|(s, e)| v >= *s && v < *e)
}

fn push_xref(out: &mut Vec<Xref>, from_va: u64, to_va: u64, bits: u8) {
    if let (Ok(from), Ok(to)) = (
        Address::new(AddressKind::VA, from_va, bits, None, None),
        Address::new(AddressKind::VA, to_va, bits, None, None),
    ) {
        out.push(Xref { from, to });
    }
}

/// Given instructions and a set of data ranges (VA start,end), produce xrefs where
/// an instruction contains an immediate in one of the ranges. Also recovers
/// AArch64 ADRP+{ADD,LDR,STR} pairs that materialize a pointer across two
/// instructions. Best-effort MVP.
pub fn code_to_data_xrefs(
    insns: &[Instruction],
    data_ranges: &[(u64, u64)],
    bits: u8,
    max_xrefs: usize,
) -> Vec<Xref> {
    let mut out = Vec::new();

    // First pass: AArch64 multi-instruction literal reconstruction.
    // We only run this when the input looks like ARM64 so we don't misinterpret
    // other architectures' `add`/`ldr` mnemonics.
    let looks_aarch64 = insns
        .iter()
        .any(|i| i.arch.eq_ignore_ascii_case("ARM64") || i.arch.eq_ignore_ascii_case("aarch64"));
    let mut resolved_indices = std::collections::HashSet::new();
    if looks_aarch64 {
        for lit in aarch64_literals::resolve_literals(insns) {
            if out.len() >= max_xrefs {
                return out;
            }
            if in_ranges(lit.target_va, data_ranges) {
                let from_va = insns[lit.instr_index].address.value;
                push_xref(&mut out, from_va, lit.target_va, bits);
                resolved_indices.insert(lit.instr_index);
                // Also skip the ADRP that seeded this literal so we don't
                // emit a spurious page-only xref for it.
                if lit.instr_index > 0 {
                    resolved_indices.insert(lit.instr_index - 1);
                }
            }
        }
    }

    // Second pass: single-instruction immediates (the original MVP path),
    // skipping instructions already handled by ADRP+X reconstruction so we
    // don't emit the partial (page-only) xref on top of the real one.
    for (i, ins) in insns.iter().enumerate() {
        if out.len() >= max_xrefs {
            break;
        }
        if resolved_indices.contains(&i) {
            continue;
        }
        if let Some(imm) = ins.operands.iter().find_map(|op| op.immediate) {
            let v = imm as u64;
            if in_ranges(v, data_ranges) {
                push_xref(&mut out, ins.address.value, v, bits);
            }
        }
    }
    out
}

/// Candidate target VA for a memory operand, if its effective address is a
/// concrete constant (absolute addressing — no base/index or RIP folded).
fn memop_absolute_target(m: &MemOp) -> Option<u64> {
    if m.base.is_some() || m.index.is_some() {
        return None;
    }
    if m.disp <= 0 {
        return None;
    }
    Some(m.disp as u64)
}

/// Extract code→data xrefs from a lifted function.
///
/// Scans every LLIR op for concrete VA references:
/// * `Op::Assign { src: Value::Addr(v) }` — produced by RIP-relative LEAs
///   on x86-64, which the lifter already resolves to an absolute VA.
/// * `Op::Load` / `Op::Store` whose memory operand is a plain absolute
///   displacement (no base / index).
///
/// The returned xrefs use the *machine instruction's* VA as the source, so
/// callers can correlate with the original instruction even though multiple
/// LLIR ops may share a VA.
pub fn llir_to_data_xrefs(
    lf: &LlirFunction,
    data_ranges: &[(u64, u64)],
    bits: u8,
    max_xrefs: usize,
) -> Vec<Xref> {
    let mut out = Vec::new();
    // Dedupe by (from, to) — a single machine instruction can expand into
    // multiple LLIR ops and we do not want to double-count its xref.
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    for block in &lf.blocks {
        for ins in &block.instrs {
            if out.len() >= max_xrefs {
                return out;
            }
            let target = match &ins.op {
                Op::Assign {
                    src: Value::Addr(v),
                    ..
                } => Some(*v),
                Op::Load { addr, .. } | Op::Store { addr, .. } => memop_absolute_target(addr),
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Addr(v)),
                } => Some(*v),
                _ => None,
            };
            let Some(to_va) = target else { continue };
            if !in_ranges(to_va, data_ranges) {
                continue;
            }
            if !seen.insert((ins.va, to_va)) {
                continue;
            }
            push_xref(&mut out, ins.va, to_va, bits);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::instruction::{Access, Operand};

    fn mk_arm64(mnem: &str, addr: u64, ops: Vec<Operand>) -> Instruction {
        Instruction {
            address: Address::new(AddressKind::VA, addr, 64, None, None).unwrap(),
            bytes: vec![0; 4],
            mnemonic: mnem.to_string(),
            operands: ops,
            length: 4,
            arch: "ARM64".to_string(),
            semantics: None,
            side_effects: None,
            prefixes: None,
            groups: None,
        }
    }

    #[test]
    fn aarch64_adrp_add_xref_resolves_to_data_range() {
        // adrp x0, #0x10000
        // add  x0, x0, #0x123   -> target 0x10123 (inside [0x10000, 0x11000))
        let insns = vec![
            mk_arm64(
                "adrp",
                0x8000,
                vec![
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::immediate(0x10000, 0),
                ],
            ),
            mk_arm64(
                "add",
                0x8004,
                vec![
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::immediate(0x123, 0),
                ],
            ),
        ];
        let xrefs = code_to_data_xrefs(&insns, &[(0x10000, 0x11000)], 64, 16);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from.value, 0x8004);
        assert_eq!(xrefs[0].to.value, 0x10123);
    }

    #[test]
    fn llir_assign_addr_produces_xref() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1008,
                instrs: vec![LlirInstr {
                    va: 0x1000,
                    op: Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Addr(0x20050),
                    },
                }],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x20000, 0x21000)], 64, 16);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].from.value, 0x1000);
        assert_eq!(xrefs[0].to.value, 0x20050);
    }

    #[test]
    fn llir_xrefs_are_deduped_per_source_va() {
        // Two LLIR ops with the same va and the same resolved target should
        // collapse to a single xref.
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x2000,
            blocks: vec![LlirBlock {
                start_va: 0x2000,
                end_va: 0x2010,
                instrs: vec![
                    LlirInstr {
                        va: 0x2000,
                        op: Op::Assign {
                            dst: VReg::phys("rax"),
                            src: Value::Addr(0x9000),
                        },
                    },
                    LlirInstr {
                        va: 0x2000,
                        op: Op::Load {
                            dst: VReg::phys("rbx"),
                            addr: MemOp {
                                base: None,
                                index: None,
                                scale: 0,
                                disp: 0x9000,
                                size: 8,
                                ..Default::default()
                            },
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x8000, 0xa000)], 64, 16);
        assert_eq!(xrefs.len(), 1, "expected dedupe to one xref");
    }

    #[test]
    fn llir_xrefs_recover_string_references_on_real_binary() {
        // End-to-end: discover functions via CFG, lift each, collect xrefs
        // from their LLIR, and assert that *some* xref points into the binary's
        // readable-data range. This catches regressions in any of the glue
        // between lifting and xref recovery.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        use object::{Object, ObjectSection};
        use std::path::Path;

        let path = Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            eprintln!("sample missing: {}", path.display());
            return;
        }
        let data = std::fs::read(path).expect("read sample");

        // Build readable-data ranges from the object's sections whose names
        // suggest read-only data (.rodata, .data, .data.rel.ro).
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        if let Ok(obj) = object::read::File::parse(&data[..]) {
            for s in obj.sections() {
                let name = s.name().unwrap_or("").to_ascii_lowercase();
                if name.contains(".rodata")
                    || name.contains(".data")
                    || name.contains(".bss")
                {
                    let addr = s.address();
                    let size = s.size();
                    if size > 0 {
                        ranges.push((addr, addr.saturating_add(size)));
                    }
                }
            }
        }
        assert!(!ranges.is_empty(), "no data ranges discovered");

        let budgets = Budgets {
            max_functions: 16,
            max_blocks: 512,
            max_instructions: 10_000,
            timeout_ms: 500,
        };
        let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
        let mut any_xref = false;
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let xrefs = llir_to_data_xrefs(&lf, &ranges, 64, 64);
                if !xrefs.is_empty() {
                    any_xref = true;
                    // Every xref must land inside one of the data ranges.
                    for x in &xrefs {
                        assert!(
                            ranges
                                .iter()
                                .any(|(s, e)| x.to.value >= *s && x.to.value < *e),
                            "xref target 0x{:x} outside data ranges",
                            x.to.value
                        );
                    }
                }
            }
        }
        assert!(
            any_xref,
            "expected at least one LLIR-derived data xref on hello-gcc-O2"
        );
    }

    #[test]
    fn llir_memop_with_base_register_is_not_absolute() {
        // A load through [rbp + 0x10] must NOT be treated as an absolute xref.
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg};
        let lf = LlirFunction {
            entry_va: 0x3000,
            blocks: vec![LlirBlock {
                start_va: 0x3000,
                end_va: 0x3004,
                instrs: vec![LlirInstr {
                    va: 0x3000,
                    op: Op::Load {
                        dst: VReg::phys("rax"),
                        addr: MemOp {
                            base: Some(VReg::phys("rbp")),
                            index: None,
                            scale: 0,
                            disp: 0x10,
                            size: 8,
                            ..Default::default()
                        },
                    },
                }],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0, u64::MAX)], 64, 16);
        assert!(xrefs.is_empty(), "rbp-relative load must not produce xref");
    }

    #[test]
    fn aarch64_adrp_alone_does_not_emit_partial_xref_when_completed() {
        // Confirms the "dedupe" behaviour: the ADRP's own page immediate lies
        // in the data range (0x10000), but because it is completed by the
        // following ADD we should only emit the reconstructed xref, not two.
        let insns = vec![
            mk_arm64(
                "adrp",
                0x8000,
                vec![
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::immediate(0x10000, 0),
                ],
            ),
            mk_arm64(
                "add",
                0x8004,
                vec![
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::register("x0".to_string(), 0, Access::Read),
                    Operand::immediate(0x8, 0),
                ],
            ),
        ];
        let xrefs = code_to_data_xrefs(&insns, &[(0x10000, 0x11000)], 64, 16);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].to.value, 0x10008);
    }
}
