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
use crate::core::binary::Arch;
use crate::core::function::Function;
use crate::core::instruction::Instruction;
use crate::ir::lift_function::lift_function_from_bytes;
use crate::ir::types::{LlirFunction, MemOp, Op, Value};
use object::{Object, ObjectSection, SectionKind};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct Xref {
    pub from: Address,
    pub to: Address,
}

#[derive(Debug, Clone)]
pub struct FunctionDataXref {
    pub from: Address,
    pub to: Address,
    pub function_va: Address,
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

fn canonical_x86_reg(name: &str) -> Option<&'static str> {
    match name {
        "rax" | "eax" | "ax" | "al" | "ah" => Some("rax"),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => Some("rbx"),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => Some("rcx"),
        "rdx" | "edx" | "dx" | "dl" | "dh" => Some("rdx"),
        "rsi" | "esi" | "si" | "sil" => Some("rsi"),
        "rdi" | "edi" | "di" | "dil" => Some("rdi"),
        "rbp" | "ebp" | "bp" | "bpl" => Some("rbp"),
        "rsp" | "esp" | "sp" | "spl" => Some("rsp"),
        "r8" | "r8d" | "r8w" | "r8b" => Some("r8"),
        "r9" | "r9d" | "r9w" | "r9b" => Some("r9"),
        "r10" | "r10d" | "r10w" | "r10b" => Some("r10"),
        "r11" | "r11d" | "r11w" | "r11b" => Some("r11"),
        "r12" | "r12d" | "r12w" | "r12b" => Some("r12"),
        "r13" | "r13d" | "r13w" | "r13b" => Some("r13"),
        "r14" | "r14d" | "r14w" | "r14b" => Some("r14"),
        "r15" | "r15d" | "r15w" | "r15b" => Some("r15"),
        _ => None,
    }
}

fn reg_key(reg: &crate::ir::types::VReg) -> crate::ir::types::VReg {
    match reg {
        crate::ir::types::VReg::Phys(name) => crate::ir::types::VReg::Phys(
            canonical_x86_reg(name.as_str())
                .unwrap_or(name.as_str())
                .to_string(),
        ),
        _ => reg.clone(),
    }
}

type AddrState = HashMap<crate::ir::types::VReg, u64>;

fn value_known_addr(value: &Value, known: &AddrState) -> Option<u64> {
    match value {
        Value::Addr(v) => Some(*v),
        Value::Reg(reg) => known.get(&reg_key(reg)).copied(),
        Value::Const(_) => None,
    }
}

fn checked_add_i64(base: u64, disp: i64) -> Option<u64> {
    if disp >= 0 {
        base.checked_add(disp as u64)
    } else {
        base.checked_sub(disp.unsigned_abs())
    }
}

fn memop_known_target(m: &MemOp, known: &AddrState) -> Option<u64> {
    if m.segment.is_some() {
        return None;
    }
    if m.base.is_none() && m.index.is_none() {
        return memop_absolute_target(m);
    }

    let base_value = m
        .base
        .as_ref()
        .and_then(|base| known.get(&reg_key(base)).copied());
    let index_value = m
        .index
        .as_ref()
        .and_then(|index| known.get(&reg_key(index)).copied());

    let mut target = match (&m.base, base_value, &m.index, index_value) {
        (Some(_), Some(base), _, _) => base,
        (Some(_), None, Some(_), Some(index)) if m.scale.max(1) == 1 => index,
        (None, _, Some(_), Some(index)) => index.checked_mul(u64::from(m.scale.max(1)))?,
        (None, _, None, _) => 0,
        _ => return None,
    };
    if let Some(value) = index_value {
        if base_value.is_some() {
            let scale = u64::from(m.scale.max(1));
            target = target.checked_add(value.checked_mul(scale)?)?;
        }
    } else if base_value.is_some() && m.index.is_some() {
        // The common string-table pattern is `[known_base + variable
        // index * scale + disp]`; keep the known base as the xref target so
        // the use-site remains attached to the table/string range without
        // inventing a concrete indexed element.
    }
    checked_add_i64(target, m.disp)
}

fn update_known_addrs(op: &Op, known_addrs: &mut AddrState, data_ranges: &[(u64, u64)]) {
    match op {
        Op::Assign { dst, src } => {
            let dst = reg_key(dst);
            if let Some(value) =
                value_known_addr(src, known_addrs).filter(|value| in_ranges(*value, data_ranges))
            {
                known_addrs.insert(dst, value);
            } else {
                known_addrs.remove(&dst);
            }
        }
        Op::Bin { dst, op, lhs, rhs } => {
            let dst = reg_key(dst);
            let value = match (op, value_known_addr(lhs, known_addrs), rhs) {
                (crate::ir::types::BinOp::Add, Some(base), Value::Const(disp)) => {
                    checked_add_i64(base, *disp)
                }
                (crate::ir::types::BinOp::Sub, Some(base), Value::Const(disp)) => {
                    checked_add_i64(base, -*disp)
                }
                _ => None,
            };
            if let Some(value) = value.filter(|value| in_ranges(*value, data_ranges)) {
                known_addrs.insert(dst, value);
            } else {
                known_addrs.remove(&dst);
            }
        }
        Op::Load { dst, .. } | Op::Un { dst, .. } | Op::Cmp { dst, .. } => {
            known_addrs.remove(&reg_key(dst));
        }
        Op::CondAssign { dst, .. } => {
            known_addrs.remove(&reg_key(dst));
        }
        _ => {}
    }
}

fn block_out_known_addrs(
    block: &crate::ir::types::LlirBlock,
    input: &AddrState,
    data_ranges: &[(u64, u64)],
) -> AddrState {
    let mut out = input.clone();
    for ins in &block.instrs {
        update_known_addrs(&ins.op, &mut out, data_ranges);
    }
    out
}

fn merged_pred_state(preds: &[usize], out_states: &[AddrState]) -> AddrState {
    let Some((first, rest)) = preds.split_first() else {
        return HashMap::new();
    };
    let mut merged = out_states[*first].clone();
    for pred in rest {
        merged.retain(|reg, value| out_states[*pred].get(reg) == Some(value));
    }
    merged
}

fn compute_known_addr_in_states(lf: &LlirFunction, data_ranges: &[(u64, u64)]) -> Vec<AddrState> {
    let mut block_index: HashMap<u64, usize> = HashMap::new();
    for (idx, block) in lf.blocks.iter().enumerate() {
        block_index.insert(block.start_va, idx);
    }

    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); lf.blocks.len()];
    for (idx, block) in lf.blocks.iter().enumerate() {
        for succ in &block.succs {
            if let Some(succ_idx) = block_index.get(succ).copied() {
                preds[succ_idx].push(idx);
            }
        }
    }

    let entry_idx = block_index.get(&lf.entry_va).copied();
    let mut in_states: Vec<AddrState> = vec![HashMap::new(); lf.blocks.len()];
    let mut out_states: Vec<AddrState> = vec![HashMap::new(); lf.blocks.len()];
    let max_iters = lf.blocks.len().saturating_mul(4).max(1);

    for _ in 0..max_iters {
        let mut changed = false;
        for idx in 0..lf.blocks.len() {
            let new_in = if Some(idx) == entry_idx || preds[idx].is_empty() {
                HashMap::new()
            } else {
                merged_pred_state(&preds[idx], &out_states)
            };
            let new_out = block_out_known_addrs(&lf.blocks[idx], &new_in, data_ranges);
            if new_in != in_states[idx] {
                in_states[idx] = new_in;
                changed = true;
            }
            if new_out != out_states[idx] {
                out_states[idx] = new_out;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    in_states
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
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let in_states = compute_known_addr_in_states(lf, data_ranges);
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        let mut known_addrs = in_states[block_idx].clone();
        for ins in &block.instrs {
            if out.len() >= max_xrefs {
                return out;
            }
            let target = match &ins.op {
                Op::Assign {
                    src: Value::Addr(v),
                    ..
                } => Some(*v),
                Op::CondAssign { src, .. } => value_known_addr(src, &known_addrs),
                Op::Load { addr, .. } => memop_known_target(addr, &known_addrs),
                Op::Store { addr, src } => value_known_addr(src, &known_addrs)
                    .or_else(|| memop_known_target(addr, &known_addrs)),
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(Value::Addr(v)),
                } => Some(*v),
                Op::Call {
                    target: crate::ir::types::CallTarget::Indirect(value),
                } => value_known_addr(value, &known_addrs),
                _ => None,
            };
            if let Some(to_va) = target {
                if in_ranges(to_va, data_ranges) && seen.insert((ins.va, to_va)) {
                    push_xref(&mut out, ins.va, to_va, bits);
                }
            }
            update_known_addrs(&ins.op, &mut known_addrs, data_ranges);
        }
    }
    out
}

fn arch_from_object(obj: &object::read::File<'_>) -> Arch {
    match obj.architecture() {
        object::Architecture::I386 => Arch::X86,
        object::Architecture::X86_64 => Arch::X86_64,
        object::Architecture::Aarch64 => Arch::AArch64,
        object::Architecture::Arm => Arch::ARM,
        object::Architecture::Mips => Arch::MIPS,
        object::Architecture::Mips64 => Arch::MIPS64,
        object::Architecture::PowerPc => Arch::PPC,
        object::Architecture::PowerPc64 => Arch::PPC64,
        object::Architecture::Riscv32 => Arch::RISCV,
        object::Architecture::Riscv64 => Arch::RISCV64,
        _ => Arch::Unknown,
    }
}

fn bits_for_arch(arch: Arch) -> u8 {
    match arch {
        Arch::X86 => 32,
        _ => 64,
    }
}

fn pe_image_base(data: &[u8]) -> Option<u64> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off.checked_add(0x18 + 0x20)? > data.len() {
        return None;
    }
    if data.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    let opt_off = pe_off + 0x18;
    let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().ok()?);
    match magic {
        0x10b => {
            let off = opt_off + 0x1c;
            Some(u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as u64)
        }
        0x20b => {
            let off = opt_off + 0x18;
            Some(u64::from_le_bytes(data[off..off + 8].try_into().ok()?))
        }
        _ => None,
    }
}

fn is_pe(data: &[u8]) -> bool {
    data.len() >= 2 && &data[..2] == b"MZ"
}

fn section_data_range(
    section: &object::read::Section<'_, '_>,
    image_base: Option<u64>,
    pe_semantics: bool,
) -> Option<(u64, u64)> {
    let size = section.size();
    if size == 0 {
        return None;
    }
    if matches!(section.kind(), SectionKind::Text) {
        return None;
    }
    let name = section.name().unwrap_or("").to_ascii_lowercase();
    if name.contains("text") || name.contains("code") || name.contains("pagekd") {
        return None;
    }
    if section
        .data()
        .ok()
        .filter(|data| !data.is_empty())
        .is_none()
    {
        return None;
    }
    let mut start = section.address();
    if pe_semantics {
        if let Some(base) = image_base {
            if start < base {
                start = start.saturating_add(base);
            }
        }
    }
    Some((start, start.saturating_add(size)))
}

/// Build non-executable, file-backed data ranges in VA form.
pub fn data_ranges_for_xrefs(data: &[u8]) -> Vec<(u64, u64)> {
    let Ok(obj) = object::read::File::parse(data) else {
        return Vec::new();
    };
    let pe_semantics = is_pe(data);
    let image_base = if pe_semantics {
        pe_image_base(data)
    } else {
        None
    };
    let mut ranges: Vec<(u64, u64)> = obj
        .sections()
        .filter_map(|section| section_data_range(&section, image_base, pe_semantics))
        .collect();
    ranges.sort_unstable();
    ranges
}

/// Extract direct code-to-data references for discovered functions.
///
/// This is the native substrate for IDA-style "who uses this string?"
/// workflows. It intentionally emits exact source instruction VAs and source
/// function entry VAs so the persistent KB can answer both callsite-level and
/// function-level questions without re-running analysis.
pub fn function_data_xrefs(
    data: &[u8],
    funcs: &[Function],
    max_xrefs: usize,
) -> Vec<FunctionDataXref> {
    let Ok(obj) = object::read::File::parse(data) else {
        return Vec::new();
    };
    let arch = arch_from_object(&obj);
    let bits = bits_for_arch(arch);
    let data_ranges = data_ranges_for_xrefs(data);
    if data_ranges.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(u64, u64, u64)> = std::collections::HashSet::new();
    for func in funcs {
        if out.len() >= max_xrefs {
            break;
        }
        let Some(lf) = lift_function_from_bytes(data, func, arch) else {
            continue;
        };
        let remaining = max_xrefs.saturating_sub(out.len());
        for xref in llir_to_data_xrefs(&lf, &data_ranges, bits, remaining) {
            let key = (xref.from.value, xref.to.value, func.entry_point.value);
            if !seen.insert(key) {
                continue;
            }
            let Ok(function_va) =
                Address::new(AddressKind::VA, func.entry_point.value, bits, None, None)
            else {
                continue;
            };
            out.push(FunctionDataXref {
                from: xref.from,
                to: xref.to,
                function_va,
            });
            if out.len() >= max_xrefs {
                break;
            }
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
    fn llir_tracks_address_register_through_indexed_load() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x4000,
            blocks: vec![LlirBlock {
                start_va: 0x4000,
                end_va: 0x4010,
                instrs: vec![
                    LlirInstr {
                        va: 0x4000,
                        op: Op::Assign {
                            dst: VReg::phys("r15"),
                            src: Value::Addr(0x1400468a8),
                        },
                    },
                    LlirInstr {
                        va: 0x4008,
                        op: Op::Load {
                            dst: VReg::phys("eax"),
                            addr: MemOp {
                                base: Some(VReg::phys("r15")),
                                index: Some(VReg::phys("rax")),
                                scale: 2,
                                disp: 0,
                                size: 2,
                                ..Default::default()
                            },
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x140040000, 0x140050000)], 64, 16);
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.from.value == 0x4008 && xref.to.value == 0x1400468a8),
            "indexed read through known string base should keep exact source VA"
        );
    }

    #[test]
    fn llir_tracks_known_index_with_unknown_base() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x4100,
            blocks: vec![LlirBlock {
                start_va: 0x4100,
                end_va: 0x4110,
                instrs: vec![
                    LlirInstr {
                        va: 0x4100,
                        op: Op::Assign {
                            dst: VReg::phys("rsi"),
                            src: Value::Addr(0x140c02690),
                        },
                    },
                    LlirInstr {
                        va: 0x4108,
                        op: Op::Load {
                            dst: VReg::phys("rdx"),
                            addr: MemOp {
                                base: Some(VReg::phys("rbx")),
                                index: Some(VReg::phys("rsi")),
                                scale: 1,
                                disp: 0,
                                size: 8,
                                ..Default::default()
                            },
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x140c00000, 0x140c10000)], 64, 16);
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.from.value == 0x4108 && xref.to.value == 0x140c02690),
            "known scale-1 index should remain visible when base is variable"
        );
    }

    #[test]
    fn llir_tracks_address_register_across_cfg_successor() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x4000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x4000,
                    end_va: 0x4008,
                    instrs: vec![LlirInstr {
                        va: 0x4000,
                        op: Op::Assign {
                            dst: VReg::phys("r15"),
                            src: Value::Addr(0x1400468a8),
                        },
                    }],
                    succs: vec![0x4010],
                },
                LlirBlock {
                    start_va: 0x4010,
                    end_va: 0x4018,
                    instrs: vec![LlirInstr {
                        va: 0x4010,
                        op: Op::Load {
                            dst: VReg::phys("eax"),
                            addr: MemOp {
                                base: Some(VReg::phys("r15")),
                                index: Some(VReg::phys("rax")),
                                scale: 2,
                                disp: 0,
                                size: 2,
                                ..Default::default()
                            },
                        },
                    }],
                    succs: vec![],
                },
            ],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x140040000, 0x140050000)], 64, 16);
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.from.value == 0x4010 && xref.to.value == 0x1400468a8),
            "successor block should inherit agreed string base"
        );
    }

    #[test]
    fn llir_does_not_merge_conflicting_address_registers() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x4000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x4000,
                    end_va: 0x4004,
                    instrs: vec![LlirInstr {
                        va: 0x4000,
                        op: Op::Nop,
                    }],
                    succs: vec![0x4010, 0x4020],
                },
                LlirBlock {
                    start_va: 0x4010,
                    end_va: 0x4018,
                    instrs: vec![LlirInstr {
                        va: 0x4010,
                        op: Op::Assign {
                            dst: VReg::phys("r15"),
                            src: Value::Addr(0x1400468a8),
                        },
                    }],
                    succs: vec![0x4030],
                },
                LlirBlock {
                    start_va: 0x4020,
                    end_va: 0x4028,
                    instrs: vec![LlirInstr {
                        va: 0x4020,
                        op: Op::Assign {
                            dst: VReg::phys("r15"),
                            src: Value::Addr(0x140014b30),
                        },
                    }],
                    succs: vec![0x4030],
                },
                LlirBlock {
                    start_va: 0x4030,
                    end_va: 0x4038,
                    instrs: vec![LlirInstr {
                        va: 0x4030,
                        op: Op::Load {
                            dst: VReg::phys("eax"),
                            addr: MemOp {
                                base: Some(VReg::phys("r15")),
                                index: None,
                                scale: 1,
                                disp: 0,
                                size: 2,
                                ..Default::default()
                            },
                        },
                    }],
                    succs: vec![],
                },
            ],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x140010000, 0x140050000)], 64, 16);
        assert!(
            !xrefs.iter().any(|xref| xref.from.value == 0x4030),
            "join block should not inherit conflicting predecessor addresses"
        );
    }

    #[test]
    fn llir_tracks_address_register_value_stores_with_aliases() {
        use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, MemOp, Op, VReg, Value};
        let lf = LlirFunction {
            entry_va: 0x5000,
            blocks: vec![LlirBlock {
                start_va: 0x5000,
                end_va: 0x5010,
                instrs: vec![
                    LlirInstr {
                        va: 0x5000,
                        op: Op::Assign {
                            dst: VReg::phys("ecx"),
                            src: Value::Addr(0x140014b30),
                        },
                    },
                    LlirInstr {
                        va: 0x5006,
                        op: Op::Store {
                            addr: MemOp {
                                base: Some(VReg::phys("rdi")),
                                index: None,
                                scale: 1,
                                disp: 0x108,
                                size: 8,
                                ..Default::default()
                            },
                            src: Value::Reg(VReg::phys("rcx")),
                        },
                    },
                ],
                succs: vec![],
            }],
        };
        let xrefs = llir_to_data_xrefs(&lf, &[(0x140010000, 0x140020000)], 64, 16);
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.from.value == 0x5006 && xref.to.value == 0x140014b30),
            "store of address-valued rcx should produce a string xref"
        );
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

        let path =
            Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
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
                if name.contains(".rodata") || name.contains(".data") || name.contains(".bss") {
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
    fn function_data_xrefs_recover_real_pe_rip_relative_string_ref() {
        use crate::core::basic_block::BasicBlock;
        use crate::core::function::{Function, FunctionKind};
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join("ntoskrnl.exe");
        if !path.exists() {
            eprintln!(
                "skipping PE data-xref fixture test: {} is not present",
                path.display()
            );
            return;
        }

        let data = std::fs::read(path).expect("read ntoskrnl.exe");

        let target_va = 0x14003deb0;
        let ranges = data_ranges_for_xrefs(&data);
        assert!(
            ranges
                .iter()
                .any(|(start, end)| target_va >= *start && target_va < *end),
            "expected selected string VA to land in a PE data range"
        );

        let function_va = 0x14029dda0;
        let mut func = Function::new(
            "HalDisableInterrupt".to_string(),
            Address::new(AddressKind::VA, function_va, 64, None, None).unwrap(),
            FunctionKind::Normal,
        )
        .unwrap();
        func.basic_blocks.push(BasicBlock::new(
            "bb0".to_string(),
            Address::new(AddressKind::VA, 0x140496523, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x14049652a, 64, None, None).unwrap(),
            1,
            None,
            None,
        ));

        let xrefs = function_data_xrefs(&data, &[func], 16);
        assert!(
            xrefs.iter().any(|xref| {
                xref.from.value == 0x140496523
                    && xref.to.value == target_va
                    && xref.function_va.value == function_va
            }),
            "expected selected ntoskrnl string xref with exact source and function VAs"
        );
    }

    #[test]
    fn function_data_xrefs_recover_real_pe_register_held_string_ref() {
        use crate::core::basic_block::BasicBlock;
        use crate::core::function::{Function, FunctionKind};
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join("ntoskrnl.exe");
        if !path.exists() {
            eprintln!(
                "skipping PE register-held string-xref fixture test: {} is not present",
                path.display()
            );
            return;
        }

        let data = std::fs::read(path).expect("read ntoskrnl.exe");
        let target_va = 0x1400468a8;
        let function_va = 0x1409d35ec;
        let mut func = Function::new(
            "EncodeAttributeName".to_string(),
            Address::new(AddressKind::VA, function_va, 64, None, None).unwrap(),
            FunctionKind::Normal,
        )
        .unwrap();
        func.basic_blocks.push(BasicBlock::new(
            "bb0".to_string(),
            Address::new(AddressKind::VA, 0x1409d365e, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1409d36cd, 64, None, None).unwrap(),
            16,
            None,
            None,
        ));

        let xrefs = function_data_xrefs(&data, &[func], 32);
        for source_va in [0x1409d365e, 0x1409d3691, 0x1409d36a2] {
            assert!(
                xrefs.iter().any(|xref| {
                    xref.from.value == source_va
                        && xref.to.value == target_va
                        && xref.function_va.value == function_va
                }),
                "expected ntoskrnl register-held string xref from 0x{source_va:x}"
            );
        }
    }

    #[test]
    fn function_data_xrefs_recover_real_pe_known_index_pointer_ref() {
        use crate::core::basic_block::BasicBlock;
        use crate::core::function::{Function, FunctionKind};
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("msvc-pdb")
            .join("ntoskrnl.exe");
        if !path.exists() {
            eprintln!(
                "skipping PE indexed pointer xref fixture test: {} is not present",
                path.display()
            );
            return;
        }

        let data = std::fs::read(path).expect("read ntoskrnl.exe");
        let target_va = 0x140c02690;
        let function_va = 0x140801848;
        let mut func = Function::new(
            "CmpBuildMachineHiveMountPoint".to_string(),
            Address::new(AddressKind::VA, function_va, 64, None, None).unwrap(),
            FunctionKind::Normal,
        )
        .unwrap();
        func.basic_blocks.push(BasicBlock::new(
            "bb0".to_string(),
            Address::new(AddressKind::VA, function_va, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x140801890, 64, None, None).unwrap(),
            17,
            Some(vec!["bb1".to_string(), "bb2".to_string()]),
            None,
        ));
        func.basic_blocks.push(BasicBlock::new(
            "bb1".to_string(),
            Address::new(AddressKind::VA, 0x140801890, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1408018a8, 64, None, None).unwrap(),
            8,
            Some(vec![]),
            Some(vec!["bb0".to_string(), "bb2".to_string()]),
        ));
        func.basic_blocks.push(BasicBlock::new(
            "bb2".to_string(),
            Address::new(AddressKind::VA, 0x1408018a9, 64, None, None).unwrap(),
            Address::new(AddressKind::VA, 0x1408018b4, 64, None, None).unwrap(),
            3,
            Some(vec!["bb1".to_string()]),
            Some(vec!["bb0".to_string()]),
        ));

        let xrefs = function_data_xrefs(&data, &[func], 32);
        assert!(
            xrefs.iter().any(|xref| {
                xref.from.value == 0x1408018a9
                    && xref.to.value == target_va
                    && xref.function_va.value == function_va
            }),
            "expected ntoskrnl known-index pointer xref from 0x1408018a9"
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
