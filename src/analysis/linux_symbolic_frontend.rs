//! Strict Linux AArch64 `ET_REL` handler admission for symbolic execution.
//!
//! Kernel modules use section-relative symbol values, so independently based
//! executable sections can all begin at zero.  The generic image CFG path is
//! therefore not authoritative for `.ko` handlers: it assumes globally unique
//! virtual addresses.  This module gives each section a deterministic synthetic
//! address range before lifting one exact function into executable LLIR.

use crate::ir::lift_arm64;
use crate::ir::types::{BinOp, CallTarget, LlirBlock, LlirFunction, LlirInstr, Op, Value};
use object::read::{Object, ObjectSection, ObjectSymbol};
use object::{
    Architecture, BinaryFormat, ObjectKind, RelocationFlags, RelocationTarget, SectionKind,
    SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

const SYNTHETIC_SECTION_BASE: u64 = 0x0000_1000_0000_0000;
const SYNTHETIC_SECTION_STRIDE: u64 = 0x0000_0001_0000_0000;
const SYNTHETIC_EXTERNAL_BASE: u64 = 0x0000_f000_0000_0000;
const SYNTHETIC_EXTERNAL_STRIDE: u64 = 0x1000;

/// A control-flow relocation applied while admitting a handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxHandlerRelocation {
    pub handler_offset: u64,
    pub kind: String,
    pub target_symbol: String,
    pub target_va: u64,
    pub addend: i64,
}

/// A Linux kernel handler admitted to the symbolic-execution frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSymbolicFunction {
    pub symbol: String,
    pub section: String,
    pub section_index: usize,
    pub section_offset: u64,
    pub synthetic_va: u64,
    pub size: u64,
    /// Exact bytes that produced `llir`, retained for replay and hashing.
    pub bytes: Vec<u8>,
    /// Every supported in-handler control-flow relocation, in offset order.
    pub relocations: Vec<LinuxHandlerRelocation>,
    /// Synthetic external target VA to stable ELF symbol name.
    pub external_calls: BTreeMap<u64, String>,
    /// Direct same-section callee VA to stable ELF symbol name.
    pub local_calls: BTreeMap<u64, String>,
    pub llir: LlirFunction,
}

/// Fail-closed reasons why a candidate cannot enter symbolic execution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinuxSymbolicFrontendError {
    #[error("input is not a supported object file: {0}")]
    Parse(String),
    #[error("expected an ELF relocatable object, found {0}")]
    NotRelocatable(String),
    #[error("expected AArch64, found {0}")]
    UnsupportedArchitecture(String),
    #[error("handler symbol `{0}` was not found")]
    MissingSymbol(String),
    #[error("handler symbol `{0}` is ambiguous")]
    AmbiguousSymbol(String),
    #[error("handler symbol `{symbol}` is not defined text (kind {kind})")]
    NotText { symbol: String, kind: String },
    #[error("handler symbol `{0}` has zero size")]
    ZeroSizedSymbol(String),
    #[error("handler symbol `{symbol}` range [{start:#x}, {end:#x}) is outside section `{section}` ({section_size:#x} bytes)")]
    SymbolOutOfBounds {
        symbol: String,
        section: String,
        start: u64,
        end: u64,
        section_size: u64,
    },
    #[error("handler symbol `{symbol}` has non-AArch64-aligned size {size}")]
    MisalignedSymbol { symbol: String, size: u64 },
    #[error("handler symbol `{symbol}` decoded only {decoded_bytes} of {size} bytes")]
    IncompleteDecode {
        symbol: String,
        decoded_bytes: u64,
        size: u64,
    },
    #[error("handler symbol `{symbol}` has unsupported control-flow instruction `{mnemonic}` at +{offset:#x}")]
    UnsupportedControlFlow {
        symbol: String,
        offset: u64,
        mnemonic: String,
    },
    #[error("handler symbol `{symbol}` has unsupported relocation {kind} at +{offset:#x}")]
    UnsupportedRelocation {
        symbol: String,
        offset: u64,
        kind: String,
    },
    #[error(
        "handler symbol `{symbol}` relocation at +{offset:#x} has unsupported target {target}"
    )]
    UnsupportedRelocationTarget {
        symbol: String,
        offset: u64,
        target: String,
    },
    #[error("handler symbol `{symbol}` relocation {kind} at +{offset:#x} did not match lifted control flow")]
    RelocationApplication {
        symbol: String,
        offset: u64,
        kind: String,
    },
}

/// Admit one exact AArch64 handler from an ELF relocatable object.
pub fn admit_linux_aarch64_handler(
    data: &[u8],
    symbol: &str,
) -> Result<LinuxSymbolicFunction, LinuxSymbolicFrontendError> {
    let object = object::read::File::parse(data)
        .map_err(|error| LinuxSymbolicFrontendError::Parse(error.to_string()))?;
    if object.format() != BinaryFormat::Elf || object.kind() != ObjectKind::Relocatable {
        return Err(LinuxSymbolicFrontendError::NotRelocatable(format!(
            "{:?}/{:?}",
            object.format(),
            object.kind()
        )));
    }
    if object.architecture() != Architecture::Aarch64 {
        return Err(LinuxSymbolicFrontendError::UnsupportedArchitecture(
            format!("{:?}", object.architecture()),
        ));
    }

    let mut matches = object
        .symbols()
        .filter(|candidate| candidate.name().ok() == Some(symbol));
    let candidate = matches
        .next()
        .ok_or_else(|| LinuxSymbolicFrontendError::MissingSymbol(symbol.to_string()))?;
    if matches.next().is_some() {
        return Err(LinuxSymbolicFrontendError::AmbiguousSymbol(
            symbol.to_string(),
        ));
    }
    let Some(section_index) = candidate.section_index() else {
        return Err(LinuxSymbolicFrontendError::NotText {
            symbol: symbol.to_string(),
            kind: format!("{:?}/undefined", candidate.kind()),
        });
    };
    let section = object.section_by_index(section_index).map_err(|error| {
        LinuxSymbolicFrontendError::Parse(format!(
            "cannot read section {} for `{symbol}`: {error}",
            section_index.0
        ))
    })?;
    if candidate.kind() != SymbolKind::Text || section.kind() != SectionKind::Text {
        return Err(LinuxSymbolicFrontendError::NotText {
            symbol: symbol.to_string(),
            kind: format!("{:?}/{:?}", candidate.kind(), section.kind()),
        });
    }
    let size = candidate.size();
    if size == 0 {
        return Err(LinuxSymbolicFrontendError::ZeroSizedSymbol(
            symbol.to_string(),
        ));
    }
    if size % 4 != 0 {
        return Err(LinuxSymbolicFrontendError::MisalignedSymbol {
            symbol: symbol.to_string(),
            size,
        });
    }

    let section_name = section.name().unwrap_or("<unnamed>").to_string();
    let section_data = section.data().map_err(|error| {
        LinuxSymbolicFrontendError::Parse(format!(
            "cannot read section `{section_name}` for `{symbol}`: {error}"
        ))
    })?;
    let Some(section_offset) = candidate.address().checked_sub(section.address()) else {
        return Err(LinuxSymbolicFrontendError::SymbolOutOfBounds {
            symbol: symbol.to_string(),
            section: section_name,
            start: candidate.address(),
            end: candidate.address().saturating_add(size),
            section_size: section_data.len() as u64,
        });
    };
    let end = section_offset.saturating_add(size);
    if end > section_data.len() as u64 {
        return Err(LinuxSymbolicFrontendError::SymbolOutOfBounds {
            symbol: symbol.to_string(),
            section: section_name,
            start: section_offset,
            end,
            section_size: section_data.len() as u64,
        });
    }
    let bytes = section_data[section_offset as usize..end as usize].to_vec();
    let section_base = SYNTHETIC_SECTION_BASE
        .checked_add((section_index.0 as u64).saturating_mul(SYNTHETIC_SECTION_STRIDE))
        .ok_or_else(|| LinuxSymbolicFrontendError::Parse("synthetic VA overflow".to_string()))?;
    let synthetic_va = section_base.checked_add(section_offset).ok_or_else(|| {
        LinuxSymbolicFrontendError::Parse("synthetic handler VA overflow".to_string())
    })?;

    let mut instructions = lift_arm64::lift_bytes(&bytes, synthetic_va);
    let decoded_vas: BTreeSet<u64> = instructions
        .iter()
        .map(|instruction| instruction.va)
        .collect();
    let decoded_bytes = decoded_vas.len() as u64 * 4;
    let complete = decoded_bytes == size
        && (0..size / 4).all(|index| decoded_vas.contains(&(synthetic_va + index * 4)));
    if !complete {
        return Err(LinuxSymbolicFrontendError::IncompleteDecode {
            symbol: symbol.to_string(),
            decoded_bytes,
            size,
        });
    }
    for instruction in &mut instructions {
        if let Op::Unknown { mnemonic } = &instruction.op {
            if is_unmodeled_control_flow(mnemonic) {
                return Err(LinuxSymbolicFrontendError::UnsupportedControlFlow {
                    symbol: symbol.to_string(),
                    offset: instruction.va.saturating_sub(synthetic_va),
                    mnemonic: mnemonic.clone(),
                });
            }
            instruction.op = Op::opaque(mnemonic.clone());
        }
    }
    let (relocations, external_calls) = apply_control_relocations(
        &object,
        &section,
        section_offset,
        size,
        synthetic_va,
        symbol,
        &mut instructions,
    )?;
    let direct_targets = instructions
        .iter()
        .filter_map(|instruction| match instruction.op {
            Op::Call {
                target: CallTarget::Direct(target),
            } => Some(target),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut local_names = BTreeMap::<u64, BTreeSet<String>>::new();
    for local in object.symbols().filter(|local| {
        local.kind() == SymbolKind::Text && local.section_index() == Some(section_index)
    }) {
        let Some(offset) = local.address().checked_sub(section.address()) else {
            continue;
        };
        let Some(target_va) = section_base.checked_add(offset) else {
            continue;
        };
        if target_va == synthetic_va || !direct_targets.contains(&target_va) {
            continue;
        }
        if let Ok(name) = local.name() {
            if !name.is_empty() {
                local_names
                    .entry(target_va)
                    .or_default()
                    .insert(name.to_string());
            }
        }
    }
    let local_calls = local_names
        .into_iter()
        .filter_map(|(target, names)| names.into_iter().next().map(|name| (target, name)))
        .collect();
    let llir = build_cfg(instructions, synthetic_va, synthetic_va + size);

    Ok(LinuxSymbolicFunction {
        symbol: symbol.to_string(),
        section: section_name,
        section_index: section_index.0,
        section_offset,
        synthetic_va,
        size,
        bytes,
        relocations,
        external_calls,
        local_calls,
        llir,
    })
}

/// Unknown data-processing instructions halt execution conservatively, but an
/// unknown branch or trap would corrupt the CFG before execution could see it.
/// Keep this list deliberately broad and fail admission before CFG recovery.
fn is_unmodeled_control_flow(mnemonic: &str) -> bool {
    mnemonic == "b"
        || mnemonic.starts_with("b.")
        || matches!(
            mnemonic,
            "bl" | "blr"
                | "br"
                | "braa"
                | "brab"
                | "braaz"
                | "brabz"
                | "blraa"
                | "blrab"
                | "blraaz"
                | "blrabz"
                | "cbz"
                | "cbnz"
                | "tbz"
                | "tbnz"
                | "ret"
                | "retaa"
                | "retab"
                | "eret"
                | "eretaa"
                | "eretab"
                | "drps"
        )
}

fn is_halting_intrinsic(op: &Op) -> bool {
    matches!(
        op,
        Op::Intrinsic { name, .. }
            if matches!(
                name.as_str(),
                "brk" | "hlt" | "svc" | "hvc" | "smc" | "udf" | "dcps1" | "dcps2" | "dcps3"
            )
    )
}

fn relocation_kind(flags: RelocationFlags) -> Option<(&'static str, u32)> {
    let RelocationFlags::Elf { r_type } = flags else {
        return None;
    };
    match r_type {
        object::elf::R_AARCH64_CALL26 => Some(("R_AARCH64_CALL26", r_type)),
        object::elf::R_AARCH64_JUMP26 => Some(("R_AARCH64_JUMP26", r_type)),
        object::elf::R_AARCH64_ADR_PREL_PG_HI21 => Some(("R_AARCH64_ADR_PREL_PG_HI21", r_type)),
        object::elf::R_AARCH64_ADD_ABS_LO12_NC => Some(("R_AARCH64_ADD_ABS_LO12_NC", r_type)),
        object::elf::R_AARCH64_LDST8_ABS_LO12_NC => Some(("R_AARCH64_LDST8_ABS_LO12_NC", r_type)),
        object::elf::R_AARCH64_LDST32_ABS_LO12_NC => Some(("R_AARCH64_LDST32_ABS_LO12_NC", r_type)),
        object::elf::R_AARCH64_LDST64_ABS_LO12_NC => Some(("R_AARCH64_LDST64_ABS_LO12_NC", r_type)),
        _ => None,
    }
}

fn section_synthetic_base(index: usize) -> Option<u64> {
    SYNTHETIC_SECTION_BASE.checked_add((index as u64).checked_mul(SYNTHETIC_SECTION_STRIDE)?)
}

fn add_signed(base: u64, addend: i64) -> Option<u64> {
    if addend >= 0 {
        base.checked_add(addend as u64)
    } else {
        base.checked_sub(addend.unsigned_abs())
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_control_relocations<'data, 'file>(
    object: &object::read::File<'data>,
    section: &object::read::Section<'data, 'file>,
    handler_section_offset: u64,
    handler_size: u64,
    handler_va: u64,
    handler_symbol: &str,
    instructions: &mut [LlirInstr],
) -> Result<(Vec<LinuxHandlerRelocation>, BTreeMap<u64, String>), LinuxSymbolicFrontendError> {
    let handler_end = handler_section_offset.saturating_add(handler_size);
    let relevant: Vec<_> = section
        .relocations()
        .filter(|(offset, _)| *offset >= handler_section_offset && *offset < handler_end)
        .collect();

    let mut external_names = BTreeSet::new();
    for (_, relocation) in &relevant {
        let RelocationTarget::Symbol(index) = relocation.target() else {
            continue;
        };
        let target = object.symbol_by_index(index).map_err(|error| {
            LinuxSymbolicFrontendError::Parse(format!(
                "cannot read relocation target {}: {error}",
                index.0
            ))
        })?;
        if target.section_index().is_none() {
            external_names.insert(target.name().unwrap_or("<unnamed>").to_string());
        }
    }
    let external_vas: BTreeMap<String, u64> = external_names
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            (
                name,
                SYNTHETIC_EXTERNAL_BASE + index as u64 * SYNTHETIC_EXTERNAL_STRIDE,
            )
        })
        .collect();

    let mut applied = Vec::new();
    let mut external_calls = BTreeMap::new();
    for (section_relocation_offset, relocation) in relevant {
        let handler_offset = section_relocation_offset - handler_section_offset;
        let kind = relocation_kind(relocation.flags()).ok_or_else(|| {
            LinuxSymbolicFrontendError::UnsupportedRelocation {
                symbol: handler_symbol.to_string(),
                offset: handler_offset,
                kind: format!("{:?}", relocation.flags()),
            }
        })?;
        let RelocationTarget::Symbol(target_index) = relocation.target() else {
            return Err(LinuxSymbolicFrontendError::UnsupportedRelocationTarget {
                symbol: handler_symbol.to_string(),
                offset: handler_offset,
                target: format!("{:?}", relocation.target()),
            });
        };
        let target = object.symbol_by_index(target_index).map_err(|error| {
            LinuxSymbolicFrontendError::Parse(format!(
                "cannot read relocation target {}: {error}",
                target_index.0
            ))
        })?;
        let target_name = target.name().unwrap_or("<unnamed>").to_string();
        let base_target_va = if let Some(target_section_index) = target.section_index() {
            let target_section =
                object
                    .section_by_index(target_section_index)
                    .map_err(|error| {
                        LinuxSymbolicFrontendError::Parse(format!(
                            "cannot read target section {}: {error}",
                            target_section_index.0
                        ))
                    })?;
            let target_offset = target
                .address()
                .checked_sub(target_section.address())
                .ok_or_else(|| LinuxSymbolicFrontendError::UnsupportedRelocationTarget {
                    symbol: handler_symbol.to_string(),
                    offset: handler_offset,
                    target: target_name.clone(),
                })?;
            section_synthetic_base(target_section_index.0)
                .and_then(|base| base.checked_add(target_offset))
                .ok_or_else(|| {
                    LinuxSymbolicFrontendError::Parse("target VA overflow".to_string())
                })?
        } else {
            *external_vas.get(&target_name).ok_or_else(|| {
                LinuxSymbolicFrontendError::UnsupportedRelocationTarget {
                    symbol: handler_symbol.to_string(),
                    offset: handler_offset,
                    target: target_name.clone(),
                }
            })?
        };
        let target_va = add_signed(base_target_va, relocation.addend()).ok_or_else(|| {
            LinuxSymbolicFrontendError::Parse("relocation addend overflow".to_string())
        })?;
        let instruction_va = handler_va + handler_offset;
        let mut matched = false;
        for instruction in instructions
            .iter_mut()
            .filter(|item| item.va == instruction_va)
        {
            match kind.1 {
                object::elf::R_AARCH64_CALL26 if matches!(instruction.op, Op::Call { .. }) => {
                    instruction.op = Op::Call {
                        target: CallTarget::Direct(target_va),
                    };
                    matched = true;
                }
                object::elf::R_AARCH64_JUMP26 if matches!(instruction.op, Op::Jump { .. }) => {
                    instruction.op = Op::Jump { target: target_va };
                    matched = true;
                }
                object::elf::R_AARCH64_ADR_PREL_PG_HI21 => {
                    if let Op::Assign { src, .. } = &mut instruction.op {
                        *src = Value::Addr(target_va & !0xfff);
                        matched = true;
                    }
                }
                object::elf::R_AARCH64_ADD_ABS_LO12_NC => {
                    if let Op::Bin {
                        op: BinOp::Add,
                        rhs,
                        ..
                    } = &mut instruction.op
                    {
                        *rhs = Value::Const((target_va & 0xfff) as i64);
                        matched = true;
                    }
                }
                object::elf::R_AARCH64_LDST8_ABS_LO12_NC
                | object::elf::R_AARCH64_LDST32_ABS_LO12_NC
                | object::elf::R_AARCH64_LDST64_ABS_LO12_NC => match &mut instruction.op {
                    Op::Load { addr, .. } | Op::Store { addr, .. } => {
                        addr.disp = (target_va & 0xfff) as i64;
                        matched = true;
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        if !matched {
            return Err(LinuxSymbolicFrontendError::RelocationApplication {
                symbol: handler_symbol.to_string(),
                offset: handler_offset,
                kind: kind.0.to_string(),
            });
        }
        if target.section_index().is_none()
            && matches!(
                kind.1,
                object::elf::R_AARCH64_CALL26 | object::elf::R_AARCH64_JUMP26
            )
        {
            external_calls.insert(target_va, target_name.clone());
        }
        applied.push(LinuxHandlerRelocation {
            handler_offset,
            kind: kind.0.to_string(),
            target_symbol: target_name,
            target_va,
            addend: relocation.addend(),
        });
    }
    applied.sort_by(|left, right| {
        left.handler_offset
            .cmp(&right.handler_offset)
            .then(left.target_symbol.cmp(&right.target_symbol))
    });
    Ok((applied, external_calls))
}

fn build_cfg(instructions: Vec<LlirInstr>, entry: u64, end: u64) -> LlirFunction {
    let mut boundaries = BTreeSet::from([entry, end]);
    for instruction in &instructions {
        match &instruction.op {
            Op::Jump { target } | Op::CondJump { target, .. } => {
                if *target >= entry && *target < end {
                    boundaries.insert(*target);
                }
                if instruction.va + 4 < end {
                    boundaries.insert(instruction.va + 4);
                }
            }
            Op::Return => {
                if instruction.va + 4 < end {
                    boundaries.insert(instruction.va + 4);
                }
            }
            op if is_halting_intrinsic(op) => {
                if instruction.va + 4 < end {
                    boundaries.insert(instruction.va + 4);
                }
            }
            _ => {}
        }
    }

    let starts: Vec<u64> = boundaries.into_iter().collect();
    let mut blocks = Vec::new();
    for window in starts.windows(2) {
        let start = window[0];
        let block_end = window[1];
        if start >= end {
            continue;
        }
        let block_instructions: Vec<LlirInstr> = instructions
            .iter()
            .filter(|instruction| instruction.va >= start && instruction.va < block_end)
            .cloned()
            .collect();
        if block_instructions.is_empty() {
            continue;
        }

        let last_va = block_instructions
            .last()
            .map(|instruction| instruction.va)
            .unwrap_or(start);
        let terminal_ops: Vec<&Op> = block_instructions
            .iter()
            .filter(|instruction| instruction.va == last_va)
            .map(|instruction| &instruction.op)
            .collect();
        let mut succs = Vec::new();
        if terminal_ops
            .iter()
            .any(|op| matches!(op, Op::Return) || is_halting_intrinsic(op))
        {
            // no successor
        } else if let Some(target) = terminal_ops.iter().find_map(|op| match op {
            Op::Jump { target } => Some(*target),
            _ => None,
        }) {
            if target >= entry && target < end {
                succs.push(target);
            }
        } else if let Some(target) = terminal_ops.iter().find_map(|op| match op {
            Op::CondJump { target, .. } => Some(*target),
            _ => None,
        }) {
            if target >= entry && target < end {
                succs.push(target);
            }
            if block_end < end {
                succs.push(block_end);
            }
        } else if block_end < end {
            succs.push(block_end);
        }
        succs.sort_unstable();
        succs.dedup();
        blocks.push(LlirBlock {
            start_va: start,
            end_va: block_end,
            instrs: block_instructions,
            succs,
        });
    }

    LlirFunction {
        entry_va: entry,
        blocks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::Op;

    fn real_ko() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/android/foo_drv.ko");
        std::fs::read(path).expect("read real AArch64 ET_REL fixture")
    }

    fn relocation_ko() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/android/reloc_drv.ko");
        std::fs::read(path).expect("read AArch64 text-relocation fixture")
    }

    #[test]
    fn admits_zero_offset_handler_from_real_aarch64_et_rel() {
        let admitted =
            admit_linux_aarch64_handler(&real_ko(), "foo_ioctl").expect("admit exact handler");

        assert_eq!(admitted.symbol, "foo_ioctl");
        assert_eq!(admitted.section, ".text");
        assert_eq!(admitted.section_offset, 0);
        assert_eq!(admitted.size, 104);
        assert_ne!(admitted.synthetic_va, 0);
        assert_eq!(admitted.llir.entry_va, admitted.synthetic_va);
        assert!(admitted.llir.blocks.len() > 1, "handler CFG was split");
        assert_eq!(admitted.llir.blocks[0].start_va, admitted.synthetic_va);

        let mut machine_vas = std::collections::BTreeSet::new();
        for block in &admitted.llir.blocks {
            assert!(!block.instrs.is_empty());
            for instruction in &block.instrs {
                machine_vas.insert(instruction.va);
                assert!(
                    !matches!(instruction.op, Op::Unknown { .. }),
                    "executable boundary retained an untyped hole"
                );
            }
        }
        assert_eq!(machine_vas.len(), 26, "all 104 bytes decoded exactly once");
    }

    #[test]
    fn admission_is_byte_deterministic() {
        let data = real_ko();
        let first = admit_linux_aarch64_handler(&data, "foo_ioctl").unwrap();
        let second = admit_linux_aarch64_handler(&data, "foo_ioctl").unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn resolves_call26_to_named_deterministic_external_target() {
        let admitted = admit_linux_aarch64_handler(&relocation_ko(), "reloc_ioctl")
            .expect("admit relocated handler");
        assert_eq!(admitted.relocations.len(), 9);
        let kinds: BTreeSet<&str> = admitted
            .relocations
            .iter()
            .map(|relocation| relocation.kind.as_str())
            .collect();
        assert_eq!(
            kinds,
            BTreeSet::from([
                "R_AARCH64_ADR_PREL_PG_HI21",
                "R_AARCH64_ADD_ABS_LO12_NC",
                "R_AARCH64_CALL26",
                "R_AARCH64_LDST8_ABS_LO12_NC",
                "R_AARCH64_LDST32_ABS_LO12_NC",
                "R_AARCH64_LDST64_ABS_LO12_NC",
            ])
        );
        let relocation = admitted
            .relocations
            .iter()
            .find(|relocation| relocation.kind == "R_AARCH64_CALL26")
            .expect("call relocation");
        assert_eq!(relocation.handler_offset, 0x2c);
        assert_eq!(relocation.target_symbol, "external_copy_from_user");
        assert!(relocation.target_va >= SYNTHETIC_EXTERNAL_BASE);

        let call_va = admitted.synthetic_va + relocation.handler_offset;
        let call = admitted
            .llir
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .find(|instruction| instruction.va == call_va)
            .expect("relocated call instruction");
        assert_eq!(
            call.op,
            Op::Call {
                target: crate::ir::types::CallTarget::Direct(relocation.target_va)
            }
        );
        assert_eq!(
            admitted.external_calls.get(&relocation.target_va),
            Some(&"external_copy_from_user".to_string())
        );
        assert_eq!(admitted.local_calls.len(), 1);
        let (&local_target, local_name) = admitted.local_calls.iter().next().unwrap();
        assert_eq!(local_name, "local_adjust");
        assert!(admitted
            .llir
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .any(|instruction| {
                instruction.op
                    == Op::Call {
                        target: crate::ir::types::CallTarget::Direct(local_target),
                    }
            }));

        let add = admitted
            .relocations
            .iter()
            .find(|item| item.kind == "R_AARCH64_ADD_ABS_LO12_NC")
            .expect("low12 add relocation");
        assert_eq!(add.addend, 37);
        let add_op = admitted
            .llir
            .blocks
            .iter()
            .flat_map(|block| &block.instrs)
            .find(|instruction| instruction.va == admitted.synthetic_va + add.handler_offset)
            .map(|instruction| &instruction.op)
            .expect("relocated add");
        assert!(matches!(
            add_op,
            Op::Bin {
                rhs: crate::ir::types::Value::Const(37),
                ..
            }
        ));
    }

    #[test]
    fn rejects_non_object_input_precisely() {
        let error = admit_linux_aarch64_handler(b"not an elf", "handler").unwrap_err();
        assert!(matches!(error, LinuxSymbolicFrontendError::Parse(_)));
        assert!(error.to_string().contains("supported object file"));
    }

    #[test]
    fn rejects_wrong_architecture_before_symbol_lookup() {
        let mut data = real_ko();
        // ELF64 e_machine is bytes 18..20. EM_X86_64 = 62.
        data[18..20].copy_from_slice(&62u16.to_le_bytes());
        let error = admit_linux_aarch64_handler(&data, "handler").unwrap_err();
        assert_eq!(
            error,
            LinuxSymbolicFrontendError::UnsupportedArchitecture("X86_64".to_string())
        );
    }

    #[test]
    fn rejects_missing_symbol_precisely() {
        let error = admit_linux_aarch64_handler(&real_ko(), "absent_handler").unwrap_err();
        assert_eq!(
            error,
            LinuxSymbolicFrontendError::MissingSymbol("absent_handler".to_string())
        );
    }

    #[test]
    fn rejects_non_text_symbol() {
        let error = admit_linux_aarch64_handler(&real_ko(), "foo_fops").unwrap_err();
        assert!(matches!(error, LinuxSymbolicFrontendError::NotText { .. }));
    }

    #[test]
    fn trap_intrinsic_terminates_its_cfg_block() {
        let mut data = real_ko();
        let object = object::read::File::parse(data.as_slice()).expect("parse fixture");
        let text = object.section_by_name(".text").expect("text section");
        let (file_offset, _) = text.file_range().expect("file-backed text");
        drop(object);

        // BRK #0 = 0xd4200000 (little endian). It must be an explicit halting
        // intrinsic rather than an opaque fall-through instruction.
        data[file_offset as usize..file_offset as usize + 4]
            .copy_from_slice(&[0x00, 0x00, 0x20, 0xd4]);
        let admitted = admit_linux_aarch64_handler(&data, "foo_ioctl").expect("admit trap");
        let entry = admitted
            .llir
            .blocks
            .iter()
            .find(|block| block.start_va == admitted.synthetic_va)
            .expect("entry block");
        assert!(entry.succs.is_empty(), "trap block must not fall through");
        assert!(matches!(
            &entry.instrs[0].op,
            Op::Intrinsic { name, .. } if name == "brk"
        ));
    }

    #[test]
    fn rejects_unmodeled_control_before_cfg_recovery() {
        let mut data = real_ko();
        let object = object::read::File::parse(data.as_slice()).expect("parse fixture");
        let text = object.section_by_name(".text").expect("text section");
        let (file_offset, _) = text.file_range().expect("file-backed text");
        drop(object);

        // ERET = 0xd69f03e0 (little endian). No v1 kernel-handler execution
        // semantics exist, so admission must fail instead of inventing an edge.
        data[file_offset as usize..file_offset as usize + 4]
            .copy_from_slice(&[0xe0, 0x03, 0x9f, 0xd6]);
        let error = admit_linux_aarch64_handler(&data, "foo_ioctl").unwrap_err();
        assert_eq!(
            error,
            LinuxSymbolicFrontendError::UnsupportedControlFlow {
                symbol: "foo_ioctl".to_string(),
                offset: 0,
                mnemonic: "eret".to_string(),
            }
        );
    }
}
