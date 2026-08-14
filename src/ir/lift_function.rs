//! Bridge between CFG-discovered `Function`s and LLIR.
//!
//! The CFG pass in `crate::analysis::cfg` already enumerates every basic
//! block's VA range. This module lifts each block's raw bytes through
//! `lift_x86::lift_bytes` and assembles an `LlirFunction`.
//!
//! Only x86 and x86-64 are supported today (the only ISA the lifter covers);
//! other architectures return `None` so callers can handle the unsupported
//! case explicitly rather than receive a silently-incomplete result.

use crate::analysis::entry::va_to_code_file_offset;
use crate::core::binary::Arch;
use crate::core::function::Function;
use crate::ir::types::*;
use crate::ir::use_def::def_uses;
use crate::ir::{lift_arm32, lift_arm64, lift_x86};

/// Lift a byte window into LLIR using the appropriate per-arch lifter.
///
/// `image` is the whole file the window came from. ARM32 needs it: its
/// constants live in a literal pool read through `ldr Rd,[pc,#imm]`, and the
/// pool sits after the function's last basic block — outside every per-block
/// window this function lifts.
fn lift_window(
    bytes: &[u8],
    start_va: u64,
    arch: Arch,
    thumb: bool,
    image: &[u8],
) -> Vec<LlirInstr> {
    match arch {
        Arch::X86 => lift_x86::lift_bytes(bytes, start_va, 32),
        Arch::X86_64 => lift_x86::lift_bytes(bytes, start_va, 64),
        Arch::AArch64 => lift_arm64::lift_bytes(bytes, start_va),
        Arch::ARM => lift_arm32::lift_bytes_in_image(bytes, start_va, thumb, Some(image)),
        _ => Vec::new(),
    }
}

/// Returns true when an LLIR lifter exists for the given architecture.
pub fn supports_arch(arch: Arch) -> bool {
    matches!(arch, Arch::X86 | Arch::X86_64 | Arch::AArch64 | Arch::ARM)
}

/// Intersect a heuristic basic block with the authoritative chunks owned by
/// `func`.
///
/// CFG recovery can temporarily attach blocks beyond a function boundary (for
/// example, when a requested entry is analysed before the following ELF
/// symbol). DWARF then replaces `func.chunks` with the exact ranges, but the
/// heuristic block list intentionally remains available to analysis clients.
/// The lifter is the semantic boundary: it must never import instructions from
/// a different function. A block that starts in an owned chunk is clipped at
/// that chunk's end; a block that starts outside every chunk is rejected.
/// Legacy `Function`s with no range metadata retain their historical behavior.
fn clip_block_to_owned_ranges(func: &Function, start: u64, end: u64) -> Option<(u64, u64)> {
    if end <= start {
        return None;
    }
    let ranges = func.all_ranges();
    if ranges.is_empty() {
        return Some((start, end));
    }
    ranges.into_iter().find_map(|range| {
        let range_start = range.start.value;
        let range_end = range_start.saturating_add(range.size);
        (start >= range_start && start < range_end).then_some((start, end.min(range_end)))
    })
}

/// An explicit "these bytes were never decoded" marker.
///
/// Design rule 8: a failed proof becomes an explicit unknown, never a silent
/// omission. Bytes we could not read still transfer control and still touch
/// memory, so the marker declares the maximal footprint — reads memory, writes
/// memory, no known outputs. That keeps every dataflow consumer conservative,
/// where dropping the block instead invites the much worse conclusion that the
/// code was never there at all.
fn undecoded_bytes(va: u64) -> LlirInstr {
    LlirInstr {
        va,
        op: Op::Intrinsic {
            name: "undecoded_bytes".to_string(),
            ins: Vec::new(),
            outs: Vec::new(),
            reads_mem: true,
            writes_mem: true,
        },
    }
}

/// Lift every basic block of `func` from `data` into LLIR blocks.
///
/// Returns `None` when the architecture has no LLIR lifter yet.
///
/// Blocks outside every range the function owns belong to a neighbouring
/// function and are excluded. Blocks the function *does* own whose bytes cannot
/// be located, or whose window is clipped by the end of the image, are kept and
/// marked [`undecoded_bytes`] rather than skipped.
pub fn lift_function_from_bytes(data: &[u8], func: &Function, arch: Arch) -> Option<LlirFunction> {
    lift_function(data, func, arch, None)
}

/// Lift a function while reusing the immutable indices in `image`.
pub fn lift_function_from_image(
    image: &crate::program::image::ProgramImage,
    func: &Function,
) -> Option<LlirFunction> {
    image
        .target()
        .code_mode_for_function(func.has_flag(crate::core::function::FunctionFlags::IS_THUMB))?;
    lift_function(
        image.bytes(),
        func,
        image.target().architecture(),
        Some(image),
    )
}

fn lift_function(
    data: &[u8],
    func: &Function,
    arch: Arch,
    image: Option<&crate::program::image::ProgramImage>,
) -> Option<LlirFunction> {
    if !supports_arch(arch) {
        return None;
    }

    let mut blocks: Vec<LlirBlock> = Vec::with_capacity(func.basic_blocks.len());

    for bb in &func.basic_blocks {
        let Some((start, end)) =
            clip_block_to_owned_ranges(func, bb.start_address.value, bb.end_address.value)
        else {
            // Outside every range this function owns, so the block belongs to a
            // neighbouring function. Excluding it — and pruning edges into it
            // below — is correct, not lossy.
            continue;
        };

        // Successors are the CFG successor block starts, which we can recover
        // from bb.successor_ids by finding the corresponding BasicBlock.
        //
        // Computed before the bytes are located, because they must survive the
        // case where the bytes cannot be: a block we failed to decode still
        // transfers control, and dropping its edges would leave the CFG better
        // formed than the truth.
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

        let size = (end - start) as usize;
        let thumb = func.has_flag(crate::core::function::FunctionFlags::IS_THUMB);
        let window = image
            .map_or_else(
                || va_to_code_file_offset(data, start),
                |image| image.va_to_code_file_offset(start),
            )
            .map(|foff| (foff, foff.saturating_add(size).min(data.len())))
            .filter(|(foff, end_off)| foff < end_off);

        let instrs = match window {
            // The VA maps to no file offset, or maps past the end of the image.
            // Emit the block as explicitly undecoded rather than dropping it.
            None => vec![undecoded_bytes(start)],
            Some((foff, end_off)) => {
                let mut instrs = lift_window(&data[foff..end_off], start, arch, thumb, data);
                if end_off - foff < size {
                    // The window was clipped by the end of the image, so this
                    // block's tail was never decoded. A silently short block
                    // reads downstream as a complete one.
                    instrs.push(undecoded_bytes(start + (end_off - foff) as u64));
                }
                instrs
            }
        };

        blocks.push(LlirBlock {
            start_va: start,
            end_va: end,
            instrs,
            succs,
        });
    }

    // A clipped-out target must not survive as a dangling LLIR edge. This is
    // especially important for oversized heuristic graphs corrected by DWARF:
    // their last in-range block can still name the next function's entry.
    let owned_starts: std::collections::HashSet<u64> =
        blocks.iter().map(|block| block.start_va).collect();
    for block in &mut blocks {
        block.succs.retain(|target| owned_starts.contains(target));
    }

    recover_proven_direct_tail_calls(&mut blocks, func);
    resolve_pc_thunk_calls(&mut blocks, |target| {
        image_pc_thunk_register(image, data, arch, target)
    });
    annotate_resolved_switch_indices(&mut blocks);

    if blocks.is_empty() {
        return None;
    }

    // Every SSA/dominance/structuring consumer defines block index zero as the
    // semantic entry. Keep the remaining blocks VA-sorted for determinism, but
    // never let a lower-address cold split become block zero.
    let entry_va = func.entry_point.value;
    blocks.sort_by_key(|block| (block.start_va != entry_va, block.start_va));

    // Both the SysV and Microsoft x86 calling conventions require DF clear at
    // function boundaries. Materialize that ABI fact only for functions that
    // contain a repeated string-memory effect; CLD/STD instructions then
    // replace it through ordinary SSA like any other flag definition.
    let direction_flag = VReg::Flag(Flag::D);
    let needs_direction_flag = blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .any(|instruction| {
            let (_, uses) = def_uses(&instruction.op);
            uses.contains(&direction_flag)
        });
    if needs_direction_flag {
        blocks[0].instrs.insert(
            0,
            LlirInstr {
                va: entry_va,
                op: Op::Assign {
                    dst: VReg::Flag(Flag::D),
                    src: Value::Const(0),
                },
            },
        );
    }

    // Phase 0 (task 0.7): the executable IR has no untyped holes. Rewrite any
    // residual `Op::Unknown` the per-arch lifters emitted into a conservative,
    // footprint-declaring `Op::Intrinsic` so downstream execution/dataflow stays
    // sound. The lifters keep emitting `Unknown` internally (their unit tests
    // assert on it); this pass is the single migration point at the function
    // boundary.
    lower_unknowns(&mut blocks);

    Some(LlirFunction {
        entry_va: func.entry_point.value,
        blocks,
    })
}

/// Attach the normalized index to CFG-proven multiway indirect jumps.
///
/// The x86 instruction itself only says `jmp rax`; the table index is an
/// earlier value in the address expression.  In GCC -O0 the source register is
/// reused for the table base before the load, so retaining a late `rax` use
/// names the table target rather than the switch value.  Snapshotting the
/// recovered index at its last safe point gives SSA and AST lowering an exact
/// value identity, matching the normalized-variable artifact carried by
/// Ghidra/Kuna jump-table recovery.
fn annotate_resolved_switch_indices(blocks: &mut [LlirBlock]) {
    let mut next_temp = blocks
        .iter()
        .flat_map(|block| block.instrs.iter())
        .flat_map(|instruction| {
            let (def, uses) = def_uses(&instruction.op);
            def.into_iter().chain(uses)
        })
        .filter_map(|register| match register {
            VReg::Temp(id) => Some(id),
            _ => None,
        })
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    for block in blocks {
        // Only a CFG-proven dispatch receives this semantic annotation. An
        // arbitrary computed jump with zero/one successor must stay opaque.
        if block.succs.len() < 3 {
            continue;
        }
        let Some(jump_index) = block
            .instrs
            .iter()
            .rposition(|instruction| matches!(instruction.op, Op::IndirectJump { .. }))
        else {
            continue;
        };
        let Some((source, insert_at)) = switch_index_source_before(&block.instrs, jump_index)
        else {
            continue;
        };
        let snapshot = VReg::Temp(next_temp);
        next_temp = next_temp.saturating_add(1);
        let va = block
            .instrs
            .get(insert_at)
            .map_or(block.start_va, |instruction| instruction.va);
        block.instrs.insert(
            insert_at,
            LlirInstr {
                va,
                op: Op::Assign {
                    dst: snapshot.clone(),
                    src: source,
                },
            },
        );
        let adjusted_jump = jump_index + usize::from(insert_at <= jump_index);
        if let Some(LlirInstr {
            op: Op::IndirectJump { index, .. },
            ..
        }) = block.instrs.get_mut(adjusted_jump)
        {
            *index = Some(Value::Reg(snapshot));
        }
    }
}

/// Find the table index and the instruction position before which it must be
/// snapshotted. A locally materialized table address identifies the other
/// component as the index. For a CFG-proven dispatch whose table base was
/// materialized in a predecessor block, the x86 addressing mode itself is
/// sufficient when it has exactly one scale-one base and one scale-four index.
fn switch_index_source_before(
    instructions: &[LlirInstr],
    jump_index: usize,
) -> Option<(Value, usize)> {
    for load_index in (0..jump_index).rev() {
        let Op::Load { addr, .. } = &instructions[load_index].op else {
            continue;
        };
        if addr.size != 4 || addr.disp != 0 {
            continue;
        }
        let mut components = Vec::with_capacity(2);
        if let Some(base) = &addr.base {
            components.push((base, 1u64));
        }
        if let Some(index) = &addr.index {
            components.push((index, u64::from(addr.scale.max(1))));
        }
        let cross_block_index =
            if components.len() == 2 && components.iter().any(|(_, scale)| *scale == 1) {
                components
                    .iter()
                    .find_map(|(register, scale)| (*scale == 4).then_some((*register).clone()))
            } else {
                None
            };
        let has_table_base = components.iter().any(|(register, address_scale)| {
            *address_scale == 1
                && resolves_to_address(instructions, register, load_index, 0).is_some()
        });
        if !has_table_base {
            if let Some(index) = cross_block_index {
                return Some((Value::Reg(index), load_index));
            }
            continue;
        }
        for (register, address_scale) in components {
            if resolves_to_address(instructions, register, load_index, 0).is_some() {
                continue;
            }
            if address_scale == 4 {
                return Some((Value::Reg(register.clone()), load_index));
            }
            if address_scale == 1 {
                if let Some(found) = scaled_index_source(instructions, register, load_index, 0) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn latest_definition(instructions: &[LlirInstr], register: &VReg, before: usize) -> Option<usize> {
    (0..before)
        .rev()
        .find(|index| def_uses(&instructions[*index].op).0.as_ref() == Some(register))
}

fn resolves_to_address(
    instructions: &[LlirInstr],
    register: &VReg,
    before: usize,
    depth: usize,
) -> Option<u64> {
    if depth > 8 {
        return None;
    }
    let definition = latest_definition(instructions, register, before)?;
    match &instructions[definition].op {
        Op::Assign {
            src: Value::Addr(address),
            ..
        } => Some(*address),
        Op::Assign {
            src: Value::Reg(source),
            ..
        }
        | Op::ZExt {
            src: Value::Reg(source),
            ..
        }
        | Op::SExt {
            src: Value::Reg(source),
            ..
        } => resolves_to_address(instructions, source, definition, depth + 1),
        _ => None,
    }
}

fn resolves_to_zero(
    instructions: &[LlirInstr],
    value: &Value,
    before: usize,
    depth: usize,
) -> bool {
    if depth > 8 {
        return false;
    }
    match value {
        Value::Const(0) => true,
        Value::Reg(register) => {
            let Some(definition) = latest_definition(instructions, register, before) else {
                return false;
            };
            match &instructions[definition].op {
                Op::Assign { src, .. } => {
                    resolves_to_zero(instructions, src, definition, depth + 1)
                }
                _ => false,
            }
        }
        Value::Const(_) | Value::Addr(_) => false,
    }
}

fn scaled_index_source(
    instructions: &[LlirInstr],
    register: &VReg,
    before: usize,
    depth: usize,
) -> Option<(Value, usize)> {
    if depth > 8 {
        return None;
    }
    let definition = latest_definition(instructions, register, before)?;
    match &instructions[definition].op {
        Op::Assign {
            src: Value::Reg(source),
            ..
        }
        | Op::ZExt {
            src: Value::Reg(source),
            ..
        }
        | Op::SExt {
            src: Value::Reg(source),
            ..
        } => scaled_index_source(instructions, source, definition, depth + 1),
        Op::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
            ..
        } => match (lhs, rhs) {
            (source @ Value::Reg(_), Value::Const(4))
            | (Value::Const(4), source @ Value::Reg(_)) => Some((source.clone(), definition)),
            _ => None,
        },
        Op::Bin {
            op: BinOp::Shl,
            lhs: source @ Value::Reg(_),
            rhs: Value::Const(2),
            ..
        } => Some((source.clone(), definition)),
        Op::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
            ..
        } => {
            if resolves_to_zero(instructions, lhs, definition, depth + 1) {
                if let Value::Reg(source) = rhs {
                    return scaled_index_source(instructions, source, definition, depth + 1);
                }
            }
            if resolves_to_zero(instructions, rhs, definition, depth + 1) {
                if let Value::Reg(source) = lhs {
                    return scaled_index_source(instructions, source, definition, depth + 1);
                }
            }
            None
        }
        _ => None,
    }
}

/// Materialize CFG-proven nonlocal direct jumps as LLIR tail calls.
///
/// Delaying this conversion until the AST loses the argument-register writes:
/// SSA and value numbering quite reasonably see a plain `Jump` as reading no ABI
/// arguments.  The discovery pass has already separated strong sibling-call
/// targets from local CFG successors and retained their exact addresses in
/// `Function::callees`, so making the call semantics explicit here keeps both the
/// arguments and the returned value live through every downstream pass.
fn recover_proven_direct_tail_calls(blocks: &mut [LlirBlock], func: &Function) {
    let local_starts: std::collections::HashSet<u64> =
        blocks.iter().map(|block| block.start_va).collect();
    let callee_vas: std::collections::HashSet<u64> =
        func.callees.iter().map(|address| address.value).collect();

    for block in blocks {
        // A compiler-split child can first be discovered as a sibling and only
        // later merged into its DWARF parent. Its direct branch may therefore
        // have no relationship metadata even though the target block is now
        // owned locally. Restore that exact machine edge before deciding
        // whether any remaining target is a true tail call.
        if let Some(Op::Jump { target } | Op::CondJump { target, .. }) =
            block.instrs.last().map(|instruction| &instruction.op)
        {
            if local_starts.contains(target) && !block.succs.contains(target) {
                block.succs.push(*target);
            }
        }
        if !block.succs.is_empty() {
            continue;
        }
        let Some(last) = block.instrs.last_mut() else {
            continue;
        };
        let Op::Jump { target } = last.op else {
            continue;
        };
        if local_starts.contains(&target) || !callee_vas.contains(&target) {
            continue;
        }
        let va = last.va;
        last.op = Op::Call {
            target: CallTarget::Direct(target),
            effects: Some(CallEffects {
                is_tail_call: true,
                ..CallEffects::default()
            }),
        };
        block.instrs.push(LlirInstr { va, op: Op::Return });
    }
}

/// Replace each `call <PC thunk>` with the constant address it materialises.
///
/// See [`lift_x86::pc_thunk_register`] for what a PC thunk is and why it is
/// recognised by its body rather than its name. `thunk_register` answers "what
/// does the function at this VA leave in which register", and is a parameter so
/// this rewrite is testable without an ELF image.
///
/// The materialised value is the address of the instruction *after* the call —
/// the return address the thunk loads off the stack. That is the VA of the next
/// LLIR instruction in the block, or the block's end when the call is last.
/// [`Value::Addr`] rather than [`Value::Const`] so `const_fold` folds the
/// following `add $_GLOBAL_OFFSET_TABLE_,%reg` into a single named address,
/// exactly as it already does for the AArch64 `adrp`/`add` pair.
fn resolve_pc_thunk_calls(
    blocks: &mut [LlirBlock],
    thunk_register: impl Fn(u64) -> Option<String>,
) {
    for block in blocks.iter_mut() {
        for index in 0..block.instrs.len() {
            let Op::Call {
                target: CallTarget::Direct(target),
                ..
            } = block.instrs[index].op
            else {
                continue;
            };
            let Some(register) = thunk_register(target) else {
                continue;
            };
            let va = block.instrs[index].va;
            let return_va = block.instrs[index + 1..]
                .iter()
                .map(|instruction| instruction.va)
                .find(|next| *next != va)
                .unwrap_or(block.end_va);
            block.instrs[index].op = Op::Assign {
                dst: VReg::phys(&register),
                src: Value::Addr(return_va),
            };
        }
    }
}

/// The PC-thunk destination register for the function at `va` in `data`, if it
/// is one. Only 32-bit x86 has the idiom: x86-64 addresses everything
/// RIP-relative and never emits it, so the 64-bit lane is left untouched.
fn image_pc_thunk_register(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: Arch,
    va: u64,
) -> Option<String> {
    if arch != Arch::X86 {
        return None;
    }
    let offset = image.map_or_else(
        || va_to_code_file_offset(data, va),
        |image| image.va_to_code_file_offset(va),
    )?;
    let end = offset.saturating_add(4).min(data.len());
    lift_x86::pc_thunk_register(data.get(offset..end)?).map(str::to_string)
}

/// Rewrite every residual [`Op::Unknown`] in `blocks` into a conservative
/// [`Op::Intrinsic`] (see [`Op::opaque`]).
fn lower_unknowns(blocks: &mut [LlirBlock]) {
    for b in blocks.iter_mut() {
        for ins in &mut b.instrs {
            if let Op::Unknown { mnemonic } = &ins.op {
                ins.op = Op::opaque(mnemonic.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
    use std::path::Path;

    /// The i386 PIC preamble `call __x86.get_pc_thunk.bx ; add $GOT,%ebx` must
    /// leave `ebx` holding the address of the instruction after the call — not a
    /// call to a callee with no C spelling.
    #[test]
    fn a_pc_thunk_call_becomes_the_address_it_materialises() {
        let mut blocks = vec![LlirBlock {
            start_va: 0x11ba,
            end_va: 0x11ca,
            instrs: vec![
                LlirInstr {
                    va: 0x11c0,
                    op: Op::Call {
                        target: CallTarget::Direct(0x1380),
                        effects: None,
                    },
                },
                LlirInstr {
                    va: 0x11c5,
                    op: Op::Bin {
                        dst: VReg::phys("ebx"),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::phys("ebx")),
                        rhs: Value::Const(0x2e2f),
                    },
                },
            ],
            succs: vec![],
        }];
        resolve_pc_thunk_calls(&mut blocks, |target| {
            (target == 0x1380).then(|| "ebx".to_string())
        });
        assert_eq!(
            blocks[0].instrs[0].op,
            Op::Assign {
                dst: VReg::phys("ebx"),
                src: Value::Addr(0x11c5),
            }
        );
    }

    /// A thunk call that terminates its block has no following instruction to
    /// read the return address from; the block's end VA is that address.
    #[test]
    fn a_trailing_pc_thunk_call_uses_the_block_end_as_its_return_address() {
        let mut blocks = vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1005,
            instrs: vec![LlirInstr {
                va: 0x1000,
                op: Op::Call {
                    target: CallTarget::Direct(0x2000),
                    effects: None,
                },
            }],
            succs: vec![0x1005],
        }];
        resolve_pc_thunk_calls(&mut blocks, |_| Some("eax".to_string()));
        assert_eq!(
            blocks[0].instrs[0].op,
            Op::Assign {
                dst: VReg::phys("eax"),
                src: Value::Addr(0x1005),
            }
        );
    }

    /// An ordinary callee is not a thunk and must stay a call.
    #[test]
    fn a_non_thunk_call_is_left_alone() {
        let call = Op::Call {
            target: CallTarget::Direct(0x2000),
            effects: None,
        };
        let mut blocks = vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1005,
            instrs: vec![LlirInstr {
                va: 0x1000,
                op: call.clone(),
            }],
            succs: vec![],
        }];
        resolve_pc_thunk_calls(&mut blocks, |_| None);
        assert_eq!(blocks[0].instrs[0].op, call);
    }

    /// x86-64 has RIP-relative addressing and never emits the idiom, so the
    /// image probe must refuse to look at all — the 64-bit lane cannot be
    /// perturbed by this rewrite even if some callee happened to start with
    /// those bytes.
    #[test]
    fn the_pc_thunk_image_probe_is_thirty_two_bit_only() {
        // `mov (%esp),%ebx ; ret` at file offset 0 of a byte blob. The probe is
        // asked about it under both architectures.
        let data = std::fs::read(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0",
        )
        .expect("sample binary");
        let entry = 0u64;
        assert_eq!(
            image_pc_thunk_register(None, &data, Arch::X86_64, entry),
            None
        );
        assert_eq!(image_pc_thunk_register(None, &data, Arch::ARM, entry), None);
    }

    #[test]
    fn resolved_gcc_switch_snapshots_the_index_before_table_base_clobber() {
        let mut blocks = vec![LlirBlock {
            start_va: 0x118a,
            end_va: 0x11ad,
            instrs: vec![
                LlirInstr {
                    va: 0x118c,
                    op: Op::Assign {
                        dst: VReg::Temp(0),
                        src: Value::Const(0),
                    },
                },
                LlirInstr {
                    va: 0x118c,
                    op: Op::Bin {
                        dst: VReg::Temp(1),
                        op: BinOp::Mul,
                        lhs: Value::Reg(VReg::phys("rax")),
                        rhs: Value::Const(4),
                    },
                },
                LlirInstr {
                    va: 0x118c,
                    op: Op::Bin {
                        dst: VReg::Temp(0),
                        op: BinOp::Add,
                        lhs: Value::Reg(VReg::Temp(0)),
                        rhs: Value::Reg(VReg::Temp(1)),
                    },
                },
                LlirInstr {
                    va: 0x118c,
                    op: Op::Assign {
                        dst: VReg::phys("rdx"),
                        src: Value::Reg(VReg::Temp(0)),
                    },
                },
                LlirInstr {
                    va: 0x1194,
                    op: Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Addr(0x2020),
                    },
                },
                LlirInstr {
                    va: 0x119b,
                    op: Op::Load {
                        dst: VReg::Temp(0),
                        addr: MemOp::plain(
                            Some(VReg::phys("rdx")),
                            Some(VReg::phys("rax")),
                            1,
                            0,
                            4,
                        ),
                    },
                },
                LlirInstr {
                    va: 0x11aa,
                    op: Op::IndirectJump {
                        target: Value::Reg(VReg::phys("rax")),
                        index: None,
                    },
                },
            ],
            succs: (0..8).map(|index| 0x1200 + index * 0x10).collect(),
        }];

        annotate_resolved_switch_indices(&mut blocks);

        let (snapshot, source) = blocks[0]
            .instrs
            .iter()
            .find_map(|instruction| match &instruction.op {
                Op::Assign {
                    dst: snapshot @ VReg::Temp(id),
                    src: source @ Value::Reg(VReg::Phys(name)),
                } if *id > 1 && name == "rax" => Some((snapshot.clone(), source.clone())),
                _ => None,
            })
            .expect("snapshot the normalized rax index before assigning the table base to rax");
        assert_eq!(source, Value::Reg(VReg::phys("rax")));
        assert!(matches!(
            blocks[0].instrs.last().map(|instruction| &instruction.op),
            Some(Op::IndirectJump {
                index: Some(Value::Reg(index)),
                ..
            }) if index == &snapshot
        ));
    }

    #[test]
    fn resolved_switch_snapshots_an_index_with_a_cross_block_table_base() {
        let mut blocks = vec![LlirBlock {
            start_va: 0x11bd,
            end_va: 0x11cc,
            instrs: vec![
                LlirInstr {
                    va: 0x11c1,
                    op: Op::Assign {
                        dst: VReg::phys("rax"),
                        src: Value::Reg(VReg::phys("rdx")),
                    },
                },
                LlirInstr {
                    va: 0x11c3,
                    op: Op::Load {
                        dst: VReg::Temp(0),
                        addr: MemOp::plain(
                            Some(VReg::phys("r9")),
                            Some(VReg::phys("rax")),
                            4,
                            0,
                            4,
                        ),
                    },
                },
                LlirInstr {
                    va: 0x11ca,
                    op: Op::IndirectJump {
                        target: Value::Reg(VReg::phys("rax")),
                        index: None,
                    },
                },
            ],
            succs: vec![0x11cc, 0x11e0, 0x11a0, 0x1224],
        }];

        annotate_resolved_switch_indices(&mut blocks);

        assert!(matches!(
            blocks[0].instrs.last().map(|instruction| &instruction.op),
            Some(Op::IndirectJump {
                index: Some(Value::Reg(_)),
                ..
            })
        ));
    }

    #[test]
    fn proven_nonlocal_direct_jump_becomes_tail_call_before_ssa() {
        let entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x1000,
            64,
            None,
            None,
        )
        .unwrap();
        let callee = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x5000,
            64,
            None,
            None,
        )
        .unwrap();
        let mut func = Function::new(
            "tail_wrapper".to_string(),
            entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        func.add_callee(callee);
        let mut blocks = vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1010,
            instrs: vec![
                LlirInstr {
                    va: 0x1000,
                    op: Op::Assign {
                        dst: VReg::phys("esi"),
                        src: Value::Const(24),
                    },
                },
                LlirInstr {
                    va: 0x1005,
                    op: Op::Jump { target: 0x5000 },
                },
            ],
            succs: vec![],
        }];

        recover_proven_direct_tail_calls(&mut blocks, &func);

        assert!(matches!(
            blocks[0].instrs[1].op,
            Op::Call {
                target: CallTarget::Direct(0x5000),
                effects: Some(CallEffects {
                    is_tail_call: true,
                    ..
                })
            }
        ));
        assert!(matches!(blocks[0].instrs[2].op, Op::Return));
    }

    #[test]
    fn local_direct_jump_remains_control_flow() {
        let entry = crate::core::address::Address::new(
            crate::core::address::AddressKind::VA,
            0x1000,
            64,
            None,
            None,
        )
        .unwrap();
        let mut func = Function::new(
            "loop".to_string(),
            entry,
            crate::core::function::FunctionKind::Normal,
        )
        .unwrap();
        func.add_callee(
            crate::core::address::Address::new(
                crate::core::address::AddressKind::VA,
                0x1000,
                64,
                None,
                None,
            )
            .unwrap(),
        );
        let mut blocks = vec![LlirBlock {
            start_va: 0x1000,
            end_va: 0x1010,
            instrs: vec![LlirInstr {
                va: 0x1005,
                op: Op::Jump { target: 0x1000 },
            }],
            succs: vec![],
        }];

        recover_proven_direct_tail_calls(&mut blocks, &func);

        assert!(matches!(
            blocks[0].instrs.as_slice(),
            [LlirInstr {
                op: Op::Jump { target: 0x1000 },
                ..
            }]
        ));
        assert_eq!(
            blocks[0].succs,
            vec![0x1000],
            "an owned jump target must remain an explicit LLIR CFG edge"
        );
    }

    #[test]
    fn lifts_hello_gcc_entry_function() {
        // Real-binary end-to-end: discover functions via cfg, lift the one
        // containing the entry VA, and check that we got sensible LLIR.
        let path =
            Path::new("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
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
            total_timeout_ms: 0,
        };
        let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
        assert!(!funcs.is_empty(), "cfg produced no functions");

        // Lift the first function (entry).
        let f = &funcs[0];
        let lf = lift_function_from_bytes(&data, f, Arch::X86_64).expect("lift function");
        assert_eq!(lf.entry_va, f.entry_point.value);
        assert!(!lf.blocks.is_empty(), "lifted function has no blocks");
        // Every block's start VA must match a block in the source function.
        let src_starts: std::collections::HashSet<u64> = f
            .basic_blocks
            .iter()
            .map(|b| b.start_address.value)
            .collect();
        for b in &lf.blocks {
            assert!(
                src_starts.contains(&b.start_va),
                "block start 0x{:x} not in source function",
                b.start_va
            );
            assert!(
                f.contains_va(b.start_va) && b.end_va > b.start_va && f.contains_va(b.end_va - 1),
                "lifted block [{:#x}, {:#x}) escaped authoritative chunks {:?}",
                b.start_va,
                b.end_va,
                f.all_ranges()
            );
            assert!(
                !b.instrs.is_empty(),
                "empty LLIR block at 0x{:x}",
                b.start_va
            );
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
                Op::Return
                    | Op::Call { .. }
                    | Op::Jump { .. }
                    | Op::CondJump { .. }
                    | Op::CondReturn { .. }
                    // Unmodelled terminators are lowered to Intrinsic (task 0.7).
                    | Op::Intrinsic { .. }
            ),
            "unexpected terminator at 0x{:x}: {:?}",
            last.va,
            last.op
        );

        // Phase 0 task 0.7 exit criterion: a lifted function has NO residual
        // `Op::Unknown` — every unmodelled instruction is a typed Intrinsic.
        for b in &lf.blocks {
            for i in &b.instrs {
                assert!(
                    !matches!(&i.op, Op::Unknown { .. }),
                    "residual Op::Unknown at 0x{:x} after lift",
                    i.va
                );
            }
        }
    }

    #[test]
    fn lowered_functions_have_no_residual_unknown_x86_and_arm64() {
        // Stronger, multi-function form of the exit criterion across both arches.
        for (rel, arch) in [
            (
                "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
                Arch::X86_64,
            ),
            (
                "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
                Arch::AArch64,
            ),
        ] {
            let path = Path::new(rel);
            if !path.exists() {
                continue;
            }
            let data = std::fs::read(path).expect("read sample");
            let budgets = Budgets {
                max_functions: 32,
                max_blocks: 256,
                max_instructions: 20_000,
                timeout_ms: 2000,
                total_timeout_ms: 0,
            };
            let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
            let mut checked = 0;
            for f in &funcs {
                if let Some(lf) = lift_function_from_bytes(&data, f, arch) {
                    for b in &lf.blocks {
                        for i in &b.instrs {
                            assert!(
                                !matches!(&i.op, Op::Unknown { .. }),
                                "residual Op::Unknown at 0x{:x} ({:?})",
                                i.va,
                                arch
                            );
                        }
                    }
                    checked += 1;
                }
            }
            assert!(checked > 0, "no functions lifted for {:?}", arch);
        }
    }

    #[test]
    fn returns_none_for_unsupported_arch() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::function::{Function, FunctionKind};
        let entry = Address::new(AddressKind::VA, 0, 64, None, None).unwrap();
        let f = Function::new("f".into(), entry, FunctionKind::Normal).unwrap();
        assert!(lift_function_from_bytes(&[0u8; 0], &f, Arch::MIPS64).is_none());
        assert!(lift_function_from_bytes(&[0u8; 0], &f, Arch::RISCV64).is_none());
    }

    #[test]
    fn authoritative_chunks_clip_and_reject_heuristic_blocks() {
        use crate::core::address::{Address, AddressKind};
        use crate::core::address_range::AddressRange;
        use crate::core::function::{Function, FunctionKind};

        let entry = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        let mut f = Function::new("bounded".into(), entry, FunctionKind::Normal).unwrap();
        f.add_chunk(
            AddressRange::new(
                Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap(),
                0x10,
                None,
            )
            .unwrap(),
        );
        f.add_chunk(
            AddressRange::new(
                Address::new(AddressKind::VA, 0x2000, 64, None, None).unwrap(),
                0x08,
                None,
            )
            .unwrap(),
        );

        assert_eq!(
            clip_block_to_owned_ranges(&f, 0x1004, 0x1018),
            Some((0x1004, 0x1010))
        );
        assert_eq!(clip_block_to_owned_ranges(&f, 0x1010, 0x1020), None);
        assert_eq!(
            clip_block_to_owned_ranges(&f, 0x2000, 0x2010),
            Some((0x2000, 0x2008))
        );
    }

    #[test]
    fn supports_arch_enumerates_lifters() {
        assert!(supports_arch(Arch::X86));
        assert!(supports_arch(Arch::X86_64));
        assert!(supports_arch(Arch::AArch64));
        assert!(supports_arch(Arch::ARM));
        assert!(!supports_arch(Arch::MIPS));
    }

    #[test]
    fn lifts_hello_arm64_entry_function() {
        let path =
            Path::new("samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc");
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
            total_timeout_ms: 0,
        };
        let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
        assert!(!funcs.is_empty(), "cfg produced no functions for arm64");
        let f = &funcs[0];
        let lf = lift_function_from_bytes(&data, f, Arch::AArch64).expect("lift arm64 function");
        assert_eq!(lf.entry_va, f.entry_point.value);
        assert!(!lf.blocks.is_empty(), "no blocks lifted");
        // At least one block's instr list must be non-empty and contain a
        // recognised op kind.
        assert!(lf.blocks.iter().any(|b| b
            .instrs
            .iter()
            .any(|i| !matches!(&i.op, Op::Unknown { .. }))));
    }

    /// How often does the undecodable path actually fire on real input?
    ///
    /// The marker is the honest representation, but a marker that fires
    /// routinely would mean the lifter is losing real code and the CFG has been
    /// quietly approximate all along. Measured here rather than assumed: across
    /// every sample binary this test can find, no owned block fails to decode.
    /// If that ever stops being true the count is a finding, not a nuisance —
    /// re-read the failing VAs before relaxing the assertion.
    #[test]
    fn no_owned_block_in_the_sample_corpus_is_undecodable() {
        let mut lifted = 0usize;
        let mut undecoded = Vec::new();
        for (rel, arch) in [
            (
                "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
                Arch::X86_64,
            ),
            (
                "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
                Arch::X86_64,
            ),
            (
                "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
                Arch::AArch64,
            ),
        ] {
            let path = Path::new(rel);
            if !path.exists() {
                continue;
            }
            let data = std::fs::read(path).expect("read sample");
            let budgets = Budgets {
                max_functions: 64,
                max_blocks: 512,
                max_instructions: 40_000,
                timeout_ms: 4000,
                total_timeout_ms: 0,
            };
            let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
            for f in &funcs {
                let Some(lf) = lift_function_from_bytes(&data, f, arch) else {
                    continue;
                };
                lifted += 1;
                for block in &lf.blocks {
                    for instr in &block.instrs {
                        if matches!(&instr.op, Op::Intrinsic { name, .. } if name == "undecoded_bytes")
                        {
                            undecoded.push((rel, instr.va));
                        }
                    }
                }
            }
        }
        assert!(lifted > 0, "no sample binary was available to measure");
        assert!(
            undecoded.is_empty(),
            "{} owned block(s) failed to decode across {lifted} functions: {:x?}",
            undecoded.len(),
            undecoded
        );
    }

    /// Build a function of `n` adjacent 4-byte blocks, each falling through to
    /// the next, at VAs that no byte buffer here will ever map.
    #[cfg(test)]
    fn chain_at_unmapped_vas(n: usize) -> crate::core::function::Function {
        use crate::core::address::{Address, AddressKind};
        use crate::core::basic_block::BasicBlock;
        use crate::core::function::{Function, FunctionKind};

        let va = |v: u64| Address::new(AddressKind::VA, v, 64, None, None).unwrap();
        let base = 0x7fff_0000_0000u64;
        let mut f = Function::new("unmapped".into(), va(base), FunctionKind::Normal).unwrap();
        for i in 0..n as u64 {
            let succ = (i + 1 < n as u64).then(|| vec![format!("b{}", i + 1)]);
            f.basic_blocks.push(BasicBlock::new(
                format!("b{i}"),
                va(base + i * 4),
                va(base + i * 4 + 4),
                1,
                succ,
                None,
            ));
        }
        f
    }

    /// Design rule 8: a block we own but cannot decode becomes an explicit
    /// unknown, never a silent omission. Before this, both the block and every
    /// edge into it disappeared, leaving a CFG strictly better formed than the
    /// truth — the one shape no consumer can detect, because there is nothing
    /// left to detect.
    #[test]
    fn undecodable_owned_blocks_survive_as_explicit_unknowns() {
        let f = chain_at_unmapped_vas(3);
        let data = vec![0u8; 16]; // not an object file: nothing maps
        let lf = lift_function_from_bytes(&data, &f, Arch::X86_64)
            .expect("a function of undecodable blocks is still a function");

        assert_eq!(lf.blocks.len(), 3, "every owned block must survive");
        for block in &lf.blocks {
            assert!(
                matches!(
                    block.instrs.as_slice(),
                    [LlirInstr {
                        op: Op::Intrinsic { name, reads_mem: true, writes_mem: true, .. },
                        ..
                    }] if name == "undecoded_bytes"
                ),
                "undecoded block must carry a maximal-footprint marker, got {:?}",
                block.instrs
            );
        }
    }

    /// The edges matter as much as the blocks. A dropped block used to take its
    /// predecessors' edges with it via the `succs.retain` prune below, which is
    /// how an unreadable block turned into a plausible-looking straight line.
    #[test]
    fn edges_into_undecodable_blocks_are_not_pruned() {
        let f = chain_at_unmapped_vas(3);
        let data = vec![0u8; 16];
        let lf = lift_function_from_bytes(&data, &f, Arch::X86_64).expect("lift");

        let succs: Vec<&[u64]> = lf.blocks.iter().map(|b| b.succs.as_slice()).collect();
        assert_eq!(
            succs,
            vec![
                &[0x7fff_0000_0004u64][..],
                &[0x7fff_0000_0008u64][..],
                &[][..],
            ],
            "the chain must stay a chain"
        );
    }
}
