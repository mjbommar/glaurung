//! Conservative machine-level evidence for multi-register call results.
//!
//! A callee defining a second ABI result register is not enough to claim an
//! aggregate result: ordinary scalar functions can leave scratch residue in
//! that register. A caller reading a second result register is not enough
//! either: without a callee definition it is merely an undefined live-in.
//! This module joins both facts and deliberately recognizes only direct calls.

use std::collections::{HashMap, VecDeque};

use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, CallTarget, LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::use_def::{for_each_def, for_each_use};

/// Whether this exact direct-call boundary proves a two-register INTEGER result.
#[cfg(test)]
fn proves_integer_pair_return(
    caller: &LlirFunction,
    callee: &LlirFunction,
    target: u64,
    cc: CallConv,
) -> bool {
    caller_observes_integer_pair(caller, target, cc)
        && callee_defines_integer_pair_on_every_return(callee, cc)
}

/// Require both halves to be consumed after the call, using the original
/// registers or full-width stack spills reloaded in the same block. A stack
/// write without a read is insufficient: outgoing areas also contain padding.
/// The bounded same-block walk is intentional: crossing a CFG
/// join would require reaching-definition identity, and declining that shape is
/// safer than attributing an unrelated later register use to this call.
pub(crate) fn caller_observes_integer_pair(
    caller: &LlirFunction,
    target: u64,
    cc: CallConv,
) -> bool {
    caller_observes_integer_pair_impl(caller, target, cc, None)
}

/// Include machine-proven stack inputs of a subsequent direct receiver.
pub(crate) fn caller_observes_integer_pair_in_image(
    caller: &LlirFunction,
    target: u64,
    cc: CallConv,
    image: &crate::program::image::ProgramImage,
) -> bool {
    caller_observes_integer_pair_impl(caller, target, cc, Some(image))
}

fn caller_observes_integer_pair_impl(
    caller: &LlirFunction,
    target: u64,
    cc: CallConv,
    image: Option<&crate::program::image::ProgramImage>,
) -> bool {
    if crate::ir::abi::wide_integer_return_pair(cc, crate::ir::abi::wide_integer_return_width(cc))
        .is_none()
    {
        return false;
    }

    let stack_entries = stack_coordinate_entries(caller, cc);
    for (block_index, block) in caller.blocks.iter().enumerate() {
        for (call_index, instruction) in block.instrs.iter().enumerate() {
            if !matches!(
                instruction.op,
                Op::Call {
                    target: CallTarget::Direct(found),
                    ..
                } if found == target
            ) {
                continue;
            }
            let mut observed = [false; 2];
            let mut overwritten = [false; 2];
            let Some(mut coordinates) = stack_entries[block_index].clone() else {
                continue;
            };
            for prefix in &block.instrs[..=call_index] {
                advance_stack_coordinates(&prefix.op, &mut coordinates, cc);
            }
            let mut spills: HashMap<(i64, u8), usize> = HashMap::new();
            for later in &block.instrs[call_index + 1..] {
                // A later call owns fresh result registers even before ABI
                // effects have been attached to the lifted instruction.
                if let Op::Call {
                    target: receiver,
                    effects,
                } = &later.op
                {
                    if let Some(effects) = effects {
                        for argument in &effects.args {
                            if effects.args_are_exact || effects.proven_args.contains(argument) {
                                if let Some(part) = pair_part(cc, argument) {
                                    if !overwritten[part] {
                                        observed[part] = true;
                                    }
                                }
                            }
                        }
                    }
                    if !spills.is_empty() {
                        if let (Some(image), CallTarget::Direct(receiver)) = (image, receiver) {
                            let return_bytes = call_stack_return_bytes(cc);
                            for (offset, size) in receiver_stack_reads(image, *receiver, cc) {
                                let Some(offset) = coordinates
                                    .get(&stack_pointer(cc))
                                    .copied()
                                    .and_then(|base| base.checked_sub(return_bytes))
                                    .and_then(|base| base.checked_add(offset))
                                else {
                                    continue;
                                };
                                for ((saved_offset, saved_size), part) in &spills {
                                    if *saved_offset == offset && *saved_size == size {
                                        observed[*part] = true;
                                    }
                                }
                            }
                        }
                    }
                    if observed == [true, true] {
                        return true;
                    }
                    break;
                }
                if let Op::Store { addr, src } = &later.op {
                    if let Some(key) = local_stack_key(addr, &coordinates) {
                        // Writing a stack slot alone proves neither a source
                        // argument nor a returned high half: it may be padding.
                        spills.retain(|(offset, size), _| {
                            offset.saturating_add(i64::from(*size)) <= key.0
                                || key.0.saturating_add(i64::from(key.1)) <= *offset
                        });
                        if let Value::Reg(register) = src {
                            if let Some(part) = pair_part(cc, register) {
                                let part_bytes = crate::ir::abi::wide_integer_return_width(cc) / 2;
                                if !overwritten[part] && addr.size == part_bytes {
                                    spills.insert(key, part);
                                }
                            }
                        }
                        continue;
                    }
                    // An untracked store can alias a saved stack value.
                    spills.clear();
                }
                if let Op::CondStore { addr, .. } = &later.op {
                    if let Some((offset, size)) = local_stack_key(addr, &coordinates) {
                        spills.retain(|(saved, saved_size), _| {
                            saved.saturating_add(i64::from(*saved_size)) <= offset
                                || offset.saturating_add(i64::from(size)) <= *saved
                        });
                    } else {
                        spills.clear();
                    }
                    continue;
                }
                if matches!(later.op, Op::Unknown { .. }) {
                    break;
                }
                if matches!(later.op, Op::Intrinsic { .. }) {
                    spills.clear();
                }
                if let Op::Load { addr, .. } = &later.op {
                    if let Some(part) = local_stack_key(addr, &coordinates)
                        .and_then(|key| spills.get(&key))
                        .copied()
                    {
                        observed[part] = true;
                    }
                }
                let zero_idiom = matches!(&later.op,
                    Op::Bin { op: BinOp::Xor | BinOp::Sub, lhs: Value::Reg(left), rhs: Value::Reg(right), .. }
                    if left == right);
                if !zero_idiom {
                    for_each_use(&later.op, |register| {
                        if let Some(part) = pair_part(cc, register) {
                            if !overwritten[part] {
                                observed[part] = true;
                            }
                        }
                    });
                }
                if observed == [true, true] {
                    return true;
                }
                for_each_def(&later.op, |register| {
                    if let Some(part) = pair_part(cc, register) {
                        if !observed[part] {
                            overwritten[part] = true;
                        }
                    }
                });
                advance_stack_coordinates(&later.op, &mut coordinates, cc);
            }
        }
    }
    false
}

/// Prove with a forward must-analysis that both result registers have a
/// definition on every reachable machine-return path.
pub(crate) fn callee_defines_integer_pair_on_every_return(
    callee: &LlirFunction,
    cc: CallConv,
) -> bool {
    if crate::ir::abi::wide_integer_return_pair(cc, crate::ir::abi::wide_integer_return_width(cc))
        .is_none()
    {
        return false;
    }
    let by_va = callee
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect::<HashMap<_, _>>();
    let Some(&entry) = by_va.get(&callee.entry_va) else {
        return false;
    };

    let mut incoming = vec![None; callee.blocks.len()];
    let mut outgoing = vec![None; callee.blocks.len()];
    incoming[entry] = Some([false, false]);
    let mut work = VecDeque::from([entry]);
    while let Some(index) = work.pop_front() {
        let Some(mut state) = incoming[index] else {
            continue;
        };
        for instruction in &callee.blocks[index].instrs {
            for_each_def(&instruction.op, |register| {
                if let Some(part) = pair_part(cc, register) {
                    state[part] = true;
                }
            });
        }
        if outgoing[index] == Some(state) {
            continue;
        }
        outgoing[index] = Some(state);
        for successor in &callee.blocks[index].succs {
            let Some(&successor) = by_va.get(successor) else {
                return false;
            };
            let merged =
                incoming[successor].map_or(state, |old| [old[0] && state[0], old[1] && state[1]]);
            if incoming[successor] != Some(merged) {
                incoming[successor] = Some(merged);
                work.push_back(successor);
            }
        }
    }

    let mut returns = 0;
    for (index, block) in callee.blocks.iter().enumerate() {
        let Some(mut state) = incoming[index] else {
            continue;
        };
        for instruction in &block.instrs {
            if is_machine_return(&instruction.op) {
                returns += 1;
                if state != [true, true] {
                    return false;
                }
            }
            for_each_def(&instruction.op, |register| {
                if let Some(part) = pair_part(cc, register) {
                    state[part] = true;
                }
            });
        }
        if block.succs.is_empty()
            && !block
                .instrs
                .last()
                .is_some_and(|instruction| is_machine_return(&instruction.op))
        {
            return false;
        }
    }
    returns != 0
}

fn call_stack_return_bytes(cc: CallConv) -> i64 {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => {
            i64::from(crate::ir::abi::machine_word_bytes(cc))
        }
        CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64 => 0,
    }
}

// Read only the receiver's entry block: crossing a join needs reaching memory
// definitions. Coordinates describe its incoming SP, including a pushed return
// address on x86. Stores block overlapping later reads from serving as inputs.
fn receiver_stack_reads(
    image: &crate::program::image::ProgramImage,
    target: u64,
    cc: CallConv,
) -> Vec<(i64, u8)> {
    let budgets = crate::analysis::cfg::Budgets {
        max_blocks: 1,
        max_instructions: 128,
        timeout_ms: 10,
        ..crate::analysis::cfg::Budgets::default()
    };
    let Some(function) = crate::analysis::cfg::discover_function_image_at(image, &budgets, target)
    else {
        return vec![];
    };
    let Ok(lifted) = crate::ir::lift_function::lift_function_from_image(image, &function) else {
        return vec![];
    };
    let Some(entry) = lifted
        .blocks
        .iter()
        .find(|block| block.start_va == lifted.entry_va)
    else {
        return vec![];
    };
    let mut coordinates = HashMap::from([(stack_pointer(cc), 0i64)]);
    let mut writes: Vec<(i64, u8)> = vec![];
    let mut reads = vec![];
    for instruction in entry.instrs.iter().take(128) {
        let op = &instruction.op;
        if matches!(
            op,
            Op::Call { .. } | Op::Unknown { .. } | Op::Intrinsic { .. }
        ) {
            break;
        }
        let coordinate = |addr: &MemOp| {
            if addr.index.is_some() || addr.segment.is_some() {
                return None;
            }
            coordinates
                .get(addr.base.as_ref()?)
                .copied()?
                .checked_add(addr.disp)
        };
        if let Op::Load { addr, .. } = op {
            if let Some(offset) = coordinate(addr) {
                if offset >= call_stack_return_bytes(cc)
                    && !writes.iter().any(|(start, size)| {
                        start.saturating_add(i64::from(*size)) > offset
                            && offset.saturating_add(i64::from(addr.size)) > *start
                    })
                {
                    reads.push((offset, addr.size));
                }
            }
        }
        if let Op::Store { addr, .. } | Op::CondStore { addr, .. } = op {
            let Some(offset) = coordinate(addr) else {
                break;
            };
            writes.push((offset, addr.size));
        }
        advance_stack_coordinates(op, &mut coordinates, cc);
    }
    reads
}

fn local_stack_key(addr: &MemOp, coordinates: &HashMap<VReg, i64>) -> Option<(i64, u8)> {
    if addr.index.is_some() || addr.segment.is_some() {
        return None;
    }
    Some((
        coordinates
            .get(addr.base.as_ref()?)?
            .checked_add(addr.disp)?,
        addr.size,
    ))
}

fn stack_pointer(cc: CallConv) -> VReg {
    VReg::phys(match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => "rsp",
        CallConv::Cdecl32 => "esp",
        CallConv::Arm | CallConv::ArmHardFloat | CallConv::Aarch64 => "sp",
    })
}

fn advance_stack_coordinates(op: &Op, coordinates: &mut HashMap<VReg, i64>, cc: CallConv) {
    if matches!(op, Op::Unknown { .. }) {
        coordinates.clear();
        return;
    }
    let adjusted = match op {
        Op::Assign {
            dst,
            src: Value::Reg(source),
        } => coordinates
            .get(source)
            .copied()
            .map(|offset| (dst.clone(), offset)),
        Op::Bin {
            dst,
            op,
            lhs: Value::Reg(source),
            rhs: Value::Const(change),
        } => {
            let change = match op {
                BinOp::Add => Some(*change),
                BinOp::Sub => change.checked_neg(),
                _ => None,
            };
            coordinates
                .get(source)
                .copied()
                .and_then(|base| change.and_then(|change| base.checked_add(change)))
                .map(|offset| (dst.clone(), offset))
        }
        _ => None,
    };
    for_each_def(op, |register| {
        coordinates.remove(register);
    });
    if matches!(op, Op::Call { .. }) {
        for name in crate::ir::abi::caller_saved_registers(cc) {
            coordinates.remove(&VReg::phys(*name));
        }
    }
    if let Some((register, offset)) = adjusted {
        coordinates.insert(register, offset);
    }
}

fn stack_coordinate_entries(
    function: &LlirFunction,
    cc: CallConv,
) -> Vec<Option<HashMap<VReg, i64>>> {
    let by_va: HashMap<_, _> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect();
    let mut incoming = vec![None; function.blocks.len()];
    let Some(&entry) = by_va.get(&function.entry_va) else {
        return incoming;
    };
    incoming[entry] = Some(HashMap::from([(stack_pointer(cc), 0)]));
    let mut queue = VecDeque::from([entry]);
    while let Some(index) = queue.pop_front() {
        let Some(mut outgoing) = incoming[index].clone() else {
            continue;
        };
        for instruction in &function.blocks[index].instrs {
            advance_stack_coordinates(&instruction.op, &mut outgoing, cc);
        }
        for successor in &function.blocks[index].succs {
            let Some(&successor) = by_va.get(successor) else {
                continue;
            };
            let merged = incoming[successor].as_ref().map_or_else(
                || outgoing.clone(),
                |previous| {
                    previous
                        .iter()
                        .filter(|(key, value)| outgoing.get(*key) == Some(*value))
                        .map(|(key, value)| (key.clone(), *value))
                        .collect()
                },
            );
            if incoming[successor].as_ref() != Some(&merged) {
                incoming[successor] = Some(merged);
                queue.push_back(successor);
            }
        }
    }
    incoming
}

fn pair_part(cc: CallConv, register: &VReg) -> Option<usize> {
    let VReg::Phys(name) = register else {
        return None;
    };
    crate::ir::abi::wide_integer_return_part(cc, name)
}

fn is_machine_return(op: &Op) -> bool {
    matches!(
        op,
        Op::Return | Op::ReturnValue { .. } | Op::CondReturn { .. } | Op::CondReturnValue { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{LlirBlock, LlirInstr, Value};

    #[test]
    fn compiled_call_boundaries_do_not_claim_padding_or_later_results() {
        use crate::program::image::ProgramImage;
        use std::process::Command;
        let directory = tempfile::tempdir().expect("call fixture directory");
        let binary = directory.path().join("calls.elf");
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cfg/return_pair_consumption.S");
        let output = Command::new("clang")
            .args([
                "--target=x86_64-linux-gnu",
                "-nostdlib",
                "-fuse-ld=lld",
                "-no-pie",
                "-Wl,-e,padding_caller",
                "-o",
            ])
            .arg(&binary)
            .arg(source)
            .output()
            .expect("compile real call fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let image = ProgramImage::from_bytes(std::fs::read(binary).expect("read fixture"))
            .expect("index fixture");
        let lift = |name| {
            let address = image
                .unique_defined_text_symbol_address(name)
                .expect("fixture symbol");
            let function = crate::analysis::cfg::discover_function_image_at(
                &image,
                &crate::analysis::cfg::Budgets::default(),
                address,
            )
            .expect("fixture CFG");
            crate::ir::lift_function::lift_function_from_image(&image, &function)
                .expect("lift fixture")
        };
        let scalar = lift("scalar_error");
        let pair = lift("unrelated_pair");
        assert!(
            caller_observes_integer_pair_in_image(
                &lift("stack_pair_caller"),
                pair.entry_va,
                CallConv::SysVAmd64,
                &image
            ),
            "both returned parts consumed by a stack receiver must remain recoverable"
        );
        let cc = CallConv::SysVAmd64;
        assert!(
            !caller_observes_integer_pair_in_image(
                &lift("clear_only_caller"),
                scalar.entry_va,
                cc,
                &image
            ),
            "architectural self-zeroing is a definition, not consumption"
        );
        assert!(
            !caller_observes_integer_pair_in_image(
                &lift("partial_overwrite_caller"),
                scalar.entry_va,
                cc,
                &image
            ),
            "a partial slot overwrite must invalidate full-width high-half provenance"
        );

        assert!(
            caller_observes_integer_pair_in_image(
                &lift("frame_pair_caller"),
                pair.entry_va,
                cc,
                &image
            ),
            "spills read through proven frame aliases must remain recoverable"
        );
        assert!(
            !caller_observes_integer_pair_in_image(
                &lift("alias_overwrite_caller"),
                scalar.entry_va,
                cc,
                &image
            ),
            "an overwritten frame-alias slot must not retain high-half provenance"
        );

        assert!(
            !caller_observes_integer_pair_in_image(
                &lift("padding_caller"),
                scalar.entry_va,
                cc,
                &image
            ),
            "receiver consumes the scalar slot, not its adjacent padding"
        );
        assert!(
            proves_integer_pair_return(&lift("pair_caller"), &pair, pair.entry_va, cc),
            "real pair must remain recoverable"
        );
        assert!(
            proves_integer_pair_return(&lift("spill_pair_caller"), &pair, pair.entry_va, cc),
            "a wide result saved and reloaded must remain recoverable"
        );
        assert!(
            !proves_integer_pair_return(&lift("later_call_caller"), &scalar, scalar.entry_va, cc),
            "later call's results must not prove earlier scalar return"
        );
        assert!(
            !proves_integer_pair_return(&lift("padding_caller"), &scalar, scalar.entry_va, cc),
            "unused padding must not prove a scalar's high result"
        );
    }

    fn instruction(va: u64, op: Op) -> LlirInstr {
        LlirInstr { va, op }
    }

    fn direct_call() -> LlirInstr {
        instruction(
            0x2000,
            Op::Call {
                target: CallTarget::Direct(0x1000),
                effects: None,
            },
        )
    }

    fn pair_registers(cc: CallConv) -> (&'static str, &'static str) {
        crate::ir::abi::wide_integer_return_pair(cc, crate::ir::abi::wide_integer_return_width(cc))
            .expect("test convention has a two-register INTEGER result")
    }

    fn pair_callee(cc: CallConv) -> LlirFunction {
        let (low, high) = pair_registers(cc);
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x100c,
                instrs: vec![
                    instruction(
                        0x1000,
                        Op::Assign {
                            dst: VReg::phys(low),
                            src: Value::Const(1),
                        },
                    ),
                    instruction(
                        0x1004,
                        Op::Assign {
                            dst: VReg::phys(high),
                            src: Value::Const(2),
                        },
                    ),
                    instruction(0x1008, Op::Return),
                ],
                succs: vec![],
            }],
        }
    }

    fn pair_caller(cc: CallConv) -> LlirFunction {
        let (low, high) = pair_registers(cc);
        LlirFunction {
            entry_va: 0x2000,
            blocks: vec![LlirBlock {
                start_va: 0x2000,
                end_va: 0x200c,
                instrs: vec![
                    direct_call(),
                    instruction(
                        0x2004,
                        Op::Assign {
                            dst: VReg::Temp(0),
                            src: Value::Reg(VReg::phys(high)),
                        },
                    ),
                    instruction(
                        0x2008,
                        Op::Assign {
                            dst: VReg::Temp(1),
                            src: Value::Reg(VReg::phys(low)),
                        },
                    ),
                ],
                succs: vec![],
            }],
        }
    }

    #[test]
    fn joins_callee_must_definitions_with_caller_consumption() {
        assert!(proves_integer_pair_return(
            &pair_caller(CallConv::SysVAmd64),
            &pair_callee(CallConv::SysVAmd64),
            0x1000,
            CallConv::SysVAmd64
        ));
    }

    #[test]
    fn declines_scratch_residue_the_caller_does_not_consume() {
        let mut caller = pair_caller(CallConv::SysVAmd64);
        caller.blocks[0].instrs.remove(1);
        assert!(!proves_integer_pair_return(
            &caller,
            &pair_callee(CallConv::SysVAmd64),
            0x1000,
            CallConv::SysVAmd64
        ));
    }

    #[test]
    fn declines_when_one_return_path_does_not_define_the_high_half() {
        let mut callee = pair_callee(CallConv::SysVAmd64);
        callee.blocks = vec![
            LlirBlock {
                start_va: 0x1000,
                end_va: 0x1004,
                instrs: vec![],
                succs: vec![0x1010, 0x1020],
            },
            callee.blocks[0].clone(),
            LlirBlock {
                start_va: 0x1020,
                end_va: 0x1028,
                instrs: vec![
                    instruction(
                        0x1020,
                        Op::Assign {
                            dst: VReg::phys("rax"),
                            src: Value::Const(3),
                        },
                    ),
                    instruction(0x1024, Op::Return),
                ],
                succs: vec![],
            },
        ];
        callee.blocks[1].start_va = 0x1010;
        assert!(!proves_integer_pair_return(
            &pair_caller(CallConv::SysVAmd64),
            &callee,
            0x1000,
            CallConv::SysVAmd64
        ));
    }

    #[test]
    fn declines_a_high_half_overwritten_before_its_first_use() {
        let mut caller = pair_caller(CallConv::SysVAmd64);
        caller.blocks[0].instrs.insert(
            1,
            instruction(
                0x2002,
                Op::Assign {
                    dst: VReg::phys("rdx"),
                    src: Value::Const(9),
                },
            ),
        );
        assert!(!proves_integer_pair_return(
            &caller,
            &pair_callee(CallConv::SysVAmd64),
            0x1000,
            CallConv::SysVAmd64
        ));
    }

    #[test]
    fn follows_each_supported_abi_pair_and_declines_win64() {
        for cc in [
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
            CallConv::SysVAmd64,
            CallConv::Aarch64,
        ] {
            assert!(
                proves_integer_pair_return(&pair_caller(cc), &pair_callee(cc), 0x1000, cc),
                "two-register proof must follow {cc:?}"
            );
        }

        assert!(!caller_observes_integer_pair(
            &pair_caller(CallConv::SysVAmd64),
            0x1000,
            CallConv::Win64
        ));
        assert!(!callee_defines_integer_pair_on_every_return(
            &pair_callee(CallConv::SysVAmd64),
            CallConv::Win64
        ));
    }
}
