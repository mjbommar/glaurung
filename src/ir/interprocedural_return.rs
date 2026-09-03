//! Conservative machine-level evidence for multi-register call results.
//!
//! A callee defining a second ABI result register is not enough to claim an
//! aggregate result: ordinary scalar functions can leave scratch residue in
//! that register. A caller reading a second result register is not enough
//! either: without a callee definition it is merely an undefined live-in.
//! This module joins both facts and deliberately recognizes only direct calls.

use std::collections::{HashMap, VecDeque};

use crate::ir::call_args::CallConv;
use crate::ir::types::{CallTarget, LlirFunction, Op, VReg};
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

/// Require both halves to be consumed after the call and before either storage
/// is overwritten. The bounded same-block walk is intentional: crossing a CFG
/// join would require reaching-definition identity, and declining that shape is
/// safer than attributing an unrelated later register use to this call.
pub(crate) fn caller_observes_integer_pair(
    caller: &LlirFunction,
    target: u64,
    cc: CallConv,
) -> bool {
    if crate::ir::abi::wide_integer_return_pair(cc, crate::ir::abi::wide_integer_return_width(cc))
        .is_none()
    {
        return false;
    }

    for block in &caller.blocks {
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
            for later in &block.instrs[call_index + 1..] {
                for_each_use(&later.op, |register| {
                    if let Some(part) = pair_part(cc, register) {
                        if !overwritten[part] {
                            observed[part] = true;
                        }
                    }
                });
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
