//! ARM machine idioms that refine function-input evidence.
//!
//! This module does not infer source parameters. It recognizes narrow,
//! fully-balanced machine scaffolding whose syntactic register reads must not
//! be presented to the generic live-in classifier as source-input evidence.

use std::collections::HashSet;

use crate::ir::call_args::CallConv;
use crate::ir::types::{LlirFunction, MemOp, Op, VReg, Value};
use crate::ir::use_def::{def_uses, InstrAddr};

/// Proven LLIR operands that are stack-alignment padding, not source inputs.
#[derive(Debug, Default)]
pub(crate) struct ArmAlignmentPadding {
    save_sites: HashSet<InstrAddr>,
}

impl ArmAlignmentPadding {
    /// Recognize balanced caller-saved padding in `function`.
    pub(crate) fn classify(function: &LlirFunction, convention: CallConv) -> Self {
        if !matches!(convention, CallConv::Arm | CallConv::ArmHardFloat) {
            return Self::default();
        }

        let mut save_sites = HashSet::new();
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for (store_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Store {
                    addr: saved_slot,
                    src: Value::Reg(saved_register),
                } = &instruction.op
                else {
                    continue;
                };
                if !has_base(saved_register, "r3")
                    || !is_word_stack_slot(saved_slot)
                    || saved_slot.index.is_some()
                {
                    continue;
                }

                let saves_link_register = block.instrs.iter().any(|sibling| {
                    if sibling.va != instruction.va {
                        return false;
                    }
                    let Op::Store {
                        addr,
                        src: Value::Reg(register),
                    } = &sibling.op
                    else {
                        return false;
                    };
                    (has_base(register, "lr") || has_base(register, "r14"))
                        && same_stack_base(addr, saved_slot)
                        && same_access_shape(addr, saved_slot)
                        && (addr.disp - saved_slot.disp).abs() == i64::from(saved_slot.size)
                });
                if !saves_link_register {
                    continue;
                }

                let Some(restore_idx) = block.instrs[store_idx + 1..]
                    .iter()
                    .position(|candidate| {
                        matches!(&candidate.op,
                            Op::Load { dst, addr }
                                if has_base(dst, "r3") && same_stack_slot(addr, saved_slot))
                    })
                    .map(|offset| store_idx + 1 + offset)
                else {
                    continue;
                };

                let suffix = &block.instrs[restore_idx + 1..];
                let returns_without_observing_r3 =
                    matches!(
                        suffix.last().map(|candidate| &candidate.op),
                        Some(Op::Return)
                    ) && suffix.iter().enumerate().all(|(index, candidate)| {
                        let is_final_return =
                            index + 1 == suffix.len() && matches!(candidate.op, Op::Return);
                        if !is_final_return
                            && matches!(
                                candidate.op,
                                Op::Call { .. }
                                    | Op::Jump { .. }
                                    | Op::CondJump { .. }
                                    | Op::IndirectJump { .. }
                                    | Op::Return
                            )
                        {
                            return false;
                        }
                        let (_, uses) = def_uses(&candidate.op);
                        !uses.iter().any(|register| has_base(register, "r3"))
                    });
                if returns_without_observing_r3 {
                    save_sites.insert(InstrAddr {
                        block_idx,
                        instr_idx: store_idx,
                    });
                }
            }
        }
        Self { save_sites }
    }

    /// Whether this exact use is the caller-saved padding operand.
    pub(crate) fn excludes_use(&self, site: InstrAddr, register: &VReg) -> bool {
        self.save_sites.contains(&site) && has_base(register, "r3")
    }
}

fn has_base(register: &VReg, expected: &str) -> bool {
    matches!(register, VReg::Phys(name) if crate::ir::abi::ssa_base(name) == expected)
}

fn is_word_stack_slot(access: &MemOp) -> bool {
    access.size == 4
        && matches!(&access.base, Some(base) if has_base(base, "sp") || has_base(base, "r13"))
}

fn same_stack_base(left: &MemOp, right: &MemOp) -> bool {
    is_word_stack_slot(left)
        && is_word_stack_slot(right)
        && left
            .base
            .as_ref()
            .zip(right.base.as_ref())
            .is_some_and(|(left, right)| match (left, right) {
                (VReg::Phys(left), VReg::Phys(right)) => {
                    crate::ir::abi::ssa_base(left) == crate::ir::abi::ssa_base(right)
                }
                _ => left == right,
            })
}

fn same_access_shape(left: &MemOp, right: &MemOp) -> bool {
    left.index == right.index
        && left.scale == right.scale
        && left.size == right.size
        && left.segment == right.segment
        && left.endian == right.endian
}

fn same_stack_slot(left: &MemOp, right: &MemOp) -> bool {
    same_stack_base(left, right) && same_access_shape(left, right) && left.disp == right.disp
}
