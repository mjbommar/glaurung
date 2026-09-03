//! Which SSA values address the stack frame.
//!
//! Stack *mechanics* are masked -- the prologue's `sub rsp, N`, the epilogue's
//! restore, the frame-pointer dance -- and BSim abstracts them away entirely
//! ("abstracting stack mechanics"), as does Binary Ninja's MLIL ("the stack as
//! a concept is not present"). What is kept is that a value addresses the
//! frame, because a local is identified by its frame offset and nothing else
//! survives the compiler.

use std::collections::BTreeSet;

use super::operands::{operands, Operand};
use super::widths;
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{is_promoted_local_reg, BinOp, LlirFunction, Op, VReg};
use crate::ir::use_def::InstrAddr;

/// Every SSA value derived from a stack or frame pointer.
///
/// A small monotone fixed point: a stack register is stack-derived, and so is
/// anything obtained from one by an addition, a subtraction, a bitwise or, a
/// copy or an extension, or by merging such values. Notably a *load* from a
/// stack address is not: the value in a local is not the local's address.
pub(crate) fn stack_derived_values(
    function: &LlirFunction,
    ssa: &SsaInfo,
    stack_registers: &BTreeSet<&'static str>,
) -> BTreeSet<SsaValue> {
    let is_stack_storage = |register: &VReg| match register {
        VReg::Phys(name) => {
            stack_registers.contains(name.to_ascii_lowercase().as_str())
                || is_promoted_local_reg(register)
        }
        _ => false,
    };
    let mut tainted: BTreeSet<SsaValue> = BTreeSet::new();
    // Seed: a read of a stack register at version zero is the incoming frame
    // pointer, which nothing inside the function defines. Hoisted out of the
    // fixed point below because it depends on nothing the fixed point learns --
    // leaving it inside re-walked every operand of every instruction on every
    // one of up to `MAX_ROUNDS` sweeps to discover the same set.
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            for operand in operands(&instruction.op) {
                if let Operand::Reg { use_index } = operand {
                    if let Some(value) = ssa.use_value_ref(function, addr, use_index) {
                        if is_stack_storage(&value.base) {
                            tainted.insert(value.clone());
                        }
                    }
                }
            }
        }
    }
    for _ in 0..widths::MAX_ROUNDS {
        let mut changed = false;
        for (block_idx, block) in function.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                let propagates = matches!(
                    instruction.op,
                    Op::Assign { .. }
                        | Op::ZExt { .. }
                        | Op::SExt { .. }
                        | Op::Trunc { .. }
                        | Op::Bin {
                            op: BinOp::Add | BinOp::Sub | BinOp::Or,
                            ..
                        }
                );
                let mut inherits = false;
                if propagates {
                    for operand in operands(&instruction.op) {
                        if let Operand::Reg { use_index } = operand {
                            if let Some(value) = ssa.use_value_ref(function, addr, use_index) {
                                if tainted.contains(value) {
                                    inherits = true;
                                }
                            }
                        }
                    }
                }
                for value in ssa.def_values(function, addr) {
                    if (is_stack_storage(&value.base) || inherits) && tainted.insert(value) {
                        changed = true;
                    }
                }
            }
        }
        for phi in &ssa.phis {
            let inherits = phi.incoming.iter().any(|(_, version)| {
                tainted.contains(&SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                })
            });
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            if (is_stack_storage(&result.base) || inherits) && tainted.insert(result) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    tainted
}

/// Register names that hold a stack or frame pointer, by calling convention.
///
/// Name-keyed rather than architecture-keyed because `VReg::Phys` carries only
/// a name, and the names collide across ISAs: `r11` is ARM32's frame pointer
/// and an x86-64 scratch register, `sp` is a 16-bit x86 view and AArch64's
/// 64-bit stack pointer.
pub fn stack_registers_for(cc: crate::ir::call_args::CallConv) -> BTreeSet<&'static str> {
    use crate::ir::call_args::CallConv;
    let names: &[&'static str] = match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rsp", "rbp", "esp", "ebp"],
        CallConv::Cdecl32 => &["esp", "ebp", "sp", "bp"],
        CallConv::Aarch64 => &["sp", "x29", "fp"],
        CallConv::Arm | CallConv::ArmHardFloat => &["sp", "r13", "fp", "r11"],
    };
    names.iter().copied().collect()
}
