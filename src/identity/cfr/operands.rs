//! One positional operand model, shared by width inference and graph building.
//!
//! [`crate::ir::use_def::for_each_use`] enumerates an operation's *register*
//! reads and nothing else, but a CFR node's operand edges must also carry
//! constants, absolute addresses and effective-address displacements, and every
//! operand needs a stable position so non-commutative operators can be mixed
//! positionally. This module supplies both, in exactly `for_each_use`'s order
//! for the register subset -- which is what makes an operand's `use_index` a
//! valid key into [`crate::ir::ssa::SsaInfo::use_value_ref`].
//!
//! The invariant that the two orders agree is asserted, not assumed: see
//! `register_operands_match_for_each_use` below.

use crate::ir::types::{CallTarget, MemOp, Op, Value};

/// One positional operand of an LLIR operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    /// A register read. `use_index` is its position among the operation's
    /// register uses, which is the index
    /// [`crate::ir::ssa::SsaInfo::use_value_ref`] expects.
    Reg { use_index: usize },
    /// A literal integer.
    Const(i64),
    /// An absolute virtual address resolved at lift time.
    Addr(u64),
    /// An optional operand the operation does not have (an effective address
    /// with no index register, an indirect jump with no recovered index). Kept
    /// as a slot so operand positions do not shift underneath a positional mix.
    Absent,
}

/// Positional operands of `op`, with register uses in `for_each_use` order.
///
/// An effective address always contributes exactly four operands -- base,
/// index, scale, displacement -- so a `[rbp - 8]` and a `[rax + rcx*4 + 16]`
/// occupy the same positions and the difference shows up in the operand labels
/// rather than in the arity.
pub(crate) fn operands(op: &Op) -> Vec<Operand> {
    let mut out = Vec::with_capacity(6);
    let mut next_use = 0usize;
    push_operands(op, &mut out, &mut next_use);
    out
}

fn push_value(value: &Value, out: &mut Vec<Operand>, next_use: &mut usize) {
    match value {
        Value::Reg(_) => {
            out.push(Operand::Reg {
                use_index: *next_use,
            });
            *next_use += 1;
        }
        Value::Const(constant) => out.push(Operand::Const(*constant)),
        Value::Addr(address) => out.push(Operand::Addr(*address)),
    }
}

fn push_reg(out: &mut Vec<Operand>, next_use: &mut usize) {
    out.push(Operand::Reg {
        use_index: *next_use,
    });
    *next_use += 1;
}

fn push_memop(memory: &MemOp, out: &mut Vec<Operand>, next_use: &mut usize) {
    if memory.base.is_some() {
        push_reg(out, next_use);
    } else {
        out.push(Operand::Absent);
    }
    if memory.index.is_some() {
        push_reg(out, next_use);
    } else {
        out.push(Operand::Absent);
    }
    // Zero is the legacy spelling for unity (see `MemOp::scale`); normalising
    // it here keeps two spellings of `[rax + rcx]` in one feature.
    let scale = if memory.scale == 0 { 1 } else { memory.scale };
    out.push(Operand::Const(i64::from(scale)));
    out.push(Operand::Const(memory.disp));
}

fn push_operands(op: &Op, out: &mut Vec<Operand>, next_use: &mut usize) {
    match op {
        Op::Assign { src, .. } => push_value(src, out, next_use),
        Op::Undef { .. } => {}
        Op::Bin { lhs, rhs, .. } => {
            push_value(lhs, out, next_use);
            push_value(rhs, out, next_use);
        }
        Op::IndirectJump { target, index } => {
            push_value(target, out, next_use);
            match index {
                Some(index) => push_value(index, out, next_use),
                None => out.push(Operand::Absent),
            }
        }
        Op::Un { src, .. } => push_value(src, out, next_use),
        Op::Cmp { lhs, rhs, .. } => {
            push_value(lhs, out, next_use);
            push_value(rhs, out, next_use);
        }
        Op::Load { addr, .. } => push_memop(addr, out, next_use),
        Op::CondLoad { addr, fallback, .. } => {
            push_reg(out, next_use);
            push_memop(addr, out, next_use);
            push_value(fallback, out, next_use);
        }
        Op::Store { addr, src } => {
            push_memop(addr, out, next_use);
            push_value(src, out, next_use);
        }
        Op::CondStore { addr, src, .. } => {
            push_reg(out, next_use);
            push_memop(addr, out, next_use);
            push_value(src, out, next_use);
        }
        Op::CondJump { .. } | Op::CondReturn { .. } => push_reg(out, next_use),
        Op::CondReturnValue { value, .. } => {
            push_reg(out, next_use);
            push_value(value, out, next_use);
        }
        Op::Call { target, effects } => {
            if let CallTarget::Indirect(value) = target {
                push_value(value, out, next_use);
            }
            if let Some(effects) = effects {
                for _ in &effects.args {
                    push_reg(out, next_use);
                }
            }
        }
        Op::ReturnValue { value } => push_value(value, out, next_use),
        Op::ZExt { src, .. } | Op::SExt { src, .. } | Op::Trunc { src, .. } => {
            push_value(src, out, next_use)
        }
        Op::Extract { src, .. } => push_value(src, out, next_use),
        Op::Concat { hi, lo, .. } => {
            push_value(hi, out, next_use);
            push_value(lo, out, next_use);
        }
        Op::Ite { t, e, .. } => {
            push_reg(out, next_use);
            push_value(t, out, next_use);
            push_value(e, out, next_use);
        }
        Op::Intrinsic { ins, .. } => {
            for value in ins {
                push_value(value, out, next_use);
            }
        }
        Op::Jump { .. } | Op::Return | Op::Nop | Op::Unknown { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{BinOp, CallEffects, CmpOp, Flag, UnOp, VReg, Width};
    use crate::ir::use_def::use_count;

    /// Every operation shape this IR has, so the invariant below is checked
    /// over the whole `Op` surface rather than the three shapes a test author
    /// happened to think of.
    fn every_op_shape() -> Vec<Op> {
        let reg = || VReg::phys("rax");
        let mem = MemOp::plain(Some(VReg::phys("rbp")), Some(VReg::phys("rcx")), 4, -8, 8);
        vec![
            Op::Assign {
                dst: reg(),
                src: Value::Reg(VReg::phys("rbx")),
            },
            Op::Assign {
                dst: reg(),
                src: Value::Const(7),
            },
            Op::Undef {
                dst: reg(),
                reason: "test".into(),
            },
            Op::Bin {
                dst: reg(),
                op: BinOp::Add,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Const(1),
            },
            Op::Un {
                dst: reg(),
                op: UnOp::Neg,
                src: Value::Reg(VReg::phys("rbx")),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::phys("rbx")),
                rhs: Value::Reg(VReg::phys("rcx")),
            },
            Op::Load {
                dst: reg(),
                addr: mem.clone(),
            },
            Op::Load {
                dst: reg(),
                addr: MemOp::plain(None, None, 0, 16, 4),
            },
            Op::CondLoad {
                dst: reg(),
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                addr: mem.clone(),
                fallback: Value::Const(0),
            },
            Op::Store {
                addr: mem.clone(),
                src: Value::Reg(VReg::phys("rbx")),
            },
            Op::CondStore {
                cond: VReg::Flag(Flag::Z),
                inverted: true,
                addr: mem.clone(),
                src: Value::Const(3),
            },
            Op::Jump { target: 0x1000 },
            Op::IndirectJump {
                target: Value::Reg(reg()),
                index: Some(Value::Reg(VReg::phys("rcx"))),
            },
            Op::IndirectJump {
                target: Value::Reg(reg()),
                index: None,
            },
            Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target: 0x1000,
                inverted: false,
            },
            Op::CondReturn {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
            },
            Op::CondReturnValue {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                value: Value::Reg(reg()),
            },
            Op::Call {
                target: CallTarget::Direct(0x2000),
                effects: Some(CallEffects {
                    result: Some(reg()),
                    args: vec![VReg::phys("rdi"), VReg::phys("rsi")],
                    ..CallEffects::default()
                }),
            },
            Op::Call {
                target: CallTarget::Indirect(Value::Reg(reg())),
                effects: None,
            },
            Op::ReturnValue {
                value: Value::Reg(reg()),
            },
            Op::Return,
            Op::Nop,
            Op::ZExt {
                dst: reg(),
                src: Value::Reg(VReg::phys("ebx")),
                from: Width::W32,
                to: Width::W64,
            },
            Op::SExt {
                dst: reg(),
                src: Value::Reg(VReg::phys("ebx")),
                from: Width::W32,
                to: Width::W64,
            },
            Op::Trunc {
                dst: reg(),
                src: Value::Reg(VReg::phys("rbx")),
                from: Width::W64,
                to: Width::W32,
            },
            Op::Extract {
                dst: reg(),
                src: Value::Reg(VReg::phys("rbx")),
                hi: 32,
                lo: 8,
            },
            Op::Concat {
                dst: reg(),
                hi: Value::Reg(VReg::phys("rbx")),
                lo: Value::Const(0),
            },
            Op::Ite {
                dst: reg(),
                cond: VReg::Flag(Flag::Z),
                t: Value::Reg(VReg::phys("rbx")),
                e: Value::Const(0),
                width: Width::W64,
            },
            Op::Intrinsic {
                name: "cpuid".into(),
                ins: vec![Value::Reg(reg()), Value::Const(1)],
                outs: vec![(VReg::phys("rax"), Width::W64)],
                reads_mem: false,
                writes_mem: false,
            },
            Op::Unknown {
                mnemonic: "vpshufb".into(),
            },
        ]
    }

    /// The load-bearing invariant: an operand's `use_index` is only a valid SSA
    /// key while this module's register order is `for_each_use`'s order. If the
    /// IR gains an operand and only one of the two walks learns about it, every
    /// operand edge past that point silently points at the wrong SSA value.
    #[test]
    fn register_operands_match_for_each_use() {
        for op in every_op_shape() {
            let ours: Vec<usize> = operands(&op)
                .into_iter()
                .filter_map(|operand| match operand {
                    Operand::Reg { use_index } => Some(use_index),
                    _ => None,
                })
                .collect();
            let expected: Vec<usize> = (0..use_count(&op)).collect();
            assert_eq!(ours, expected, "operand/use order disagree for {op:?}");
        }
    }
}
