//! AArch64 condition codes and the flag definitions arithmetic leaves behind.
//!
//! Two halves of one concern, in the same shape as [`crate::ir::lift_arm32`]'s
//! `flags` child. [`cond_flag_for_bcond`] and [`cond_flag_for_code`] read a
//! condition -- the `eq`/`ne`/`hi`/`ls` tail of a `b.<cond>` mnemonic, or the
//! 4-bit `cond` field recovered from the instruction word -- and say which LLIR
//! flag decides it and whether it is read inverted; [`conditional_select`]
//! lowers that answer straight into an [`Op::Ite`]. [`compare_flags`] and
//! [`result_flags`] are the other end: what a comparison or a flag-setting
//! arithmetic instruction WRITES into Z/C/Slt/Sle/Ule, with [`FlagForm`] and
//! [`flag_setting_arith`] deciding which of the two an `s`-suffixed mnemonic
//! gets.
//!
//! [`signed_view`] and [`unsigned_view`] are what make the two ends agree.
//! `ssa::parent64` gives `w0` and `x0` one identity, so a sub-width operand
//! arrives here already widened by whatever wrote it last; each predicate is
//! re-materialised at the width the machine actually compared at, which
//! [`machine_width`] recovers from whichever operand names a register.

use crate::core::instruction::Instruction;
use crate::ir::types::*;

use super::{low_mask, temp_for};

/// Which flags a flag-setting arithmetic instruction can be said to define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FlagForm {
    /// Flags of `cmp lhs, rhs` — what `subs` sets.
    Compare,
    /// Only "is the result zero / negative" — what can be claimed for `adds`
    /// and `ands` without modelling carry and overflow.
    ResultVsZero,
}

/// The `S`-suffixed arithmetic forms, mapped to their operation, flag effect,
/// and whether the last source operand is COMPLEMENTED before the operation.
///
/// `bics` is AND-NOT (ARM DDI 0487 C6.2.34: `Rd = Rn AND NOT(shift(Rm))`), not
/// AND. Mapping it to a plain `BinOp::And` computed `Rn & Rm` — the wrong value
/// for every bit of `Rm` that is set, and silently, because the mnemonic was
/// recognised.
pub(super) fn flag_setting_arith(m: &str) -> Option<(BinOp, FlagForm, bool)> {
    Some(match m {
        "subs" => (BinOp::Sub, FlagForm::Compare, false),
        "adds" => (BinOp::Add, FlagForm::ResultVsZero, false),
        "ands" => (BinOp::And, FlagForm::ResultVsZero, false),
        "bics" => (BinOp::And, FlagForm::ResultVsZero, true),
        _ => return None,
    })
}

/// The machine width at which a value participates in arithmetic: the width of
/// the register spelling, or 64 bits for a constant or an unnamed temporary.
pub(super) fn operand_width(value: &Value) -> Option<Width> {
    match value {
        Value::Reg(register) => register.width(),
        _ => None,
    }
}

/// The width an instruction operates at, taken from whichever operand names a
/// register. `cmp w0,#5` is a 32-bit comparison even though its second operand
/// carries no width of its own.
pub(super) fn machine_width(operands: [&Value; 2]) -> Width {
    operands
        .into_iter()
        .find_map(operand_width)
        .unwrap_or(Width::W64)
}

/// Materialise the SIGN-extended 64-bit view of a sub-width operand.
///
/// `ssa::parent64` gives `w0` and `x0` one identity, so by the time a consumer
/// reads the value it is holding the ZERO-extended parent that the 32-bit write
/// produced. A signed 32-bit comparison of -1 against 0 would then compare
/// 0x00000000ffffffff against 0 and take the wrong branch. Mirrors
/// `lift_x86::signed_cmp_value`.
pub(super) fn signed_view(value: Value, width: Width, temp: VReg, ops: &mut Vec<Op>) -> Value {
    if width.bits() >= 64 || !matches!(&value, Value::Reg(_)) {
        return value;
    }
    ops.push(Op::SExt {
        dst: temp.clone(),
        src: value,
        from: width,
        to: Width::W64,
    });
    Value::Reg(temp)
}

/// Materialise the ZERO-extended 64-bit view of a sub-width operand — the
/// unsigned word the machine actually compares. The parent's high half is
/// normally already clear (see [`super::with_parent_zero_extension`]), but not when the
/// last write to it was a 64-bit one, as in `ldr x0,[..]` followed by `cbz w0`.
pub(super) fn unsigned_view(value: Value, width: Width, temp: VReg, ops: &mut Vec<Op>) -> Value {
    if width.bits() >= 64 {
        return value;
    }
    match value {
        value @ Value::Reg(_) => {
            ops.push(Op::ZExt {
                dst: temp.clone(),
                src: value,
                from: width,
                to: Width::W64,
            });
            Value::Reg(temp)
        }
        Value::Const(c) => Value::Const((c as u64 & low_mask(width.bits())) as i64),
        other => other,
    }
}

/// The flag set an AArch64 `cmp lhs, rhs` produces, in the same order and with
/// the same `VReg::Flag` identities the `"cmp"` arm emits — a reader of ZF must
/// not care whether the producer was `cmp` or `subs`.
///
/// Each predicate is given the operand view it is actually evaluated over: NZCV
/// is computed on the encoded 32- or 64-bit word, so the signed predicates read
/// a sign-extended operand and the unsigned ones a zero-extended operand.
pub(super) fn compare_flags(ins: &Instruction, lhs: Value, rhs: Value) -> Vec<Op> {
    let width = machine_width([&lhs, &rhs]);
    let mut ops = Vec::new();
    let ulhs = unsigned_view(lhs.clone(), width, temp_for(ins, 8), &mut ops);
    let urhs = unsigned_view(rhs.clone(), width, temp_for(ins, 9), &mut ops);
    let slhs = signed_view(lhs, width, temp_for(ins, 10), &mut ops);
    let srhs = signed_view(rhs, width, temp_for(ins, 11), &mut ops);
    ops.extend([
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: ulhs.clone(),
            rhs: urhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ult,
            lhs: ulhs.clone(),
            rhs: urhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Ule),
            op: CmpOp::Ule,
            lhs: ulhs,
            rhs: urhs,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Slt),
            op: CmpOp::Slt,
            lhs: slhs.clone(),
            rhs: srhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Sle),
            op: CmpOp::Sle,
            lhs: slhs,
            rhs: srhs,
        },
    ]);
    ops
}

/// Zero and sign facts about a computed result. Carry and overflow are omitted
/// rather than guessed: a wrong flag is worse than an absent one, because a
/// later branch will read it and render a condition the CPU never evaluates.
/// `width` is explicit rather than read off `result` because the result may live
/// in an unnamed temporary, which carries no width at all — and defaulting such
/// a value to 64 bits would test bit 63 of a 32-bit result and report every
/// negative number as positive.
pub(super) fn result_flags(ins: &Instruction, result: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let unsigned = unsigned_view(result.clone(), width, temp_for(ins, 11), &mut ops);
    let signed = signed_view(result, width, temp_for(ins, 12), &mut ops);
    ops.extend([
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: unsigned,
            rhs: Value::Const(0),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Slt),
            op: CmpOp::Slt,
            lhs: signed,
            rhs: Value::Const(0),
        },
    ]);
    ops
}

/// Map a `b.<cond>` mnemonic (e.g. "b.eq") onto the LLIR flag whose truth
/// determines whether the branch is taken. Returns `(flag, inverted)`: the
/// negated sibling (`b.ne` vs `b.eq`) reads the same flag with the inverted
/// bit set, so a downstream consumer can render the branch as `!=` vs `==`.
pub(super) fn cond_flag_for_bcond(suffix: &str) -> Option<(VReg, bool)> {
    Some(match suffix {
        "eq" => (VReg::Flag(Flag::Z), false),
        "ne" => (VReg::Flag(Flag::Z), true),
        // AArch64 uses "LO" (same as CS / unsigned lower) and "HS" (HI or
        // equal) for unsigned-less-than.
        "lo" | "cc" => (VReg::Flag(Flag::C), false),
        "cs" | "hs" => (VReg::Flag(Flag::C), true),
        "lt" => (VReg::Flag(Flag::Slt), false),
        "ge" => (VReg::Flag(Flag::Slt), true),
        "le" => (VReg::Flag(Flag::Sle), false),
        "gt" => (VReg::Flag(Flag::Sle), true),
        "ls" => (VReg::Flag(Flag::Ule), false),
        "hi" => (VReg::Flag(Flag::Ule), true),
        // MI/PL read the raw sign; with cmp-driven flows this coincides with
        // signed-less-than, so we approximate similarly to x86 Js/Jns.
        "mi" => (VReg::Flag(Flag::Slt), false),
        "pl" => (VReg::Flag(Flag::Slt), true),
        "vs" => (VReg::Flag(Flag::O), false),
        "vc" => (VReg::Flag(Flag::O), true),
        _ => return None,
    })
}

pub(super) fn cond_flag_for_code(code: u32) -> Option<(VReg, bool)> {
    let suffix = match code & 0xf {
        0x0 => "eq",
        0x1 => "ne",
        0x2 => "hs",
        0x3 => "lo",
        0x4 => "mi",
        0x5 => "pl",
        0x6 => "vs",
        0x7 => "vc",
        0x8 => "hi",
        0x9 => "ls",
        0xa => "ge",
        0xb => "lt",
        0xc => "gt",
        0xd => "le",
        _ => return None,
    };
    cond_flag_for_bcond(suffix)
}

pub(super) fn conditional_select(
    dst: VReg,
    cond_code: u32,
    if_true: Value,
    if_false: Value,
) -> Option<Op> {
    let width = dst.width()?;
    let (cond, inverted) = cond_flag_for_code(cond_code)?;
    let (t, e) = if inverted {
        (if_false, if_true)
    } else {
        (if_true, if_false)
    };
    Some(Op::Ite {
        dst,
        cond,
        t,
        e,
        width,
    })
}
