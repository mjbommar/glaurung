//! ARM32 condition codes and the flag definitions the ALU leaves behind.
//!
//! Two halves of one concern. [`cond_flag_for`] and [`a32_predicate`] read a
//! condition *suffix* -- the `eq`/`ne`/`hi`/`ls` tail of a mnemonic, or the
//! A32 `cond` field recovered from the instruction word -- and say which LLIR
//! flag decides it and whether it is read inverted. [`flags_for_arith`],
//! [`cmp_flag_ops`] and [`arm_carry_arithmetic`] are the other end: what an
//! ARM arithmetic, comparison or carry-propagating instruction *writes* into
//! Z/C/Slt/Sle/Ult/Ule.
//!
//! One convention ties them together and must not be read as an accident: the
//! `C` flag is stored as ARM's architectural carry INVERTED, because the IR
//! models it as `Ult` and `lo`/`cc` read it directly. [`arm_carry_arithmetic`]
//! converts back and forth at the two points that care. [`arm_unsigned32`] and
//! [`arm_signed32`] give a flag definition the 32-bit width the machine
//! actually compares at, since the IR canonicalises registers wider.

use crate::core::instruction::Instruction;
use crate::ir::types::*;

use super::shifts::arm32_word;

/// The three-operand (and two-operand accumulate) data-processing mnemonics.
/// The optional `s` flag-setting suffix is stripped by the caller.
pub(super) fn bin_for_mnem(m: &str) -> Option<BinOp> {
    Some(match m {
        "add" | "adds" | "addw" => BinOp::Add,
        "sub" | "subs" | "subw" => BinOp::Sub,
        "and" | "ands" => BinOp::And,
        "orr" | "orrs" => BinOp::Or,
        "eor" | "eors" => BinOp::Xor,
        "lsl" | "lsls" => BinOp::Shl,
        "lsr" | "lsrs" => BinOp::Shr,
        "asr" | "asrs" => BinOp::Sar,
        "mul" | "muls" => BinOp::Mul,
        // ARMv7 hardware divide (Cortex-M4/A). Signedness is approximated: the
        // IR has a single Div; sdiv/udiv both map to it.
        "sdiv" | "udiv" => BinOp::Div,
        _ => return None,
    })
}

/// Map an ARM condition suffix onto the LLIR flag whose truth decides the
/// branch, plus whether it reads the flag inverted. ARM condition codes are
/// architecturally identical to AArch64's; this also covers `hi`/`ls`.
pub(super) fn cond_flag_for(suffix: &str) -> Option<(VReg, bool)> {
    Some(match suffix {
        "eq" => (VReg::Flag(Flag::Z), false),
        "ne" => (VReg::Flag(Flag::Z), true),
        "lo" | "cc" => (VReg::Flag(Flag::C), false),
        "hs" | "cs" => (VReg::Flag(Flag::C), true),
        // Unsigned higher / lower-or-same use the Ule flag.
        "ls" => (VReg::Flag(Flag::Ule), false),
        "hi" => (VReg::Flag(Flag::Ule), true),
        "lt" => (VReg::Flag(Flag::Slt), false),
        "ge" => (VReg::Flag(Flag::Slt), true),
        "le" => (VReg::Flag(Flag::Sle), false),
        "gt" => (VReg::Flag(Flag::Sle), true),
        "mi" => (VReg::Flag(Flag::S), false),
        "pl" => (VReg::Flag(Flag::S), true),
        "vs" => (VReg::Flag(Flag::O), false),
        "vc" => (VReg::Flag(Flag::O), true),
        _ => return None,
    })
}

/// Decode the predicate carried by an A32 instruction word and remove the
/// matching suffix from Capstone's mnemonic.
///
/// Unlike Thumb-2 IT blocks, every ordinary A32 word has a four-bit condition
/// field. Reading the encoding is authoritative: suffix-only parsing can
/// confuse mnemonics such as `bls` (branch-lower-or-same) with an unrelated
/// spelling and cannot distinguish the unconditional `AL` encoding.
pub(super) fn a32_predicate(ins: &Instruction, mnemonic: &str) -> Option<(String, VReg, bool)> {
    let condition = arm32_word(ins)? >> 28;
    let aliases: &[&str] = match condition {
        0x0 => &["eq"],
        0x1 => &["ne"],
        0x2 => &["hs", "cs"],
        0x3 => &["lo", "cc"],
        0x4 => &["mi"],
        0x5 => &["pl"],
        0x6 => &["vs"],
        0x7 => &["vc"],
        0x8 => &["hi"],
        0x9 => &["ls"],
        0xa => &["ge"],
        0xb => &["lt"],
        0xc => &["gt"],
        0xd => &["le"],
        // AL is unconditional; 0xf belongs to unconditional/special encodings.
        _ => return None,
    };
    let suffix = aliases.iter().find(|suffix| mnemonic.ends_with(**suffix))?;
    let base = mnemonic.strip_suffix(*suffix)?;
    if base.is_empty() {
        return None;
    }
    let (cond, inverted) = cond_flag_for(suffix)?;
    Some((base.to_string(), cond, inverted))
}

/// The four flag writes an ARM `cmp a, b` performs — identical to x86/AArch64.
/// Flags written by an `S`-suffixed data-processing instruction.
///
/// `subs Rd, Rn, Op2` sets exactly the flags of `cmp Rn, Op2` — `cmp` is
/// architecturally `subs` discarding its result — so the operand comparison is
/// reused verbatim and a reader of ZF cannot tell which instruction produced it.
///
/// Every other form claims only zero and sign, computed from the result. Carry
/// and overflow depend on width and signedness this lifter does not model, and
/// a *wrong* flag is worse than an absent one: a later branch will read it and
/// render a condition the CPU never evaluated.
pub(super) fn flags_for_arith(op: BinOp, dst: &VReg, lhs: Value, rhs: Value) -> (Vec<Op>, Vec<Op>) {
    if matches!(op, BinOp::Sub) {
        // Read the OPERANDS, so these must run before the result is written:
        // `subs r3,#1` has `Rd == Rn`, and taking the comparison from the
        // already-updated `r3` made the zero flag mean `r3_old == 2` instead of
        // `r3_old == 1`. The real `dec_loop` countdown then decompiled to
        // `while (i != 1)` and never terminated.
        return (cmp_flag_ops(lhs, rhs), Vec::new());
    }
    // Read the RESULT, so these must run after it exists.
    (
        Vec::new(),
        vec![
            Op::Cmp {
                dst: VReg::Flag(Flag::Z),
                op: CmpOp::Eq,
                lhs: Value::Reg(dst.clone()),
                rhs: Value::Const(0),
            },
            Op::Cmp {
                dst: VReg::Flag(Flag::S),
                op: CmpOp::Slt,
                lhs: Value::Reg(dst.clone()),
                rhs: Value::Const(0),
            },
        ],
    )
}

/// The flag set an ARM `cmp lhs, rhs` produces.
///
/// [`Flag::Ule`] is here because `cond_flag_for` binds `ls`/`hi` to it: without
/// a definition, every `bls`/`bhi` in the corpus — 22 sites — read an undefined
/// flag, so the recovered branch was decided by whatever the uninitialised
/// variable happened to hold.
pub(super) fn cmp_flag_ops(lhs: Value, rhs: Value) -> Vec<Op> {
    let mut ops: Vec<Op> = [
        (Flag::Z, CmpOp::Eq),
        (Flag::C, CmpOp::Ult),
        (Flag::Ule, CmpOp::Ule),
        (Flag::Slt, CmpOp::Slt),
        (Flag::Sle, CmpOp::Sle),
    ]
    .into_iter()
    .map(|(flag, op)| Op::Cmp {
        dst: VReg::Flag(flag),
        op,
        lhs: lhs.clone(),
        rhs: rhs.clone(),
    })
    .collect();
    // Raw N and V are also architectural outputs. The direct signed-less
    // predicate above is N xor V, so after materialising the wrapped result's
    // sign, V is exactly N xor signed-less.
    let result = VReg::Temp(40);
    let signed_result = VReg::Temp(41);
    ops.extend([
        Op::Bin {
            dst: result.clone(),
            op: BinOp::Sub,
            lhs,
            rhs,
        },
        Op::Trunc {
            dst: result.clone(),
            src: Value::Reg(result.clone()),
            from: Width::W64,
            to: Width::W32,
        },
        Op::SExt {
            dst: signed_result.clone(),
            src: Value::Reg(result),
            from: Width::W32,
            to: Width::W64,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::S),
            op: CmpOp::Slt,
            lhs: Value::Reg(signed_result),
            rhs: Value::Const(0),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::Xor,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(VReg::Flag(Flag::Slt)),
        },
    ]);
    ops
}

fn arm_unsigned32(value: Value, temp: VReg, out: &mut Vec<Op>) -> Value {
    match value {
        value @ Value::Reg(_) => {
            out.push(Op::ZExt {
                dst: temp.clone(),
                src: value,
                from: Width::W32,
                to: Width::W64,
            });
            Value::Reg(temp)
        }
        Value::Const(value) => Value::Const((value as u32) as i64),
        value => value,
    }
}

fn arm_signed32(value: Value, temp: VReg, out: &mut Vec<Op>) -> Value {
    match value {
        value @ Value::Reg(_) => {
            out.push(Op::SExt {
                dst: temp.clone(),
                src: value,
                from: Width::W32,
                to: Width::W64,
            });
            Value::Reg(temp)
        }
        Value::Const(value) => Value::Const((value as u32 as i32) as i64),
        value => value,
    }
}

/// ARM32 ADD/SUB with optional architectural carry input.
///
/// This backend intentionally stores `Flag::C` in *borrow/no-carry* polarity:
/// `lo/cc` read it directly and `hs/cs` invert it. Therefore ADC first converts
/// the stored bit back to architectural carry (`C_arch = !Flag::C`), while SBC
/// subtracts the stored borrow directly (`lhs - rhs - Flag::C`). The output is
/// kept in the same convention so the existing 22 `bls`/`bhi` sites retain
/// their polarity.
pub(super) fn arm_carry_arithmetic(
    dst: VReg,
    lhs: Value,
    rhs: Value,
    add: bool,
    with_carry: bool,
    sets_flags: bool,
) -> Vec<Op> {
    let arithmetic = if add { BinOp::Add } else { BinOp::Sub };
    let old_borrow = VReg::Temp(20);
    let saved_lhs = VReg::Temp(21);
    let saved_rhs = VReg::Temp(22);
    let partial = VReg::Temp(23);
    let mut out = Vec::new();
    if with_carry {
        out.push(Op::Assign {
            dst: old_borrow.clone(),
            src: Value::Reg(VReg::Flag(Flag::C)),
        });
    }
    // Keep the architectural destination in the same portable machine-word
    // representation as every other ARM32 arithmetic lift. The wrapped 32-bit
    // view is a private flag input, not a second write to `dst`: materialising
    // `dst = (uint32_t)dst` truncates recompiled host pointers carried in a core
    // register and made the ARM execution gate fault across ordinary loops.
    out.extend([
        Op::Assign {
            dst: saved_lhs.clone(),
            src: lhs,
        },
        Op::Assign {
            dst: saved_rhs.clone(),
            src: rhs,
        },
    ]);
    let unsigned_lhs = arm_unsigned32(Value::Reg(saved_lhs.clone()), VReg::Temp(24), &mut out);
    let unsigned_rhs = arm_unsigned32(Value::Reg(saved_rhs.clone()), VReg::Temp(25), &mut out);
    let signed_lhs = arm_signed32(Value::Reg(saved_lhs.clone()), VReg::Temp(26), &mut out);
    let signed_rhs = arm_signed32(Value::Reg(saved_rhs.clone()), VReg::Temp(27), &mut out);
    let lhs_negative = VReg::Temp(28);
    let rhs_negative = VReg::Temp(29);
    out.extend([
        Op::Cmp {
            dst: lhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_lhs,
            rhs: Value::Const(0),
        },
        Op::Cmp {
            dst: rhs_negative.clone(),
            op: CmpOp::Slt,
            lhs: signed_rhs,
            rhs: Value::Const(0),
        },
        Op::Bin {
            dst: dst.clone(),
            op: arithmetic,
            lhs: Value::Reg(saved_lhs),
            rhs: Value::Reg(saved_rhs),
        },
        Op::Trunc {
            dst: partial.clone(),
            src: Value::Reg(dst.clone()),
            from: Width::W64,
            to: Width::W32,
        },
    ]);

    if with_carry {
        let adjustment = if add {
            let architectural_carry = VReg::Temp(30);
            out.push(Op::Cmp {
                dst: architectural_carry.clone(),
                op: CmpOp::Eq,
                lhs: Value::Reg(VReg::Flag(Flag::C)),
                rhs: Value::Const(0),
            });
            Value::Reg(architectural_carry)
        } else {
            Value::Reg(VReg::Flag(Flag::C))
        };
        out.extend([Op::Bin {
            dst: dst.clone(),
            op: arithmetic,
            lhs: Value::Reg(dst.clone()),
            rhs: adjustment,
        }]);
    }

    if !sets_flags {
        return out;
    }

    let unsigned_partial = arm_unsigned32(Value::Reg(partial.clone()), VReg::Temp(31), &mut out);
    let wrapped_result = if with_carry {
        let wrapped = VReg::Temp(38);
        out.push(Op::Trunc {
            dst: wrapped.clone(),
            src: Value::Reg(dst),
            from: Width::W64,
            to: Width::W32,
        });
        wrapped
    } else {
        partial
    };
    let unsigned_result =
        arm_unsigned32(Value::Reg(wrapped_result.clone()), VReg::Temp(32), &mut out);
    let signed_result = arm_signed32(Value::Reg(wrapped_result), VReg::Temp(33), &mut out);
    out.extend([
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: unsigned_result.clone(),
            rhs: Value::Const(0),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::S),
            op: CmpOp::Slt,
            lhs: signed_result,
            rhs: Value::Const(0),
        },
    ]);

    let first = VReg::Temp(34);
    let second = VReg::Temp(35);
    if add {
        out.push(Op::Cmp {
            dst: first.clone(),
            op: CmpOp::Ule,
            lhs: unsigned_lhs,
            rhs: unsigned_partial.clone(),
        });
        if with_carry {
            out.extend([
                Op::Cmp {
                    dst: second.clone(),
                    op: CmpOp::Ule,
                    lhs: unsigned_partial,
                    rhs: unsigned_result,
                },
                Op::Bin {
                    dst: VReg::Flag(Flag::C),
                    op: BinOp::And,
                    lhs: Value::Reg(first),
                    rhs: Value::Reg(second),
                },
            ]);
        } else {
            out.push(Op::Assign {
                dst: VReg::Flag(Flag::C),
                src: Value::Reg(first),
            });
        }
    } else {
        out.push(Op::Cmp {
            dst: first.clone(),
            op: CmpOp::Ult,
            lhs: unsigned_lhs,
            rhs: unsigned_rhs,
        });
        if with_carry {
            out.extend([
                Op::Cmp {
                    dst: second.clone(),
                    op: CmpOp::Ult,
                    lhs: unsigned_partial,
                    rhs: Value::Reg(old_borrow),
                },
                Op::Bin {
                    dst: VReg::Flag(Flag::C),
                    op: BinOp::Or,
                    lhs: Value::Reg(first),
                    rhs: Value::Reg(second),
                },
            ]);
        } else {
            out.push(Op::Assign {
                dst: VReg::Flag(Flag::C),
                src: Value::Reg(first),
            });
        }
    }

    let operand_sign_relation = VReg::Temp(36);
    let result_sign_changed = VReg::Temp(37);
    out.extend([
        Op::Cmp {
            dst: operand_sign_relation.clone(),
            op: if add { CmpOp::Eq } else { CmpOp::Ne },
            lhs: Value::Reg(lhs_negative.clone()),
            rhs: Value::Reg(rhs_negative),
        },
        Op::Cmp {
            dst: result_sign_changed.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(lhs_negative),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::And,
            lhs: Value::Reg(operand_sign_relation),
            rhs: Value::Reg(result_sign_changed),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::Slt),
            op: BinOp::Xor,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(VReg::Flag(Flag::O)),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::Sle),
            op: BinOp::Or,
            lhs: Value::Reg(VReg::Flag(Flag::Z)),
            rhs: Value::Reg(VReg::Flag(Flag::Slt)),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::Ule),
            op: BinOp::Or,
            lhs: Value::Reg(VReg::Flag(Flag::C)),
            rhs: Value::Reg(VReg::Flag(Flag::Z)),
        },
    ]);
    out
}
