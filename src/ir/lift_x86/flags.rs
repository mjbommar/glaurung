//! x86 flag semantics: the ALU emitters that define EFLAGS, and the helpers
//! that give each definition the width the machine actually observes.
//!
//! Everything in this module answers one question — what does an x86 arithmetic,
//! logical, shift, rotate or carry-propagating instruction leave in ZF/CF/SF/OF,
//! and what is deliberately poisoned instead. Three facts shape the whole file:
//!
//! * The IR canonicalises GP sub-registers to their 64-bit parent, so a flag
//!   defined at an encoded operand width must first narrow its inputs. That is
//!   [`signed_cmp_value`] and [`unsigned_cmp_value`], and every emitter below
//!   goes through them rather than comparing raw parent registers.
//! * PF and AF have no modelled low-bit expression. They are written as explicit
//!   [`Op::Undef`] poison ([`undef_flag`]) rather than left stale, so a consumer
//!   that reads them cannot silently pick up an unrelated earlier definition.
//! * The result write and the flag writes are one unit. Splitting them is what
//!   makes a dead-flag pruner able to remove machine bookkeeping without taking
//!   source-visible dataflow with it.
//!
//! [`emit_bin_with_flags`] is the operator-indexed entry the lifter reaches
//! through [`emit_machine_bin_with_flags`], which adds the explicit read/write
//! width effects x86-64 sub-register writes imply. ADC/SBB live here too because
//! their carry predicates are the same width machinery applied twice.

use iced_x86::{Mnemonic, OpKind};

use crate::ir::regview;
use crate::ir::types::*;

use super::{cmp_operand_as_value, mem_op_of, operand_width, reg_name};

/// Give a signed comparison the value at the machine operand's width.
pub(super) fn signed_cmp_value(value: Value, width: Width, temp: VReg, ops: &mut Vec<Op>) -> Value {
    if width.bits() < 64 && matches!(&value, Value::Reg(_)) {
        ops.push(Op::SExt {
            dst: temp.clone(),
            src: value,
            from: width,
            to: Width::W64,
        });
        Value::Reg(temp)
    } else {
        value
    }
}

/// Give equality/carry predicates the unsigned word the machine actually
/// observes at `width`. Canonical parent registers may otherwise carry
/// different high halves depending on whether their latest 32-bit source was
/// made explicit, even though x86 ZF/CF compare only the encoded low word.
pub(super) fn unsigned_cmp_value(
    value: Value,
    width: Width,
    temp: VReg,
    ops: &mut Vec<Op>,
) -> Value {
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
        Value::Const(value) => {
            let bits = width.bits();
            let mask = if bits == 0 { 0 } else { (1u64 << bits) - 1 };
            Value::Const((value as u64 & mask) as i64)
        }
        other => other,
    }
}

/// Emit LLIR for a reg/reg or reg/imm binary op (`dst = dst <op> src`).
fn emit_bin(dst: VReg, op: BinOp, src: Value) -> Op {
    Op::Bin {
        dst: dst.clone(),
        op,
        lhs: Value::Reg(dst),
        rhs: src,
    }
}

pub(super) fn undef_flag(flag: Flag, reason: impl Into<String>) -> Op {
    Op::Undef {
        dst: VReg::Flag(flag),
        reason: reason.into(),
    }
}

pub(super) fn append_undef_flags(ops: &mut Vec<Op>, flags: &[Flag], reason: &str) {
    ops.extend(flags.iter().map(|flag| undef_flag(*flag, reason)));
}

/// Snapshot the FULL signed product of a truncating x86 multiply.
///
/// `imul r, r/m` and `imul r, r/m, imm` write only the low `width` bits of a
/// `2 * width`-bit product, so the truncation itself is the only thing CF/OF
/// report — and reconstructing it after the fact is impossible, because the
/// two-operand form's destination IS one of the multiplicands. Take the wide
/// product before the architectural result is written; [`append_imul_overflow_flags`]
/// turns it into flags afterwards.
///
/// Returns `None` when the wide product does not fit the IR's canonical 64-bit
/// value width (i.e. at `width == 64`, where the architecture computes a 128-bit
/// intermediate). Callers keep explicit poison for that case.
pub(super) fn imul_wide_product(
    ops: &mut Vec<Op>,
    lhs: Value,
    rhs: Value,
    width: Width,
) -> Option<VReg> {
    if width.bits() >= Width::W64.bits() {
        return None;
    }
    let lhs = signed_cmp_value(lhs, width, VReg::Temp(80), ops);
    let rhs = signed_cmp_value(rhs, width, VReg::Temp(81), ops);
    let product = VReg::Temp(82);
    ops.push(Op::Bin {
        dst: product.clone(),
        op: BinOp::Mul,
        lhs,
        rhs,
    });
    Some(product)
}

/// Exact CF/OF for a truncating x86 multiply, from a [`imul_wide_product`] snapshot.
///
/// Intel SDM Vol. 2A, IMUL: "the CF and OF flags are set when the signed integer
/// value of the intermediate product differs from the sign extended
/// operand-size-truncated product, and cleared otherwise." That is literally the
/// predicate emitted here — `product != sext_width(trunc_width(product))` — and it
/// is what `seto` / `jo` after an `imul` reads. Marking those flags undefined is
/// not the conservative choice: a reader of OF would be reading a value the IR has
/// declared meaningless, which is exactly how `Rust`'s `overflowing_mul` /
/// `checked_mul` / `saturating_mul` lost their overflow verdict.
///
/// `product == None` means the width has no representable wide product, so the two
/// flags stay explicit poison rather than becoming a silently wrong predicate.
pub(super) fn append_imul_overflow_flags(ops: &mut Vec<Op>, product: Option<VReg>, width: Width) {
    let Some(product) = product else {
        append_undef_flags(
            ops,
            &[Flag::C, Flag::O],
            "x86 IMUL defines CF/OF from a 128-bit intermediate product, which is wider \
             than any IR value width",
        );
        return;
    };
    let truncated = VReg::Temp(83);
    let extended = VReg::Temp(84);
    ops.extend([
        Op::Trunc {
            dst: truncated.clone(),
            src: Value::Reg(product.clone()),
            from: Width::W64,
            to: width,
        },
        Op::SExt {
            dst: extended.clone(),
            src: Value::Reg(truncated),
            from: width,
            to: Width::W64,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ne,
            lhs: Value::Reg(product.clone()),
            rhs: Value::Reg(extended.clone()),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::O),
            op: CmpOp::Ne,
            lhs: Value::Reg(product),
            rhs: Value::Reg(extended),
        },
    ]);
}

/// Exact CF/OF for the ONE-operand x86 multiplies, which keep the whole product
/// in `hi:lo` instead of truncating it.
///
/// SDM Vol. 2A, MUL: "the CF and OF flags are set to 0 if the upper half of the
/// result is 0; otherwise, they are set to 1". IMUL's one-operand form sets them
/// when the upper half is not the sign extension of the lower half. Both sentences
/// say "the product does not fit in `width` bits" — unsigned for MUL, signed for
/// IMUL — so both are expressed here as a fit test on a product taken at double
/// width, and the signed case is literally the truncating-IMUL predicate.
///
/// Below 64 bits the predicate is built from the MULTIPLICANDS, not from the
/// `hi`/`lo` registers the instruction just defined. At 16 bits those halves are
/// `dx`/`ax` — bit-preserving views `regview::ssa_parent` declines to merge — so a
/// bare read of one is a read of a name nothing in the function defines, the exact
/// failure [`super::wide_arith::wide_mul_ops`]'s accumulator snapshot exists to
/// avoid.
///
/// At 64 bits there is no wide product to take: the IR has no 128-bit value. But
/// this form does not need one, because the high half is already a materialised
/// output, and at that width the halves are `rdx`/`rax` — canonical names, safe to
/// read back. `mul r64; seto` is a real sequence, not a corner: it is how Clang
/// range-checks a `malloc`/VLA byte count (`33_knapsack:clang:O2` reaches it), and
/// poisoning OF there turned the check into `__unknown(0)`.
pub(super) fn append_wide_mul_overflow_flags(
    ops: &mut Vec<Op>,
    lhs: Value,
    rhs: Value,
    width: Width,
    signed: bool,
    halves: (&str, &str),
) {
    if width.bits() >= Width::W64.bits() {
        let (lo_name, hi_name) = halves;
        // Unsigned: the product overflows exactly when the high half is nonzero.
        // Signed: exactly when the high half is not the low half's sign extension.
        let expected = if signed {
            let sign = VReg::Temp(85);
            ops.push(Op::Bin {
                dst: sign.clone(),
                op: BinOp::Sar,
                lhs: Value::Reg(VReg::phys(lo_name)),
                rhs: Value::Const(i64::from(width.bits()) - 1),
            });
            Value::Reg(sign)
        } else {
            Value::Const(0)
        };
        ops.extend([Flag::C, Flag::O].map(|flag| Op::Cmp {
            dst: VReg::Flag(flag),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::phys(hi_name)),
            rhs: expected.clone(),
        }));
        return;
    }
    if signed {
        let product = imul_wide_product(ops, lhs, rhs, width);
        append_imul_overflow_flags(ops, product, width);
        return;
    }
    let lhs = unsigned_cmp_value(lhs, width, VReg::Temp(85), ops);
    let rhs = unsigned_cmp_value(rhs, width, VReg::Temp(86), ops);
    let product = VReg::Temp(87);
    let truncated = VReg::Temp(88);
    let extended = VReg::Temp(89);
    ops.extend([
        Op::Bin {
            dst: product.clone(),
            op: BinOp::Mul,
            lhs,
            rhs,
        },
        Op::Trunc {
            dst: truncated.clone(),
            src: Value::Reg(product.clone()),
            from: Width::W64,
            to: width,
        },
        Op::ZExt {
            dst: extended.clone(),
            src: Value::Reg(truncated),
            from: width,
            to: Width::W64,
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ne,
            lhs: Value::Reg(product.clone()),
            rhs: Value::Reg(extended.clone()),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::O),
            op: CmpOp::Ne,
            lhs: Value::Reg(product),
            rhs: Value::Reg(extended),
        },
    ]);
}

/// Define ZF and the actual architectural SF for `result` at `width`.
pub(super) fn zero_sign_flags(result: Value, width: Width, signed_temp: u32, ops: &mut Vec<Op>) {
    let unsigned = unsigned_cmp_value(result.clone(), width, VReg::Temp(signed_temp + 100), ops);
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::Z),
        op: CmpOp::Eq,
        lhs: unsigned,
        rhs: Value::Const(0),
    });
    let signed = signed_cmp_value(result, width, VReg::Temp(signed_temp), ops);
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::S),
        op: CmpOp::Slt,
        lhs: signed,
        rhs: Value::Const(0),
    });
}

/// Exact ZF/CF/SF/OF effects of subtraction, plus explicit poison for the two
/// defined-but-not-yet-materialised low-bit flags. `cmp` uses the same helper
/// with `write_result = false` semantics encoded by its private result temp.
fn emit_sub_with_flags(dst: VReg, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let lhs = Value::Reg(dst.clone());
    let signed_lhs = signed_cmp_value(lhs.clone(), width, VReg::Temp(30), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(31), &mut ops);
    let unsigned_lhs = unsigned_cmp_value(lhs.clone(), width, VReg::Temp(34), &mut ops);
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(35), &mut ops);
    let signed_less = VReg::Temp(32);
    ops.push(Op::Cmp {
        dst: signed_less.clone(),
        op: CmpOp::Slt,
        lhs: signed_lhs,
        rhs: signed_rhs,
    });
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::C),
        op: CmpOp::Ult,
        lhs: unsigned_lhs,
        rhs: unsigned_rhs,
    });
    ops.push(emit_bin(dst.clone(), BinOp::Sub, rhs));
    zero_sign_flags(Value::Reg(dst), width, 33, &mut ops);
    // For subtraction, signed-less == SF xor OF, therefore OF == signed-less xor SF.
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::O),
        op: BinOp::Xor,
        lhs: Value::Reg(signed_less),
        rhs: Value::Reg(VReg::Flag(Flag::S)),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 SUB defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

pub(super) fn cmp_flag_ops(lhs: Value, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let signed_lhs = signed_cmp_value(lhs.clone(), width, VReg::Temp(30), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(31), &mut ops);
    let unsigned_lhs = unsigned_cmp_value(lhs.clone(), width, VReg::Temp(35), &mut ops);
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(36), &mut ops);
    let signed_less = VReg::Temp(32);
    let result = VReg::Temp(33);
    ops.extend([
        Op::Cmp {
            dst: signed_less.clone(),
            op: CmpOp::Slt,
            lhs: signed_lhs,
            rhs: signed_rhs,
        },
        Op::Bin {
            dst: result.clone(),
            op: BinOp::Sub,
            lhs: lhs.clone(),
            rhs: rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::Z),
            op: CmpOp::Eq,
            lhs: unsigned_lhs.clone(),
            rhs: unsigned_rhs.clone(),
        },
        Op::Cmp {
            dst: VReg::Flag(Flag::C),
            op: CmpOp::Ult,
            lhs: unsigned_lhs,
            rhs: unsigned_rhs,
        },
    ]);
    zero_sign_flags(Value::Reg(result), width, 34, &mut ops);
    // `zero_sign_flags` also emitted a result-based ZF. Preserve the cleaner,
    // exact `lhs == rhs` definition above by removing only that duplicate.
    let result_zf = ops
        .iter()
        .rposition(|op| {
            matches!(
                op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    ..
                }
            )
        })
        .expect("zero_sign_flags emits ZF");
    ops.remove(result_zf);
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::O),
        op: BinOp::Xor,
        lhs: Value::Reg(signed_less),
        rhs: Value::Reg(VReg::Flag(Flag::S)),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 CMP defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

/// Exact ZF/CF/SF/OF effects of addition. PF/AF are new poisoned values rather
/// than stale values until their low-bit expressions are materialised.
pub(super) fn emit_add_with_flags(dst: VReg, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = Vec::new();
    let original = VReg::Temp(30);
    ops.push(Op::Assign {
        dst: original.clone(),
        src: Value::Reg(dst.clone()),
    });
    let signed_lhs = signed_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(31),
        &mut ops,
    );
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(32), &mut ops);
    let lhs_negative = VReg::Temp(33);
    let rhs_negative = VReg::Temp(34);
    ops.extend([
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
        emit_bin(dst.clone(), BinOp::Add, rhs),
    ]);
    zero_sign_flags(Value::Reg(dst.clone()), width, 35, &mut ops);
    let unsigned_result =
        unsigned_cmp_value(Value::Reg(dst.clone()), width, VReg::Temp(38), &mut ops);
    let unsigned_original = unsigned_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(39),
        &mut ops,
    );
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::C),
        op: CmpOp::Ult,
        lhs: unsigned_result,
        rhs: unsigned_original,
    });
    let same_sign = VReg::Temp(36);
    let sign_changed = VReg::Temp(37);
    ops.extend([
        Op::Cmp {
            dst: same_sign.clone(),
            op: CmpOp::Eq,
            lhs: Value::Reg(lhs_negative),
            rhs: Value::Reg(rhs_negative),
        },
        Op::Cmp {
            dst: sign_changed.clone(),
            op: CmpOp::Ne,
            lhs: Value::Reg(VReg::Flag(Flag::S)),
            rhs: Value::Reg(VReg::Temp(33)),
        },
        Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::And,
            lhs: Value::Reg(same_sign),
            rhs: Value::Reg(sign_changed),
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        "x86 ADD defines PF/AF, but their exact low-bit expressions are not modelled",
    );
    ops
}

fn emit_logic_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    let mut ops = vec![emit_bin(dst.clone(), op, rhs)];
    zero_sign_flags(Value::Reg(dst), width, 30, &mut ops);
    ops.extend([
        Op::Assign {
            dst: VReg::Flag(Flag::C),
            src: Value::Const(0),
        },
        Op::Assign {
            dst: VReg::Flag(Flag::O),
            src: Value::Const(0),
        },
        undef_flag(
            Flag::P,
            "x86 logic defines PF, but its exact low-byte parity expression is not modelled",
        ),
        undef_flag(Flag::A, "x86 logic leaves AF architecturally undefined"),
    ]);
    ops
}

fn emit_shift_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    let mask = if width.bits() == 64 { 63 } else { 31 };
    match rhs {
        Value::Const(raw) => {
            let count = raw & mask;
            if count == 0 {
                // A masked zero count preserves the destination and every flag.
                return vec![Op::Nop];
            }
            let mut ops = vec![emit_bin(dst.clone(), op, Value::Const(count))];
            zero_sign_flags(Value::Reg(dst), width, 30, &mut ops);
            ops.push(undef_flag(
                Flag::C,
                "x86 shift defines CF, but the shifted-out-bit expression is not modelled",
            ));
            ops.push(if count == 1 {
                undef_flag(
                    Flag::O,
                    "x86 one-bit shift defines OF, but its exact expression is not modelled",
                )
            } else {
                undef_flag(
                    Flag::O,
                    "x86 multi-bit shift leaves OF architecturally undefined",
                )
            });
            ops.extend([
                undef_flag(
                    Flag::P,
                    "x86 shift defines PF, but its exact low-byte parity expression is not modelled",
                ),
                undef_flag(Flag::A, "x86 shift leaves AF architecturally undefined"),
            ]);
            ops
        }
        variable => {
            // Every x86 variable-count shift masks CL before executing: five
            // bits for 8/16/32-bit operands and six for 64-bit operands. C does
            // not—it makes a count at least as wide as the promoted left
            // operand undefined—so leaving the raw count in the AST changes
            // executable behavior for precisely those values. Preserve the
            // architectural count as ordinary dataflow.
            let masked_count = VReg::Temp(29);
            let mut ops = vec![
                Op::Bin {
                    dst: masked_count.clone(),
                    op: BinOp::And,
                    lhs: variable,
                    rhs: Value::Const(mask),
                },
                emit_bin(dst, op, Value::Reg(masked_count)),
            ];
            append_undef_flags(
                &mut ops,
                &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 variable-count shift has count-sensitive flag effects not yet modelled",
            );
            ops
        }
    }
}

/// Append the two flag effects of a non-zero ROL/ROR.  ZF/SF/PF/AF are
/// architecturally preserved and therefore deliberately absent.
pub(super) fn append_rotate_flags(
    ops: &mut Vec<Op>,
    dst: VReg,
    rotate_left: bool,
    width: Width,
    count: i64,
) {
    let top_shift = (width.bits() - 1) as i64;
    if rotate_left {
        ops.push(Op::Bin {
            dst: VReg::Flag(Flag::C),
            op: BinOp::And,
            lhs: Value::Reg(dst.clone()),
            rhs: Value::Const(1),
        });
    } else {
        let top = VReg::Temp(50);
        ops.extend([
            Op::Bin {
                dst: top.clone(),
                op: BinOp::Shr,
                lhs: Value::Reg(dst.clone()),
                rhs: Value::Const(top_shift),
            },
            Op::Bin {
                dst: VReg::Flag(Flag::C),
                op: BinOp::And,
                lhs: Value::Reg(top),
                rhs: Value::Const(1),
            },
        ]);
    }

    if count != 1 {
        ops.push(undef_flag(
            Flag::O,
            "x86 multi-bit rotate leaves OF architecturally undefined",
        ));
        return;
    }

    let top = VReg::Temp(51);
    ops.push(Op::Bin {
        dst: top.clone(),
        op: BinOp::Shr,
        lhs: Value::Reg(dst.clone()),
        rhs: Value::Const(top_shift),
    });
    if rotate_left {
        ops.push(Op::Bin {
            dst: VReg::Flag(Flag::O),
            op: BinOp::Xor,
            lhs: Value::Reg(top),
            rhs: Value::Reg(VReg::Flag(Flag::C)),
        });
    } else {
        let next = VReg::Temp(52);
        ops.extend([
            Op::Bin {
                dst: next.clone(),
                op: BinOp::Shr,
                lhs: Value::Reg(dst),
                rhs: Value::Const(top_shift - 1),
            },
            Op::Bin {
                dst: next.clone(),
                op: BinOp::And,
                lhs: Value::Reg(next.clone()),
                rhs: Value::Const(1),
            },
            Op::Bin {
                dst: VReg::Flag(Flag::O),
                op: BinOp::Xor,
                lhs: Value::Reg(top),
                rhs: Value::Reg(next),
            },
        ]);
    }
}

fn emit_bin_with_flags(dst: VReg, op: BinOp, rhs: Value, width: Width) -> Vec<Op> {
    match op {
        BinOp::Add => emit_add_with_flags(dst, rhs, width),
        BinOp::Sub => emit_sub_with_flags(dst, rhs, width),
        BinOp::And | BinOp::Or | BinOp::Xor => emit_logic_with_flags(dst, op, rhs, width),
        BinOp::Shl | BinOp::Shr | BinOp::Sar => emit_shift_with_flags(dst, op, rhs, width),
        BinOp::Mul => {
            // The destination is also the multiplicand, so the wide product has to
            // be snapshotted BEFORE the truncating write clobbers it.
            let mut ops = Vec::new();
            let product = imul_wide_product(&mut ops, Value::Reg(dst.clone()), rhs.clone(), width);
            ops.push(emit_bin(dst, op, rhs));
            append_imul_overflow_flags(&mut ops, product, width);
            append_undef_flags(
                &mut ops,
                &[Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 IMUL leaves ZF/SF/PF/AF architecturally undefined",
            );
            ops
        }
        BinOp::Div => {
            let mut ops = vec![emit_bin(dst, op, rhs)];
            append_undef_flags(
                &mut ops,
                &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
                "x86 DIV leaves arithmetic flags architecturally undefined",
            );
            ops
        }
        BinOp::LogicalAnd | BinOp::LogicalOr => {
            unreachable!("source-level short-circuit operators are not x86 ALU operations")
        }
    }
}

/// Apply an x86 ALU operation at its encoded operand width, even though the
/// downstream SSA model canonicalises GP sub-registers to their full parent.
///
/// Most low-word arithmetic happens to retain the right low bits when computed
/// at 64 bits, but right shifts do not: `sar eax,1` must replicate bit 31, not
/// the already-zeroed bit 63, and `shr` must never shift stale parent bits down
/// into the low word. Make that read width explicit before the operation. A
/// 32-bit GP destination on x86-64 then zero-extends into its parent, so record
/// that write effect explicitly after the flag values have consumed the result.
///
/// The narrowing is stated against the IR's CANONICAL 64-bit value width on both
/// x86-64 and i386, not against the target's register width. On i386 a 32-bit
/// operand is the whole machine register, so the extension looks redundant — but
/// the IR value it names is 64 bits wide, and the recovered C is rebuilt at the
/// host word, where a `long` local really can carry bits above 31. Omitting it
/// there made `t >>= 8` on a negative `int` shift a sign-extended 64-bit value:
/// `03_loop_shapes:i386:O0:dowhile_recompute` ran eight loop iterations instead
/// of four.
pub(super) fn emit_machine_bin_with_flags(
    dst: VReg,
    op: BinOp,
    rhs: Value,
    width: Width,
    bits: u32,
) -> Vec<Op> {
    let machine_width = Width::W64;
    let mut ops = Vec::new();
    if width < machine_width && matches!(op, BinOp::Shr | BinOp::Sar) {
        let src = Value::Reg(dst.clone());
        ops.push(if op == BinOp::Sar {
            Op::SExt {
                dst: dst.clone(),
                src,
                from: width,
                to: machine_width,
            }
        } else {
            Op::ZExt {
                dst: dst.clone(),
                src,
                from: width,
                to: machine_width,
            }
        });
    }
    ops.extend(emit_bin_with_flags(dst.clone(), op, rhs, width));
    let zero_extends_parent = bits == 64
        && width == Width::W32
        && matches!(
            &dst,
            VReg::Phys(name)
                if regview::view(regview::Arch::X86_64, name).is_some_and(|view| view.zero_extends())
        );
    if zero_extends_parent {
        ops.push(Op::ZExt {
            dst: dst.clone(),
            src: Value::Reg(dst),
            from: Width::W32,
            to: Width::W64,
        });
    }
    ops
}

pub(super) fn emit_inc_dec_with_flags(dst: VReg, increment: bool, width: Width) -> Vec<Op> {
    let original = VReg::Temp(40);
    let mut ops = vec![Op::Assign {
        dst: original.clone(),
        src: Value::Reg(dst.clone()),
    }];
    ops.push(emit_bin(
        dst.clone(),
        if increment { BinOp::Add } else { BinOp::Sub },
        Value::Const(1),
    ));
    zero_sign_flags(Value::Reg(dst), width, 41, &mut ops);
    let signed_original = signed_cmp_value(Value::Reg(original), width, VReg::Temp(42), &mut ops);
    let boundary = if increment {
        if width.bits() == 64 {
            i64::MAX
        } else {
            (1_i64 << (width.bits() - 1)) - 1
        }
    } else if width.bits() == 64 {
        i64::MIN
    } else {
        -(1_i64 << (width.bits() - 1))
    };
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::O),
        op: CmpOp::Eq,
        lhs: signed_original,
        rhs: Value::Const(boundary),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        if increment {
            "x86 INC defines PF/AF, but their exact low-bit expressions are not modelled"
        } else {
            "x86 DEC defines PF/AF, but their exact low-bit expressions are not modelled"
        },
    );
    // CF is intentionally absent: INC/DEC preserve it.
    ops
}

pub(super) fn bin_for(mnem: Mnemonic) -> Option<BinOp> {
    Some(match mnem {
        Mnemonic::Add => BinOp::Add,
        Mnemonic::Sub => BinOp::Sub,
        Mnemonic::And => BinOp::And,
        Mnemonic::Or => BinOp::Or,
        Mnemonic::Xor => BinOp::Xor,
        Mnemonic::Shl => BinOp::Shl,
        Mnemonic::Shr => BinOp::Shr,
        Mnemonic::Sar => BinOp::Sar,
        Mnemonic::Imul => BinOp::Mul,
        _ => return None,
    })
}

/// Exact CF/ZF/SF/OF effects for one ADC/SBB destination.
///
/// The arithmetic is deliberately split into two machine-width steps. Besides
/// matching the instruction's dataflow, that gives carry/borrow two exact
/// predicates that work at 64 bits without trying to represent `2^64` in an IR
/// constant:
///
/// * ADC carry is `(partial < lhs) || (result < partial)`;
/// * SBB borrow is `(lhs < rhs) || (partial < old_cf)`.
///
/// Signed overflow follows the architectural sign relation. ADC overflows when
/// the operand signs agree and the result sign changes; SBB when they disagree
/// and the result sign changes. PF/AF remain explicit poison rather than stale
/// values because their low-bit expressions are not yet modelled.
fn emit_adc_sbb_with_flags(dst: VReg, rhs: Value, width: Width, add: bool) -> Vec<Op> {
    let arithmetic = if add { BinOp::Add } else { BinOp::Sub };
    let old_carry = VReg::Temp(60);
    let original = VReg::Temp(61);
    let partial = VReg::Temp(62);
    let mut ops = vec![
        Op::Assign {
            dst: old_carry.clone(),
            src: Value::Reg(VReg::Flag(Flag::C)),
        },
        Op::Assign {
            dst: original.clone(),
            src: Value::Reg(dst.clone()),
        },
    ];

    let unsigned_lhs = unsigned_cmp_value(
        Value::Reg(original.clone()),
        width,
        VReg::Temp(63),
        &mut ops,
    );
    let unsigned_rhs = unsigned_cmp_value(rhs.clone(), width, VReg::Temp(64), &mut ops);
    let signed_lhs = signed_cmp_value(Value::Reg(original), width, VReg::Temp(65), &mut ops);
    let signed_rhs = signed_cmp_value(rhs.clone(), width, VReg::Temp(66), &mut ops);
    let lhs_negative = VReg::Temp(67);
    let rhs_negative = VReg::Temp(68);
    ops.extend([
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
        emit_bin(dst.clone(), arithmetic, rhs),
    ]);
    if width.bits() < 64 {
        ops.push(Op::Trunc {
            dst: dst.clone(),
            src: Value::Reg(dst.clone()),
            from: Width::W64,
            to: width,
        });
    }
    ops.push(Op::Assign {
        dst: partial.clone(),
        src: Value::Reg(dst.clone()),
    });
    ops.push(emit_bin(
        dst.clone(),
        arithmetic,
        Value::Reg(old_carry.clone()),
    ));
    if width.bits() < 64 {
        ops.push(Op::Trunc {
            dst: dst.clone(),
            src: Value::Reg(dst.clone()),
            from: Width::W64,
            to: width,
        });
    }
    zero_sign_flags(Value::Reg(dst.clone()), width, 69, &mut ops);

    let unsigned_partial = unsigned_cmp_value(Value::Reg(partial), width, VReg::Temp(70), &mut ops);
    let unsigned_result = unsigned_cmp_value(Value::Reg(dst), width, VReg::Temp(71), &mut ops);
    let first_carry = VReg::Temp(72);
    let second_carry = VReg::Temp(73);
    if add {
        ops.extend([
            Op::Cmp {
                dst: first_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_partial.clone(),
                rhs: unsigned_lhs,
            },
            Op::Cmp {
                dst: second_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_result,
                rhs: unsigned_partial,
            },
        ]);
    } else {
        ops.extend([
            Op::Cmp {
                dst: first_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_lhs,
                rhs: unsigned_rhs,
            },
            Op::Cmp {
                dst: second_carry.clone(),
                op: CmpOp::Ult,
                lhs: unsigned_partial,
                rhs: Value::Reg(old_carry),
            },
        ]);
    }
    ops.push(Op::Bin {
        dst: VReg::Flag(Flag::C),
        op: BinOp::Or,
        lhs: Value::Reg(first_carry),
        rhs: Value::Reg(second_carry),
    });

    let operand_sign_relation = VReg::Temp(74);
    let result_sign_changed = VReg::Temp(75);
    ops.extend([
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
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::P, Flag::A],
        if add {
            "x86 ADC defines PF/AF, but their exact low-bit expressions are not modelled"
        } else {
            "x86 SBB defines PF/AF, but their exact low-bit expressions are not modelled"
        },
    );
    ops
}

fn adc_sbb_ops(instr: &iced_x86::Instruction, add: bool) -> Vec<Op> {
    let mnemonic = if add { "adc" } else { "sbb" };
    if instr.op_count() != 2 {
        return vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }];
    }

    let width = operand_width(instr, 0);
    match instr.op_kind(0) {
        OpKind::Register => {
            let dst = VReg::phys(reg_name(instr.op_register(0)));
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(0), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: mnemonic.into(),
                }];
            };
            ops.extend(emit_adc_sbb_with_flags(dst, rhs, width, add));
            ops
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            let mut ops = Vec::new();
            let Some(rhs) = cmp_operand_as_value(instr, 1, VReg::Temp(1), &mut ops) else {
                return vec![Op::Unknown {
                    mnemonic: mnemonic.into(),
                }];
            };
            let tmp = VReg::Temp(0);
            ops.insert(
                0,
                Op::Load {
                    dst: tmp.clone(),
                    addr: addr.clone(),
                },
            );
            ops.extend(emit_adc_sbb_with_flags(tmp.clone(), rhs, width, add));
            ops.push(Op::Store {
                addr,
                src: Value::Reg(tmp),
            });
            ops
        }
        _ => vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }],
    }
}

pub(super) fn adc_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    adc_sbb_ops(instr, true)
}

pub(super) fn sbb_ops(instr: &iced_x86::Instruction) -> Vec<Op> {
    adc_sbb_ops(instr, false)
}
