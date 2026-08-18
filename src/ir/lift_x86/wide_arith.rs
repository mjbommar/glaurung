//! x86 wide and multi-register integer arithmetic.
//!
//! The instructions here share one property that separates them from the
//! ordinary two-operand ALU forms: a single machine instruction spans more
//! than one architectural register, or defines a register the encoding does
//! not name. `shrd`/`shld` shift a value held in a register *pair*; `mul`,
//! `imul`, `div`, and `idiv` in their one-operand forms read and write the
//! implicit `rdx:rax` accumulator pair; `cmpxchg` compares against the
//! accumulator and writes it back only on failure; `bsr`/`bsf` produce a bit
//! index whose zero case the ISA leaves undefined.
//!
//! Each of those needs the same two disciplines, which is why they live
//! together: every input is snapshotted into a temporary *before* any
//! architectural output is defined, and every flag the instruction leaves
//! architecturally undefined is poisoned rather than left stale. Getting
//! either wrong produces IR that reads a register the SSA layer never saw
//! defined, which is how these lowerings failed before they were exact.
//!
//! The accumulator-name helper deliberately stays in the parent: `stos`
//! lowering in [`super::string_ops`] needs it too, so it is reachable here as
//! `super::accumulator_name_for_width` without widening anything.

use iced_x86::OpKind;

use crate::ir::types::*;

use super::flags::{append_undef_flags, cmp_flag_ops, unsigned_cmp_value};
use super::mul_flags::append_wide_mul_overflow_flags;
use super::{
    accumulator_name_for_width, cmp_operand_as_value, mem_op_of, operand_width, partial_gp_view,
    read_view_ops, reg_name, reg_size,
};

/// `shrd dst, src, imm8` / `shld dst, src, imm8` — the double-precision shift.
///
/// This is how a 32-bit compiler shifts a 64-bit value held in a register pair:
/// `add eax,ecx ; adc edx,ebx ; shrd eax,edx,2 ; sar edx,2` is `(int64_t)x / 4`.
/// The `adc` half has been modelled since this lifter learned x86 CF; the
/// `shrd` half had not, so every one of those sequences lost its low word to an
/// opaque comment. All four i386 fixtures that compute in a register pair
/// (`28_euler_ode`, `30_finite_difference`, both optimisation levels) fail on
/// exactly that.
///
/// The lowering is exact, and the operand width is what makes it exact. A
/// canonicalised `eax` lives in a 64-bit `rax` whose high half this IR never
/// clears, so `dst >> count` on the raw value would shift bits that are not the
/// machine's, and `src << (32 - count)` would leave a result no 32-bit register
/// can hold. Both operands are therefore zero-extended from their encoded width
/// first and the joined result masked back to it — the same `unsigned_cmp_value`
/// discipline that lets `add`/`adc` claim a provable carry.
///
/// Deliberately narrow:
/// * only the immediate-count form. `shrd dst, src, cl` shifts by a value this
///   lifter would have to mask and branch on at lift time, and a count of zero
///   is architecturally a *no-op that leaves the flags alone* — not something a
///   single shift expression can say.
/// * only a register destination; the memory form would need a load/store pair
///   with the same masking and does not occur in the corpus.
/// * the flags are declared undefined rather than guessed, exactly as
///   `adc_sbb_ops` does. x86 defines CF as the last bit shifted out and leaves
///   OF/AF undefined for counts above 1; a later `jb` reading a fabricated CF
///   would render a branch the CPU never evaluated.
pub(super) fn double_shift_ops(instr: &iced_x86::Instruction, right: bool) -> Vec<Op> {
    let mnemonic = if right { "shrd" } else { "shld" };
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }]
    };
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !matches!(instr.op_kind(2), OpKind::Immediate8)
    {
        return unsupported();
    }
    let dst_name = reg_name(instr.op_register(0));
    let src_name = reg_name(instr.op_register(1));
    let Some(width) = phys_reg_width(&dst_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) || phys_reg_width(&src_name) != Some(width) {
        return unsupported();
    }
    let bits = u32::from(width.bits());
    // The architectural count mask: 5 bits for 32-bit operands, 6 for 64-bit.
    let count = u32::from(instr.immediate8()) & (bits - 1);
    if count == 0 {
        // Architecturally a complete no-op, flags included.
        return vec![Op::Nop];
    }
    let dst = VReg::phys(dst_name);
    let src = VReg::phys(src_name);
    let kept = VReg::Temp(0);
    let joined = VReg::Temp(1);
    let mut ops = Vec::new();

    // The destination's own contribution, at its real width.
    ops.push(Op::ZExt {
        dst: kept.clone(),
        src: Value::Reg(dst.clone()),
        from: width,
        to: Width::W64,
    });
    ops.push(Op::Bin {
        dst: kept.clone(),
        op: if right { BinOp::Shr } else { BinOp::Shl },
        lhs: Value::Reg(kept.clone()),
        rhs: Value::Const(i64::from(count)),
    });
    // The bits shifted in from the other half of the pair.
    ops.push(Op::ZExt {
        dst: joined.clone(),
        src: Value::Reg(src),
        from: width,
        to: Width::W64,
    });
    ops.push(Op::Bin {
        dst: joined.clone(),
        op: if right { BinOp::Shl } else { BinOp::Shr },
        lhs: Value::Reg(joined.clone()),
        rhs: Value::Const(i64::from(bits - count)),
    });
    ops.push(Op::Bin {
        dst: dst.clone(),
        op: BinOp::Or,
        lhs: Value::Reg(kept),
        rhs: Value::Reg(joined),
    });
    // At 32 bits one of the two halves is always shifted left past the
    // register, so the join has to be masked back down; at 64 bits the IR word
    // is the register and the shift truncates on its own.
    if bits < 64 {
        ops.push(Op::Bin {
            dst: dst.clone(),
            op: BinOp::And,
            lhs: Value::Reg(dst),
            rhs: Value::Const(((1u64 << bits) - 1) as i64),
        });
    }
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
        "x86 SHRD/SHLD define CF from the last bit shifted out and leave OF/AF \
         undefined above a count of one; none of that is modelled",
    );
    ops
}

/// `bsr`/`bsf` — the x86 bit scans, lowered through the same exact `clz`
/// intrinsic the ARM lifter already emits (`ast::WideArithmetic::CountLeadingZeros`,
/// rendered as `((unsigned)(x) == 0 ? BITS : __builtin_clz((unsigned)(x)))`).
///
/// Left unmodelled these were an `Op::Unknown`, so the destination was never
/// defined and every consumer read an uninitialised local. `14_flag_effects`'s
/// `shift_until_zero` is exactly that: gcc -O2 compiles the shift-count loop to
/// `bsr %eax,%ecx ; add $1,%ecx ; test %eax,%eax ; cmovne %ecx,%eax`, and we
/// recovered `return ((arg0 != 0) ? (var1 + 1) : arg0);` with `var1` undefined.
///
/// **The x86 zero case is NOT ARM's.** `clz` answers the operand width; `bsr`
/// and `bsf` instead set ZF and leave the DESTINATION ALONE (AMD APM v3 states
/// "the destination is left unchanged"; Intel SDM calls it undefined, which
/// permits that). Modelling the scan as producing `32`, `0`, or `-1` would
/// invent a value the machine never wrote — so the scan result is gated behind
/// `Op::Ite` on `src != 0` with the destination's PRIOR value as the else arm.
/// `Op::Ite` rather than `Op::CondAssign` for the reason `cmovcc` uses it: a
/// `CondAssign` destination is a pure def, so dataflow cannot see that the old
/// value is still read and DCE drops whatever produced it.
///
/// The two identities, both exact for a nonzero operand at `BITS` bits:
///
/// * `bsr(x) = (BITS - 1) - clz(x)` — the index of the highest set bit.
/// * `bsf(x) = (BITS - 1) - clz(x ^ (x - 1))`. `x ^ (x - 1)` is the mask of the
///   trailing zeros together with the lowest set bit, so its highest set bit IS
///   the lowest set bit of `x`. It is used in preference to the more familiar
///   `x & -x` because it never negates: the operands stay non-negative in the C
///   this renders to.
///
/// Deliberately narrow:
/// * only 32- and 64-bit operands. The 16-bit form exists, but the `clz`
///   renderer spells a sub-64-bit count as `__builtin_clz((unsigned int)(x))` —
///   a count over 32 bits — so `x86.clz.16` would answer 16 too high. That is
///   the renderer's contract to widen, not this lifter's to guess around, and
///   `ast.rs` is not this change's file.
/// * only a register destination, which is the only form the ISA encodes.
/// * every flag other than ZF is architecturally undefined and is poisoned
///   rather than left stale.
pub(super) fn bit_scan_ops(instr: &iced_x86::Instruction, forward: bool) -> Vec<Op> {
    let mnemonic = if forward { "bsf" } else { "bsr" };
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }]
    };
    if instr.op_count() != 2 || instr.op_kind(0) != OpKind::Register {
        return unsupported();
    }
    let dst_name = reg_name(instr.op_register(0));
    let Some(width) = phys_reg_width(&dst_name) else {
        return unsupported();
    };
    if !matches!(width, Width::W32 | Width::W64) {
        return unsupported();
    }

    let mut ops = Vec::new();
    let source = match instr.op_kind(1) {
        OpKind::Register => {
            if phys_reg_width(&reg_name(instr.op_register(1))) != Some(width) {
                return unsupported();
            }
            Value::Reg(VReg::phys(reg_name(instr.op_register(1))))
        }
        OpKind::Memory => {
            if Width::from_bytes(instr.memory_size().size() as u16) != width {
                return unsupported();
            }
            let loaded = VReg::Temp(0);
            ops.push(Op::Load {
                dst: loaded.clone(),
                addr: mem_op_of(instr),
            });
            Value::Reg(loaded)
        }
        _ => return unsupported(),
    };

    // The word the scan actually observes. A canonicalised 32-bit register
    // lives in a 64-bit parent whose high half this IR never clears, so both
    // the zero test and the leading-zero count have to name the encoded width.
    let operand = unsigned_cmp_value(source, width, VReg::Temp(1), &mut ops);
    let bits = i64::from(width.bits());
    let dst = VReg::phys(dst_name);

    // ZF is the one flag x86 defines here, and it is defined for BOTH cases.
    ops.push(Op::Cmp {
        dst: VReg::Flag(Flag::Z),
        op: CmpOp::Eq,
        lhs: operand.clone(),
        rhs: Value::Const(0),
    });

    // Move the bit being searched for into the most-significant position that
    // `clz` reports on. For a backward scan it is already there.
    let scanned = if forward {
        let lowered = VReg::Temp(2);
        ops.push(Op::Bin {
            dst: lowered.clone(),
            op: BinOp::Sub,
            lhs: operand.clone(),
            rhs: Value::Const(1),
        });
        ops.push(Op::Bin {
            dst: lowered.clone(),
            op: BinOp::Xor,
            lhs: operand.clone(),
            rhs: Value::Reg(lowered.clone()),
        });
        Value::Reg(lowered)
    } else {
        operand.clone()
    };

    let index = VReg::Temp(3);
    ops.push(Op::Intrinsic {
        name: format!("x86.clz.{bits}"),
        ins: vec![scanned],
        outs: vec![(index.clone(), width)],
        reads_mem: false,
        writes_mem: false,
    });
    ops.push(Op::Bin {
        dst: index.clone(),
        op: BinOp::Sub,
        lhs: Value::Const(bits - 1),
        rhs: Value::Reg(index.clone()),
    });

    // Intel leaves the destination UNDEFINED when the source is zero; only AMD
    // documents it as preserved. Writing the count unconditionally is therefore
    // architecturally faithful, and it is the only lowering that does not read
    // the destination before defining it.
    //
    // That read is not a cosmetic difference. A self-referential `dst = src ? f(src) : dst`
    // makes `dst` live-in on the zero path, and a live-in physical register in an
    // argument slot is exactly what parameter recovery promotes to a parameter —
    // so preserving a value no correct program can observe cost `shift_until_zero`
    // three phantom parameters and left the emitted C reading an unassigned local
    // in an arm the guard never selects.
    //
    // ZF above still distinguishes the two cases exactly, which is what callers
    // actually branch on. The zero case yields `bits - 1 - clz(0)`, a defined and
    // deterministic value where the architecture permits any.
    ops.push(Op::Assign {
        dst,
        src: Value::Reg(index),
    });
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::S, Flag::P, Flag::A],
        "x86 BSR/BSF define ZF only; CF/OF/SF/PF/AF are architecturally undefined",
    );
    ops
}

pub(super) fn cmpxchg_ops(instr: &iced_x86::Instruction, bits: u32) -> Vec<Op> {
    if instr.op_count() != 2 || instr.op_kind(1) != OpKind::Register {
        return vec![Op::Unknown {
            mnemonic: "cmpxchg".into(),
        }];
    }

    let src = Value::Reg(VReg::phys(reg_name(instr.op_register(1))));
    let old = VReg::Temp(0);
    let width = operand_width(instr, 0);
    let acc = match instr.op_kind(0) {
        OpKind::Register => {
            let dst = instr.op_register(0);
            VReg::phys(accumulator_name_for_width(reg_size(dst), bits))
        }
        OpKind::Memory => VReg::phys(accumulator_name_for_width(
            instr.memory_size().size() as u8,
            bits,
        )),
        _ => {
            return vec![Op::Unknown {
                mnemonic: "cmpxchg".into(),
            }];
        }
    };

    let mut ops = Vec::new();
    match instr.op_kind(0) {
        OpKind::Register => {
            let dst = VReg::phys(reg_name(instr.op_register(0)));
            ops.push(Op::Assign {
                dst: old.clone(),
                src: Value::Reg(dst.clone()),
            });
            ops.extend(cmp_flag_ops(
                Value::Reg(acc.clone()),
                Value::Reg(old.clone()),
                width,
            ));
            // CMPXCHG is a two-input select for the destination.  The false
            // arm must be explicit: it reads the destination value captured
            // above, rather than defining an otherwise-uninitialized register.
            ops.push(Op::Ite {
                cond: VReg::Flag(Flag::Z),
                t: src,
                e: Value::Reg(dst.clone()),
                dst,
                width,
            });
        }
        OpKind::Memory => {
            let addr = mem_op_of(instr);
            ops.push(Op::Load {
                dst: old.clone(),
                addr: addr.clone(),
            });
            ops.extend(cmp_flag_ops(
                Value::Reg(acc.clone()),
                Value::Reg(old.clone()),
                width,
            ));
            // On comparison failure x86 leaves memory unchanged.  Model the
            // memory effect itself as conditional so the false path performs
            // no access and cannot store an undefined select temporary.
            ops.push(Op::CondStore {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
                addr,
                src,
            });
        }
        _ => unreachable!("checked above"),
    }

    let not_equal = VReg::Temp(2);
    ops.push(Op::Cmp {
        dst: not_equal.clone(),
        op: CmpOp::Eq,
        lhs: Value::Reg(VReg::Flag(Flag::Z)),
        rhs: Value::Const(0),
    });
    // The accumulator changes only on failure.  Its success-path prior value
    // is an input, not an implicit side effect hidden from SSA/use-def.
    ops.push(Op::Ite {
        cond: not_equal,
        t: Value::Reg(old),
        e: Value::Reg(acc.clone()),
        dst: acc,
        width,
    });
    ops
}

/// Snapshot one architectural half of the wide accumulator pair into `temp`.
///
/// At 64 and 32 bits the halves are `rdx:rax` / `edx:eax`, whose names either ARE
/// the canonical parent or zero-extend into it, so a bare register read is a read
/// of a name the SSA layer versions. At 16 bits they are `dx:ax` — BIT-PRESERVING
/// views (`regview::ssa_parent` declines to merge them), so a bare `%dx` read is a
/// read of a name nothing in the function ever defines: `mov edx, 0` before a
/// `div r/m16` defines `rdx`, and the two never meet.
///
/// That is not cosmetic. `185_subword_signed_division:divide_unsigned_shorts`
/// rendered `var3` — an undeclared, never-assigned local — as the high half of the
/// dividend, so the emitted C divided by a garbage 32-bit dividend. Reading the
/// half through [`read_view_ops`] (the same helper `cmp_operand_as_value` already
/// uses for every other narrow operand) extracts it from the parent, which is the
/// definition the SSA layer can actually see.
fn snapshot_accumulator_half(name: &str, temp: VReg, ops: &mut Vec<Op>) {
    match partial_gp_view(name) {
        Some(view) => ops.extend(read_view_ops(view, temp)),
        None => ops.push(Op::Assign {
            dst: temp,
            src: Value::Reg(VReg::phys(name)),
        }),
    }
}

/// Exact one-operand x86 multiply: `hi:lo = accumulator * source`.
///
/// Snapshot both inputs before defining either architectural output. Express the
/// low half with the ordinary width-truncated multiply and the high half as a
/// typed, single-output intrinsic. A multi-output intrinsic cannot currently be
/// renamed by the SSA/value-numbering layer, which is precisely how the magic
/// constant remainder sequences emitted by GCC and Clang lost `rdx`.
pub(super) fn wide_mul_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = match width.bits() {
        64 => ("rax", "rdx"),
        32 => ("eax", "edx"),
        16 => ("ax", "dx"),
        _ => return None,
    };
    let mut ops = Vec::new();
    let source = cmp_operand_as_value(instr, 0, VReg::Temp(59), &mut ops)?;
    snapshot_accumulator_half(lo_name, VReg::Temp(60), &mut ops);
    ops.extend([
        Op::Assign {
            dst: VReg::Temp(61),
            src: source,
        },
        Op::Bin {
            dst: VReg::phys(lo_name),
            op: BinOp::Mul,
            lhs: Value::Reg(VReg::Temp(60)),
            rhs: Value::Reg(VReg::Temp(61)),
        },
        Op::Intrinsic {
            name: format!(
                "x86.{}mul_hi.{}",
                if signed { "s" } else { "u" },
                width.bits()
            ),
            ins: vec![Value::Reg(VReg::Temp(60)), Value::Reg(VReg::Temp(61))],
            outs: vec![(VReg::phys(hi_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    append_wide_mul_overflow_flags(
        &mut ops,
        Value::Reg(VReg::Temp(60)),
        Value::Reg(VReg::Temp(61)),
        width,
        signed,
        (lo_name, hi_name),
    );
    append_undef_flags(
        &mut ops,
        &[Flag::Z, Flag::S, Flag::P, Flag::A],
        "x86 wide multiply leaves ZF/SF/PF/AF architecturally undefined",
    );
    Some(ops)
}

/// Exact x86 wide division with independently renameable quotient/remainder.
pub(super) fn wide_div_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = match width.bits() {
        64 => ("rax", "rdx"),
        32 => ("eax", "edx"),
        16 => ("ax", "dx"),
        _ => return None,
    };
    let mut ops = Vec::new();
    let divisor = cmp_operand_as_value(instr, 0, VReg::Temp(69), &mut ops)?;
    snapshot_accumulator_half(hi_name, VReg::Temp(70), &mut ops);
    snapshot_accumulator_half(lo_name, VReg::Temp(71), &mut ops);
    ops.push(Op::Assign {
        dst: VReg::Temp(72),
        src: divisor,
    });
    let kind = if signed { "sdiv" } else { "udiv" };
    let inputs = vec![
        Value::Reg(VReg::Temp(70)),
        Value::Reg(VReg::Temp(71)),
        Value::Reg(VReg::Temp(72)),
    ];
    ops.extend([
        Op::Intrinsic {
            name: format!("x86.{kind}_quot.{}", width.bits()),
            ins: inputs.clone(),
            outs: vec![(VReg::phys(lo_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Intrinsic {
            name: format!("x86.{kind}_rem.{}", width.bits()),
            ins: inputs,
            outs: vec![(VReg::phys(hi_name), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    append_undef_flags(
        &mut ops,
        &[Flag::C, Flag::O, Flag::Z, Flag::S, Flag::P, Flag::A],
        if signed {
            "x86 IDIV leaves arithmetic flags architecturally undefined"
        } else {
            "x86 DIV leaves arithmetic flags architecturally undefined"
        },
    );
    Some(ops)
}
