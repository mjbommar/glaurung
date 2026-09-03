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
    partial_write_ops, read_view_ops, reg_name, reg_size,
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
/// * only a register destination; the memory form would need a load/store pair
///   with the same masking and does not occur in the corpus.
/// * the flags are declared undefined rather than guessed, exactly as
///   `adc_sbb_ops` does. x86 defines CF as the last bit shifted out and leaves
///   OF/AF undefined for counts above 1; a later `jb` reading a fabricated CF
///   would render a branch the CPU never evaluated.
///
/// The `cl` count form is handled too, and it is NOT the same expression. A
/// literal `src << (bits - n)` is undefined C at `n == 0`, and `n == 0` is
/// precisely the architectural no-op the immediate path returns `Op::Nop` for —
/// so a variable count cannot use that spelling and cannot branch on the count
/// at lift time either. Splitting the join into two shifts,
/// `(src << 1) << (bits - 1 - n)`, is exact for EVERY `n` in `0..bits`: both
/// amounts stay below the operand width, and at `n == 0` the first shift moves
/// the only bit that could survive the second one out of range, so the join
/// contributes zero and the destination is left exactly as it was. The one
/// thing that path cannot reproduce is the flag behaviour: at `n == 0` x86
/// preserves every flag, and this poisons them. That is the same direction of
/// error the immediate path already takes for `n != 0` (where x86 defines ZF,
/// SF and PF and this poisons them anyway), and an undefined flag is a read the
/// analysis can see rather than a stale value it cannot.
pub(super) fn double_shift_ops(instr: &iced_x86::Instruction, right: bool) -> Vec<Op> {
    let mnemonic = if right { "shrd" } else { "shld" };
    let unsupported = || {
        vec![Op::Unknown {
            mnemonic: mnemonic.into(),
        }]
    };
    let variable_count = instr.op_count() == 3
        && instr.op_kind(2) == OpKind::Register
        && instr.op_register(2) == iced_x86::Register::CL;
    if instr.op_count() != 3
        || instr.op_kind(0) != OpKind::Register
        || instr.op_kind(1) != OpKind::Register
        || !(variable_count || matches!(instr.op_kind(2), OpKind::Immediate8))
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
    let count = if variable_count {
        None
    } else {
        let count = u32::from(instr.immediate8()) & (bits - 1);
        if count == 0 {
            // Architecturally a complete no-op, flags included.
            return vec![Op::Nop];
        }
        Some(count)
    };
    let dst = VReg::phys(dst_name);
    let src = VReg::phys(src_name);
    let kept = VReg::Temp(0);
    let joined = VReg::Temp(1);
    let masked_count = VReg::Temp(2);
    let complement_count = VReg::Temp(3);
    let mut ops = Vec::new();

    // The CL encoding reads the value written through ECX, exactly as the
    // ordinary variable shifts in `lift_one_inner` do: naming a separate `cl`
    // register would invent an undefined live-in. Only the low five or six bits
    // survive the mask, and those are the same in `ecx` and `rcx`.
    if variable_count {
        ops.push(Op::Bin {
            dst: masked_count.clone(),
            op: BinOp::And,
            lhs: Value::Reg(VReg::phys("ecx")),
            rhs: Value::Const(i64::from(bits - 1)),
        });
    }
    let count_value = |count: Option<u32>| match count {
        Some(count) => Value::Const(i64::from(count)),
        None => Value::Reg(masked_count.clone()),
    };

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
        rhs: count_value(count),
    });
    // The bits shifted in from the other half of the pair.
    ops.push(Op::ZExt {
        dst: joined.clone(),
        src: Value::Reg(src),
        from: width,
        to: Width::W64,
    });
    let opposite = if right { BinOp::Shl } else { BinOp::Shr };
    match count {
        Some(count) => ops.push(Op::Bin {
            dst: joined.clone(),
            op: opposite,
            lhs: Value::Reg(joined.clone()),
            rhs: Value::Const(i64::from(bits - count)),
        }),
        None => {
            // `(src <op> 1) <op> (bits - 1 - n)`. See the doc comment: this is
            // the whole reason the variable form is not the immediate form with
            // a register in the shift amount.
            ops.push(Op::Bin {
                dst: joined.clone(),
                op: opposite,
                lhs: Value::Reg(joined.clone()),
                rhs: Value::Const(1),
            });
            ops.push(Op::Bin {
                dst: complement_count.clone(),
                op: BinOp::Sub,
                lhs: Value::Const(i64::from(bits - 1)),
                rhs: Value::Reg(masked_count.clone()),
            });
            ops.push(Op::Bin {
                dst: joined.clone(),
                op: opposite,
                lhs: Value::Reg(joined.clone()),
                rhs: Value::Reg(complement_count),
            });
        }
    }
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
/// * only 32- and 64-bit operands. The 16-bit form exists and is not lifted —
///   but NOT for the reason this comment used to give. It claimed the renderer
///   made the identity impossible: `x86.clz.16` spells its count as
///   `__builtin_clz((unsigned int)(x))`, which for a zero-extended 16-bit
///   operand answers `16 + clz16(x)`, i.e. sixteen too high. True, and
///   irrelevant — the offset constant absorbs it exactly.
///   `bsr16(x) = 31 - clz32(zext16(x))` is an identity, so the 16-bit arm is
///   the 32/64-bit arm with `31` in place of `bits - 1`. Nothing about the
///   renderer blocks it.
///
///   The real blocker is the register model. `bsr si,cx` — the only form the
///   committed corpus contains, four occurrences, all 16-bit — reads a
///   bit-preserving partial view of `rcx` and writes a bit-preserving partial
///   view of `rsi`. `VReg::phys("si")` is a name of its own, not the low half
///   of `rsi`, so lifting it that way would invent an undefined live-in for the
///   source and drop the upper 48 bits of the destination. It needs
///   [`super::read_view_ops`] for the source and [`super::partial_write_ops`]
///   for the destination, which is a different and larger change than the width
///   check above. Four occurrences of legacy 16-bit code did not justify
///   reworking a function whose exactness is what three fixtures depend on.
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
    if !matches!(width, Width::W16 | Width::W32 | Width::W64) {
        return unsupported();
    }
    let destination_view = if width == Width::W16 {
        let Some(view) = partial_gp_view(&dst_name) else {
            return unsupported();
        };
        Some(view)
    } else {
        None
    };

    let mut ops = Vec::new();
    let source = match instr.op_kind(1) {
        OpKind::Register => {
            let source_name = reg_name(instr.op_register(1));
            if phys_reg_width(&source_name) != Some(width) {
                return unsupported();
            }
            if width == Width::W16 {
                let Some(view) = partial_gp_view(&source_name) else {
                    return unsupported();
                };
                let snapshot = VReg::Temp(10);
                ops.extend(read_view_ops(view, snapshot.clone()));
                Value::Reg(snapshot)
            } else {
                Value::Reg(VReg::phys(source_name))
            }
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
    // Rust/C expose 16-bit CLZ through a 32-bit operand. Zero-extending the
    // encoded word makes `31 - clz32(word)` exactly the 16-bit BSR index.
    let scan_width = if width == Width::W16 {
        Width::W32
    } else {
        width
    };
    let bits = i64::from(scan_width.bits());

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
        outs: vec![(index.clone(), scan_width)],
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
    if let Some(view) = destination_view {
        ops.extend(partial_write_ops(view, Value::Reg(index)));
    } else {
        ops.push(Op::Assign {
            dst: VReg::phys(dst_name),
            src: Value::Reg(index),
        });
    }
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

/// Which register the op that COMPUTES one architectural half should write.
///
/// The write side of [`snapshot_accumulator_half`]'s hazard, and the worse
/// half of it. At 64 and 32 bits the half names the canonical SSA value (`rax`,
/// or `eax`, which zero-extends into it), so the computing op writes the
/// register itself. At 16 and 8 bits the half is a BIT-PRESERVING view — `ax`,
/// `dx`, `al`, `ah` — that `regview::ssa_parent` refuses to merge with its
/// parent, and every READ of such a view is lowered as an extract from that
/// parent. So a definition spelled `ax` is a definition nothing can ever reach:
/// the def and the use are two unrelated names.
///
/// That was not hypothetical. `185_subword_signed_division:divide_unsigned_shorts`
/// lifts `divw -0x2(%rbp)`, whose quotient this lowering deposited in a bare
/// `ax`; the `movzwl %ax,%eax` two bytes later read `rax`, found the untouched
/// dividend, and the function decompiled to `return dividend;` with the divide
/// silently absent.
///
/// A partial half is therefore computed into `scratch` and deposited afterwards
/// by [`deposit_accumulator_half`].
fn accumulator_half_destination(name: &str, scratch: VReg) -> VReg {
    match partial_gp_view(name) {
        Some(_) => scratch,
        None => VReg::phys(name),
    }
}

/// Deposit a half computed into `scratch` into the parent register it really
/// lives in, as the masked read-modify-write `mov %al, …` already uses.
///
/// A no-op when [`accumulator_half_destination`] gave the computing op the
/// architectural register directly, which keeps the 32- and 64-bit lowerings
/// exactly the op sequences they were.
///
/// Deposits must follow EVERY computation, never interleave with one: at 8 bits
/// both halves (`al` and `ah`) live in the same parent, so a deposit performed
/// before the second half is computed would be read back by that computation.
fn deposit_accumulator_half(name: &str, scratch: VReg, ops: &mut Vec<Op>) {
    if let Some(view) = partial_gp_view(name) {
        ops.extend(partial_write_ops(view, Value::Reg(scratch)));
    }
}

/// The `(low, high)` architectural halves of the implicit accumulator pair a
/// one-operand `mul`/`imul`/`div`/`idiv` of this operand width reads and writes.
///
/// Three of the four rows are a register PAIR (`rdx:rax`, `edx:eax`, `dx:ax`).
/// The byte forms are not: SDM Vol. 2A gives `mul r/m8` the destination `AX`
/// alone and `div r/m8` the dividend `AX` alone, so the "pair" is the two byte
/// views of one 16-bit window in `rax` — `al` low, `ah` high. That is why the
/// halves are named rather than derived from a register number, and why the
/// deposit discipline above exists: at this width the two halves alias.
fn accumulator_halves(width: Width) -> Option<(&'static str, &'static str)> {
    match width.bits() {
        64 => Some(("rax", "rdx")),
        32 => Some(("eax", "edx")),
        16 => Some(("ax", "dx")),
        8 => Some(("al", "ah")),
        _ => None,
    }
}

/// Exact one-operand x86 multiply: `hi:lo = accumulator * source`.
///
/// Snapshot both inputs before defining either architectural output. Express the
/// low half with the ordinary width-truncated multiply and the high half as a
/// typed, single-output intrinsic. A multi-output intrinsic cannot currently be
/// renamed by the SSA/value-numbering layer, which is precisely how the magic
/// constant remainder sequences emitted by GCC and Clang lost `rdx`.
///
/// At 8 bits `hi:lo` is `ah:al` — see [`accumulator_halves`] — and both halves
/// are deposited into `rax` after both are computed. Byte multiplies are how
/// GCC divides a `uint8_t` by a constant: `nrw194_u8_mix` lowers `narrowed / 3u`
/// to `mov $0xffffffab,%edx ; mul %dl ; shr $0x8,%ax ; shr $1,%dl`. While this
/// returned `None` for that width the instruction fell to the unhandled path
/// and the reciprocal 0xAB appeared nowhere in the recovered C.
pub(super) fn wide_mul_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = accumulator_halves(width)?;
    let mut ops = Vec::new();
    let source = cmp_operand_as_value(instr, 0, VReg::Temp(59), &mut ops)?;
    snapshot_accumulator_half(lo_name, VReg::Temp(60), &mut ops);
    let low = accumulator_half_destination(lo_name, VReg::Temp(62));
    let high = accumulator_half_destination(hi_name, VReg::Temp(63));
    ops.extend([
        Op::Assign {
            dst: VReg::Temp(61),
            src: source,
        },
        Op::Bin {
            dst: low.clone(),
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
            outs: vec![(high.clone(), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    deposit_accumulator_half(lo_name, low, &mut ops);
    deposit_accumulator_half(hi_name, high, &mut ops);
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
///
/// At 8 bits the dividend is `AX` alone and the results are `AL` (quotient) and
/// `AH` (remainder) — SDM Vol. 2A, DIV/IDIV. Expressed through
/// [`accumulator_halves`] that is the same `hi:lo` shape as every other width,
/// so the three-input intrinsics need no byte-specific spelling.
pub(super) fn wide_div_ops(instr: &iced_x86::Instruction, signed: bool) -> Option<Vec<Op>> {
    if instr.op_count() != 1 {
        return None;
    }
    let width = operand_width(instr, 0);
    let (lo_name, hi_name) = accumulator_halves(width)?;
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
    let quotient = accumulator_half_destination(lo_name, VReg::Temp(73));
    let remainder = accumulator_half_destination(hi_name, VReg::Temp(74));
    ops.extend([
        Op::Intrinsic {
            name: format!("x86.{kind}_quot.{}", width.bits()),
            ins: inputs.clone(),
            outs: vec![(quotient.clone(), width)],
            reads_mem: false,
            writes_mem: false,
        },
        Op::Intrinsic {
            name: format!("x86.{kind}_rem.{}", width.bits()),
            ins: inputs,
            outs: vec![(remainder.clone(), width)],
            reads_mem: false,
            writes_mem: false,
        },
    ]);
    deposit_accumulator_half(lo_name, quotient, &mut ops);
    deposit_accumulator_half(hi_name, remainder, &mut ops);
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
