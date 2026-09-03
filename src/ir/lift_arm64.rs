//! AArch64 → LLIR lifter.
//!
//! Decodes fixed-width 4-byte ARM64 instructions using the existing
//! [`crate::disasm::capstone::CapstoneDisassembler`] and emits LLIR ops.
//!
//! Coverage (v1):
//!
//! * `nop` → [`Op::Nop`]
//! * `mov`, `movz` → [`Op::Assign`]
//! * `add`, `sub`, `and`, `orr`, `eor`, `lsl`, `lsr`, `asr` → [`Op::Bin`]
//! * `cmp` → five [`Op::Cmp`] writes (Z, C, Ule, Slt, Sle) — same as x86
//! * `adrp` → [`Op::Assign`] of the resolved page address (capstone folds the
//!   PC arithmetic into the immediate operand)
//! * `ldr`/`ldrb`/`ldrh`/`ldrsw` with `[base, #disp]` → [`Op::Load`]
//! * `str`/`strb`/`strh` with `[base, #disp]` → [`Op::Store`]
//! * `b` (near target), `b.<cond>`, `cbz`/`cbnz`, `tbz`/`tbnz` →
//!   [`Op::Jump`] / [`Op::CondJump`]
//! * `bl` (direct), `blr` (indirect) → [`Op::Call`]
//! * `br` (indirect, without a link/return edge) → [`Op::IndirectJump`]
//! * `ret` → [`Op::Return`]
//!
//! Anything else becomes [`Op::Unknown`] carrying the capstone mnemonic so
//! downstream passes can flag unsupported instructions.

use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::core::instruction::{Instruction, Operand, OperandKind};
use crate::disasm::capstone::CapstoneDisassembler;

use crate::ir::regview;
use crate::ir::types::*;
use crate::ir::use_def::def_uses;

mod flags;
mod modifiers;
mod packed;
use flags::{
    compare_flags, cond_flag_for_bcond, cond_flag_for_code, conditional_select, flag_setting_arith,
    machine_width, operand_width, result_flags, signed_view, unsigned_view, FlagForm,
};
use modifiers::{modified_last_operand, scaled_memop};
use packed::Transfer as PackedTransfer;

/// Does a write through this register name totally overwrite its 64-bit parent
/// with a zero-extended value? True for exactly the `wN` views (ARM DDI 0487
/// B1.2.1: "the upper 32 bits of the X register are set to zero").
fn zero_extends_parent(dst: &VReg) -> bool {
    matches!(dst, VReg::Phys(name)
        if regview::view(regview::Arch::AArch64, name).is_some_and(|v| v.zero_extends()))
}

/// Append the zero-extension every 32-bit register write performs.
///
/// [`crate::ir::ssa`] gives `wN` and `xN` one SSA identity, which is the only way
/// `ldr w0,[sp,#12]` can reach `lsl x1,x0,#32` at all. That merge is only sound
/// if the 32-bit write is modelled as the TOTAL write the architecture defines:
/// without this, `and w0,w0,#0xffffff` on a register holding a 64-bit value would
/// leave bits 32..63 intact and the next `x0` read would see them.
///
/// This is the AArch64 mirror of what [`crate::ir::lift_x86`] does for `eax`, and
/// it deliberately uses the same shared [`regview`] descriptor rather than a
/// private list of names.
/// Only the LAST write of a given register within one instruction is widened:
/// an alias lowered as a multi-step read-modify-write (`movk`, `bfi`) overwrites
/// its own intermediates, so widening those too would be pure noise.
fn with_parent_zero_extension(ops: Vec<Op>) -> Vec<Op> {
    // `ZExt`-to-64 producers are already total writes of the parent.
    let widened = |op: &Op| {
        (!matches!(op, Op::ZExt { to: Width::W64, .. }))
            .then(|| def_uses(op).0)
            .flatten()
            .filter(zero_extends_parent)
    };
    let mut last_def: Vec<Option<VReg>> = ops.iter().map(widened).collect();
    if last_def.iter().all(Option::is_none) {
        return ops;
    }
    let mut seen: Vec<VReg> = Vec::new();
    for slot in last_def.iter_mut().rev() {
        match slot {
            Some(dst) if seen.contains(dst) => *slot = None,
            Some(dst) => seen.push(dst.clone()),
            None => {}
        }
    }
    let mut out = Vec::with_capacity(ops.len() + seen.len());
    for (op, widen) in ops.into_iter().zip(last_def) {
        out.push(op);
        out.extend(widen.map(|dst| Op::ZExt {
            src: Value::Reg(dst.clone()),
            dst,
            from: Width::W32,
            to: Width::W64,
        }));
    }
    out
}

fn operand_reg(op: &Operand) -> Option<VReg> {
    if matches!(op.kind, OperandKind::Register) {
        op.register.clone().map(VReg::phys)
    } else {
        None
    }
}

/// Whether two AArch64 register spellings are views of the same storage.
fn same_register_family(lhs: &VReg, rhs: &VReg) -> bool {
    match (lhs, rhs) {
        (VReg::Phys(lhs), VReg::Phys(rhs)) => {
            regview::same_family(regview::Arch::AArch64, lhs, rhs)
        }
        _ => lhs == rhs,
    }
}

/// `xzr`/`wzr` are not registers with a value — the architecture defines a read
/// of either as zero (ARM DDI 0487 C1.2.5). Reading them as an ordinary register
/// name made `str wzr,[sp,#24]` — the ordinary way gcc zeroes a local, 133 sites
/// across the fixture corpus — store an undefined value instead of 0.
fn is_zero_register(name: &str) -> bool {
    matches!(name, "xzr" | "wzr")
}

fn operand_to_value(op: &Operand) -> Option<Value> {
    match op.kind {
        OperandKind::Register => op.register.clone().map(|n| {
            if is_zero_register(&n) {
                Value::Const(0)
            } else {
                Value::Reg(VReg::phys(n))
            }
        }),
        OperandKind::Immediate => op.immediate.map(Value::Const),
        _ => None,
    }
}

fn operand_to_memop(op: &Operand, size: u8) -> Option<MemOp> {
    if !matches!(op.kind, OperandKind::Memory) {
        return None;
    }
    let base = op.base.clone().map(VReg::phys);
    let index = op.index.clone().map(VReg::phys);
    let disp = op.displacement.unwrap_or(0);
    Some(MemOp {
        base,
        index,
        scale: op.scale.unwrap_or(0),
        disp,
        size,
        segment: None, // ARM64 has no segment registers
        endian: Endian::Little,
    })
}

fn scalar_access_size(mnemonic: &str, register: &Operand) -> u8 {
    match mnemonic.trim_start_matches("ldu").trim_start_matches("ld") {
        "rb" | "rsb" | "b" | "sb" => 1,
        "rh" | "rsh" | "h" | "sh" => 2,
        "rsw" | "sw" => 4,
        _ => match mnemonic {
            "strb" | "sturb" => 1,
            "strh" | "sturh" => 2,
            _ => match register.register.as_deref() {
                Some(name) if name.starts_with('q') || name.starts_with('v') => 16,
                Some(name) if name.starts_with('w') || name.starts_with('s') => 4,
                Some(name) if name.starts_with('h') => 2,
                Some(name) if name.starts_with('b') => 1,
                _ => 8,
            },
        },
    }
}

/// The load mnemonics whose result is SIGN-extended to the destination register.
///
/// Missing this was not a rendering nicety: `ldrsb w0,[sp,#31]` lifted to a plain
/// byte load, so `sext_i8(0xFF)` decompiled to `(unsigned int)(unsigned char)v`
/// and returned 255 where the source returns -1.
fn sign_extending_load(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ldrsb" | "ldrsh" | "ldrsw" | "ldursb" | "ldursh" | "ldursw"
    )
}

fn instruction_word(ins: &Instruction) -> Option<u32> {
    let bytes: [u8; 4] = ins.bytes.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn intrinsic(name: &str, outs: Vec<(VReg, Width)>) -> Op {
    Op::Intrinsic {
        name: name.to_string(),
        ins: Vec::new(),
        outs,
        reads_mem: false,
        writes_mem: false,
    }
}

fn semantic_intrinsic(name: &str, ins: Vec<Value>) -> Op {
    Op::Intrinsic {
        name: name.to_string(),
        ins,
        outs: Vec::new(),
        reads_mem: false,
        writes_mem: false,
    }
}

/// A temporary private to one lifted instruction.
///
/// The multiplier bounds how many temporaries a single instruction may claim
/// before it collides with the next one's. It is 32 rather than 4 because
/// `ccmp` needs a snapshot of its condition plus one temporary per flag it
/// selects; at the old spacing lane 16 was the *following* instruction's lane 0.
const TEMP_LANES: u32 = 32;

fn temp_for(ins: &Instruction, lane: u32) -> VReg {
    debug_assert!(
        lane < TEMP_LANES,
        "temp lane {lane} escapes its instruction"
    );
    VReg::Temp(
        (ins.address.value as u32)
            .wrapping_mul(TEMP_LANES)
            .wrapping_add(lane),
    )
}

fn bin_for_mnem(m: &str) -> Option<BinOp> {
    Some(match m {
        "add" => BinOp::Add,
        "sub" => BinOp::Sub,
        "and" => BinOp::And,
        "orr" => BinOp::Or,
        "eor" => BinOp::Xor,
        "lsl" => BinOp::Shl,
        "lsr" => BinOp::Shr,
        "asr" => BinOp::Sar,
        "mul" => BinOp::Mul,
        _ => return None,
    })
}

/// The condition an `S`-less conditional instruction tests, from bits 15:12 of
/// the encoding. Capstone surfaces the condition as a printed suffix rather than
/// an operand, so it is read from the word — which is also what the `csel`,
/// `cset` and `cinc` arms already do.
fn cond_field(ins: &Instruction) -> Option<u32> {
    instruction_word(ins).map(|word| (word >> 12) & 0xf)
}

/// `Op::Bin` on a fresh temporary, the shape most of the composite lowerings
/// below are built from.
fn bin_temp(dst: VReg, op: BinOp, lhs: Value, rhs: Value) -> Op {
    Op::Bin { dst, op, lhs, rhs }
}

/// `dst = (src >>u amount) | (src <<(width-amount))`, the exact rotate for both
/// the immediate and the register forms.
///
/// `(width - amount) & (width - 1)` rather than `width - amount` is deliberate:
/// with a register amount of zero the naive form shifts by the full width, which
/// is undefined in C and would silently produce a different answer than the CPU.
fn rotate_right_ops(ins: &Instruction, dst: VReg, src: Value, amount: Value) -> Vec<Op> {
    let Some(width) = dst.width() else {
        return vec![Op::Unknown {
            mnemonic: "ror".into(),
        }];
    };
    let bits = i64::from(width.bits());
    let mut out = Vec::new();
    let src = unsigned_view(src, width, temp_for(ins, 0), &mut out);
    let masked = match &amount {
        Value::Const(c) => Value::Const(c & (bits - 1)),
        other => {
            let temp = temp_for(ins, 1);
            out.push(bin_temp(
                temp.clone(),
                BinOp::And,
                other.clone(),
                Value::Const(bits - 1),
            ));
            Value::Reg(temp)
        }
    };
    let complement = match &masked {
        Value::Const(c) => Value::Const((bits - c) & (bits - 1)),
        other => {
            let raw = temp_for(ins, 2);
            let temp = temp_for(ins, 3);
            out.push(bin_temp(
                raw.clone(),
                BinOp::Sub,
                Value::Const(bits),
                other.clone(),
            ));
            out.push(bin_temp(
                temp.clone(),
                BinOp::And,
                Value::Reg(raw),
                Value::Const(bits - 1),
            ));
            Value::Reg(temp)
        }
    };
    let low = temp_for(ins, 4);
    let high = temp_for(ins, 5);
    out.push(bin_temp(low.clone(), BinOp::Shr, src.clone(), masked));
    out.push(bin_temp(high.clone(), BinOp::Shl, src, complement));
    out.push(bin_temp(dst, BinOp::Or, Value::Reg(low), Value::Reg(high)));
    out
}

/// `dst = extend(src[field-1:0]) << lsb` — the `UBFIZ`/`SBFIZ` aliases.
fn bitfield_insert_in_zero_ops(ins: &Instruction, signed: bool) -> Option<Vec<Op>> {
    if ins.operands.len() != 4 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_to_value(&ins.operands[1])?;
    let lsb = u16::try_from(ins.operands[2].immediate?).ok()?;
    let field = u16::try_from(ins.operands[3].immediate?).ok()?;
    let dst_width = dst.width()?;
    if field == 0 || lsb.checked_add(field)? > dst_width.bits() {
        return None;
    }
    let fragment = temp_for(ins, 0);
    let extended = temp_for(ins, 1);
    let widen = if signed {
        Op::SExt {
            dst: extended.clone(),
            src: Value::Reg(fragment.clone()),
            from: Width(field),
            to: dst_width,
        }
    } else {
        Op::ZExt {
            dst: extended.clone(),
            src: Value::Reg(fragment.clone()),
            from: Width(field),
            to: dst_width,
        }
    };
    Some(vec![
        Op::Extract {
            dst: fragment,
            src,
            hi: field,
            lo: 0,
        },
        widen,
        bin_temp(
            dst,
            BinOp::Shl,
            Value::Reg(extended),
            Value::Const(i64::from(lsb)),
        ),
    ])
}

/// The widening multiply forms: `Xd = Xa ± extend(Wn) * extend(Wm)`.
fn long_multiply_ops(ins: &Instruction, signed: bool, subtract: bool) -> Option<Vec<Op>> {
    let dst = operand_reg(&ins.operands[0])?;
    let lhs = operand_to_value(&ins.operands[1])?;
    let rhs = operand_to_value(&ins.operands[2])?;
    // The 3-operand `smull`/`umull`/`smnegl` forms are the 4-operand ones with
    // XZR as the accumulator.
    let addend = match ins.operands.len() {
        3 => Value::Const(0),
        4 => operand_to_value(&ins.operands[3])?,
        _ => return None,
    };
    let mut out = Vec::new();
    let widen = |value: Value, temp: VReg, out: &mut Vec<Op>| {
        if signed {
            signed_view(value, Width::W32, temp, out)
        } else {
            unsigned_view(value, Width::W32, temp, out)
        }
    };
    let lhs = widen(lhs, temp_for(ins, 0), &mut out);
    let rhs = widen(rhs, temp_for(ins, 1), &mut out);
    let product = temp_for(ins, 2);
    out.push(bin_temp(product.clone(), BinOp::Mul, lhs, rhs));
    out.push(bin_temp(
        dst,
        if subtract { BinOp::Sub } else { BinOp::Add },
        addend,
        Value::Reg(product),
    ));
    Some(out)
}

/// AArch64 division is a plain two-operand quotient, but C decides signedness
/// from the operand *types*, which the renderer cannot be relied on to have
/// recovered. Route it through the shared wide-division lowering instead, whose
/// `__int128` form states the signedness explicitly: the high word is zero for
/// `udiv`, and the replicated sign bit for `sdiv`, which makes the 128-bit
/// dividend numerically equal to the 64-bit one in both cases.
fn division_ops(ins: &Instruction, signed: bool) -> Option<Vec<Op>> {
    if ins.operands.len() != 3 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let dividend = operand_to_value(&ins.operands[1])?;
    let divisor = operand_to_value(&ins.operands[2])?;
    let width = dst.width()?;
    let mut out = Vec::new();
    let high = if signed {
        let signed_dividend = signed_view(dividend.clone(), width, temp_for(ins, 0), &mut out);
        let temp = temp_for(ins, 1);
        out.push(bin_temp(
            temp.clone(),
            BinOp::Sar,
            signed_dividend,
            Value::Const(i64::from(width.bits()) - 1),
        ));
        Value::Reg(temp)
    } else {
        Value::Const(0)
    };
    let stem = if signed { "sdiv" } else { "udiv" };
    out.push(Op::Intrinsic {
        name: format!("aarch64.{stem}_quot.{}", width.bits()),
        ins: vec![high, dividend, divisor],
        outs: vec![(dst, width)],
        reads_mem: false,
        writes_mem: false,
    });
    Some(out)
}

/// `ccmp`: the flags become those of a comparison when `cond` holds, and the
/// literal NZCV immediate when it does not. gcc emits it for every short-circuit
/// `&&`/`||` at -O2 — 58 of the AArch64 fixture functions contain one.
///
/// The condition is snapshotted first because every flag this writes is also a
/// flag the condition may read.
fn conditional_compare_ops(ins: &Instruction, negate_rhs: bool) -> Option<Vec<Op>> {
    if ins.operands.len() != 3 {
        return None;
    }
    let lhs = operand_to_value(&ins.operands[0])?;
    let rhs = operand_to_value(&ins.operands[1])?;
    // `ccmn Rn, #imm` is `ccmp Rn, #-imm`: SUBS(Rn, -imm) and ADDS(Rn, imm) are
    // the same operation, flag for flag. The register form would need a negated
    // temporary and is left unlifted rather than approximated.
    let rhs = match (negate_rhs, rhs) {
        (false, rhs) => rhs,
        (true, Value::Const(c)) => Value::Const(c.checked_neg()?),
        (true, _) => return None,
    };
    let nzcv = u32::try_from(ins.operands[2].immediate?).ok()?;
    let (cond, inverted) = cond_flag_for_code(cond_field(ins)?)?;
    let arm_n = (nzcv >> 3) & 1 == 1;
    let arm_z = (nzcv >> 2) & 1 == 1;
    let arm_c = (nzcv >> 1) & 1 == 1;
    let arm_v = nzcv & 1 == 1;
    // Our flag identities are predicates, not raw NZCV bits: `Flag::C` is
    // "unsigned lower", which is ARM's C *clear*.
    let literal = |flag: Flag| {
        let value = match flag {
            Flag::Z => arm_z,
            Flag::C => !arm_c,
            Flag::Ule => !arm_c || arm_z,
            Flag::Slt => arm_n != arm_v,
            Flag::Sle => arm_z || (arm_n != arm_v),
            _ => return None,
        };
        Some(Value::Const(i64::from(value)))
    };
    let predicate = temp_for(ins, 15);
    let mut out = vec![Op::Assign {
        dst: predicate.clone(),
        src: Value::Reg(cond),
    }];
    // Reuse the one definition of what a comparison sets, then redirect each
    // write into a temporary so the select can choose between it and the
    // literal.
    for (lane, op) in compare_flags(ins, lhs, rhs).into_iter().enumerate() {
        let Op::Cmp { dst, op, lhs, rhs } = op else {
            out.push(op);
            continue;
        };
        let VReg::Flag(flag) = dst else {
            out.push(Op::Cmp { dst, op, lhs, rhs });
            continue;
        };
        let computed = temp_for(ins, 16 + lane as u32);
        let literal = literal(flag)?;
        let (t, e) = if inverted {
            (literal, Value::Reg(computed.clone()))
        } else {
            (Value::Reg(computed.clone()), literal)
        };
        out.push(Op::Cmp {
            dst: computed,
            op,
            lhs,
            rhs,
        });
        out.push(Op::Ite {
            dst: VReg::Flag(flag),
            cond: predicate.clone(),
            t,
            e,
            width: Width::W1,
        });
    }
    Some(out)
}

fn low_mask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn bitfield_operands(ins: &Instruction) -> Option<(VReg, Value, u16, u16, Width)> {
    if ins.operands.len() != 4 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_to_value(&ins.operands[1])?;
    let lsb = u16::try_from(ins.operands[2].immediate?).ok()?;
    let field = u16::try_from(ins.operands[3].immediate?).ok()?;
    let dst_width = dst.width()?;
    let src_width = match &src {
        Value::Reg(register) => register.width()?,
        _ => return None,
    };
    if field == 0 || lsb.checked_add(field)? > src_width.bits() || field > dst_width.bits() {
        return None;
    }
    Some((dst, src, lsb, field, dst_width))
}

/// The scalar IEEE width an AArch64 floating-point register name states.
///
/// Unlike x86's `xmm0`, the AArch64 spelling carries the width: `s0` is
/// binary32 and `d0` binary64, so nothing has to be inferred from the mnemonic.
/// The half/byte views (`h`, `b`) and the vector spellings (`q`, `v`) have no
/// scalar C type in this lowering and get `None`, which leaves them on the
/// existing paths instead of giving them a plausible wrong width.
fn scalar_float_width(register: &VReg) -> Option<Width> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let base = crate::ir::abi::ssa_base(name);
    let (class, index) = base.split_at(base.char_indices().nth(1)?.0);
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match class {
        "s" => Some(Width::W32),
        "d" => Some(Width::W64),
        _ => None,
    }
}

/// Lift one AArch64 scalar floating-point instruction.
///
/// IEEE arithmetic has semantics `Op::Bin` — integer arithmetic — cannot
/// represent, so these become typed intrinsics carrying an exact register
/// footprint, exactly as `lift_arm32` does for VFP. The names emitted are
/// deliberately ARM32's `vadd.f64`/`vmov.f32` spellings rather than a new
/// AArch64 namespace: `ast::scalar_float_intrinsic` already lowers those to C
/// arithmetic, so one lowering serves both producers — the same choice
/// `ast::wide_integer_intrinsic` records for `umulh`/`sdiv`.
///
/// Before this, EVERY AArch64 scalar float instruction lifted to `Op::Unknown`:
/// no definition, no use, no footprint at all. `compensation_of_step`
/// (`181_compensated_summation`, `-O2`) is three instructions —
/// `fadd d31,d0,d1; fsub d0,d31,d0; fsub d0,d0,d1` — and recovered as
/// `return arg0;` with all three dropped to asm comments.
fn scalar_float_ops(ins: &Instruction, mnem: &str) -> Option<Vec<Op>> {
    let stem = match mnem {
        "fadd" => "vadd",
        "fsub" => "vsub",
        "fmul" => "vmul",
        "fdiv" => "vdiv",
        "fneg" => "vneg",
        "fmov" => "vmov",
        _ => return None,
    };
    // No 4-operand arm: FMA (`fmadd`/`fmsub`/`fnmadd`/`fnmsub`) is deliberately
    // NOT lifted here. Mapping it to an opaque intrinsic was tried and measured
    // -- it recovered the prototype of every function ending in an FMA and
    // broke `217_complex_arithmetic:aarch64:O2:complex_add_conj` from pass to
    // fail, because the emitted C then calls `__unknown(0)` and uses its
    // result. A definition the renderer cannot express is worse than no
    // definition. FMA is ternary and `float_gate`'s operator table has only
    // `Move`, `Negate` and `Binary`; it needs a form there first.
    let arity = if matches!(stem, "vneg" | "vmov") {
        2
    } else {
        3
    };
    if ins.operands.len() != arity {
        return None;
    }
    let dst = operand_reg(ins.operands.first()?)?;
    let width = scalar_float_width(&dst)?;
    let mut sources = Vec::with_capacity(arity - 1);
    for operand in &ins.operands[1..] {
        // `fmov Dd,#imm` materialises a float constant. Capstone renders the
        // immediate rather than a register, so the register-only path below
        // rejected it and the destination went undefined -- which is enough on
        // its own to lose a function, since the constant usually feeds the
        // instruction that computes the return value. Carry it as an input so
        // the definition exists; the intrinsic name records that this is a
        // float move, and no arithmetic identity is claimed for the value.
        if stem == "vmov" && matches!(operand.kind, OperandKind::Immediate) {
            if let Some(v) = operand_to_value(operand) {
                sources.push(v);
                continue;
            }
        }
        let source = operand_reg(operand)?;
        // Every operand of a scalar FP instruction is the same IEEE width as
        // its destination. An `fmov` reading a general register is a BIT
        // reinterpretation rather than this conversion-free move, and a
        // register whose name states a different width is a form this lowering
        // does not model; both stay on `packed::scalar_fmov`'s exact-lane path.
        if scalar_float_width(&source) != Some(width) {
            return None;
        }
        sources.push(Value::Reg(source));
    }
    Some(vec![Op::Intrinsic {
        name: format!("{stem}.f{}", width.bits()),
        ins: sources,
        outs: vec![(dst, width)],
        reads_mem: false,
        writes_mem: false,
    }])
}

/// The C arithmetic type an AArch64 register holds under a conversion
/// mnemonic, spelled the way ARM's `vcvt.<to>.<from>` suffix does.
///
/// `float_class` says how the mnemonic READS the register, which is the whole
/// content of a conversion instruction: `scvtf s0, s0` reads `s0` as a 32-bit
/// signed integer and writes it back as binary32, so the same register name is
/// `s32` at one end and `f32` at the other. The width still comes from the
/// name — `w`/`s` are four bytes, `x`/`d` eight — because AArch64 states it
/// there.
fn conversion_end(register: &VReg, float_class: bool) -> Option<String> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let base = crate::ir::abi::ssa_base(name);
    let (class, index) = base.split_at(base.char_indices().nth(1)?.0);
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let bits = match class {
        "w" | "s" => 32,
        "x" | "d" => 64,
        _ => return None,
    };
    Some(format!("{}{bits}", if float_class { 'f' } else { 's' }))
}

/// Lift one AArch64 scalar conversion between a signed integer and an IEEE
/// value, or between the two IEEE widths.
///
/// The name emitted is ARM32's `vcvt.<to>.<from>` spelling, which
/// `ast::arm_scalar_conversion_intrinsic` lowers to the exact C cast.
///
/// `ucvtf`/`fcvtzu` are absent on purpose: `ast::ScalarType` cannot say
/// "unsigned", and rendering them as their signed neighbour disagrees for every
/// value above the signed maximum — which is precisely what
/// `173_float_int_conversions:truncate_to_unsigned` measures. A wrong answer
/// that type-checks is worse than the opaque comment.
///
/// `fcvtzs` is the truncating form, which is what a C cast does; the
/// rounding-mode variants (`fcvtas`, `fcvtms`, `fcvtns`, `fcvtps`) are not C
/// casts and stay opaque.
fn scalar_conversion_ops(ins: &Instruction, mnem: &str) -> Option<Vec<Op>> {
    let (destination_is_float, source_is_float) = match mnem {
        "scvtf" => (true, false),
        "fcvtzs" => (false, true),
        "fcvt" => (true, true),
        _ => return None,
    };
    if ins.operands.len() != 2 {
        return None;
    }
    let dst = operand_reg(&ins.operands[0])?;
    let src = operand_reg(&ins.operands[1])?;
    let to = conversion_end(&dst, destination_is_float)?;
    let from = conversion_end(&src, source_is_float)?;
    if to == from {
        return None;
    }
    // The destination of every one of these is a floating-point register except
    // `fcvtzs`, which writes a general one; either way its declared width is
    // the width its name states.
    let width = match to.strip_prefix(['f', 's'])? {
        "32" => Width::W32,
        _ => Width::W64,
    };
    Some(vec![Op::Intrinsic {
        name: format!("vcvt.{to}.{from}"),
        ins: vec![Value::Reg(src)],
        outs: vec![(dst, width)],
        reads_mem: false,
        writes_mem: false,
    }])
}

fn lift_one(ins: &Instruction) -> Vec<Op> {
    let mnem = ins.mnemonic.to_ascii_lowercase();

    if mnem == "add" {
        if let Some(ops) = packed::dword_binary(ins, BinOp::Add) {
            return ops;
        }
    }

    if let Some(ops) = scalar_float_ops(ins, &mnem) {
        return ops;
    }

    if let Some(ops) = scalar_conversion_ops(ins, &mnem) {
        return ops;
    }

    // Three-operand arithmetic: <op> Xd, Xn, <reg|imm>
    if let Some(op) = bin_for_mnem(&mnem) {
        if ins.operands.len() == 3 {
            let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ins.operands[0]),
                operand_to_value(&ins.operands[1]),
                operand_to_value(&ins.operands[2]),
            ) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            // A right shift is the one binary form whose result depends on bits
            // OUTSIDE the operand width: at 32 bits `asr` must shift a
            // sign-extended word and `lsr` a zero-extended one. Every other
            // operation here (add/sub/and/orr/eor/lsl/mul) is determined by the
            // low bits alone, so the trailing parent zero-extension is enough.
            let width = machine_width([&Value::Reg(dst.clone()), &lhs]);
            let mut out = Vec::new();
            // `lsl`/`lsr`/`asr` are themselves the shifted-register encoding of
            // `orr`, so a modifier must not be applied on top of them.
            let rhs = if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) {
                rhs
            } else {
                modified_last_operand(ins, rhs, width, &mut out)
            };
            let lhs = match op {
                BinOp::Sar => signed_view(lhs, width, temp_for(ins, 13), &mut out),
                BinOp::Shr => unsigned_view(lhs, width, temp_for(ins, 13), &mut out),
                _ => lhs,
            };
            out.push(Op::Bin { dst, op, lhs, rhs });
            return out;
        }
    }

    // Flag-setting arithmetic: `adds`/`subs`/`ands` are the plain operation
    // plus the flag write that `cmp`/`tst` would have produced.
    //
    // Leaving these unlifted did more damage than losing one instruction. A
    // dropped flag write breaks the flag's def-use chain, so the reader of that
    // flag binds to a *stale* earlier definition — in a stripped AArch64
    // `parsenum`, `subs` before the epilogue was dropped and the stack-canary
    // branch bound to a comparison from the top of the function. `subs` and
    // `adds` alone accounted for 50 of the 302 unlifted-instruction markers
    // across the AArch64 corpus.
    if let Some((op, flag_form, complement_rhs)) = flag_setting_arith(&mnem) {
        if ins.operands.len() == 3 {
            let (Some(dst), Some(lhs), Some(rhs)) = (
                operand_reg(&ins.operands[0]),
                operand_to_value(&ins.operands[1]),
                operand_to_value(&ins.operands[2]),
            ) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let width = machine_width([&Value::Reg(dst.clone()), &lhs]);
            let mut out = Vec::new();
            let mut rhs = modified_last_operand(ins, rhs, width, &mut out);
            if complement_rhs {
                // `bics Rd, Rn, Rm` is `Rn AND NOT(Rm)`; materialise the
                // complement rather than pretending the operation is a plain
                // AND.
                let inverted = temp_for(ins, 26);
                out.push(Op::Un {
                    dst: inverted.clone(),
                    op: UnOp::Not,
                    src: rhs,
                });
                rhs = Value::Reg(inverted);
            }
            // The comparison flags are a function of the PRE-operation operands,
            // so they are emitted before the write that may destroy one of them.
            // `subs x3, x3, x2` — the shape gcc's stack-canary epilogue uses —
            // otherwise compared the already-updated `x3` against `x2` and
            // rendered `(saved - current) == current`, a condition the CPU never
            // evaluates. It made every canary check take the failure branch.
            let compare = match flag_form {
                // `subs Xd, Xn, Xm` sets exactly the flags of `cmp Xn, Xm`, and
                // `cmp` is architecturally `subs XZR, Xn, Xm`.
                FlagForm::Compare => compare_flags(ins, lhs.clone(), rhs.clone()),
                FlagForm::ResultVsZero => Vec::new(),
            };
            out.extend(compare);
            out.push(Op::Bin {
                dst: dst.clone(),
                op,
                lhs: lhs.clone(),
                rhs: rhs.clone(),
            });
            match flag_form {
                FlagForm::Compare => {}
                // For `adds`/`ands` the useful, provable fact is whether the
                // result is zero or negative — which, unlike the comparison
                // flags, is read from the destination AFTER the write.
                FlagForm::ResultVsZero => out.extend(result_flags(ins, Value::Reg(dst), width)),
            }
            return out;
        }
    }

    // b.<cond> conditional branches.
    if let Some(suffix) = mnem.strip_prefix("b.") {
        if let Some((cond, inverted)) = cond_flag_for_bcond(suffix) {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::CondJump {
                    cond,
                    target: target as u64,
                    inverted,
                }];
            }
        }
        return vec![Op::Unknown { mnemonic: mnem }];
    }

    match mnem.as_str() {
        "nop" => vec![Op::Nop],
        "dup" => {
            packed::dword_duplicate(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }])
        }
        "movi" => packed::dword_immediate_splat(ins, false)
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "mvni" => packed::dword_immediate_splat(ins, true)
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "smax" => {
            packed::dword_signed_max(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }])
        }
        "ushl" => packed::dword_unsigned_shift(ins)
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "cmtst" => {
            packed::dword_compare_test(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }])
        }
        "bit" => {
            packed::byte_bit_insert(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }])
        }
        "umaxp" => packed::dword_pairwise_unsigned_max(ins)
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "tbl" => packed::byte_table_16(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "addv" => packed::dword_horizontal_add(ins)
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "fmov" => packed::scalar_fmov(ins).unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "mov" => {
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(src) = operand_to_value(&ins.operands[1]) {
                    return vec![Op::Assign { dst, src }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "movz" => {
            // movz <Xd>, #imm — low 16-bit move-with-zero; we emit Assign for
            // the simple (no-shift) case. More general movz + movk sequences
            // are handled by a later materialization pass.
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Const(imm),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "movk" => {
            if ins.operands.is_empty() {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let Some(dst) = operand_reg(&ins.operands[0]) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let Some(word) = instruction_word(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let width = if word >> 31 == 0 { 32u32 } else { 64u32 };
            let shift = ((word >> 21) & 0x3) * 16;
            if shift + 16 > width {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let imm = (word >> 5) & 0xffff;
            let width_mask = if width == 64 {
                u64::MAX
            } else {
                u64::from(u32::MAX)
            };
            let field_mask = 0xffffu64 << shift;
            let keep_mask = width_mask & !field_mask;
            let inserted = u64::from(imm) << shift;
            return vec![
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(dst.clone()),
                    rhs: Value::Const(keep_mask as i64),
                },
                Op::Bin {
                    dst: dst.clone(),
                    op: BinOp::Or,
                    lhs: Value::Reg(dst),
                    rhs: Value::Const(inserted as i64),
                },
            ];
        }
        "neg" => {
            if let Some(ops) = packed::dword_negate(ins) {
                return ops;
            }
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let width = dst.width().unwrap_or(Width::W64);
                let mut out = Vec::new();
                let src = modified_last_operand(ins, src, width, &mut out);
                out.push(Op::Un {
                    dst,
                    op: UnOp::Neg,
                    src,
                });
                return out;
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // `cmn` and `tst` are `adds`/`ands` with a discarded destination, and
        // they must DEFINE the flags they set. Emitting only an opaque intrinsic
        // is modelled by the execution engine (`exec::helpers`) but is invisible
        // on the decompile path: the following `cset`/`csinv`/`b.<cond>` then
        // binds to a stale earlier definition, which is how `and_is_zero` and
        // `add_then_negative` returned a condition the CPU never evaluated.
        "cmn" | "tst" => {
            if ins.operands.len() == 2 {
                let (Some(lhs), Some(rhs)) = (
                    operand_to_value(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(width) = operand_width(&lhs) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let mut out = Vec::new();
                let rhs = modified_last_operand(ins, rhs, width, &mut out);
                // `cmn Rn,#imm` is exactly `cmp Rn,#-imm`: SUBS(Rn,-imm) and
                // ADDS(Rn,imm) are the same operation, flag for flag. That form
                // therefore gets the FULL comparison flag set, carry included.
                if mnem == "cmn" {
                    if let Value::Const(imm) = rhs {
                        if let Some(negated) = imm.checked_neg() {
                            out.extend(compare_flags(ins, lhs, Value::Const(negated)));
                            return out;
                        }
                    }
                }
                let result = temp_for(ins, 0);
                out.push(bin_temp(
                    result.clone(),
                    if mnem == "cmn" {
                        BinOp::Add
                    } else {
                        BinOp::And
                    },
                    lhs.clone(),
                    rhs.clone(),
                ));
                // The register `cmn` claims only zero and sign, for the same
                // reason `adds` does: carry and overflow are not modelled, and a
                // guessed flag is worse than an absent one.
                out.extend(result_flags(ins, Value::Reg(result), width));
                // A logical operation clears ARM's C and V unconditionally, so
                // our "unsigned lower" and "lower or same" predicates are both
                // provably true — provable, therefore stated, so a following
                // `b.ls` cannot bind to a stale comparison.
                if mnem == "tst" {
                    out.extend([
                        Op::Assign {
                            dst: VReg::Flag(Flag::C),
                            src: Value::Const(1),
                        },
                        Op::Assign {
                            dst: VReg::Flag(Flag::Ule),
                            src: Value::Const(1),
                        },
                    ]);
                }
                // Keep the fully-modelled intrinsic alongside the explicit flag
                // writes: `exec::helpers` computes NZCV exactly, including the
                // carry and overflow the explicit form declines to claim.
                out.push(semantic_intrinsic(
                    &format!("aarch64_{}{}", mnem, width.bits()),
                    vec![lhs, rhs],
                ));
                return out;
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "csel" => {
            if ins.operands.len() == 3 {
                let (Some(dst), Some(if_true), Some(if_false), Some(word)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    instruction_word(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(op) = conditional_select(dst, (word >> 12) & 0xf, if_true, if_false) {
                    return vec![op];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cset" => {
            if ins.operands.len() == 1 {
                let (Some(dst), Some(word)) =
                    (operand_reg(&ins.operands[0]), instruction_word(ins))
                else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let effective_cond = ((word >> 12) & 0xf) ^ 1;
                if let Some(op) =
                    conditional_select(dst, effective_cond, Value::Const(1), Value::Const(0))
                {
                    return vec![op];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cinc" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src), Some(word)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    instruction_word(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let incremented = temp_for(ins, 0);
                let effective_cond = ((word >> 12) & 0xf) ^ 1;
                let Some(select) = conditional_select(
                    dst,
                    effective_cond,
                    Value::Reg(incremented.clone()),
                    src.clone(),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
                    Op::Bin {
                        dst: incremented,
                        op: BinOp::Add,
                        lhs: src,
                        rhs: Value::Const(1),
                    },
                    select,
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ngc" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let negated = temp_for(ins, 0);
                let with_borrow = temp_for(ins, 1);
                let Some(select) = conditional_select(
                    dst,
                    0x3, // synthetic C is true for the lower/borrow predicate
                    Value::Reg(with_borrow.clone()),
                    Value::Reg(negated.clone()),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
                    Op::Un {
                        dst: negated.clone(),
                        op: UnOp::Neg,
                        src,
                    },
                    Op::Bin {
                        dst: with_borrow,
                        op: BinOp::Sub,
                        lhs: Value::Reg(negated),
                        rhs: Value::Const(1),
                    },
                    select,
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "madd" => {
            if ins.operands.len() == 4 {
                let (Some(dst), Some(lhs), Some(rhs), Some(addend)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    operand_to_value(&ins.operands[3]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let product = temp_for(ins, 0);
                return vec![
                    Op::Bin {
                        dst: product.clone(),
                        op: BinOp::Mul,
                        lhs,
                        rhs,
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Reg(product),
                        rhs: addend,
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "umaddl" => {
            if ins.operands.len() == 4 {
                let (Some(dst), Some(lhs), Some(rhs), Some(addend)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    operand_to_value(&ins.operands[3]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let lhs64 = temp_for(ins, 0);
                let rhs64 = temp_for(ins, 1);
                let product = temp_for(ins, 2);
                return vec![
                    Op::ZExt {
                        dst: lhs64.clone(),
                        src: lhs,
                        from: Width::W32,
                        to: Width::W64,
                    },
                    Op::ZExt {
                        dst: rhs64.clone(),
                        src: rhs,
                        from: Width::W32,
                        to: Width::W64,
                    },
                    Op::Bin {
                        dst: product.clone(),
                        op: BinOp::Mul,
                        lhs: Value::Reg(lhs64),
                        rhs: Value::Reg(rhs64),
                    },
                    Op::Bin {
                        dst,
                        op: BinOp::Add,
                        lhs: Value::Reg(product),
                        rhs: addend,
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "sxtw" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![Op::SExt {
                    dst,
                    src,
                    from: Width::W32,
                    to: Width::W64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ubfx" => {
            let Some((dst, src, lsb, field, dst_width)) = bitfield_operands(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let fragment = temp_for(ins, 0);
            vec![
                Op::Extract {
                    dst: fragment.clone(),
                    src,
                    hi: lsb + field,
                    lo: lsb,
                },
                Op::ZExt {
                    dst,
                    src: Value::Reg(fragment),
                    from: Width(field),
                    to: dst_width,
                },
            ]
        }
        "bfxil" | "bfi" => {
            let Some((dst, src, source_lsb, field, dst_width)) = bitfield_operands(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let destination_lsb = if mnem == "bfi" { source_lsb } else { 0 };
            if destination_lsb + field > dst_width.bits() {
                return vec![Op::Unknown { mnemonic: mnem }];
            }
            let extract_lsb = if mnem == "bfi" { 0 } else { source_lsb };
            let fragment = temp_for(ins, 0);
            let widened = temp_for(ins, 1);
            let placed = temp_for(ins, 2);
            let kept = temp_for(ins, 3);
            let mut out = vec![
                Op::Extract {
                    dst: fragment.clone(),
                    src,
                    hi: extract_lsb + field,
                    lo: extract_lsb,
                },
                Op::ZExt {
                    dst: widened.clone(),
                    src: Value::Reg(fragment),
                    from: Width(field),
                    to: dst_width,
                },
            ];
            let placed_value = if destination_lsb == 0 {
                Value::Reg(widened)
            } else {
                out.push(Op::Bin {
                    dst: placed.clone(),
                    op: BinOp::Shl,
                    lhs: Value::Reg(widened),
                    rhs: Value::Const(i64::from(destination_lsb)),
                });
                Value::Reg(placed)
            };
            let destination_mask = low_mask(field) << destination_lsb;
            let width_mask = low_mask(dst_width.bits());
            out.extend([
                Op::Bin {
                    dst: kept.clone(),
                    op: BinOp::And,
                    lhs: Value::Reg(dst.clone()),
                    rhs: Value::Const((width_mask & !destination_mask) as i64),
                },
                Op::Bin {
                    dst,
                    op: BinOp::Or,
                    lhs: Value::Reg(kept),
                    rhs: placed_value,
                },
            ]);
            out
        }
        // Everything left in the HINT space after capstone has named the
        // pointer-authentication forms (`bti`, `yield`, `sevl`, …) is
        // architecturally a no-op for data flow.
        "hint" | "bti" | "yield" | "sev" | "sevl" | "wfe" | "wfi" | "isb" | "dsb" | "esb" => {
            vec![Op::Nop]
        }
        "ccmp" | "ccmn" => conditional_compare_ops(ins, mnem == "ccmn")
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "sdiv" | "udiv" => division_ops(ins, mnem == "sdiv")
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        // `smulh`/`umulh` are the high half of the 64x64 product — exactly the
        // shared wide-multiply lowering, whose `__int128` rendering is already
        // exercised by the x86-64 gate.
        "smulh" | "umulh" => {
            if ins.operands.len() == 3 {
                let (Some(dst), Some(lhs), Some(rhs)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let stem = if mnem == "smulh" {
                    "smul_hi"
                } else {
                    "umul_hi"
                };
                let width = dst.width().unwrap_or(Width::W64);
                return vec![Op::Intrinsic {
                    name: format!("aarch64.{stem}.{}", width.bits()),
                    ins: vec![lhs, rhs],
                    outs: vec![(dst, width)],
                    reads_mem: false,
                    writes_mem: false,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "smull" | "smaddl" | "umull" | "smsubl" | "umsubl" | "smnegl" | "umnegl" => {
            long_multiply_ops(
                ins,
                mnem.starts_with('s'),
                matches!(mnem.as_str(), "smsubl" | "umsubl" | "smnegl" | "umnegl"),
            )
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }])
        }
        "ubfiz" | "sbfiz" => bitfield_insert_in_zero_ops(ins, mnem == "sbfiz")
            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]),
        "sbfx" => {
            let Some((dst, src, lsb, field, dst_width)) = bitfield_operands(ins) else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let fragment = temp_for(ins, 0);
            vec![
                Op::Extract {
                    dst: fragment.clone(),
                    src,
                    hi: lsb + field,
                    lo: lsb,
                },
                Op::SExt {
                    dst,
                    src: Value::Reg(fragment),
                    from: Width(field),
                    to: dst_width,
                },
            ]
        }
        "ror" => {
            if ins.operands.len() == 3 {
                let (Some(dst), Some(src), Some(amount)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return rotate_right_ops(ins, dst, src, amount);
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // `extr Rd, Rn, Rm, #lsb` takes the low `lsb` bits of Rn as the high
        // part and the high `width-lsb` bits of Rm as the low part. It is only
        // lifted where Rn == Rm, which is the rotate the assembler also spells
        // `ror`; the general double-word extract would need a wider temporary
        // than this IR models and is left unlifted rather than approximated.
        "extr" => {
            if ins.operands.len() == 4 {
                let (Some(dst), Some(high), Some(low), Some(lsb)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    operand_to_value(&ins.operands[3]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if high == low {
                    return rotate_right_ops(ins, dst, high, lsb);
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "sxtb" | "sxth" | "uxtb" | "uxth" | "uxtw" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let from = match mnem.as_str() {
                    "sxtb" | "uxtb" => Width::W8,
                    "sxth" | "uxth" => Width::W16,
                    _ => Width::W32,
                };
                let to = dst.width().unwrap_or(Width::W64);
                return vec![if mnem.starts_with('s') {
                    Op::SExt { dst, src, from, to }
                } else {
                    Op::ZExt { dst, src, from, to }
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "mvn" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let width = dst.width().unwrap_or(Width::W64);
                let mut out = Vec::new();
                let src = modified_last_operand(ins, src, width, &mut out);
                out.push(Op::Un {
                    dst,
                    op: UnOp::Not,
                    src,
                });
                return out;
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // `csinc`/`csinv`/`csneg Rd, Rn, Rm, cond` = cond ? Rn : f(Rm). Unlike
        // the `cset`/`cinc`/`cneg` aliases the condition is NOT inverted here —
        // the inversion those aliases carry is part of the alias, not the
        // instruction.
        "csinc" | "csinv" | "csneg" => {
            if ins.operands.len() == 3 {
                let (Some(dst), Some(if_true), Some(other), Some(code)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    operand_to_value(&ins.operands[2]),
                    cond_field(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let modified = temp_for(ins, 0);
                let transform = match mnem.as_str() {
                    "csinc" => bin_temp(modified.clone(), BinOp::Add, other, Value::Const(1)),
                    "csinv" => Op::Un {
                        dst: modified.clone(),
                        op: UnOp::Not,
                        src: other,
                    },
                    _ => Op::Un {
                        dst: modified.clone(),
                        op: UnOp::Neg,
                        src: other,
                    },
                };
                let Some(select) =
                    conditional_select(dst, code, if_true, Value::Reg(modified.clone()))
                else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![transform, select];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // `cneg Rd, Rn, cond` = CSNEG Rd,Rn,Rn,invert(cond) = cond ? -Rn : Rn.
        "cneg" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src), Some(code)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                    cond_field(ins),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let negated = temp_for(ins, 0);
                let Some(select) =
                    conditional_select(dst, code ^ 1, Value::Reg(negated.clone()), src.clone())
                else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![
                    Op::Un {
                        dst: negated,
                        op: UnOp::Neg,
                        src,
                    },
                    select,
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // `csetm Rd, cond` = CSINV Rd,ZR,ZR,invert(cond) = cond ? -1 : 0.
        "csetm" => {
            if ins.operands.len() == 1 {
                let (Some(dst), Some(code)) = (operand_reg(&ins.operands[0]), cond_field(ins))
                else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(op) =
                    conditional_select(dst, code ^ 1, Value::Const(-1), Value::Const(0))
                {
                    return vec![op];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "clz" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(width) = dst.width() else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if matches!(width, Width::W32 | Width::W64) {
                    return vec![Op::Intrinsic {
                        name: format!("aarch64.clz.{}", width.bits()),
                        ins: vec![src],
                        outs: vec![(dst, width)],
                        reads_mem: false,
                        writes_mem: false,
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "rev" | "rev16" => {
            if ins.operands.len() == 2 {
                let (Some(dst), Some(src)) = (
                    operand_reg(&ins.operands[0]),
                    operand_to_value(&ins.operands[1]),
                ) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let width = dst.width().unwrap_or(Width::W64);
                if matches!(width, Width::W32 | Width::W64) {
                    return vec![Op::Intrinsic {
                        // REV reverses the entire register. REV16 reverses the
                        // two bytes independently inside every halfword lane.
                        // Keep that distinction in architecture-neutral LLIR;
                        // both AST lowering and native execution consume it.
                        name: if mnem == "rev" {
                            "bswap".into()
                        } else {
                            "byte_swap_16_lanes".into()
                        },
                        ins: vec![src],
                        outs: vec![(dst, width)],
                        reads_mem: false,
                        writes_mem: false,
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "adr" => {
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Addr(imm as u64),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "msub" | "mneg" => {
            let mut operands = vec![
                operand_reg(&ins.operands[0]).map(Value::Reg),
                operand_to_value(&ins.operands[1]),
                operand_to_value(&ins.operands[2]),
            ];
            // `mneg Rd,Rn,Rm` is `msub Rd,Rn,Rm,ZR`.
            operands.push(if ins.operands.len() == 4 {
                operand_to_value(&ins.operands[3])
            } else {
                Some(Value::Const(0))
            });
            let [Some(Value::Reg(dst)), Some(lhs), Some(rhs), Some(minuend)] = &operands[..] else {
                return vec![Op::Unknown { mnemonic: mnem }];
            };
            let product = temp_for(ins, 0);
            vec![
                bin_temp(product.clone(), BinOp::Mul, lhs.clone(), rhs.clone()),
                bin_temp(
                    dst.clone(),
                    BinOp::Sub,
                    minuend.clone(),
                    Value::Reg(product),
                ),
            ]
        }
        "paciasp" | "autiasp" | "dmb" | "csdb" => vec![intrinsic(&mnem, Vec::new())],
        "mrs" => {
            // MRS Xt,SP_EL0 has fixed sysreg bits 0xd5384100; Rt is bits 4:0.
            if instruction_word(ins).is_some_and(|word| word & 0xffff_ffe0 == 0xd538_4100)
                && !ins.operands.is_empty()
            {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                return vec![intrinsic("mrs_sp_el0", vec![(dst, Width::W64)])];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "adrp" => {
            // adrp <Xd>, #<page>. Capstone already resolves the page VA into
            // the immediate operand. We surface it as an absolute address so
            // xref recovery can pair it with the subsequent add/ldr.
            if ins.operands.len() == 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(imm) = ins.operands[1].immediate {
                    return vec![Op::Assign {
                        dst,
                        src: Value::Addr(imm as u64),
                    }];
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cmp" => {
            if ins.operands.len() == 2 {
                let Some(lhs) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(rhs) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let width = machine_width([&lhs, &rhs]);
                let mut out = Vec::new();
                let rhs = modified_last_operand(ins, rhs, width, &mut out);
                out.extend(compare_flags(ins, lhs, rhs));
                return out;
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ldr" | "ldrb" | "ldrh" | "ldrsb" | "ldrsh" | "ldrsw" | "ldur" | "ldurb" | "ldurh"
        | "ldursb" | "ldursh" | "ldursw" => {
            if ins.operands.len() >= 2 {
                let Some(dst) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = scalar_access_size(&mnem, &ins.operands[0]);
                if size == 16 {
                    return packed::memory_transfer(ins, &dst, 1, 2, PackedTransfer::Load)
                        .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]);
                }
                // A narrow load reads `size` bytes and fills the rest of its
                // GPR destination. Keep the memory value distinct and make that
                // architectural widening explicit: signed forms use `SExt`,
                // while LDRB/LDRH use `ZExt`. A bare byte load into `wN` loses
                // the unsigned result when it later renders through a signed C
                // `char` dereference.
                let signed = sign_extending_load(&mnem);
                let from = Width(u16::from(size) * 8);
                let widen_to = dst.width().filter(|to| from.bits() < to.bits());
                let loaded = if widen_to.is_some() {
                    temp_for(ins, 14)
                } else {
                    dst.clone()
                };
                let widen = widen_to.map(|to| {
                    let src = Value::Reg(loaded.clone());
                    if signed {
                        Op::SExt {
                            src,
                            dst: dst.clone(),
                            from,
                            to,
                        }
                    } else {
                        Op::ZExt {
                            src,
                            dst: dst.clone(),
                            from,
                            to,
                        }
                    }
                });
                if let Some(addr) = operand_to_memop(&ins.operands[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = Vec::new();
                    let addr = scaled_memop(ins, addr, &mut out);
                    out.push(Op::Load { dst: loaded, addr });
                    out.extend(widen);
                    // Post-indexed: 3rd operand is the writeback amount.
                    if ins.operands.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[2].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
                // PC-relative literal (2-operand form).
                if ins.operands.len() == 2 {
                    if let Some(abs) = ins.operands[1].immediate {
                        let mut out = vec![Op::Load {
                            dst: loaded,
                            addr: MemOp {
                                base: None,
                                index: None,
                                scale: 0,
                                disp: abs,
                                size,
                                segment: None,
                                endian: Endian::Little,
                            },
                        }];
                        out.extend(widen);
                        return out;
                    }
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "str" | "strb" | "strh" | "stur" | "sturb" | "sturh" => {
            if ins.operands.len() >= 2 {
                let Some(src) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let size = scalar_access_size(&mnem, &ins.operands[0]);
                if size == 16 {
                    let Value::Reg(register) = &src else {
                        return vec![Op::Unknown { mnemonic: mnem }];
                    };
                    return packed::memory_transfer(ins, register, 1, 2, PackedTransfer::Store)
                        .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]);
                }
                if let Some(addr) = operand_to_memop(&ins.operands[1], size) {
                    let base_reg = addr.base.clone();
                    let mut out = Vec::new();
                    let addr = scaled_memop(ins, addr, &mut out);
                    out.push(Op::Store { addr, src });
                    if ins.operands.len() == 3 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[2].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        // Load-pair / store-pair transfers two consecutive values whose width
        // is encoded by the register class (`Wt` or `Xt`). We decompose into
        // two ordinary Load/Store ops so the rest of the pipeline (stack
        // locals, dead stores, push/pop recognition) doesn't need to know
        // about pairs, while retaining that exact element width and stride.
        "ldp" => {
            if ins.operands.len() >= 3 {
                let Some(dst1) = operand_reg(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(dst2) = operand_reg(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                match (packed::vector_name(&dst1), packed::vector_name(&dst2)) {
                    (Some(_), Some(_)) => {
                        return packed::pair_transfer(ins, &dst1, &dst2, PackedTransfer::Load)
                            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]);
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        return vec![Op::Unknown { mnemonic: mnem }];
                    }
                    (None, None) => {}
                }
                let pair_size = scalar_access_size(&mnem, &ins.operands[0]);
                if let Some(mut addr) = operand_to_memop(&ins.operands[2], pair_size) {
                    let base_reg = addr.base.clone();
                    let pair_off = i64::from(pair_size);
                    let mut out = Vec::new();
                    // LDP reads both memory operands from the pre-instruction
                    // address. If the first destination is a view of the base
                    // or index (`ldp w4,w5,[x4,#4]`), sequential scalar loads
                    // must not let that first write redirect the second load.
                    if let Some(base) = addr
                        .base
                        .as_ref()
                        .filter(|base| same_register_family(base, &dst1))
                        .cloned()
                    {
                        let preserved = temp_for(ins, 0);
                        out.push(Op::Assign {
                            dst: preserved.clone(),
                            src: Value::Reg(base),
                        });
                        addr.base = Some(preserved);
                    }
                    if let Some(index) = addr
                        .index
                        .as_ref()
                        .filter(|index| same_register_family(index, &dst1))
                        .cloned()
                    {
                        let preserved = temp_for(ins, 1);
                        out.push(Op::Assign {
                            dst: preserved.clone(),
                            src: Value::Reg(index),
                        });
                        addr.index = Some(preserved);
                    }
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = pair_size;
                    out.extend([
                        Op::Load { dst: dst1, addr },
                        Op::Load {
                            dst: dst2,
                            addr: addr2,
                        },
                    ]);
                    // Post-indexed: 4th operand is the writeback amount.
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[3].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "stp" => {
            if ins.operands.len() >= 3 {
                let Some(src1) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(src2) = operand_to_value(&ins.operands[1]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                match (&src1, &src2) {
                    (Value::Reg(first), Value::Reg(second))
                        if packed::vector_name(first).is_some()
                            && packed::vector_name(second).is_some() =>
                    {
                        return packed::pair_transfer(ins, first, second, PackedTransfer::Store)
                            .unwrap_or_else(|| vec![Op::Unknown { mnemonic: mnem }]);
                    }
                    (Value::Reg(first), Value::Reg(second))
                        if packed::vector_name(first).is_some()
                            || packed::vector_name(second).is_some() =>
                    {
                        return vec![Op::Unknown { mnemonic: mnem }];
                    }
                    _ => {}
                }
                let pair_size = scalar_access_size(&mnem, &ins.operands[0]);
                if let Some(mut addr) = operand_to_memop(&ins.operands[2], pair_size) {
                    let base_reg = addr.base.clone();
                    let pair_off = i64::from(pair_size);
                    let addr2 = MemOp {
                        disp: addr.disp.wrapping_add(pair_off),
                        ..addr.clone()
                    };
                    addr.size = pair_size;
                    let mut out = vec![
                        Op::Store { addr, src: src1 },
                        Op::Store {
                            addr: addr2,
                            src: src2,
                        },
                    ];
                    if ins.operands.len() == 4 {
                        if let (Some(base), Some(off)) = (base_reg, ins.operands[3].immediate) {
                            out.push(Op::Bin {
                                dst: base.clone(),
                                op: BinOp::Add,
                                lhs: Value::Reg(base),
                                rhs: Value::Const(off),
                            });
                        }
                    }
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "cbz" | "cbnz" => {
            // cbz <Xn>, <label>: branch if <Xn> == 0.
            // cbnz <Xn>, <label>: branch if <Xn> != 0 (inverted).
            // Emit: %zf = (Xn == 0); cond_jump (!)%zf <label>
            let inverted = mnem == "cbnz";
            if ins.operands.len() == 2 {
                let Some(reg_val) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if let Some(target) = ins.operands[1].immediate {
                    // `cbz w0` tests the low 32 bits only; the parent may still
                    // carry the high half of an earlier 64-bit write.
                    let width = machine_width([&reg_val, &Value::Const(0)]);
                    let mut out = Vec::new();
                    let reg_val = unsigned_view(reg_val, width, temp_for(ins, 8), &mut out);
                    out.extend([
                        Op::Cmp {
                            dst: VReg::Flag(Flag::Z),
                            op: CmpOp::Eq,
                            lhs: reg_val,
                            rhs: Value::Const(0),
                        },
                        Op::CondJump {
                            cond: VReg::Flag(Flag::Z),
                            target: target as u64,
                            inverted,
                        },
                    ]);
                    return out;
                }
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "tbz" | "tbnz" => {
            // TBZ/TBNZ do not modify NZCV. Extract the selected bit into a
            // dedicated non-architectural predicate so a later b.<cond> still
            // observes the preceding flag-setting instruction.
            if ins.operands.len() == 3 {
                let Some(reg) = operand_to_value(&ins.operands[0]) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(bit) = ins.operands[1].immediate else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(target) = ins.operands[2].immediate else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                let Some(width) = (match &reg {
                    Value::Reg(register) => register.width(),
                    _ => None,
                }) else {
                    return vec![Op::Unknown { mnemonic: mnem }];
                };
                if bit < 0 || bit >= i64::from(width.bits()) {
                    return vec![Op::Unknown { mnemonic: mnem }];
                }
                return vec![
                    Op::Extract {
                        dst: VReg::Flag(Flag::Bit),
                        src: reg,
                        hi: bit as u16 + 1,
                        lo: bit as u16,
                    },
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Bit),
                        target: target as u64,
                        inverted: mnem == "tbz",
                    },
                ];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "b" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Jump {
                    target: target as u64,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "bl" => {
            if let Some(target) = ins.operands.first().and_then(|o| o.immediate) {
                return vec![Op::Call {
                    target: CallTarget::Direct(target as u64),
                    effects: None,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "br" => {
            if let Some(reg) = ins.operands.first().and_then(operand_reg) {
                return vec![Op::IndirectJump {
                    target: Value::Reg(reg),
                    index: None,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "blr" => {
            if let Some(reg) = ins.operands.first().and_then(operand_reg) {
                return vec![Op::Call {
                    target: CallTarget::Indirect(Value::Reg(reg)),
                    effects: None,
                }];
            }
            vec![Op::Unknown { mnemonic: mnem }]
        }
        "ret" => vec![Op::Return],
        _ => vec![Op::Unknown { mnemonic: mnem }],
    }
}

/// Lift a byte window of AArch64 machine code into LLIR.
///
/// Returns an empty vector if the capstone backend cannot be constructed
/// (should not happen at runtime on supported platforms) or if decoding
/// fails on the very first instruction.
pub fn lift_bytes(bytes: &[u8], start_va: u64) -> Vec<LlirInstr> {
    let Some(cs) = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut va = start_va;
    while off + 4 <= bytes.len() {
        let Ok(addr) = Address::new(AddressKind::VA, va, 64, None, None) else {
            break;
        };
        let ins = match cs.disassemble_instruction(&addr, &bytes[off..]) {
            Ok(i) => i,
            Err(_) => break,
        };
        if ins.length == 0 {
            break;
        }
        for op in with_parent_zero_extension(lift_one(&ins)) {
            out.push(LlirInstr { va, op });
        }
        off += ins.length as usize;
        va = va.saturating_add(ins.length as u64);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: ARM64 is 4-byte little-endian for data and wide-immediate fields.
    // The byte sequences below are hand-assembled from instruction encodings
    // in the Arm ARM (ARM DDI 0487) so tests are hermetic and don't need a
    // real binary.

    fn last_op_mnem(out: &[LlirInstr]) -> String {
        match &out.last().unwrap().op {
            Op::Unknown { mnemonic } => mnemonic.clone(),
            other => format!("{:?}", other),
        }
    }

    /// `bics Rd, Rn, Rm` is AND-**NOT** (ARM DDI 0487 C6.2.34), not AND.
    ///
    /// `flag_setting_arith` mapped it to a plain `BinOp::And`, so the recovered
    /// value was `Rn & Rm` — wrong for every set bit of `Rm`, and silently,
    /// because the mnemonic was recognised and never showed up as unlifted.
    #[test]
    fn bics_is_and_not() {
        // bics x0, x1, x2 = 0xea220020
        let out = lift_bytes(&0xea220020u32.to_le_bytes(), 0x1000);
        let complement = out
            .iter()
            .find_map(|instruction| match &instruction.op {
                Op::Un {
                    dst,
                    op: UnOp::Not,
                    src,
                } if src == &Value::Reg(VReg::phys("x2")) => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("bics did not complement its operand: {out:#?}"));
        assert!(
            out.iter().any(|instruction| matches!(&instruction.op,
                Op::Bin { dst, op: BinOp::And, lhs, rhs }
                    if dst == &VReg::phys("x0")
                        && lhs == &Value::Reg(VReg::phys("x1"))
                        && rhs == &Value::Reg(complement.clone()))),
            "bics did not AND against the complement: {out:#?}"
        );
        // ...and it still reports whether that result is zero.
        assert!(
            out.iter().any(|instruction| matches!(
                &instruction.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    ..
                }
            )),
            "bics wrote no zero flag: {out:#?}"
        );
    }

    #[test]
    fn nop_lifts_to_nop() {
        // NOP = 0xd503201f (little-endian: 1f 20 03 d5)
        let out = lift_bytes(&[0x1f, 0x20, 0x03, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Nop);
        assert_eq!(out[0].va, 0x1000);
    }

    #[test]
    fn ret_lifts_to_return() {
        // RET (x30) = 0xd65f03c0 (LE: c0 03 5f d6)
        let out = lift_bytes(&[0xc0, 0x03, 0x5f, 0xd6], 0x2000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].op, Op::Return);
    }

    #[test]
    fn add_x0_x0_x1_lifts_to_bin_add() {
        // ADD X0, X0, X1  =  0x8b010000  (LE: 00 00 01 8b)
        let out = lift_bytes(&[0x00, 0x00, 0x01, 0x8b], 0x1000);
        assert_eq!(out.len(), 1, "expected one op; got {:?}", out);
        match &out[0].op {
            Op::Bin {
                dst,
                op: BinOp::Add,
                lhs,
                rhs,
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*lhs, Value::Reg(VReg::phys("x0")));
                assert_eq!(*rhs, Value::Reg(VReg::phys("x1")));
            }
            other => panic!("expected Bin Add; got {:?}", other),
        }
    }

    #[test]
    fn cmp_x0_x1_emits_unsigned_and_signed_flag_writes() {
        // CMP X0, X1 = SUBS XZR, X0, X1  = 0xeb01001f (LE: 1f 00 01 eb)
        let out = lift_bytes(&[0x1f, 0x00, 0x01, 0xeb], 0x1000);
        assert_eq!(out.len(), 5, "cmp should lift to 5 LLIR ops: {:?}", out);
        let flags: Vec<VReg> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Cmp { dst, .. } => Some(dst.clone()),
                _ => None,
            })
            .collect();
        for want in [
            VReg::Flag(Flag::Z),
            VReg::Flag(Flag::C),
            VReg::Flag(Flag::Ule),
            VReg::Flag(Flag::Slt),
            VReg::Flag(Flag::Sle),
        ] {
            assert!(flags.contains(&want), "missing {:?} in {:?}", want, flags);
        }
    }

    #[test]
    fn b_hi_reads_inverted_unsigned_less_or_equal_flag() {
        // B.HI +0xc from 0x1000 = 0x54000068 (LE: 68 00 00 54).
        let out = lift_bytes(&[0x68, 0x00, 0x00, 0x54], 0x1000);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].op,
            Op::CondJump {
                cond: VReg::Flag(Flag::Ule),
                target: 0x100c,
                inverted: true,
            }
        );
    }

    #[test]
    fn tbz_and_tbnz_lift_to_explicit_bit_tests_and_branches() {
        // TBZ W1,#3,+8 = 0x36180041; TBNZ W2,#31,+4 = 0x37f80022.
        let out = lift_bytes(&[0x41, 0x00, 0x18, 0x36, 0x22, 0x00, 0xf8, 0x37], 0x1000);
        assert_eq!(out.len(), 4, "each bit-test branch needs two ops: {out:#?}");
        assert!(matches!(
            &out[0].op,
            Op::Extract {
                dst: VReg::Flag(Flag::Bit),
                src: Value::Reg(reg),
                hi: 4,
                lo: 3,
            } if *reg == VReg::phys("w1")
        ));
        assert!(matches!(
            &out[1].op,
            Op::CondJump {
                target: 0x1008,
                inverted: true,
                ..
            }
        ));
        assert!(matches!(
            &out[2].op,
            Op::Extract {
                dst: VReg::Flag(Flag::Bit),
                src: Value::Reg(reg),
                hi: 32,
                lo: 31,
            } if *reg == VReg::phys("w2")
        ));
        assert!(matches!(
            &out[3].op,
            Op::CondJump {
                target: 0x1008,
                inverted: false,
                ..
            }
        ));
    }

    #[test]
    fn bl_to_direct_target_lifts_to_call_direct() {
        // BL +0x20 from 0x1000:  target = 0x1020. Encoding:
        //   0x94000008  (imm26 = 0x8 = 32/4). LE: 08 00 00 94
        let out = lift_bytes(&[0x08, 0x00, 0x00, 0x94], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Call {
                target: CallTarget::Direct(addr),
                ..
            } => assert_eq!(*addr, 0x1020),
            other => panic!("expected Call Direct; got {:?}", other),
        }
    }

    #[test]
    fn br_is_a_terminal_indirect_jump_while_blr_is_an_indirect_call() {
        // These encodings are retained from the real AArch64 indirect-dispatch
        // fixture: `br x16` is the optimized tail transfer, while `blr x2` is
        // the ordinary -O0 call that returns to its following instruction.
        let branch = lift_bytes(&0xd61f0200u32.to_le_bytes(), 0x1000);
        assert!(matches!(
            branch.as_slice(),
            [LlirInstr {
                op: Op::IndirectJump {
                    target: Value::Reg(register),
                    index: None,
                },
                ..
            }] if register == &VReg::phys("x16")
        ));

        let call = lift_bytes(&0xd63f0040u32.to_le_bytes(), 0x1000);
        assert!(matches!(
            call.as_slice(),
            [LlirInstr {
                op: Op::Call {
                    target: CallTarget::Indirect(Value::Reg(register)),
                    ..
                },
                ..
            }] if register == &VReg::phys("x2")
        ));
    }

    #[test]
    fn b_to_direct_target_lifts_to_jump() {
        // B +0x10 from 0x2000: 0x14000004  (LE: 04 00 00 14) — target 0x2010
        let out = lift_bytes(&[0x04, 0x00, 0x00, 0x14], 0x2000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Jump { target } => assert_eq!(*target, 0x2010),
            other => panic!("expected Jump; got {:?}", other),
        }
    }

    #[test]
    fn movz_x0_imm_lifts_to_assign() {
        // MOVZ X0, #0x1234 = 0xd2824680  (LE: 80 46 82 d2)
        // imm16 = 0x1234, hw = 0.
        let out = lift_bytes(&[0x80, 0x46, 0x82, 0xd2], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Assign {
                dst,
                src: Value::Const(v),
            } => {
                assert_eq!(*dst, VReg::phys("x0"));
                assert_eq!(*v, 0x1234);
            }
            other => panic!("expected Assign of const; got {:?}", other),
        }
    }

    #[test]
    fn movk_preserves_other_bits_with_a_masked_update() {
        // MOVK W8,#0x4004,LSL#16 = 0x72a80088.
        let out = lift_bytes(&[0x88, 0x00, 0xa8, 0x72], 0x1000);
        // and / or, then the zero-extension every 32-bit write performs.
        assert_eq!(out.len(), 3, "movk should be an and/or update: {out:#?}");
        assert!(matches!(
            &out[0].op,
            Op::Bin {
                dst,
                op: BinOp::And,
                lhs: Value::Reg(src),
                rhs: Value::Const(0xffff),
            } if *dst == VReg::phys("w8") && *src == VReg::phys("w8")
        ));
        assert!(matches!(
            &out[1].op,
            Op::Bin {
                dst,
                op: BinOp::Or,
                rhs: Value::Const(0x4004_0000),
                ..
            } if *dst == VReg::phys("w8")
        ));
    }

    #[test]
    fn unscaled_load_store_keep_displacement_and_register_width() {
        // LDUR W22,[X27,#-0x28]; STUR W9,[X27,#-0x30].
        let out = lift_bytes(&[0x76, 0x83, 0x5d, 0xb8, 0x69, 0x03, 0x1d, 0xb8], 0x1000);
        assert!(matches!(
            &out[0].op,
            Op::Load {
                dst,
                addr: MemOp { disp: -0x28, size: 4, .. },
            } if *dst == VReg::phys("w22")
        ));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Store {
                src: Value::Reg(src),
                addr: MemOp { disp: -0x30, size: 4, .. },
            } if *src == VReg::phys("w9")
        )));
    }

    #[test]
    fn aarch64_environment_and_hint_ops_are_typed_intrinsics() {
        // PACIASP; MRS X8,SP_EL0; DMB OSHST.
        let out = lift_bytes(
            &[
                0x3f, 0x23, 0x03, 0xd5, 0x08, 0x41, 0x38, 0xd5, 0xbf, 0x32, 0x03, 0xd5,
            ],
            0x1000,
        );
        assert!(matches!(
            &out[0].op,
            Op::Intrinsic { name, outs, .. } if name == "paciasp" && outs.is_empty()
        ));
        assert!(matches!(
            &out[1].op,
            Op::Intrinsic { name, outs, .. }
                if name == "mrs_sp_el0"
                    && outs == &vec![(VReg::phys("x8"), Width::W64)]
        ));
        assert!(matches!(
            &out[2].op,
            Op::Intrinsic { name, outs, .. } if name == "dmb" && outs.is_empty()
        ));
    }

    #[test]
    fn neg_lifts_to_unary_negation() {
        // NEG X8,X23 = 0xcb1703e8.
        let out = lift_bytes(&[0xe8, 0x03, 0x17, 0xcb], 0x1000);
        assert_eq!(
            out[0].op,
            Op::Un {
                dst: VReg::phys("x8"),
                op: UnOp::Neg,
                src: Value::Reg(VReg::phys("x23")),
            }
        );
    }

    #[test]
    fn flag_consumers_and_flag_setting_aliases_have_explicit_semantics() {
        // CMN X0,#1; TST X1,X2; CSEL X0,X1,X2,HI; CSET W0,NE;
        // CINC X0,X1,EQ; NGC X8,XZR.
        let out = lift_bytes(
            &[
                0x1f, 0x04, 0x00, 0xb1, 0x3f, 0x00, 0x02, 0xea, 0x20, 0x80, 0x82, 0x9a, 0xe0, 0x07,
                0x9f, 0x1a, 0x20, 0x14, 0x81, 0x9a, 0xe8, 0x03, 0x1f, 0xda,
            ],
            0x1000,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "residual alias hole: {out:#?}"
        );
        // `cmn X0,#1` is exactly `cmp X0,#-1`, so it lifts to the full
        // comparison flag set rather than to an opaque intrinsic.
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Cmp {
                rhs: Value::Const(-1),
                ..
            }
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Intrinsic { name, ins, .. } if name == "aarch64_tst64" && ins.len() == 2
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Ite { dst, width: Width::W64, .. } if *dst == VReg::phys("x0")
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Ite { dst, width: Width::W32, .. } if *dst == VReg::phys("w0")
        )));
    }

    #[test]
    fn bitfield_aliases_lower_without_opaque_holes() {
        // BFI W9,W10,#8,#8; BFXIL W9,W8,#0,#8; UBFX W2,W8,#4,#4.
        let out = lift_bytes(
            &[
                0x49, 0x1d, 0x18, 0x33, 0x09, 0x1d, 0x00, 0x33, 0x02, 0x1d, 0x04, 0x53,
            ],
            0x1000,
        );
        assert!(
            out.iter()
                .all(|instruction| !matches!(instruction.op, Op::Unknown { .. })),
            "residual bitfield hole: {out:#?}"
        );
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::Extract {
                src: Value::Reg(src),
                hi: 8,
                lo: 0,
                ..
            } if *src == VReg::phys("w10")
        )));
        assert!(out.iter().any(|instruction| matches!(
            &instruction.op,
            Op::ZExt {
                dst,
                from: Width(4),
                to: Width::W32,
                ..
            } if *dst == VReg::phys("w2")
        )));
    }

    #[test]
    fn pre_indexed_stp_emits_sp_writeback() {
        // STP fp, lr, [sp, #-0x30]!   encoding 0xa9bd7bfd (LE fd 7b bd a9)
        // Real glibc-style ARM64 prologue. Pre-indexed form — capstone's
        // writeback flag is set and the memory operand's disp is -0x30.
        let out = lift_bytes(&[0xfd, 0x7b, 0xbd, 0xa9], 0x1000);
        // We want: two Stores at [sp - 0x30] and [sp - 0x28], followed by
        // an explicit sp += -0x30 writeback.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        let has_sp_writeback = out.iter().any(|i| {
            matches!(
                &i.op,
                Op::Bin {
                    dst,
                    op: BinOp::Add,
                    rhs: Value::Const(-0x30),
                    ..
                } if *dst == VReg::phys("sp")
            )
        });
        assert!(
            has_sp_writeback,
            "pre-indexed STP must emit an sp writeback: {:#?}",
            out
        );
    }

    #[test]
    fn stp_pair_decomposes_into_two_stores() {
        // STP X29, X30, [SP, #-16]!   = 0xa9bf7bfd  (LE: fd 7b bf a9)
        // Pre-index form with SP writeback. Capstone reports the memory
        // operand's base as SP and disp as -16 (writeback is modeled by
        // capstone separately; we don't model writeback yet and treat this
        // as a plain memory store pair).
        let out = lift_bytes(&[0xfd, 0x7b, 0xbf, 0xa9], 0x1000);
        // Should decompose into two stores.
        let stores: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Store { .. }))
            .collect();
        assert_eq!(stores.len(), 2, "expected two stores; got {:#?}", out);
        // The two store displacements must differ by 8 bytes.
        let disps: Vec<i64> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Store {
                    addr: MemOp { disp, .. },
                    ..
                } => Some(*disp),
                _ => None,
            })
            .collect();
        assert_eq!(disps.len(), 2);
        assert_eq!((disps[1] - disps[0]).abs(), 8);
    }

    #[test]
    fn word_register_pairs_use_four_byte_accesses_and_stride() {
        // Real GCC -O2 C++ aggregate stores:
        //   stp w3, w1, [x0] = 0x29000403
        // Pair width follows Rt, not the architecture pointer width. Treating
        // this as two X-register stores overwrites adjacent int fields.
        let stores = lift_bytes(&[0x03, 0x04, 0x00, 0x29], 0x1000);
        let store_layout: Vec<_> = stores
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Store { addr, .. } => Some((addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(store_layout, vec![(0, 4), (4, 4)]);

        // The load-pair form is governed by the same encoding bit and must
        // retain the same element width and stride.
        let loads = lift_bytes(&[0x03, 0x04, 0x40, 0x29], 0x1000);
        let load_layout: Vec<_> = loads
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { addr, .. } => Some((addr.disp, addr.size)),
                _ => None,
            })
            .collect();
        assert_eq!(load_layout, vec![(0, 4), (4, 4)]);
    }

    #[test]
    fn ldp_pair_decomposes_into_two_loads() {
        // LDP X29, X30, [SP, #16]   (immediate-offset form, no writeback)
        //   encoded: imm7=2 (scaled by 8 = 16), Rt2=30, Rn=31(SP), Rt=29.
        //   raw = 0xa9417bfd  (LE: fd 7b 41 a9)
        let out = lift_bytes(&[0xfd, 0x7b, 0x41, 0xa9], 0x1000);
        let loads: Vec<_> = out
            .iter()
            .filter(|i| matches!(i.op, Op::Load { .. }))
            .collect();
        assert_eq!(loads.len(), 2, "expected two loads; got {:#?}", out);
    }

    #[test]
    fn unknown_mnemonic_preserves_source() {
        // MRS X0, NZCV = 0xd53b4200  (LE: 00 42 3b d5) — not in our lifter set.
        let out = lift_bytes(&[0x00, 0x42, 0x3b, 0xd5], 0x1000);
        assert_eq!(out.len(), 1);
        match &out[0].op {
            Op::Unknown { mnemonic } => assert!(!mnemonic.is_empty(), "empty mnemonic in Unknown"),
            other => panic!(
                "expected Unknown preserving mnemonic ({}); got {:?}",
                last_op_mnem(&out),
                other
            ),
        }
    }

    #[test]
    fn real_arm64_binary_entry_lift_no_panic() {
        // End-to-end smoke against the committed ARM64 sample.
        let sample = std::path::Path::new(
            "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
        );
        if !sample.exists() {
            eprintln!("sample missing: {}", sample.display());
            return;
        }
        let data = std::fs::read(sample).expect("read sample");
        let info = crate::analysis::entry::detect_entry(&data).expect("detect entry");
        let foff = info.file_offset.expect("file offset");
        let window = &data[foff..(foff + 128).min(data.len())];
        let ops = lift_bytes(window, info.entry_va);
        assert!(!ops.is_empty(), "no LLIR produced");
        // A compiled C entry invariably contains a call or branch within 128
        // bytes.
        assert!(
            ops.iter().any(|i| matches!(
                &i.op,
                Op::Call { .. } | Op::Jump { .. } | Op::CondJump { .. } | Op::Return
            )),
            "expected some control-flow op in {:#?}",
            ops
        );
    }

    /// `subs` must produce the arithmetic *and* the flags of `cmp`.
    ///
    /// Dropping it did more damage than losing one instruction: the flag it
    /// fails to define leaves its reader bound to a stale earlier definition,
    /// so a stack-canary branch in a stripped AArch64 function tested a
    /// comparison from the top of the body.
    #[test]
    fn subs_sets_both_the_result_and_the_compare_flags() {
        // subs x0, x1, x2  ->  0xeb020020
        let out = lift_bytes(&0xeb020020u32.to_le_bytes(), 0x1000);
        assert!(
            !out.iter().any(|i| matches!(&i.op, Op::Unknown { .. })),
            "subs still lifts to Unknown: {:?}",
            out.iter().map(|i| &i.op).collect::<Vec<_>>()
        );
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, Op::Bin { op: BinOp::Sub, .. })),
            "subs lost its subtraction"
        );
        let z = out.iter().any(|i| {
            matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    ..
                }
            )
        });
        assert!(z, "subs did not define ZF as an equality compare");
        // The flags must be the *operand* comparison, exactly as `cmp` emits,
        // so a reader cannot tell which instruction produced them.
        let carry = out.iter().any(|i| {
            matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::C),
                    op: CmpOp::Ult,
                    ..
                }
            )
        });
        assert!(carry, "subs did not define CF");
    }

    /// `adds` claims only zero/sign, never carry or overflow — those depend on
    /// width and signedness this lifter does not model, and a wrong flag is
    /// worse than an absent one because a branch will render it.
    #[test]
    fn adds_claims_only_the_flags_it_can_prove() {
        // adds x0, x1, x2  ->  0xab020020
        let out = lift_bytes(&0xab020020u32.to_le_bytes(), 0x1000);
        assert!(
            out.iter()
                .any(|i| matches!(&i.op, Op::Bin { op: BinOp::Add, .. })),
            "adds lost its addition"
        );
        assert!(
            out.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    ..
                }
            )),
            "adds did not define ZF"
        );
        assert!(
            !out.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::C),
                    ..
                }
            )),
            "adds must not claim a carry flag it cannot compute"
        );
    }

    /// A 32-bit destination totally overwrites its 64-bit parent with a
    /// zero-extended value. `ssa::parent64` merges `wN` with `xN`, so without
    /// this the merge would silently claim that `and w0,w0,#0xffffff` preserves
    /// bits 32..63 of `x0` — it does not.
    #[test]
    fn a_32_bit_destination_zero_extends_its_64_bit_parent() {
        // add w0, w1, w2  ->  0x0b020020
        let out = lift_bytes(&0x0b020020u32.to_le_bytes(), 0x1000);
        assert!(
            matches!(&out[0].op, Op::Bin { dst, op: BinOp::Add, .. } if *dst == VReg::phys("w0")),
            "lost the addition: {out:#?}"
        );
        assert_eq!(
            out[1].op,
            Op::ZExt {
                dst: VReg::phys("w0"),
                src: Value::Reg(VReg::phys("w0")),
                from: Width::W32,
                to: Width::W64,
            },
            "a w-destination must zero-extend its x parent: {out:#?}"
        );
        // A 64-bit destination is already a total write and gains nothing.
        // add x0, x1, x2  ->  0x8b020020
        let wide = lift_bytes(&0x8b020020u32.to_le_bytes(), 0x1000);
        assert_eq!(
            wide.len(),
            1,
            "x-destination must not be widened: {wide:#?}"
        );
    }

    /// Because `wN` and `xN` are one SSA value, a 32-bit consumer reads the
    /// ZERO-extended parent. Any predicate or shift whose answer depends on bits
    /// above the operand width must therefore re-establish the view it needs, or
    /// `cmp w0,w1` with w0 = -1 compares 0xffffffff against w1 and branches the
    /// wrong way.
    #[test]
    fn sub_width_consumers_re_establish_the_view_they_evaluate_over() {
        // cmp w0, w1  ->  0x6b01001f
        let out = lift_bytes(&0x6b01001fu32.to_le_bytes(), 0x1000);
        let signed_sources: Vec<&Value> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::SExt {
                    src,
                    from: Width::W32,
                    to: Width::W64,
                    ..
                } => Some(src),
                _ => None,
            })
            .collect();
        assert_eq!(
            signed_sources.len(),
            2,
            "both operands of a 32-bit compare need a signed view: {out:#?}"
        );
        for (cmp_op, want_signed) in [
            (CmpOp::Slt, true),
            (CmpOp::Sle, true),
            (CmpOp::Ult, false),
            (CmpOp::Ule, false),
            (CmpOp::Eq, false),
        ] {
            let operand = out
                .iter()
                .find_map(|i| match &i.op {
                    Op::Cmp { op, lhs, .. } if *op == cmp_op => Some(lhs.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("no {cmp_op:?} flag write in {out:#?}"));
            let widener = out.iter().find(|i| {
                matches!(&i.op, Op::SExt { dst, .. } | Op::ZExt { dst, .. }
                    if Value::Reg(dst.clone()) == operand)
            });
            let is_signed = matches!(widener.map(|i| &i.op), Some(Op::SExt { .. }));
            assert_eq!(
                is_signed, want_signed,
                "{cmp_op:?} reads the wrong operand view: {out:#?}"
            );
        }
        // A 64-bit compare is already the full word and gains no widening.
        // cmp x0, x1  ->  0xeb01001f
        let wide = lift_bytes(&0xeb01001fu32.to_le_bytes(), 0x1000);
        assert_eq!(wide.len(), 5, "64-bit cmp must not widen: {wide:#?}");
    }

    /// `asr` at 32 bits must shift a SIGN-extended word and `lsr` a
    /// ZERO-extended one — the two forms are the whole point of having both.
    #[test]
    fn thirty_two_bit_right_shifts_extend_before_shifting() {
        // asr w0, w1, #4  ->  0x13047c20 ; lsr w0, w1, #4  ->  0x53047c20
        for (word, signed) in [(0x13047c20u32, true), (0x53047c20u32, false)] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            let widened = out.iter().find_map(|i| match &i.op {
                Op::SExt {
                    dst,
                    from: Width::W32,
                    ..
                } => Some((dst.clone(), true)),
                Op::ZExt {
                    dst,
                    from: Width::W32,
                    to: Width::W64,
                    ..
                } => Some((dst.clone(), false)),
                _ => None,
            });
            let (temp, was_signed) =
                widened.unwrap_or_else(|| panic!("no widening before the shift: {out:#?}"));
            assert_eq!(was_signed, signed, "wrong shift operand view: {out:#?}");
            assert!(
                out.iter().any(|i| matches!(&i.op,
                    Op::Bin { lhs: Value::Reg(lhs), .. } if *lhs == temp)),
                "the shift did not consume the widened operand: {out:#?}"
            );
        }
        // asr x0, x1, #4 -> 0x9344fc20: already the full word, nothing to widen.
        let wide = lift_bytes(&0x9344fc20u32.to_le_bytes(), 0x1000);
        assert_eq!(wide.len(), 1, "64-bit asr must not widen: {wide:#?}");
    }

    /// A sign-extending load must sign-fill its destination. Lifting `ldrsb` as
    /// a plain byte load is a silent zero-extension: `sext_i8(0xFF)` returned
    /// 255 instead of -1.
    #[test]
    fn sign_extending_loads_sign_fill_their_destination() {
        // ldrsb w0,[sp,#31] -> 0x39c07fe0 ; ldrsh w0,[sp,#30] -> 0x79c03fe0
        // ldrsw x0,[sp,#28] -> 0xb9801fe0   (assembled, not hand-derived)
        for (word, bytes, to) in [
            (0x39c07fe0u32, 8u16, Width::W32),
            (0x79c03fe0u32, 16, Width::W32),
            (0xb9801fe0u32, 32, Width::W64),
        ] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            let Op::Load { dst: loaded, addr } = &out[0].op else {
                panic!("expected a load: {out:#?}");
            };
            assert_eq!(
                u16::from(addr.size) * 8,
                bytes,
                "wrong access size: {out:#?}"
            );
            assert!(
                out.iter().any(|i| matches!(&i.op,
                    Op::SExt { src: Value::Reg(src), from, to: t, .. }
                        if src == loaded && from.bits() == bytes && *t == to)),
                "no sign extension after a signed load: {out:#?}"
            );
        }
        // The unsigned sibling must NOT sign-extend.
        // ldrb w0,[sp,#31] -> 0x39407fe0
        let unsigned = lift_bytes(&0x39407fe0u32.to_le_bytes(), 0x1000);
        assert!(
            !unsigned.iter().any(|i| matches!(&i.op, Op::SExt { .. })),
            "ldrb must not sign-extend: {unsigned:#?}"
        );
    }

    /// An unsigned narrow load zero-fills the rest of its destination register.
    /// Keeping only the byte-sized memory access leaves the C renderer free to
    /// interpret a zero-offset dereference as signed `char`, which changes every
    /// value above 0x7f even though AArch64 `LDRB` cannot produce that result.
    #[test]
    fn narrow_unsigned_loads_zero_fill_their_destination() {
        // ldrb w0,[sp,#31] -> 0x39407fe0 (assembled, not hand-derived)
        let out = lift_bytes(&0x39407fe0u32.to_le_bytes(), 0x1000);
        let Op::Load { dst: loaded, addr } = &out[0].op else {
            panic!("expected a load: {out:#?}");
        };
        assert_eq!(addr.size, 1, "wrong access size: {out:#?}");
        assert!(
            out.iter().any(|instruction| matches!(
                &instruction.op,
                Op::ZExt {
                    src: Value::Reg(src),
                    from: Width::W8,
                    to: Width::W32,
                    ..
                } if src == loaded
            )),
            "LDRB did not zero-fill W0 from the loaded byte: {out:#?}"
        );
        assert!(
            !out.iter()
                .any(|instruction| matches!(instruction.op, Op::SExt { .. })),
            "LDRB must not sign-extend: {out:#?}"
        );
    }

    /// `xzr`/`wzr` read as zero. Treating them as ordinary registers made
    /// `str wzr,[sp,#24]` — how gcc zeroes a local — store an undefined value.
    #[test]
    fn the_zero_register_reads_as_a_constant_zero() {
        // str wzr,[sp,#24] -> 0xb9001bff
        let out = lift_bytes(&0xb9001bffu32.to_le_bytes(), 0x1000);
        assert!(
            matches!(
                &out[0].op,
                Op::Store {
                    src: Value::Const(0),
                    ..
                }
            ),
            "wzr must store a literal zero: {out:#?}"
        );
    }

    /// Every mnemonic below appears in the AArch64 fixture corpus and used to
    /// lift to `Op::Unknown`, which severs the def-use chain of whatever it
    /// wrote. The words are what `aarch64-linux-gnu-as` assembles, not
    /// hand-derived encodings.
    #[test]
    fn the_scalar_mnemonics_the_corpus_uses_all_lift() {
        let program: &[(u32, &str)] = &[
            (0xd503245f, "bti c"),
            (0x7a40c824, "ccmp w1,#0,#4,gt"),
            (0x7a42a024, "ccmp w1,w2,#4,ge"),
            (0xba401822, "ccmn x1,#0,#2,ne"),
            (0x9ac20c20, "sdiv x0,x1,x2"),
            (0x1ac20820, "udiv w0,w1,w2"),
            (0x9b028c20, "msub x0,x1,x2,x3"),
            (0x1b02fc20, "mneg w0,w1,w2"),
            (0x9b427c20, "smulh x0,x1,x2"),
            (0x9bc27c20, "umulh x0,x1,x2"),
            (0x9ba27c20, "umull x0,w1,w2"),
            (0x9b227c20, "smull x0,w1,w2"),
            (0x9b220c20, "smaddl x0,w1,w2,x3"),
            (0x9ba28c20, "umsubl x0,w1,w2,x3"),
            (0x9b228c20, "smsubl x0,w1,w2,x3"),
            (0x531d3020, "ubfiz w0,w1,#3,#13"),
            (0x131d3020, "sbfiz w0,w1,#3,#13"),
            (0x13042c20, "sbfx w0,w1,#4,#8"),
            (0x13811c20, "ror w0,w1,#7"),
            (0x1ac22c20, "ror w0,w1,w2"),
            // `extr Rd,Rn,Rn,#lsb` IS the rotate — the assembler emits this very
            // word for it, and capstone spells it `ror`.
            (0x93c11c20, "ror x0,x1,#7"),
            (0x13001c20, "sxtb w0,w1"),
            (0x13003c20, "sxth w0,w1"),
            (0x93401c20, "sxtb x0,w1"),
            (0x53001c20, "uxtb w0,w1"),
            (0x53003c20, "uxth w0,w1"),
            (0xaa2103e0, "mvn x0,x1"),
            (0x9a820420, "csinc x0,x1,x2,eq"),
            (0xda820020, "csinv x0,x1,x2,eq"),
            (0xda820420, "csneg x0,x1,x2,eq"),
            (0x5a811420, "cneg w0,w1,eq"),
            (0x5a9f03e0, "csetm w0,ne"),
            (0xdac00c20, "rev x0,x1"),
            (0x10000000, "adr x0,."),
        ];
        for (word, text) in program {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            assert!(!out.is_empty(), "{text} produced nothing");
            let holes: Vec<&str> = out
                .iter()
                .filter_map(|i| match &i.op {
                    Op::Unknown { mnemonic } => Some(mnemonic.as_str()),
                    _ => None,
                })
                .collect();
            assert!(holes.is_empty(), "{text} still lifts to Unknown: {holes:?}");
        }
        // `extr` with two DIFFERENT sources is a double-word extract this IR
        // cannot express, and must stay unlifted rather than be approximated.
        let general = lift_bytes(&0x93c21c20u32.to_le_bytes(), 0x1000); // extr x0,x1,x2,#7
        assert!(
            general.iter().any(|i| matches!(&i.op, Op::Unknown { .. })),
            "extr with distinct sources must not be guessed at: {general:#?}"
        );
    }

    /// CLZ's input width is part of its value, and the destination must be
    /// defined even for zero (`clz(0) == width`). Leaving it opaque made GCC's
    /// optimized `32 - clz(x)` bit-length idiom read an uninitialized local.
    #[test]
    fn clz_lifts_to_the_shared_width_aware_intrinsic() {
        for (word, width, name, dst, src) in [
            (0x5ac01002u32, Width::W32, "aarch64.clz.32", "w2", "w0"),
            (0xdac01002u32, Width::W64, "aarch64.clz.64", "x2", "x0"),
        ] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            assert!(
                out.iter().any(|instruction| matches!(
                    &instruction.op,
                    Op::Intrinsic {
                        name: actual_name,
                        ins,
                        outs,
                        reads_mem: false,
                        writes_mem: false,
                    } if actual_name == name
                        && ins == &[Value::Reg(VReg::phys(src))]
                        && outs == &[(VReg::phys(dst), width)]
                )),
                "CLZ did not retain its operand width and destination: {out:#?}"
            );
        }
    }

    /// A rotate has to be exact at both ends: the amount is masked to the
    /// operand width, and the complementary shift is masked too, or a
    /// register-form rotate by zero shifts by the full width — undefined in C
    /// and a different answer than the CPU gives.
    #[test]
    fn rotate_right_is_exact_including_a_zero_amount() {
        // ror w0, w1, #7  ->  0x13811c20
        let immediate = lift_bytes(&0x13811c20u32.to_le_bytes(), 0x1000);
        let shifts: Vec<(BinOp, i64)> = immediate
            .iter()
            .filter_map(|i| match &i.op {
                Op::Bin {
                    op: op @ (BinOp::Shr | BinOp::Shl),
                    rhs: Value::Const(c),
                    ..
                } => Some((*op, *c)),
                _ => None,
            })
            .collect();
        assert!(
            shifts.contains(&(BinOp::Shr, 7)) && shifts.contains(&(BinOp::Shl, 25)),
            "32-bit ror #7 must be >>7 | <<25: {immediate:#?}"
        );
        // ror w0, w1, w2 -> 0x1ac22c20: both the amount and its complement are
        // masked to 31 so an amount of zero stays a shift of zero.
        let register = lift_bytes(&0x1ac22c20u32.to_le_bytes(), 0x1000);
        let masks: Vec<i64> = register
            .iter()
            .filter_map(|i| match &i.op {
                Op::Bin {
                    op: BinOp::And,
                    rhs: Value::Const(c),
                    ..
                } => Some(*c),
                _ => None,
            })
            .collect();
        assert_eq!(
            masks.iter().filter(|c| **c == 31).count(),
            2,
            "both the rotate amount and its complement need masking: {register:#?}"
        );
    }

    /// REV16 reverses bytes independently inside each 16-bit lane.  It is not
    /// a full-register REV/BSWAP: 0x11223344 becomes 0x22114433.
    #[test]
    fn rev16_declares_a_halfword_lane_byte_swap() {
        // rev16 w0, w0 -> 0x5ac00400
        let out = lift_bytes(&0x5ac00400u32.to_le_bytes(), 0x1000);
        assert!(
            matches!(
                out.as_slice(),
                [
                    LlirInstr {
                        op: Op::Intrinsic {
                            name,
                            ins,
                            outs,
                            reads_mem: false,
                            writes_mem: false,
                        },
                        ..
                    },
                    LlirInstr {
                        op: Op::ZExt {
                            from: Width::W32,
                            to: Width::W64,
                            ..
                        },
                        ..
                    }
                ] if name == "byte_swap_16_lanes"
                    && ins == &[Value::Reg(VReg::phys("w0"))]
                    && outs == &[(VReg::phys("w0"), Width::W32)]
            ),
            "REV16 must retain its lane-local byte order semantics: {out:#?}"
        );
    }

    #[test]
    fn load_pair_snapshots_an_aliased_address_base() {
        // GCC 15 -O2 `rb_validate`:
        //   ldp w4, w5, [x4, #4]
        // Both loads address the OLD x4. Lowering them sequentially without a
        // snapshot makes the first w4 destination redirect the second load.
        let out = lift_bytes(&0x29409484u32.to_le_bytes(), 0x8c0);
        let snapshot = out.iter().find_map(|instruction| match &instruction.op {
            Op::Assign {
                dst,
                src: Value::Reg(src),
            } if *src == VReg::phys("x4") => Some(dst.clone()),
            _ => None,
        });
        let snapshot = snapshot.expect("aliased pair load did not preserve its old base");
        let loads: Vec<_> = out
            .iter()
            .filter_map(|instruction| match &instruction.op {
                Op::Load { dst, addr } => Some((dst.clone(), addr.base.clone(), addr.disp)),
                _ => None,
            })
            .collect();
        assert_eq!(
            loads,
            vec![
                (VReg::phys("w4"), Some(snapshot.clone()), 4),
                (VReg::phys("w5"), Some(snapshot), 8),
            ],
            "pair load did not keep one pre-instruction address: {out:#?}"
        );
    }

    /// `ccmp` must produce the comparison's flags when its condition holds and
    /// the literal NZCV immediate when it does not — and it must snapshot the
    /// condition first, because every flag it writes is one the condition may
    /// read.
    #[test]
    fn conditional_compare_selects_between_a_comparison_and_its_nzcv_literal() {
        // ccmp w1, #0, #4, gt  ->  0x7a40c824. #4 = NZCV 0b0100, i.e. Z set,
        // C/N/V clear: the false arm is "equal", which is what makes gcc's
        // `a > 0 && b > 0` fail closed.
        let out = lift_bytes(&0x7a40c824u32.to_le_bytes(), 0x1000);
        assert!(
            !out.iter().any(|i| matches!(&i.op, Op::Unknown { .. })),
            "ccmp did not lift: {out:#?}"
        );
        // The condition (`gt` reads Sle inverted) is read before anything is
        // written to a flag.
        let first_flag_write = out
            .iter()
            .position(|i| matches!(def_uses(&i.op).0, Some(VReg::Flag(_))));
        let snapshot = out.iter().position(|i| {
            matches!(
                &i.op,
                Op::Assign {
                    src: Value::Reg(VReg::Flag(Flag::Sle)),
                    ..
                }
            )
        });
        assert!(
            snapshot.is_some() && snapshot < first_flag_write,
            "ccmp must snapshot its condition before overwriting flags: {out:#?}"
        );
        let selected: Vec<(Flag, Value, Value)> = out
            .iter()
            .filter_map(|i| match &i.op {
                Op::Ite {
                    dst: VReg::Flag(f),
                    t,
                    e,
                    ..
                } => Some((*f, t.clone(), e.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(selected.len(), 5, "all five predicates: {out:#?}");
        // `gt` is Sle INVERTED, so the taken arm is `e`. NZCV=4 gives ARM
        // Z=1, C=0, N=0, V=0 -> our Z=1, C(unsigned lower)=1, Ule=1, Slt=0,
        // Sle=1.
        for (flag, want) in [
            (Flag::Z, 1),
            (Flag::C, 1),
            (Flag::Ule, 1),
            (Flag::Slt, 0),
            (Flag::Sle, 1),
        ] {
            let (_, literal, computed) = selected
                .iter()
                .find(|(f, _, _)| *f == flag)
                .unwrap_or_else(|| panic!("no select for {flag:?}: {out:#?}"));
            assert_eq!(
                *literal,
                Value::Const(want),
                "{flag:?} takes the wrong NZCV literal when `gt` is false"
            );
            assert!(
                matches!(computed, Value::Reg(VReg::Temp(_))),
                "{flag:?} must take the comparison when `gt` holds"
            );
        }
    }

    /// A shifted or extended register operand must reach the operation
    /// transformed. Capstone drops `lsl #3` and `sxtw` from its operand list, so
    /// `add x0,x1,x2,lsl #3` and `add x0,x1,x2` were the same instruction to
    /// this lifter — every scaled array index was off by its element size.
    #[test]
    fn shifted_and_extended_register_operands_reach_the_operation() {
        // add x0, x1, x2, lsl #3  ->  0x8b020c20 (assembled)
        let shifted = lift_bytes(&0x8b020c20u32.to_le_bytes(), 0x1000);
        let scaled = shifted
            .iter()
            .find_map(|i| match &i.op {
                Op::Bin {
                    dst,
                    op: BinOp::Shl,
                    lhs: Value::Reg(lhs),
                    rhs: Value::Const(3),
                } if *lhs == VReg::phys("x2") => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("lsl #3 was dropped: {shifted:#?}"));
        assert!(
            shifted.iter().any(|i| matches!(&i.op,
                Op::Bin { op: BinOp::Add, rhs: Value::Reg(rhs), .. } if *rhs == scaled)),
            "the addition did not consume the shifted operand: {shifted:#?}"
        );
        // The unshifted sibling must stay a single op.
        // add x0, x1, x2  ->  0x8b020020
        let plain = lift_bytes(&0x8b020020u32.to_le_bytes(), 0x1000);
        assert_eq!(plain.len(), 1, "lsl #0 must add nothing: {plain:#?}");

        // add x0, x1, w2, sxtw #2  ->  0x8b22c820
        let extended = lift_bytes(&0x8b22c820u32.to_le_bytes(), 0x1000);
        let widened = extended
            .iter()
            .find_map(|i| match &i.op {
                Op::SExt {
                    dst,
                    src: Value::Reg(src),
                    from: Width::W32,
                    to: Width::W64,
                } if *src == VReg::phys("w2") => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("sxtw was dropped: {extended:#?}"));
        assert!(
            extended.iter().any(|i| matches!(&i.op,
                Op::Bin { op: BinOp::Shl, lhs: Value::Reg(lhs), rhs: Value::Const(2), .. }
                    if *lhs == widened)),
            "the extend's `lsl #2` was dropped: {extended:#?}"
        );
        // sub x0, x1, w2, uxth  ->  0xcb222020: unsigned, from 16 bits, no shift.
        let unsigned = lift_bytes(&0xcb222020u32.to_le_bytes(), 0x1000);
        assert!(
            unsigned.iter().any(|i| matches!(
                &i.op,
                Op::ZExt {
                    from: Width::W16,
                    to: Width::W64,
                    ..
                }
            )),
            "uxth was dropped or claimed signed: {unsigned:#?}"
        );
        // cmp x1, w2, sxtw  ->  0xeb22c03f: the alias carries a modifier too.
        let compare = lift_bytes(&0xeb22c03fu32.to_le_bytes(), 0x1000);
        assert!(
            compare.iter().any(|i| matches!(
                &i.op,
                Op::SExt {
                    from: Width::W32,
                    ..
                }
            )),
            "cmp dropped its extended operand: {compare:#?}"
        );
    }

    /// A register-offset load scales its index by the access size when the `S`
    /// bit is set, and widens a 32-bit index first. Both were dropped: the scale
    /// arrived as 0, which every consumer reads as 1.
    #[test]
    fn register_offset_addressing_keeps_its_scale_and_index_extension() {
        // ldr x0, [x1, x2, lsl #3]  ->  0xf8627820 (assembled)
        let scaled = lift_bytes(&0xf8627820u32.to_le_bytes(), 0x1000);
        assert!(
            scaled.iter().any(|i| matches!(&i.op,
                Op::Load { addr: MemOp { scale: 8, index: Some(index), size: 8, .. }, .. }
                    if *index == VReg::phys("x2"))),
            "the 8-byte element scale was dropped: {scaled:#?}"
        );
        // ldr x0, [x1, x2]  ->  0xf8626820: S clear, so no scaling.
        let unscaled = lift_bytes(&0xf8626820u32.to_le_bytes(), 0x1000);
        assert!(
            unscaled.iter().any(|i| matches!(
                &i.op,
                Op::Load {
                    addr: MemOp { scale: 1, .. },
                    ..
                }
            )),
            "an unscaled index must not be scaled: {unscaled:#?}"
        );
        // ldr w0, [x1, w2, sxtw #2]  ->  0xb862d820
        let widened = lift_bytes(&0xb862d820u32.to_le_bytes(), 0x1000);
        let index = widened
            .iter()
            .find_map(|i| match &i.op {
                Op::SExt {
                    dst,
                    src: Value::Reg(src),
                    from: Width::W32,
                    to: Width::W64,
                } if *src == VReg::phys("w2") => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("sxtw index was dropped: {widened:#?}"));
        assert!(
            widened.iter().any(|i| matches!(&i.op,
                Op::Load { addr: MemOp { scale: 4, index: Some(used), .. }, .. }
                    if *used == index)),
            "the load did not use the widened index: {widened:#?}"
        );
        // str x0, [x1, x2, lsl #3]  ->  0xf8227820
        let store = lift_bytes(&0xf8227820u32.to_le_bytes(), 0x1000);
        assert!(
            store.iter().any(|i| matches!(
                &i.op,
                Op::Store {
                    addr: MemOp { scale: 8, .. },
                    ..
                }
            )),
            "stores need the same scaling as loads: {store:#?}"
        );
    }

    /// `cmn` and `tst` must DEFINE the flags they set. Only modelling them as an
    /// opaque intrinsic left the following `cset`/`csinv` bound to a stale
    /// earlier comparison — the exact stale-flag failure this file warns about.
    #[test]
    fn cmn_and_tst_define_the_flags_they_set() {
        // tst w0, w1  ->  0x6a01001f
        let tst = lift_bytes(&0x6a01001fu32.to_le_bytes(), 0x1000);
        let anded = tst
            .iter()
            .find_map(|i| match &i.op {
                Op::Bin {
                    dst,
                    op: BinOp::And,
                    ..
                } => Some(dst.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("tst lost its conjunction: {tst:#?}"));
        assert!(
            tst.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::Z),
                    op: CmpOp::Eq,
                    ..
                }
            )),
            "tst did not define ZF: {tst:#?}"
        );
        // The sign test must be taken at the OPERAND width. The conjunction
        // lives in a 64-bit temporary, so testing it directly would report every
        // negative 32-bit result as positive.
        assert!(
            tst.iter().any(|i| matches!(&i.op,
                Op::SExt { src: Value::Reg(src), from: Width::W32, to: Width::W64, .. }
                    if *src == anded)),
            "tst tested the sign of a 64-bit container: {tst:#?}"
        );
        // A logical operation provably clears ARM's C and V.
        for flag in [Flag::C, Flag::Ule] {
            assert!(
                tst.iter().any(|i| matches!(&i.op,
                    Op::Assign { dst: VReg::Flag(f), src: Value::Const(1) } if *f == flag)),
                "tst left {flag:?} to a stale definition: {tst:#?}"
            );
        }

        // cmn w0, #1  ->  0x3100041f is `cmp w0, #-1`, and gets the FULL
        // comparison flag set because the two are the same operation.
        let immediate = lift_bytes(&0x3100041fu32.to_le_bytes(), 0x1000);
        let flags: Vec<Flag> = immediate
            .iter()
            .filter_map(|i| match &i.op {
                Op::Cmp {
                    dst: VReg::Flag(f), ..
                } => Some(*f),
                _ => None,
            })
            .collect();
        for want in [Flag::Z, Flag::C, Flag::Ule, Flag::Slt, Flag::Sle] {
            assert!(
                flags.contains(&want),
                "cmn #imm must set {want:?} exactly: {immediate:#?}"
            );
        }
        assert!(
            immediate.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    rhs: Value::Const(-1),
                    ..
                }
            )),
            "cmn #1 must compare against -1: {immediate:#?}"
        );
        // The register form claims only what `adds` claims — never a carry.
        // cmn w0, w1 -> 0x2b01001f
        let register = lift_bytes(&0x2b01001fu32.to_le_bytes(), 0x1000);
        assert!(
            !register.iter().any(|i| matches!(
                &i.op,
                Op::Cmp {
                    dst: VReg::Flag(Flag::C),
                    ..
                }
            )),
            "the register cmn must not claim a carry it cannot compute: {register:#?}"
        );
    }

    /// `subs Rd, Rn, Rm` where Rd IS Rn must compare the operands the CPU
    /// compared, not the value it just wrote over one of them.
    ///
    /// This is gcc's stack-canary epilogue (`subs x3, x3, x2; b.eq ok`). Reading
    /// the flags off the updated register turned it into
    /// `(saved - current) == current`, so every protected function took the
    /// `__stack_chk_fail` branch.
    #[test]
    fn a_flag_setting_subtract_compares_its_operands_not_its_result() {
        // subs x3, x3, x2  ->  0xeb020063
        let out = lift_bytes(&0xeb020063u32.to_le_bytes(), 0x1000);
        let write = out
            .iter()
            .position(|i| {
                matches!(&i.op, Op::Bin { dst, op: BinOp::Sub, .. }
                if *dst == VReg::phys("x3"))
            })
            .expect("subs lost its subtraction");
        let equality = out
            .iter()
            .position(|i| {
                matches!(
                    &i.op,
                    Op::Cmp {
                        dst: VReg::Flag(Flag::Z),
                        ..
                    }
                )
            })
            .expect("subs did not define ZF");
        assert!(
            equality < write,
            "the flags must be taken before the destination is overwritten: {out:#?}"
        );
        assert!(
            out.iter().any(|i| matches!(&i.op,
                Op::Cmp { dst: VReg::Flag(Flag::Z), lhs: Value::Reg(l), rhs: Value::Reg(r), .. }
                    if *l == VReg::phys("x3") && *r == VReg::phys("x2"))),
            "ZF must compare the two source operands: {out:#?}"
        );
    }

    /// Pointer authentication is already modelled as a zero-output intrinsic,
    /// so it is transparent to dataflow. Pinned here because the `/* asm: */`
    /// text it renders reads like an unlifted instruction and was miscounted as
    /// one — 85 of 302 apparent AArch64 gaps were this rendering, not a gap.
    #[test]
    fn pointer_authentication_is_dataflow_transparent() {
        for (name, word) in [("paciasp", 0xd503233fu32), ("autiasp", 0xd50323bfu32)] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            assert!(
                out.iter().all(|i| !matches!(&i.op, Op::Unknown { .. })),
                "{name} lifts to Unknown"
            );
            assert!(
                out.iter()
                    .all(|i| !matches!(&i.op, Op::Intrinsic { outs, .. } if !outs.is_empty())),
                "{name} must not claim to define a value"
            );
        }
    }

    /// `181_compensated_summation:compensation_of_step` at `gcc -O2` on
    /// AArch64 is three instructions and no memory:
    ///
    ///     fadd d31, d0, d1
    ///     fsub d0, d31, d0
    ///     fsub d0, d0, d1
    ///     ret
    ///
    /// Every AArch64 scalar floating-point instruction used to lift to
    /// `Op::Unknown` — no definition, no use, no register footprint at all —
    /// so the recovered C was `return arg0;` with all three dropped to
    /// `/* asm: */` comments. It was one of 20 aarch64-only fixture failures
    /// whose recovered body still names a dropped scalar FP mnemonic.
    #[test]
    fn scalar_double_arithmetic_carries_its_exact_register_footprint() {
        let out = lift_bytes(
            &[
                0x1f, 0x28, 0x61, 0x1e, // fadd d31, d0, d1
                0xe0, 0x3b, 0x60, 0x1e, // fsub d0, d31, d0
                0x00, 0x38, 0x61, 0x1e, // fsub d0, d0, d1
            ],
            0x768,
        );
        let observed: Vec<_> = out
            .iter()
            .map(|instruction| match &instruction.op {
                Op::Intrinsic {
                    name, ins, outs, ..
                } => (name.clone(), ins.clone(), outs.clone()),
                other => panic!("scalar FP arithmetic did not lift: {other:#?}"),
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (
                    "vadd.f64".to_string(),
                    vec![Value::Reg(VReg::phys("d0")), Value::Reg(VReg::phys("d1"))],
                    vec![(VReg::phys("d31"), Width::W64)],
                ),
                (
                    "vsub.f64".to_string(),
                    vec![Value::Reg(VReg::phys("d31")), Value::Reg(VReg::phys("d0"))],
                    vec![(VReg::phys("d0"), Width::W64)],
                ),
                (
                    "vsub.f64".to_string(),
                    vec![Value::Reg(VReg::phys("d0")), Value::Reg(VReg::phys("d1"))],
                    vec![(VReg::phys("d0"), Width::W64)],
                ),
            ],
            "the names must be ARM32's `.f64` spellings, which \
             `ast::scalar_float_intrinsic` already lowers to C arithmetic"
        );
    }

    /// `fmov` spans two unrelated operations. Between two floating-point
    /// registers it is the conversion-free move this lowering models; with a
    /// general-purpose register on either end it is a BIT reinterpretation that
    /// `packed::scalar_fmov` owns, and claiming it here would silently turn a
    /// reinterpreted integer into a float value.
    #[test]
    fn only_the_float_to_float_fmov_becomes_a_scalar_move() {
        let float_to_float = lift_bytes(&0x1e604000u32.to_le_bytes(), 0x1000); // fmov d0, d0
        assert!(
            matches!(&float_to_float[0].op, Op::Intrinsic { name, outs, .. }
                if name == "vmov.f64" && outs == &[(VReg::phys("d0"), Width::W64)]),
            "fmov d0,d0 must be a scalar move: {float_to_float:#?}"
        );

        // `fmov w0, s31` — the lane extraction `packed::scalar_fmov` lowers.
        let float_to_general = lift_bytes(&0x1e2603e0u32.to_le_bytes(), 0x1000);
        assert!(
            !float_to_general.iter().any(
                |instruction| matches!(&instruction.op, Op::Intrinsic { name, .. }
                    if name.starts_with("vmov"))
            ),
            "a float-to-general fmov is a bit reinterpretation, not a scalar \
             move: {float_to_general:#?}"
        );
    }

    /// `173_float_int_conversions:widen_int_to_float` is `return (float)value;`
    /// and at `gcc -O0` on AArch64 it is `scvtf s31, s31` — the SIMD form,
    /// which reads `s31` as a 32-bit SIGNED INTEGER and writes it back as
    /// binary32. Dropping it left the integer's bits in a float register, and
    /// the renderer then spelled the only thing that remained true: a
    /// reinterpreting `union { unsigned int bits; float value; }`, which is
    /// `*(float *)&value`, not `(float)value`.
    #[test]
    fn signed_integer_to_float_conversions_name_both_ends() {
        for (word, expected, width) in [
            (0x5e21dbffu32, "vcvt.f32.s32", Width::W32), // scvtf s31, s31
            (0x5e61dbffu32, "vcvt.f64.s64", Width::W64), // scvtf d31, d31
        ] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            let [instruction] = out.as_slice() else {
                panic!("expected one op: {out:#?}");
            };
            match &instruction.op {
                Op::Intrinsic {
                    name, ins, outs, ..
                } => {
                    assert_eq!(name, expected);
                    assert_eq!(ins.len(), 1, "a conversion reads exactly one value");
                    assert_eq!(outs.len(), 1);
                    assert_eq!(outs[0].1, width);
                }
                other => panic!("{expected} did not lift: {other:#?}"),
            }
        }
    }

    /// The unsigned conversions must NOT be lifted: `ast::ScalarType` cannot
    /// say "unsigned", so the only available spelling is the signed neighbour,
    /// which disagrees for every value above the signed maximum — the exact
    /// disagreement `truncate_to_unsigned` exists to catch. An opaque comment
    /// is a visible gap; a wrong cast that type-checks is not.
    #[test]
    fn unsigned_conversions_stay_opaque_rather_than_render_a_signed_cast() {
        for (name, word) in [
            ("ucvtf", 0x7e21d800u32),  // ucvtf s0, s0
            ("fcvtzu", 0x7ea1b800u32), // fcvtzu s0, s0
        ] {
            let out = lift_bytes(&word.to_le_bytes(), 0x1000);
            assert!(
                out.iter().all(|instruction| !matches!(
                    &instruction.op,
                    Op::Intrinsic { name, .. } if name.starts_with("vcvt")
                )),
                "{name} must not acquire a signed meaning: {out:#?}"
            );
        }
    }
}
