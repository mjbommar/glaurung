//! ARM32 shifted-register operands and the instruction-word fields that encode
//! them.
//!
//! Capstone reports the operand *list* of an ARM32 instruction but drops the
//! shift modifier that qualifies it, so `add r0,r1,r2,lsl #3` and
//! `add r0,r1,r2` arrive here indistinguishable and `[r1,r2,lsl #2]` arrives
//! with `scale: 0`. Everything in this module exists to put that back: it
//! re-reads the raw encoding out of the instruction bytes ([`arm32_word`],
//! [`thumb32_halfwords`]) and decodes the fields the operand list lost --
//! the data-processing shift, the load/store index scale, pre-indexed
//! writeback, and the A32 modified-immediate `#<imm8>, #<rot>` pair.
//!
//! A32 and T32 encode these in unrelated field layouts, so every decoder here
//! branches on `ctx.thumb` and reads the two forms separately. The lifter
//! reaches the whole family through [`shifted_operand`], which is the only
//! way to read a data-processing source operand without silently dropping its
//! modifier.

use crate::core::instruction::{Instruction, Operand, OperandKind};
use crate::ir::types::*;

use super::{operand_to_value, resolve_pc, LiftCtx};

// ---------------------------------------------------------------------------
// Shifted register operands
// ---------------------------------------------------------------------------

/// A shift applied to a source register *before* the operation sees it.
///
/// Capstone's operand list carries the register and the immediate but drops
/// `lsl #3` and `asr #31` entirely, so `add r0,r1,r2,lsl #3` and `add r0,r1,r2`
/// arrived at the lifter indistinguishable, and `[r1,r2,lsl #2]` arrived with
/// `scale: 0`. That is a silent wrong answer wherever an index is scaled or a
/// divide-by-power-of-two is lowered — 500 sites across the armv7 fixture corpus
/// — so the modifier is decoded here from the instruction word, the same source
/// [`crate::ir::lift_arm64`] reads for the AArch64 forms. The two encodings are
/// unrelated and are decoded separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RegShift {
    pub(super) kind: ShiftKind,
    /// Shift distance in bits: 1..=32 for `lsr`/`asr`, 0..=31 otherwise.
    pub(super) amount: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ShiftKind {
    Lsl,
    Lsr,
    Asr,
    Ror,
    /// Rotate-right-with-extend: a 33-bit rotate *through the carry flag*. Not
    /// representable without a carry this lifter declines to fabricate.
    Rrx,
}

/// `DecodeImmShift` (ARM DDI 0406C A8.4.3), shared by A32 and T32: an encoded
/// shift of zero means "no shift" for `lsl`, 32 for `lsr`/`asr`, and `rrx` for
/// `ror`.
fn decode_imm_shift(kind_bits: u32, imm5: u32) -> RegShift {
    match kind_bits & 0b11 {
        0b00 => RegShift {
            kind: ShiftKind::Lsl,
            amount: imm5 as u8,
        },
        0b01 => RegShift {
            kind: ShiftKind::Lsr,
            amount: if imm5 == 0 { 32 } else { imm5 as u8 },
        },
        0b10 => RegShift {
            kind: ShiftKind::Asr,
            amount: if imm5 == 0 { 32 } else { imm5 as u8 },
        },
        _ if imm5 == 0 => RegShift {
            kind: ShiftKind::Rrx,
            amount: 1,
        },
        _ => RegShift {
            kind: ShiftKind::Ror,
            amount: imm5 as u8,
        },
    }
}

/// The two halfwords of a 32-bit Thumb-2 instruction, each little-endian.
fn thumb32_halfwords(ins: &Instruction) -> Option<(u32, u32)> {
    let b: [u8; 4] = ins.bytes.as_slice().try_into().ok()?;
    Some((
        u32::from(u16::from_le_bytes([b[0], b[1]])),
        u32::from(u16::from_le_bytes([b[2], b[3]])),
    ))
}

/// The 32-bit A32 instruction word.
pub(super) fn arm32_word(ins: &Instruction) -> Option<u32> {
    let b: [u8; 4] = ins.bytes.as_slice().try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Fold capstone's split `#<imm8>, #<rotation>` operand pair back into the one
/// constant the A32 *modified immediate* actually encodes, or `None` when this
/// instruction does not carry that pair.
///
/// A32 data-processing immediates are not 12-bit literals. The `imm12` field is
/// `rotation:imm8` and the constant is `ROR(imm8, 2 * rotation)` (ARM DDI 0406C
/// A5.2.4). Capstone folds that for you *only* when the assembler picked the
/// canonical rotation. When it did not — as the PLT stub preamble deliberately
/// does, since `add ip, pc, #0, #12` must occupy exactly one word whatever the
/// offset turns out to be — capstone declines to fold and reports the rotation
/// as one extra trailing immediate operand. So `add ip, pc, #0, #12` arrives
/// with FOUR operands and `mov r0, #0x40, #30` with THREE.
///
/// Every arity check in [`lift_one_decoded`] is written against the folded
/// shape, so the unfolded form matched nothing and fell through to
/// [`Op::Unknown`] — which `lift_function` then turns into an opaque intrinsic
/// declaring that it reads and writes all memory. That is what a register-plus-
/// constant `add` was costing: 128 of the 146 opaque intrinsics over the four
/// committed armhf samples, and every one of the 16 opaque `add`s in the
/// effect census, at 6.6% of all ARM32 LLIR against 0.18% on x86-64.
///
/// The fold is performed only when the instruction word *proves* the two
/// trailing immediates are that pair, which is three separate facts:
///
/// * The encoding is A32 data-processing (immediate): `word[27:25] == 0b001`,
///   excluding the `10xx0` block of `op1` that A5.2 reserves for the 16-bit
///   immediate loads (`movw`/`movt`, whose `imm12` is a plain literal half) and
///   for `msr`/hint. Getting this wrong would rewrite a `movw` literal.
/// * Capstone's last two operands are both immediates, and they are *equal to*
///   `word[7:0]` and `2 * word[11:8]`. A canonical fold puts the rotated value
///   in that slot instead, so this is what separates "capstone split the pair"
///   from "capstone folded it and these are two unrelated operands".
/// * The rotation is non-zero. A zero rotation encodes the value `imm8`, which
///   is the canonical encoding of every constant it can represent, so capstone
///   never splits it — and requiring this leaves no encoding where folding
///   would be a silent no-op over an operand list of unproven shape.
///
/// Anything that fails those checks is left exactly as capstone reported it,
/// which for a genuinely unrecognised form still means an honest opaque
/// intrinsic rather than a confidently wrong constant.
pub(super) fn fold_modified_immediate(ins: &Instruction, ctx: &LiftCtx) -> Option<Vec<Operand>> {
    if ctx.thumb {
        // T32 modified immediates use an unrelated encoding (`i:imm3:a:bcdefgh`,
        // DDI 0406C A6.3.2) and capstone does not report them as a pair.
        return None;
    }
    let word = arm32_word(ins)?;
    if (word >> 25) & 0x7 != 0b001 {
        return None;
    }
    if (word >> 23) & 0x3 == 0b10 && (word >> 20) & 1 == 0 {
        // op1 == 10xx0: `movw`/`movt` and `msr`/hint, not data processing.
        return None;
    }
    let rotation = (word >> 8) & 0xf;
    if rotation == 0 {
        return None;
    }
    let operands = &ins.operands;
    let last = operands.len().checked_sub(1)?;
    let base = last.checked_sub(1)?;
    let literal = immediate_operand(&operands[base])?;
    let reported_rotation = immediate_operand(&operands[last])?;
    if literal != i64::from(word & 0xff) || reported_rotation != i64::from(2 * rotation) {
        return None;
    }

    // ROR over the 32-bit value, then sign-extended through `i32` so the folded
    // constant is spelled the same way capstone spells the ones it folds itself.
    let value = (word & 0xff).rotate_right(2 * rotation) as i32;
    let mut folded = operands[..last].to_vec();
    folded[base].immediate = Some(i64::from(value));
    Some(folded)
}

/// The value of an operand that is an immediate, or `None` for anything else.
fn immediate_operand(op: &Operand) -> Option<i64> {
    if matches!(op.kind, OperandKind::Immediate) {
        op.immediate
    } else {
        None
    }
}

/// The shift a data-processing instruction applies to its last source register.
///
/// T32: "Data-processing (shifted register)", `hw1[15:9] == 0b1110101` — the
/// whole `0xEA00..=0xEBFF` block (ARM DDI 0406C A6.3, table A6-9) and nothing
/// else. The distance is `imm3:imm2` and the kind is `type` (A6.3.11).
///
/// A32: the register forms of data processing, `word[27:25] == 0b000` with
/// `word[4] == 0` (an immediate shift; `word[4] == 1` is the far rarer
/// register-shifted-register form, which is left alone rather than guessed at).
pub(super) fn data_processing_shift(ins: &Instruction, ctx: &LiftCtx) -> Option<RegShift> {
    if ctx.thumb {
        let (hw1, hw2) = thumb32_halfwords(ins)?;
        if hw1 >> 9 != 0b111_0101 {
            return None;
        }
        let imm5 = ((hw2 >> 12) & 0x7) << 2 | ((hw2 >> 6) & 0x3);
        Some(decode_imm_shift((hw2 >> 4) & 0x3, imm5))
    } else {
        let word = arm32_word(ins)?;
        if (word >> 25) & 0x7 != 0b000 || word & (1 << 4) != 0 {
            return None;
        }
        Some(decode_imm_shift((word >> 5) & 0x3, (word >> 7) & 0x1f))
    }
}

/// The `lsl` distance a register-offset load/store applies to its index, or
/// `None` when this is not a register-offset form.
///
/// T32: the register forms of "Load/store single data item"
/// (`hw1[15:9] == 0b1111100`) are picked out by `hw1[7] == 0` (not an `imm12`
/// form) together with `hw2[11:6] == 0`, which is what separates the register
/// offset from the T4 `imm8` post/pre-indexed forms. The scale is `hw2[5:4]`.
///
/// A32: `word[27:25] == 0b011` with `word[4] == 0`; the shift sits where the
/// data-processing forms keep it. Only `lsl` can scale an index usefully — the
/// architecture allows any shift here, so anything else is declined rather than
/// approximated.
pub(super) fn index_shift(ins: &Instruction, ctx: &LiftCtx) -> Option<u8> {
    if ctx.thumb {
        let (hw1, hw2) = thumb32_halfwords(ins)?;
        if hw1 >> 9 != 0b111_1100 || hw1 & (1 << 7) != 0 || hw2 & 0x0fc0 != 0 {
            return None;
        }
        Some(((hw2 >> 4) & 0x3) as u8)
    } else {
        let word = arm32_word(ins)?;
        if (word >> 25) & 0x7 != 0b011 || word & (1 << 4) != 0 {
            return None;
        }
        match decode_imm_shift((word >> 5) & 0x3, (word >> 7) & 0x1f) {
            RegShift {
                kind: ShiftKind::Lsl,
                amount,
            } if amount < u8::BITS as u8 => Some(amount),
            _ => None,
        }
    }
}

/// Does this load/store use the PRE-indexed writeback form (`[Rn, #imm]!`)?
///
/// The address is `Rn + imm` and `Rn` is then updated to it. Capstone reports
/// the same two operands as the plain offset form and keeps the writeback flag
/// in a field the shared [`Operand`] model has no room for, so the two arrived
/// here indistinguishable — and the induction variable of every pointer-walking
/// `-O2` loop never advanced. `for_sum`'s `ldr r1,[r3,#4]!` latch decompiled to
/// `while (p != end)` over a `p` that was never incremented.
///
/// T32: the `imm8` forms of "Load/store single data item"
/// (`hw1[15:9] == 0b1111100`, `hw1[7] == 0`) are marked by `hw2[11] == 1`, and
/// carry `P` at `hw2[10]` and `W` at `hw2[8]`; pre-indexed writeback is `P=1,
/// W=1`. A32: `word[27:26] == 0b01` with `P` at bit 24 and `W` at bit 21.
///
/// The POST-indexed form (`P=0`) is deliberately not matched: capstone reports
/// it as three operands with the offset separate, and the caller already has a
/// path for it.
pub(super) fn is_preindexed_writeback(ins: &Instruction, ctx: &LiftCtx) -> bool {
    if ctx.thumb {
        let Some((hw1, hw2)) = thumb32_halfwords(ins) else {
            return false;
        };
        hw1 >> 9 == 0b111_1100
            && hw1 & (1 << 7) == 0
            && hw2 & (1 << 11) != 0
            && hw2 & (1 << 10) != 0
            && hw2 & (1 << 8) != 0
    } else {
        let Some(word) = arm32_word(ins) else {
            return false;
        };
        (word >> 26) & 0x3 == 0b01 && word & (1 << 24) != 0 && word & (1 << 21) != 0
    }
}

/// The IR temporary a shifted operand is materialised into. Fixed lanes, in the
/// style of the rest of this file: the temporary is consumed by the very next op
/// the same instruction emits, so SSA renaming separates one instruction's from
/// the next's. Lanes 0 and 1 are already claimed (`bic`, `umull`, the load
/// extensions, and `make_conditional`).
pub(super) const SHIFT_TEMP: u32 = 6;

/// Materialise `value <shift>` and return the shifted value, or `None` when the
/// shift cannot be modelled (`rrx` reads the carry flag, which this lifter
/// deliberately does not fabricate — see [`flags_for_arith`]).
///
/// `ror` is expanded as `(x >> n) | (x << (32-n))` over the 32-bit value; every
/// ARM32 core register is exactly 32 bits wide, so the width is not inferred.
pub(super) fn apply_shift(shift: RegShift, value: Value, out: &mut Vec<Op>) -> Option<Value> {
    if !matches!(value, Value::Reg(_)) {
        // The shifted forms only ever shift a register; an immediate operand
        // belongs to a different encoding and must not be touched.
        return Some(value);
    }
    let amount = i64::from(shift.amount);
    let bin = |op: BinOp, lhs: Value, rhs: Value, out: &mut Vec<Op>| -> Value {
        let dst = VReg::Temp(SHIFT_TEMP);
        out.push(Op::Bin {
            dst: dst.clone(),
            op,
            lhs,
            rhs,
        });
        Value::Reg(dst)
    };
    match shift.kind {
        ShiftKind::Lsl if shift.amount == 0 => Some(value),
        ShiftKind::Lsl => Some(bin(BinOp::Shl, value, Value::Const(amount), out)),
        ShiftKind::Lsr => Some(bin(BinOp::Shr, value, Value::Const(amount), out)),
        ShiftKind::Asr => Some(bin(BinOp::Sar, value, Value::Const(amount), out)),
        ShiftKind::Ror => {
            let low = VReg::Temp(SHIFT_TEMP + 1);
            let high = VReg::Temp(SHIFT_TEMP + 2);
            out.push(Op::Bin {
                dst: low.clone(),
                op: BinOp::Shr,
                lhs: value.clone(),
                rhs: Value::Const(amount),
            });
            out.push(Op::Bin {
                dst: high.clone(),
                op: BinOp::Shl,
                lhs: value,
                rhs: Value::Const(32 - amount),
            });
            Some(bin(BinOp::Or, Value::Reg(low), Value::Reg(high), out))
        }
        ShiftKind::Rrx => None,
    }
}

/// Read operand `i` as a value and apply whatever shift the instruction word
/// encodes for it. `None` means the operand is not a value, or its shift is not
/// representable — either way the caller must fall back to [`Op::Unknown`]
/// rather than silently drop the modifier.
pub(super) fn shifted_operand(
    ins: &Instruction,
    ctx: &LiftCtx,
    i: usize,
    out: &mut Vec<Op>,
) -> Option<Value> {
    let value = resolve_pc(operand_to_value(ins.operands.get(i)?)?, ctx.pc_at(ins));
    match data_processing_shift(ins, ctx) {
        Some(shift) => apply_shift(shift, value, out),
        None => Some(value),
    }
}
