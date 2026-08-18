//! AArch64 operand modifiers: the `lsl #3` and `sxtw` that capstone drops.
//!
//! The direct analogue of [`crate::ir::lift_arm32`]'s `shifts` child, and it
//! exists for the same reason. Capstone reports the operand *list* of an
//! AArch64 instruction but not the modifier qualifying its last source, so
//! `add x0,x1,x2,lsl #3` and `add x0,x1,x2` arrive indistinguishable and
//! `[x1, w2, sxtw #2]` arrives with the scale lost. Everything here puts that
//! back by re-reading the fixed-width instruction word and decoding the fields
//! the operand list dropped: the shifted-register and extended-register
//! data-processing forms, and the load/store register-offset index.
//!
//! Two entry points carry the whole family. [`modified_last_operand`] is the
//! only way to read a data-processing source operand without silently
//! discarding its modifier, and [`scaled_memop`] the only way to read a
//! register-offset address without losing its scale and index extension.

use crate::core::instruction::Instruction;
use crate::ir::types::*;

use super::{bin_temp, instruction_word, rotate_right_ops, signed_view, temp_for, unsigned_view};

/// A modifier applied to the last source operand of a data-processing
/// instruction before the operation sees it.
///
/// Capstone's operand list carries the register and the immediate but drops
/// `lsl #3` and `sxtw` entirely, so `add x0,x1,x2,lsl #3` and `add x0,x1,x2`
/// arrived here indistinguishable. That is a silent wrong answer wherever an
/// index is scaled or a 32-bit index widened — 320 sites across the AArch64
/// fixture corpus — so the modifier is decoded from the instruction word, the
/// same source the `movk`, `csel` and `ccmp` arms already read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandModifier {
    /// `lsl`/`lsr`/`asr`/`ror` by a constant amount.
    Shift { op: BinOp, amount: u8 },
    /// `uxtb`/`uxth`/`uxtw`/`sxtb`/`sxth`/`sxtw`, then an optional `lsl`.
    /// `uxtx`/`sxtx` on a 64-bit operand carry no extension and appear as
    /// `from: None`.
    Extend {
        from: Option<Width>,
        signed: bool,
        amount: u8,
    },
}

/// Bits 23:22 and 15:10 of the shifted-register data-processing forms
/// (ARM DDI 0487 C4.1.4): logical shifted register, and add/subtract shifted
/// register.
fn shifted_register_modifier(word: u32) -> Option<OperandModifier> {
    let amount = ((word >> 10) & 0x3f) as u8;
    let op = match (word >> 22) & 0x3 {
        0b00 => BinOp::Shl,
        0b01 => BinOp::Shr,
        0b10 => BinOp::Sar,
        // ROR is not a `BinOp`; it is expanded by `rotate_right_ops`, which the
        // caller reaches through this discriminator.
        _ => {
            return Some(OperandModifier::Shift {
                op: BinOp::Or,
                amount,
            })
        }
    };
    Some(OperandModifier::Shift { op, amount })
}

/// Bits 15:13 (`option`) and 12:10 (`imm3`) of add/subtract (extended register).
fn extended_register_modifier(word: u32) -> Option<OperandModifier> {
    let amount = ((word >> 10) & 0x7) as u8;
    if amount > 4 {
        return None; // reserved
    }
    let option = (word >> 13) & 0x7;
    let signed = option & 0b100 != 0;
    let from = match option & 0b011 {
        0b00 => Some(Width::W8),
        0b01 => Some(Width::W16),
        0b10 => Some(Width::W32),
        _ => None, // UXTX / SXTX: already the full 64-bit operand
    };
    Some(OperandModifier::Extend {
        from,
        signed,
        amount,
    })
}

/// The modifier a data-processing instruction applies to its last source
/// operand, or `None` when the encoding has no modifier field at all.
fn data_processing_modifier(word: u32) -> Option<OperandModifier> {
    match ((word >> 24) & 0x1f, (word >> 21) & 1, (word >> 22) & 0x3) {
        // Logical (shifted register). Bit 21 is the N bit here (BIC/ORN/EON),
        // not a form selector.
        (0b01010, _, _) => shifted_register_modifier(word),
        // Add/subtract (shifted register).
        (0b01011, 0, _) => shifted_register_modifier(word),
        // Add/subtract (extended register).
        (0b01011, 1, 0b00) => extended_register_modifier(word),
        _ => None,
    }
}

/// The extension and scale a load/store register-offset form applies to its
/// index (ARM DDI 0487 C4.1.5): `option` in bits 15:13, `S` in bit 12, and the
/// access size in bits 31:30 — `S` selects a shift *by the access size*, which
/// is what makes `[x1, x2, lsl #3]` an 8-byte-element array index.
fn load_store_index_modifier(word: u32) -> Option<OperandModifier> {
    let shape = (
        (word >> 27) & 0x7,
        (word >> 26) & 1,
        (word >> 24) & 0x3,
        (word >> 21) & 1,
        (word >> 10) & 0x3,
    );
    if shape != (0b111, 0, 0b00, 1, 0b10) {
        return None;
    }
    let amount = if (word >> 12) & 1 == 1 {
        ((word >> 30) & 0x3) as u8
    } else {
        0
    };
    let option = (word >> 13) & 0x7;
    Some(OperandModifier::Extend {
        from: (option & 0b011 == 0b10).then_some(Width::W32),
        signed: option & 0b100 != 0,
        amount,
    })
}

/// Materialise `modifier(value)` into a temporary, at `width`.
fn apply_modifier(
    ins: &Instruction,
    modifier: OperandModifier,
    value: Value,
    width: Width,
    out: &mut Vec<Op>,
) -> Value {
    match modifier {
        OperandModifier::Shift { amount: 0, op } if op != BinOp::Or => value,
        OperandModifier::Shift {
            op: BinOp::Or,
            amount,
        } => {
            // ROR: the only form that is not a single `Op::Bin`.
            let rotated = temp_for(ins, 20);
            let mut rotate = rotate_right_ops(
                ins,
                rotated.clone(),
                value.clone(),
                Value::Const(i64::from(amount)),
            );
            if rotate.iter().any(|op| matches!(op, Op::Unknown { .. })) {
                return value;
            }
            out.append(&mut rotate);
            Value::Reg(rotated)
        }
        OperandModifier::Shift { op, amount } => {
            let shifted = temp_for(ins, 21);
            // The same rule as a bare `lsr`/`asr`: a right shift's answer
            // depends on bits outside the operand width.
            let value = match op {
                BinOp::Sar => signed_view(value, width, temp_for(ins, 22), out),
                BinOp::Shr => unsigned_view(value, width, temp_for(ins, 22), out),
                _ => value,
            };
            out.push(bin_temp(
                shifted.clone(),
                op,
                value,
                Value::Const(i64::from(amount)),
            ));
            Value::Reg(shifted)
        }
        OperandModifier::Extend {
            from,
            signed,
            amount,
        } => {
            let value = match from {
                None => value,
                Some(from) => {
                    let extended = temp_for(ins, 23);
                    out.push(if signed {
                        Op::SExt {
                            dst: extended.clone(),
                            src: value,
                            from,
                            to: width,
                        }
                    } else {
                        Op::ZExt {
                            dst: extended.clone(),
                            src: value,
                            from,
                            to: width,
                        }
                    });
                    Value::Reg(extended)
                }
            };
            if amount == 0 {
                return value;
            }
            let shifted = temp_for(ins, 24);
            out.push(bin_temp(
                shifted.clone(),
                BinOp::Shl,
                value,
                Value::Const(i64::from(amount)),
            ));
            Value::Reg(shifted)
        }
    }
}

/// Rewrite the LAST source operand of a data-processing instruction through its
/// encoded modifier. Every shifted/extended form places it there: `add Rd,Rn,Rm,
/// <mod>`, and equally the two-operand aliases `neg Rd,Rm,<mod>`,
/// `cmp Rn,Rm,<mod>` and `mvn Rd,Rm,<mod>`.
pub(super) fn modified_last_operand(
    ins: &Instruction,
    last: Value,
    width: Width,
    out: &mut Vec<Op>,
) -> Value {
    // A modifier only ever applies to a register operand; the immediate forms
    // occupy different encodings entirely.
    if !matches!(last, Value::Reg(_)) {
        return last;
    }
    let Some(modifier) = instruction_word(ins).and_then(data_processing_modifier) else {
        return last;
    };
    apply_modifier(ins, modifier, last, width, out)
}

/// Give a register-offset memory operand the index extension and scale its
/// encoding specifies.
///
/// `[x1, x2, lsl #3]` and `[x1, x2]` reach the lifter identically, and the scale
/// arrived as `Some(0)`, which every consumer reads as 1 — so every scaled array
/// index was off by its element size. A 32-bit index (`[x1, w2, sxtw #2]`)
/// additionally needs widening before it can be added to a 64-bit base, which is
/// done into a temporary because `MemOp::index` holds a register, not an
/// expression.
pub(super) fn scaled_memop(ins: &Instruction, mut addr: MemOp, out: &mut Vec<Op>) -> MemOp {
    let Some(OperandModifier::Extend {
        from,
        signed,
        amount,
    }) = instruction_word(ins).and_then(load_store_index_modifier)
    else {
        return addr;
    };
    addr.scale = 1u8 << amount;
    let (Some(index), Some(from)) = (addr.index.clone(), from) else {
        return addr;
    };
    let widened = temp_for(ins, 25);
    out.push(if signed {
        Op::SExt {
            dst: widened.clone(),
            src: Value::Reg(index),
            from,
            to: Width::W64,
        }
    } else {
        Op::ZExt {
            dst: widened.clone(),
            src: Value::Reg(index),
            from,
            to: Width::W64,
        }
    });
    addr.index = Some(widened);
    addr
}
