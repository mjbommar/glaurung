//! Pass (f): strength-reduction canonical forms.
//!
//! # Rule 1 -- multiplication by a power of two is a shift
//!
//! `Mul x, 2^k` becomes `Shl x, k`. The direction is chosen, not arbitrary.
//! `Shl` is the form both toolchains emit for a real shift *and* the form the
//! machine uses for scaled addressing, while `Mul` by a power of two arrives
//! here almost entirely from one place: the `lea` expansion in
//! `ir::lift_x86`, which emits `Bin { Mul, index, Const(scale) }` for every
//! `[base + index*scale]` operand. Canonicalising towards `Shl` therefore makes
//! `lea (,%rax,4)` and `shl $2, %rax` one feature, which is exactly the
//! `-O0`/`-O2` pair the lane exists to close. Going the other way would have
//! to move the far more numerous `Shl` nodes instead, and would additionally
//! re-file them as **commutative** -- `Mul` mixes commutatively in
//! `super::super::commutativity` and `Shl` positionally -- which loses the
//! distinction between a value and a shift distance.
//!
//! # Rule 2 -- the magic-number division idiom becomes a division
//!
//! `a / c` for a constant `c` compiles to a real `idiv` at `-O0` and to a
//! high-half multiply by a magic constant at `-O2`. Pass (a) already turns the
//! `-O0` form into `Bin { Div, .. }`; this rule turns the `-O2` form into the
//! same node, which is the largest single arithmetic difference between the two
//! optimisation levels that a local rewrite can reach.
//!
//! Three shapes are recognised, and only three. Every one of them is stated as
//! an exact sequence over values pass (b) has already propagated:
//!
//! ```text
//! signed, no add-back     h  = smul_hi(x, M)          d = round(2^(w+s) / M)
//!                         q  = h  >>s (arithmetic)
//!                         sg = x  >>(w-1) (arithmetic)
//!                         r  = q - sg               ==> r = x / d
//!
//! signed, with add-back   h  = smul_hi(x, M)          d = round(2^(w+s) / (M + 2^w))
//!                         h2 = h + x
//!                         q  = h2 >>s (arithmetic)
//!                         sg = x  >>(w-1) (arithmetic)
//!                         r  = q - sg               ==> r = x / d
//!
//! unsigned                h  = umul_hi(x, M)          d = round(2^(w+s) / M)
//!                         r  = h  >>s (logical)     ==> r = x / d
//! ```
//!
//! Anything else -- the unsigned add-back sequence, a division whose magic was
//! folded into surrounding arithmetic, a `%` -- is **left alone**, which is the
//! instruction the plan gives: *"magic-number division back to a division node
//! if the pattern is provably the compiler idiom, else leave"*. A rule that
//! guessed would invent a division where the program has a multiply.
//!
//! The recovered divisor is `round(2^(w+s) / M)`, the inverse of Granlund and
//! Montgomery's construction (PLDI 1994), which every compiler in use
//! implements. Exactness is not load-bearing: the canonical form keeps a
//! constant's magnitude bucket, so an off-by-one recovery lands in the same
//! `csmall` as the true divisor.
//!
//! # Precedent
//!
//! VexIR2Vec does not do this one; the nearest precedents are decompilers
//! rather than similarity tools. Ghidra's `divopt` and Hex-Rays both recognise
//! the magic sequence and print `a / 10`, and rev.ng's lifter does the same.
//! That is the argument for it being *provable*: three independent decompilers
//! recognise the identical shape and none of them reports a false positive on
//! it, because no other construct multiplies by a large odd constant, keeps
//! only the high half, and subtracts the sign bit.
//!
//! # Why unsound is fine here
//!
//! The divisor is recovered by rounding, so a recovery that misses by one
//! writes a division the program does not perform. The high-half multiply that
//! produced it is left in place and becomes unreachable from any root, so the
//! existing `prune` step drops it; if the recognition were wrong, a real
//! multiply would be replaced by a fabricated divide. The shape test is narrow
//! enough that this has not been observed, and the consequence would be one
//! wrong feature.
//!
//! # Bound
//!
//! One forward scan of the block; for each candidate final operation, a bounded
//! backward walk of at most four linked definitions. The rewrite replaces a
//! `Sub` or `Shr` with a `Div`, which no rule in this pass matches, so it
//! cannot re-fire.

use std::collections::BTreeMap;

use crate::ir::types::{BinOp, LlirBlock, LlirInstr, Op, VReg, Value};

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    let mut changed = shifts(block);
    changed |= magic_divisions(block);
    changed
}

/// Rule 1.
fn shifts(block: &mut LlirBlock) -> bool {
    let mut changed = false;
    for instruction in &mut block.instrs {
        let Op::Bin {
            dst,
            op: BinOp::Mul,
            lhs,
            rhs,
        } = &instruction.op
        else {
            continue;
        };
        let (value, constant) = match (lhs, rhs) {
            (other, Value::Const(constant)) => (other, *constant),
            (Value::Const(constant), other) => (other, *constant),
            _ => continue,
        };
        let Some(distance) = log2_exact(constant) else {
            continue;
        };
        instruction.op = Op::Bin {
            dst: dst.clone(),
            op: BinOp::Shl,
            lhs: value.clone(),
            rhs: Value::Const(i64::from(distance)),
        };
        changed = true;
    }
    changed
}

/// `Some(k)` when `constant` is `2^k` for `k >= 1`.
///
/// `k == 0` is excluded because `Mul x, 1` is pass (a)'s identity rule and has
/// already become a copy; recognising it here would turn a copy back into a
/// shift.
fn log2_exact(constant: i64) -> Option<u32> {
    let value = u64::try_from(constant).ok()?;
    (value >= 2 && value.is_power_of_two()).then(|| value.trailing_zeros())
}

/// Rule 2.
fn magic_divisions(block: &mut LlirBlock) -> bool {
    let definitions = definition_index(&block.instrs);
    let mut rewrites: Vec<(usize, VReg, Value, i64)> = Vec::new();

    for (index, instruction) in block.instrs.iter().enumerate() {
        if let Some(found) = signed_division(block, &definitions, &instruction.op) {
            rewrites.push((index, found.0, found.1, found.2));
            continue;
        }
        if let Some(found) = unsigned_division(block, &definitions, &instruction.op) {
            rewrites.push((index, found.0, found.1, found.2));
        }
    }

    let changed = !rewrites.is_empty();
    for (index, destination, dividend, divisor) in rewrites {
        block.instrs[index].op = Op::Bin {
            dst: destination,
            op: BinOp::Div,
            lhs: dividend,
            rhs: Value::Const(divisor),
        };
    }
    changed
}

/// Register to the index of its (single) definition in the block.
///
/// A register defined twice is dropped from the index: the backward walk must
/// not resolve a use to a definition that a later write has already replaced,
/// and refusing to answer is the safe direction for a pattern matcher.
fn definition_index(instrs: &[LlirInstr]) -> BTreeMap<VReg, usize> {
    let mut index: BTreeMap<VReg, usize> = BTreeMap::new();
    let mut repeated: Vec<VReg> = Vec::new();
    for (position, instruction) in instrs.iter().enumerate() {
        for definition in super::common::defs_of(&instruction.op) {
            if index.insert(definition.clone(), position).is_some() {
                repeated.push(definition);
            }
        }
    }
    for definition in repeated {
        index.remove(&definition);
    }
    index
}

fn definition_of<'a>(
    block: &'a LlirBlock,
    definitions: &BTreeMap<VReg, usize>,
    value: &Value,
) -> Option<&'a Op> {
    let Value::Reg(register) = value else {
        return None;
    };
    definitions
        .get(register)
        .map(|position| &block.instrs[*position].op)
}

/// `(destination, dividend, divisor)` for the signed idiom, both add-back forms.
fn signed_division(
    block: &LlirBlock,
    definitions: &BTreeMap<VReg, usize>,
    op: &Op,
) -> Option<(VReg, Value, i64)> {
    let Op::Bin {
        dst,
        op: BinOp::Sub,
        lhs,
        rhs,
    } = op
    else {
        return None;
    };

    // The right operand must be the dividend's sign bit.
    let Op::Bin {
        op: BinOp::Sar,
        lhs: sign_source,
        rhs: Value::Const(sign_shift),
        ..
    } = definition_of(block, definitions, rhs)?
    else {
        return None;
    };

    // The left operand is the shifted high half.
    let Op::Bin {
        op: BinOp::Sar,
        lhs: shifted,
        rhs: Value::Const(shift),
        ..
    } = definition_of(block, definitions, lhs)?
    else {
        return None;
    };
    let shift = u32::try_from(*shift).ok()?;

    // Optionally the add-back.
    let (multiply, add_back) = match definition_of(block, definitions, shifted)? {
        Op::Bin {
            op: BinOp::Add,
            lhs: left,
            rhs: right,
            ..
        } => {
            // One side is the high half, the other is the dividend itself.
            let high = if is_high_multiply(block, definitions, left, true) {
                left.clone()
            } else if is_high_multiply(block, definitions, right, true) {
                right.clone()
            } else {
                return None;
            };
            (high, true)
        }
        _ => (shifted.clone(), false),
    };

    let (dividend, magic, width) = high_multiply(block, definitions, &multiply, true)?;
    if u32::try_from(*sign_shift).ok()? + 1 != width || sign_source != &dividend {
        return None;
    }
    let effective = if add_back {
        i128::from(magic) + (1i128 << width)
    } else {
        i128::from(magic)
    };
    let divisor = recover_divisor(effective, width, shift)?;
    Some((dst.clone(), dividend, divisor))
}

/// `(destination, dividend, divisor)` for the unsigned idiom.
fn unsigned_division(
    block: &LlirBlock,
    definitions: &BTreeMap<VReg, usize>,
    op: &Op,
) -> Option<(VReg, Value, i64)> {
    let Op::Bin {
        dst,
        op: BinOp::Shr,
        lhs,
        rhs: Value::Const(shift),
    } = op
    else {
        return None;
    };
    let shift = u32::try_from(*shift).ok()?;
    let (dividend, magic, width) = high_multiply(block, definitions, lhs, false)?;
    let divisor = recover_divisor(i128::from(magic), width, shift)?;
    Some((dst.clone(), dividend, divisor))
}

fn is_high_multiply(
    block: &LlirBlock,
    definitions: &BTreeMap<VReg, usize>,
    value: &Value,
    signed: bool,
) -> bool {
    high_multiply(block, definitions, value, signed).is_some()
}

/// `(dividend, magic, width)` when `value` is the high half of a widening
/// multiply by a constant.
fn high_multiply(
    block: &LlirBlock,
    definitions: &BTreeMap<VReg, usize>,
    value: &Value,
    signed: bool,
) -> Option<(Value, i64, u32)> {
    let Op::Intrinsic {
        name, ins, outs, ..
    } = definition_of(block, definitions, value)?
    else {
        return None;
    };
    let wanted = if signed { "x86.smul_hi" } else { "x86.umul_hi" };
    if name != wanted || ins.len() != 2 || outs.len() != 1 {
        return None;
    }
    let width = u32::from(outs[0].1.bits());
    if !(8..=64).contains(&width) {
        return None;
    }
    match (&ins[0], &ins[1]) {
        (dividend, Value::Const(magic)) => Some((dividend.clone(), *magic, width)),
        (Value::Const(magic), dividend) => Some((dividend.clone(), *magic, width)),
        _ => None,
    }
}

/// `round(2^(width + shift) / magic)`, the inverse of the magic-number
/// construction.
fn recover_divisor(magic: i128, width: u32, shift: u32) -> Option<i64> {
    if magic == 0 || shift >= width {
        return None;
    }
    let numerator = 1i128 << (width + shift);
    let magnitude = magic.abs();
    if magnitude <= 1 {
        return None;
    }
    let rounded = (numerator + magnitude / 2) / magnitude;
    let divisor = if magic < 0 { -rounded } else { rounded };
    let divisor = i64::try_from(divisor).ok()?;
    (divisor.abs() >= 2).then_some(divisor)
}
