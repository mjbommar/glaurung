//! Pass (b): constant folding and copy propagation, block-local.
//!
//! # The rule
//!
//! Walk the block once, forwards, carrying an environment that maps a register
//! to the value it was last *copied* from. A use of a register the environment
//! knows is replaced by that value; an operation whose operands are then all
//! constant is evaluated and becomes an [`Op::Assign`] of the result. A
//! constant reaching a memory operand's base folds into the displacement, which
//! is where the `lea` expansion's `tmp = 0` seed goes to die.
//!
//! The environment is killed for a register whenever that register is
//! redefined, and killed entirely at a call, whose clobber set the peephole
//! does not model. A register the block reads but never defines has no entry
//! and therefore no substitution: **used-but-not-defined is a parameter**, the
//! invariant `common` states.
//!
//! # Precedent
//!
//! VexINE's named passes, verbatim: *"register promotion, redundant-write
//! elimination, copy propagation, constant propagation/folding, CSE, load-store
//! and store-store elimination"*. Copy propagation and constant folding are
//! also the first two rules of every peephole optimiser since Fraser and
//! Davidson; Glaurung's own decompiler has `ir::copy_prop` and `ir::const_fold`
//! doing the sound, global version of this for rendering. This is not that
//! code and must not become it -- see the module doc on `super`.
//!
//! # Why unsound is fine here
//!
//! Folding is done in `i64` with wrapping arithmetic regardless of the
//! destination register's real width, so `Add` of two 32-bit values that
//! overflow lands on a number the machine would not have produced. It does not
//! matter: the canonical form keeps a constant's *magnitude bucket*, not its
//! value, and both the true result and the wrapped one are `csmall` or `clarge`
//! together in every case that arises from real code. Shifts are folded only
//! when the distance is in `0..64`, because a wider one has no defined answer
//! to guess at.
//!
//! # Bound
//!
//! One forward scan of the block per invocation, and the environment only
//! shrinks or is replaced at each step, so the scan is `O(n)` in instructions
//! times `O(log n)` in the environment. The pass can enable further folding on
//! a later round (a fold makes a constant available that a subsequent copy then
//! carries), which is what the driver's round cap bounds.

use std::collections::BTreeMap;

use crate::ir::types::{BinOp, CmpOp, LlirBlock, Op, UnOp, VReg, Value, Width};

use super::common;

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    let mut env: BTreeMap<VReg, Value> = BTreeMap::new();
    let mut changed = false;

    for instruction in &mut block.instrs {
        let op = &mut instruction.op;
        changed |= substitute(op, &env);
        changed |= fold(op);
        update(op, &mut env);
    }
    changed
}

/// Replace every readable operand the environment knows.
fn substitute(op: &mut Op, env: &BTreeMap<VReg, Value>) -> bool {
    let mut changed = false;

    common::for_each_value_use_mut(op, |slot| {
        if let Value::Reg(register) = slot {
            if let Some(replacement) = env.get(register) {
                if replacement != &Value::Reg(register.clone()) {
                    *slot = replacement.clone();
                    changed = true;
                }
            }
        }
    });

    // Bare register slots -- a predicate, a memory base or index -- can only
    // take another register.
    common::for_each_reg_use_mut(op, |slot| {
        if let Some(Value::Reg(replacement)) = env.get(slot) {
            if replacement != slot {
                *slot = replacement.clone();
                changed = true;
            }
        }
    });

    // A constant base folds into the displacement, which is the only way a
    // memory operand can absorb one.
    if let Some(memop) = common::memop_of_mut(op) {
        if let Some(base) = memop.base.clone() {
            match env.get(&base) {
                Some(Value::Const(constant)) => {
                    if let Some(displacement) = memop.disp.checked_add(*constant) {
                        memop.base = None;
                        memop.disp = displacement;
                        changed = true;
                    }
                }
                Some(Value::Addr(address)) => {
                    if let Some(displacement) = memop.disp.checked_add(*address as i64) {
                        memop.base = None;
                        memop.disp = displacement;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
    }

    changed
}

/// Evaluate an operation whose operands are now all constant.
fn fold(op: &mut Op) -> bool {
    let folded = match op {
        Op::Bin {
            dst,
            op: kind,
            lhs: Value::Const(left),
            rhs: Value::Const(right),
        } => binary(*kind, *left, *right).map(|value| Op::Assign {
            dst: dst.clone(),
            src: Value::Const(value),
        }),
        Op::Un {
            dst,
            op: kind,
            src: Value::Const(operand),
        } => Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(match kind {
                UnOp::Not => !*operand,
                UnOp::Neg => operand.wrapping_neg(),
            }),
        }),
        Op::Cmp {
            dst,
            op: kind,
            lhs: Value::Const(left),
            rhs: Value::Const(right),
        } => Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(i64::from(compare(*kind, *left, *right))),
        }),
        Op::ZExt {
            dst,
            src: Value::Const(operand),
            from,
            ..
        } => Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(zero_extend(*operand, *from)),
        }),
        Op::SExt {
            dst,
            src: Value::Const(operand),
            from,
            ..
        } => Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(sign_extend(*operand, *from)),
        }),
        Op::Trunc {
            dst,
            src: Value::Const(operand),
            to,
            ..
        } => Some(Op::Assign {
            dst: dst.clone(),
            src: Value::Const(zero_extend(*operand, *to)),
        }),
        _ => None,
    };
    match folded {
        Some(replacement) => {
            *op = replacement;
            true
        }
        None => false,
    }
}

/// Record what this operation makes known, and kill what it invalidates.
fn update(op: &Op, env: &mut BTreeMap<VReg, Value>) {
    // A call's clobber set is a property of the calling convention, which a
    // peephole does not model. Forget everything rather than carry a value
    // across it.
    if matches!(op, Op::Call { .. }) {
        env.clear();
        return;
    }

    for definition in common::defs_of(op) {
        env.remove(&definition);
        // Anything that was a copy OF this register is now stale.
        let stale: Vec<VReg> = env
            .iter()
            .filter(|(_, value)| matches!(value, Value::Reg(source) if source == &definition))
            .map(|(register, _)| register.clone())
            .collect();
        for register in stale {
            env.remove(&register);
        }
    }

    if let Op::Assign { dst, src } = op {
        // Resolve through the environment at insertion time, so a lookup is
        // never a chase and the map can never hold a cycle.
        let resolved = match src {
            Value::Reg(source) => env.get(source).cloned().unwrap_or_else(|| src.clone()),
            other => other.clone(),
        };
        if resolved != Value::Reg(dst.clone()) {
            env.insert(dst.clone(), resolved);
        }
    }
}

/// Wrapping `i64` evaluation. `None` where the operation has no answer.
fn binary(kind: BinOp, left: i64, right: i64) -> Option<i64> {
    let shift =
        |distance: i64| -> Option<u32> { (0..64).contains(&distance).then_some(distance as u32) };
    Some(match kind {
        BinOp::Add => left.wrapping_add(right),
        BinOp::Sub => left.wrapping_sub(right),
        BinOp::Mul => left.wrapping_mul(right),
        BinOp::Div => {
            if right == 0 {
                return None;
            }
            left.wrapping_div(right)
        }
        BinOp::And | BinOp::LogicalAnd => left & right,
        BinOp::Or | BinOp::LogicalOr => left | right,
        BinOp::Xor => left ^ right,
        BinOp::Shl => left.wrapping_shl(shift(right)?),
        BinOp::Shr => ((left as u64).wrapping_shr(shift(right)?)) as i64,
        BinOp::Sar => left.wrapping_shr(shift(right)?),
    })
}

fn compare(kind: CmpOp, left: i64, right: i64) -> bool {
    match kind {
        CmpOp::Eq => left == right,
        CmpOp::Ne => left != right,
        CmpOp::Ult => (left as u64) < (right as u64),
        CmpOp::Ule => (left as u64) <= (right as u64),
        CmpOp::Slt => left < right,
        CmpOp::Sle => left <= right,
    }
}

fn zero_extend(value: i64, from: Width) -> i64 {
    match u32::from(from.bits()) {
        bits if bits == 0 || bits >= 64 => value,
        bits => ((value as u64) & ((1u64 << bits) - 1)) as i64,
    }
}

fn sign_extend(value: i64, from: Width) -> i64 {
    match u32::from(from.bits()) {
        bits if bits == 0 || bits >= 64 => value,
        bits => {
            let shift = 64 - bits;
            (value.wrapping_shl(shift)) >> shift
        }
    }
}
