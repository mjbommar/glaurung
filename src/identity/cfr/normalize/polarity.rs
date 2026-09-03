//! Pass (e): comparison-polarity canonicalisation.
//!
//! # The rule
//!
//! A predicate and its consumer between them choose a polarity, and the choice
//! is the compiler's rather than the program's. `if (a == b) X; else Y;`
//! compiles to `cmp; je X` or to `cmp; jne Y` depending on which arm the
//! optimiser decided to fall through into, and the two produce different
//! comparison operators for one source expression. This pass pushes every
//! consumer's inversion back into the comparison that produced the predicate,
//! so a block always reads "compute the condition, then branch on it true".
//!
//! | Consumer | Producer | After |
//! |---|---|---|
//! | `CondJump { inverted: true }` | `Cmp { Eq }` | `Cmp { Ne }`, `inverted: false` |
//! | `CondJump { inverted: true }` | `Cmp { Ult a, b }` | `Cmp { Ule b, a }`, `inverted: false` |
//! | `Un { Not }` | `Cmp { Sle a, b }` | `Cmp { Slt b, a }`, the `Not` becomes a copy |
//!
//! The negation table is total on [`CmpOp`], which is why the pass can be:
//!
//! | Operator | Negation |
//! |---|---|
//! | `Eq(a,b)` | `Ne(a,b)` |
//! | `Ne(a,b)` | `Eq(a,b)` |
//! | `Ult(a,b)` | `Ule(b,a)` |
//! | `Ule(a,b)` | `Ult(b,a)` |
//! | `Slt(a,b)` | `Sle(b,a)` |
//! | `Sle(a,b)` | `Slt(b,a)` |
//!
//! The four ordered rows swap their operands, and that swap is the part that
//! moves a feature: `Ult` and `Ule` mix **positionally** in
//! `super::super::commutativity`, so `Ule(b,a)` and `Ult(a,b)` are different
//! labels today and the same label after this pass.
//!
//! `a < b` versus `b > a` needs no rule: the IR has no greater-than operator,
//! so the lifter has already made that choice once, for every architecture.
//!
//! # Conditions
//!
//! The rewrite fires only when the predicate is defined **in the same block**,
//! by a `Cmp`, and is read exactly once in that block -- by the consumer being
//! rewritten. A predicate with a second reader would have its meaning changed
//! under that reader, and a predicate defined elsewhere is a parameter of this
//! peephole and must survive untouched.
//!
//! # Precedent
//!
//! DeepSemantic and jTrans normalise the jump token rather than the
//! comparison; BinDiff and Diaphora compare decompiler output, where the
//! front end has already picked one polarity. The nearest exact precedent is
//! Ghidra's `normalize` p-code simplification, which folds `BOOL_NEGATE`
//! into the comparison it feeds, and Binary Ninja's LLIL, which "folds flags
//! into conditionals" for the same reason.
//!
//! # Why unsound is fine here
//!
//! The single-reader test is over *this block only*. A predicate that survives
//! into a successor block -- an x86 flag read by a second `setcc`, say -- is
//! rewritten anyway, and its other reader now sees the opposite truth value.
//! The alternative is a liveness analysis, which a peephole by definition does
//! not have; the error is local, deterministic, and does not leave this
//! artifact.
//!
//! # Bound
//!
//! One backward-linked scan of the block: for each consumer, at most one walk
//! back to the producing `Cmp` and one count of the predicate's readers. No
//! rewrite can re-fire, because it clears the `inverted` flag it consumed.

use crate::ir::types::{CmpOp, LlirBlock, Op, UnOp, VReg, Value};

use super::common;

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    let mut changed = false;
    for index in 0..block.instrs.len() {
        let Some(predicate) = inverted_predicate(&block.instrs[index].op) else {
            continue;
        };
        let Some(producer) = sole_producer(block, index, &predicate) else {
            continue;
        };
        let Op::Cmp {
            op: kind, lhs, rhs, ..
        } = &block.instrs[producer].op
        else {
            continue;
        };
        let (negated, left, right) = negate(*kind, lhs.clone(), rhs.clone());
        if let Op::Cmp {
            op: kind, lhs, rhs, ..
        } = &mut block.instrs[producer].op
        {
            *kind = negated;
            *lhs = left;
            *rhs = right;
        }
        clear_inversion(&mut block.instrs[index].op);
        changed = true;
    }
    changed
}

/// The predicate register an operation reads with a *negated* polarity.
fn inverted_predicate(op: &Op) -> Option<VReg> {
    match op {
        Op::CondJump {
            cond,
            inverted: true,
            ..
        }
        | Op::CondReturn {
            cond,
            inverted: true,
        }
        | Op::CondReturnValue {
            cond,
            inverted: true,
            ..
        }
        | Op::CondStore {
            cond,
            inverted: true,
            ..
        }
        | Op::CondLoad {
            cond,
            inverted: true,
            ..
        } => Some(cond.clone()),
        Op::Un {
            op: UnOp::Not,
            src: Value::Reg(source),
            ..
        } => Some(source.clone()),
        _ => None,
    }
}

/// Turn the consumer into its non-inverted form, now that the producer carries
/// the negation.
fn clear_inversion(op: &mut Op) {
    match op {
        Op::CondJump { inverted, .. }
        | Op::CondReturn { inverted, .. }
        | Op::CondReturnValue { inverted, .. }
        | Op::CondStore { inverted, .. }
        | Op::CondLoad { inverted, .. } => *inverted = false,
        Op::Un {
            dst,
            op: UnOp::Not,
            src,
        } => {
            *op = Op::Assign {
                dst: dst.clone(),
                src: src.clone(),
            };
        }
        _ => {}
    }
}

/// The index of the `Cmp` that defined `predicate` in this block, when that
/// `Cmp` is the only definition and `consumer` is the only reader.
fn sole_producer(block: &LlirBlock, consumer: usize, predicate: &VReg) -> Option<usize> {
    let mut producer = None;
    for (index, instruction) in block.instrs.iter().enumerate().take(consumer) {
        if common::defs_of(&instruction.op).contains(predicate) {
            producer = matches!(instruction.op, Op::Cmp { .. }).then_some(index);
        }
    }
    let producer = producer?;
    let readers = block
        .instrs
        .iter()
        .enumerate()
        .filter(|(index, instruction)| {
            *index > producer && common::uses_of(&instruction.op).contains(predicate)
        })
        .count();
    (readers == 1).then_some(producer)
}

/// The negation of a comparison, with the operand swap the ordered relations
/// need.
fn negate(kind: CmpOp, lhs: Value, rhs: Value) -> (CmpOp, Value, Value) {
    match kind {
        CmpOp::Eq => (CmpOp::Ne, lhs, rhs),
        CmpOp::Ne => (CmpOp::Eq, lhs, rhs),
        CmpOp::Ult => (CmpOp::Ule, rhs, lhs),
        CmpOp::Ule => (CmpOp::Ult, rhs, lhs),
        CmpOp::Slt => (CmpOp::Sle, rhs, lhs),
        CmpOp::Sle => (CmpOp::Slt, rhs, lhs),
    }
}
