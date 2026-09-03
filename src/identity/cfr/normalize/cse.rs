//! Pass (c): local common-subexpression elimination.
//!
//! # The rule
//!
//! Within one block, the second pure operation that computes an expression
//! already computed by an earlier one becomes a copy of that earlier result.
//! `t3 = rax + 8` after `t1 = rax + 8` becomes `t3 = t1`, and pass (b) then
//! forwards `t1` into `t3`'s users on the next round, so the duplicate
//! disappears from the graph entirely rather than being demoted to a copy.
//!
//! An expression's key is its operator plus its operand *values* -- so
//! [`Value::Reg`] by register identity, not by whatever that register holds.
//! An entry is invalidated the moment any register it mentions, or the register
//! it was computed into, is redefined. That is what makes the rewrite legal
//! inside a straight-line region without any dominance machinery: the earlier
//! result is still live at the later operation because nothing has written to
//! it or to its inputs in between.
//!
//! Only [`super::common::is_pure`] operations participate. A `Load` is
//! excluded even though it defines one register: two loads from one address
//! are the same value only if no store lies between them, which is pass (d)'s
//! question, not this one's.
//!
//! # Precedent
//!
//! VexINE lists CSE among its peephole passes. It is also the oldest
//! optimisation in the literature (Cocke 1970) and is what Alpern, Wegman and
//! Zadeck's global value numbering generalises -- the paper the foundations
//! report names as "the original quotient-the-program-by-an-equivalence
//! result". Glaurung has a 2,700-line sound implementation of that in
//! `src/ir/value_number.rs`, which is deliberately not what runs here.
//!
//! # Why unsound is fine here
//!
//! It is not, in fact, unsound: block-scoped CSE with invalidation on
//! redefinition preserves semantics. It is listed with the unsound passes
//! because it *runs alongside* them on a copy of the function that is never
//! rendered, and because its input has already been rewritten by (a) and (b),
//! whose output is not the program.
//!
//! # Bound
//!
//! One forward scan of the block. The table is a `BTreeMap` keyed by a
//! deterministic string encoding of the expression, so iteration order does
//! not depend on hashing and two runs over one function give one answer. Each
//! step performs at most one lookup and a linear invalidation over a table
//! bounded by the number of pure operations seen so far, giving `O(n^2 log n)`
//! worst case on a block of `n` instructions -- the largest block in the
//! fixture corpus is under two thousand, and the driver's round cap bounds the
//! repetition.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::ir::types::{LlirBlock, Op, VReg, Value};

use super::common;

/// Rewrite one block in place. Returns whether anything changed.
pub fn run(block: &mut LlirBlock) -> bool {
    // key -> (register holding the result, the registers the key mentions)
    let mut available: BTreeMap<String, (VReg, Vec<VReg>)> = BTreeMap::new();
    let mut changed = false;

    for instruction in &mut block.instrs {
        let op = &mut instruction.op;

        if common::is_pure(op) && !matches!(op, Op::Assign { .. }) {
            if let (Some(key), Some(destination)) = (key_of(op), definition_of(op)) {
                if let Some((source, _)) = available.get(&key) {
                    if source != &destination {
                        *op = Op::Assign {
                            dst: destination.clone(),
                            src: Value::Reg(source.clone()),
                        };
                        changed = true;
                    }
                }
            }
        }

        // Invalidate before recording: an operation that redefines one of its
        // own inputs must not leave an entry keyed on the old value.
        for written in common::defs_of(op) {
            available
                .retain(|_, (result, inputs)| result != &written && !inputs.contains(&written));
        }
        if matches!(op, Op::Call { .. }) {
            available.clear();
            continue;
        }

        if common::is_pure(op) && !matches!(op, Op::Assign { .. }) {
            if let (Some(key), Some(destination)) = (key_of(op), definition_of(op)) {
                let inputs = common::uses_of(op);
                available.entry(key).or_insert((destination, inputs));
            }
        }
    }

    changed
}

fn definition_of(op: &Op) -> Option<VReg> {
    let defs = common::defs_of(op);
    (defs.len() == 1).then(|| defs[0].clone())
}

/// A deterministic textual key for a pure expression.
///
/// The destination is deliberately absent: two operations computing one
/// expression into different registers are the point of the pass.
fn key_of(op: &Op) -> Option<String> {
    let mut key = String::new();
    match op {
        Op::Bin {
            op: kind, lhs, rhs, ..
        } => {
            let _ = write!(key, "bin:{kind:?}:");
            push_value(&mut key, lhs);
            key.push('|');
            push_value(&mut key, rhs);
        }
        Op::Un { op: kind, src, .. } => {
            let _ = write!(key, "un:{kind:?}:");
            push_value(&mut key, src);
        }
        Op::Cmp {
            op: kind, lhs, rhs, ..
        } => {
            let _ = write!(key, "cmp:{kind:?}:");
            push_value(&mut key, lhs);
            key.push('|');
            push_value(&mut key, rhs);
        }
        Op::ZExt { src, from, to, .. } => {
            let _ = write!(key, "zext:{}:{}:", from.bits(), to.bits());
            push_value(&mut key, src);
        }
        Op::SExt { src, from, to, .. } => {
            let _ = write!(key, "sext:{}:{}:", from.bits(), to.bits());
            push_value(&mut key, src);
        }
        Op::Trunc { src, from, to, .. } => {
            let _ = write!(key, "trunc:{}:{}:", from.bits(), to.bits());
            push_value(&mut key, src);
        }
        Op::Extract { src, hi, lo, .. } => {
            let _ = write!(key, "extract:{hi}:{lo}:");
            push_value(&mut key, src);
        }
        Op::Concat { hi, lo, .. } => {
            key.push_str("concat:");
            push_value(&mut key, hi);
            key.push('|');
            push_value(&mut key, lo);
        }
        Op::Ite {
            cond, t, e, width, ..
        } => {
            let _ = write!(key, "ite:{}:", width.bits());
            push_register(&mut key, cond);
            key.push('|');
            push_value(&mut key, t);
            key.push('|');
            push_value(&mut key, e);
        }
        _ => return None,
    }
    Some(key)
}

fn push_value(key: &mut String, value: &Value) {
    match value {
        Value::Reg(register) => push_register(key, register),
        Value::Const(constant) => {
            let _ = write!(key, "c{constant}");
        }
        Value::Addr(address) => {
            let _ = write!(key, "a{address:#x}");
        }
    }
}

fn push_register(key: &mut String, register: &VReg) {
    let _ = write!(key, "r{register:?}");
}
