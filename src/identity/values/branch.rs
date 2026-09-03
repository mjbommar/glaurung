//! Element class E2: the branch conditions, read statically off the LLIR.
//!
//! # What vSim does and what this does instead
//!
//! vSim records the boolean expression a branch tests, then splits it into the
//! symbolic part and "the comparison operator with the concrete operand" --
//! `y >= 8` becomes `(>=, 8)`. It discards the symbolic half deliberately: it
//! is already in the value set if the function computed it, and is a trivial
//! unchanged parameter if it did not.
//!
//! Two builds can spell one predicate differently (`y >= 8` and `y' > 7`), and
//! vSim handles that by *learning* a table of equivalent forms from a held-out
//! project compiled at several optimisation levels. We do not need a corpus
//! for it: over the integers `x > k` **is** `x >= k+1`, so folding every strict
//! comparison into its non-strict twin is a sound rewrite that lands both
//! spellings on one element. That is the whole of the difference, and it is a
//! simplification in our favour.
//!
//! # Why this is static and the value classes are not
//!
//! The predicate that matters is the one the *instruction* tests, not the one
//! this run's seed happened to take. Reading it off the IR makes it
//! independent of which path executed, which is what makes a condition on an
//! unexecuted branch count at all -- and it costs one pass over the blocks
//! rather than a run.

use std::collections::HashMap;

use super::fingerprint::{branch_element, BranchKind};
use crate::ir::types::{CmpOp, LlirFunction, Op, VReg, Value};

/// A comparison against a constant, before canonicalisation.
#[derive(Debug, Clone, Copy)]
struct Comparison {
    op: CmpOp,
    constant: i64,
    /// The constant was the left operand (`k OP x`), so the comparison has to
    /// be mirrored before it can be read as `x OP' k`.
    constant_on_left: bool,
}

/// The ten comparisons that exist before strict forms are folded away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

impl Relation {
    fn from(op: CmpOp) -> Self {
        match op {
            CmpOp::Eq => Relation::Eq,
            CmpOp::Ne => Relation::Ne,
            CmpOp::Ult => Relation::Ult,
            CmpOp::Ule => Relation::Ule,
            CmpOp::Slt => Relation::Slt,
            CmpOp::Sle => Relation::Sle,
        }
    }

    /// `k OP x` read as `x OP' k`.
    fn mirrored(self) -> Self {
        match self {
            Relation::Eq => Relation::Eq,
            Relation::Ne => Relation::Ne,
            Relation::Ult => Relation::Ugt,
            Relation::Ule => Relation::Uge,
            Relation::Ugt => Relation::Ult,
            Relation::Uge => Relation::Ule,
            Relation::Slt => Relation::Sgt,
            Relation::Sle => Relation::Sge,
            Relation::Sgt => Relation::Slt,
            Relation::Sge => Relation::Sle,
        }
    }

    /// The condition under which the branch is NOT taken.
    fn negated(self) -> Self {
        match self {
            Relation::Eq => Relation::Ne,
            Relation::Ne => Relation::Eq,
            Relation::Ult => Relation::Uge,
            Relation::Uge => Relation::Ult,
            Relation::Ule => Relation::Ugt,
            Relation::Ugt => Relation::Ule,
            Relation::Slt => Relation::Sge,
            Relation::Sge => Relation::Slt,
            Relation::Sle => Relation::Sgt,
            Relation::Sgt => Relation::Sle,
        }
    }

    /// Fold the strict forms into the non-strict ones over the integers.
    ///
    /// `x > k` is `x >= k+1` and `x < k` is `x <= k-1`, exactly, for both
    /// signednesses. Saturating rather than wrapping at the extremes: `x > i64::MAX`
    /// is unsatisfiable and `x >= i64::MAX` is nearly so, and an element that
    /// wrapped to the other end of the range would claim the opposite.
    fn canonical(self, constant: i64) -> (BranchKind, i64) {
        match self {
            Relation::Eq => (BranchKind::Eq, constant),
            Relation::Ne => (BranchKind::Ne, constant),
            Relation::Ule => (BranchKind::Ule, constant),
            Relation::Uge => (BranchKind::Uge, constant),
            Relation::Sle => (BranchKind::Sle, constant),
            Relation::Sge => (BranchKind::Sge, constant),
            Relation::Ult => (BranchKind::Ule, constant.saturating_sub(1)),
            Relation::Ugt => (BranchKind::Uge, constant.saturating_add(1)),
            Relation::Slt => (BranchKind::Sle, constant.saturating_sub(1)),
            Relation::Sgt => (BranchKind::Sge, constant.saturating_add(1)),
        }
    }
}

/// The branch-condition elements of one function.
///
/// One element per conditional transfer whose predicate was produced by a
/// comparison against a constant. A comparison of two registers contributes
/// nothing: there is no constant to key on, and the registers' values are
/// already in the value set if the function computed them.
pub fn branch_elements(function: &LlirFunction) -> Vec<u64> {
    let mut elements = Vec::new();
    for block in &function.blocks {
        // Flags are short-lived and block-local in practice, so the map is
        // rebuilt per block rather than threaded through the CFG. A predicate
        // computed in one block and tested in another contributes nothing,
        // which is a conservative miss rather than a wrong element.
        let mut comparisons: HashMap<VReg, Comparison> = HashMap::new();
        for instruction in &block.instrs {
            match &instruction.op {
                Op::Cmp { dst, op, lhs, rhs } => match (lhs, rhs) {
                    (Value::Const(constant), Value::Reg(_)) => {
                        comparisons.insert(
                            dst.clone(),
                            Comparison {
                                op: *op,
                                constant: *constant,
                                constant_on_left: true,
                            },
                        );
                    }
                    (Value::Reg(_), Value::Const(constant)) => {
                        comparisons.insert(
                            dst.clone(),
                            Comparison {
                                op: *op,
                                constant: *constant,
                                constant_on_left: false,
                            },
                        );
                    }
                    _ => {
                        comparisons.remove(dst);
                    }
                },
                Op::CondJump { cond, inverted, .. }
                | Op::CondReturn { cond, inverted }
                | Op::CondReturnValue { cond, inverted, .. } => {
                    if let Some(comparison) = comparisons.get(cond) {
                        elements.push(element_for(comparison, *inverted));
                    }
                }
                _ => {}
            }
        }
    }
    elements
}

fn element_for(comparison: &Comparison, inverted: bool) -> u64 {
    let mut relation = Relation::from(comparison.op);
    if comparison.constant_on_left {
        relation = relation.mirrored();
    }
    // `inverted` means "take the branch when the flag is NOT set", so the
    // condition actually tested is the negation. Keeping the taken-branch form
    // is vSim's "one condition from each pair" rule, made deterministic.
    if inverted {
        relation = relation.negated();
    }
    let (kind, constant) = relation.canonical(comparison.constant);
    branch_element(kind, constant as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{LlirBlock, LlirInstr};

    fn function(ops: Vec<Op>) -> LlirFunction {
        LlirFunction {
            entry_va: 0x1000,
            blocks: vec![LlirBlock {
                start_va: 0x1000,
                end_va: 0x1000 + 4 * ops.len() as u64,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(i, op)| LlirInstr {
                        va: 0x1000 + 4 * i as u64,
                        op,
                    })
                    .collect(),
                succs: vec![],
            }],
        }
    }

    fn flag() -> VReg {
        VReg::Flag(crate::ir::types::Flag::Z)
    }

    fn compare(op: CmpOp, constant: i64) -> Op {
        Op::Cmp {
            dst: flag(),
            op,
            lhs: Value::Reg(VReg::phys("rdi")),
            rhs: Value::Const(constant),
        }
    }

    fn jump(inverted: bool) -> Op {
        Op::CondJump {
            cond: flag(),
            target: 0x2000,
            inverted,
        }
    }

    #[test]
    fn a_comparison_against_a_register_contributes_nothing() {
        let elements = branch_elements(&function(vec![
            Op::Cmp {
                dst: flag(),
                op: CmpOp::Slt,
                lhs: Value::Reg(VReg::phys("rdi")),
                rhs: Value::Reg(VReg::phys("rsi")),
            },
            jump(false),
        ]));
        assert!(elements.is_empty());
    }

    /// The property the whole class exists for: `y >= 8` and `y > 7` are the
    /// same predicate, and two builds may spell it either way.
    #[test]
    fn strict_and_non_strict_spellings_land_on_one_element() {
        // `y >= 8`, spelled as "jump when NOT (y < 8)".
        let ge_eight = branch_elements(&function(vec![compare(CmpOp::Slt, 8), jump(true)]));
        // `y > 7`, spelled as "jump when NOT (y <= 7)".
        let gt_seven = branch_elements(&function(vec![compare(CmpOp::Sle, 7), jump(true)]));
        assert_eq!(ge_eight.len(), 1);
        assert_eq!(ge_eight, gt_seven);
    }

    #[test]
    fn a_condition_and_its_inversion_are_different_elements() {
        let taken = branch_elements(&function(vec![compare(CmpOp::Eq, 3), jump(false)]));
        let not_taken = branch_elements(&function(vec![compare(CmpOp::Eq, 3), jump(true)]));
        assert_eq!(taken.len(), 1);
        assert_ne!(taken, not_taken);
    }

    #[test]
    fn a_constant_on_the_left_is_mirrored_onto_the_right() {
        // `3 < x` spelled with the constant first, against `x > 3` spelled the
        // ordinary way. Both are `x >= 4`.
        let left = branch_elements(&function(vec![
            Op::Cmp {
                dst: flag(),
                op: CmpOp::Slt,
                lhs: Value::Const(3),
                rhs: Value::Reg(VReg::phys("rdi")),
            },
            jump(false),
        ]));
        let right = branch_elements(&function(vec![compare(CmpOp::Sle, 3), jump(true)]));
        assert_eq!(left, right);
    }

    #[test]
    fn signed_and_unsigned_comparisons_are_different_elements() {
        let signed = branch_elements(&function(vec![compare(CmpOp::Sle, 8), jump(false)]));
        let unsigned = branch_elements(&function(vec![compare(CmpOp::Ule, 8), jump(false)]));
        assert_ne!(signed, unsigned);
    }

    #[test]
    fn a_predicate_tested_twice_contributes_twice() {
        let elements = branch_elements(&function(vec![
            compare(CmpOp::Eq, 1),
            jump(false),
            jump(false),
        ]));
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0], elements[1]);
    }

    #[test]
    fn saturation_keeps_an_extreme_bound_on_its_own_side() {
        let at_max = branch_elements(&function(vec![compare(CmpOp::Sle, i64::MAX), jump(true)]));
        assert_eq!(at_max.len(), 1);
        // `x > i64::MAX` saturates to `x >= i64::MAX` rather than wrapping to
        // `x >= i64::MIN`, which would claim the opposite.
        let expected = branch_element(BranchKind::Sge, i64::MAX as u64);
        assert_eq!(at_max[0], expected);
    }
}
