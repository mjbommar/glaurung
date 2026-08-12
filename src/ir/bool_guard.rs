//! Late recovery of source-level relational guards from x86 inclusive-comparison
//! flag pairs.
//!
//! x86 has no "less-or-equal" flag. `jle`/`jbe` are decided by `ZF | (SF ^ OF)`
//! and `ZF | CF`, so a source-level `a <= b` (or its negation `a > b`) reaches
//! the AST as a *bitwise* disjunction of two separate comparisons. Our own flag
//! model then makes the two halves disagree cosmetically: `zf` is computed over
//! the unsigned view of the compared operands and `sf`/`of` over the signed
//! view, so a `cmp edi, 99` lifts to
//!
//! ```text
//! ((unsigned long)((unsigned int)(x)) == 99) | ((long)((int)(x)) < 99)
//! ```
//!
//! That is `x <= 99`, and rendering it literally is both unreadable and
//! type-wrong.
//!
//! # Why this is a separate late pass and not part of `const_fold`
//!
//! [`crate::ir::const_fold`] already merges this pair, but only when the two
//! comparisons are *syntactically identical* in their operands. The
//! signedness-tolerant form used to live there and was deliberately reverted in
//! `320e960` ("preserve switch comparison provenance"): merging that early
//! rewrites GCC's switch range flags into inequalities and destroys the
//! comparison ladder before [`crate::ir::switch_ladder`] can recognise it. The
//! refusal is still correct *at that point in the pipeline* and is still
//! asserted by `const_fold`'s
//! `equality_view_signedness_blocks_premature_inclusive_comparison`.
//!
//! This pass therefore runs at the very end of
//! [`crate::ir::ast::prepare_for_decbench`], after every switch recovery has had
//! its look at the unmerged ladder. Nothing downstream consumes the fused shape.
//!
//! # Why the merge is exact
//!
//! The rewrite is permitted only when each equality operand is the *same
//! expression under the same cast-width chain* as the corresponding strict
//! comparison operand, differing at most in cast signedness. A cast to width `w`
//! keeps the low `w` bytes whatever its signedness, and every widening of those
//! bytes — signed or unsigned — is injective. So
//!
//! ```text
//! zext(a) == zext(b)   <=>   trunc(a) == trunc(b)   <=>   sext(a) == sext(b)
//! ```
//!
//! and the equality half of the disjunction denotes the identical predicate in
//! either view. The strict half is kept verbatim, so *its* signedness — the one
//! that actually decides the recovered relation — is never reinterpreted.
//!
//! Differing widths, unmatched cast depth, and differing constants are all
//! rejected: `(x == 0) | ((long)((int)(x)) < 0)` is NOT merged, because the
//! equality there is a 64-bit test and the strict comparison a 32-bit one, and
//! the two only agree when the register's high half is already known clean.
//! That shape is common at `-O2`, where `test edi, edi` lifts to
//! `t = rdi & rdi; zf = (t == 0)` — the zero flag taken over the *untruncated*
//! parent register while `sf` narrows to `(long)((int)(t)) < 0`. Narrowing `zf`
//! in the lifter would make these merge too, but that is a change to x86 flag
//! semantics and belongs with the lifter, not here.
//!
//! # What it deliberately does not do
//!
//! A pair under an `== 0` polarity test is left eager. See
//! [`rewrite_expr_inner`]: recovering it forces an operand swap that loses the
//! source's operand order, and that was measured as a real recompilation
//! regression with no GED benefit to pay for it.
//!
//! Nothing here produces `&&` or `||`. A `|` between two comparisons is
//! overwhelmingly this flag pair rather than a compiler-fused short-circuit —
//! across the whole 56-cell DecBench corpus every single one of them is — so
//! recovering `||` from it would invent a basic block the source never had.
//! Genuine fused short-circuit trees are recovered by
//! `const_fold::recover_eager_boolean_guard`, which requires SETcc byte-view
//! provenance to tell the two apart.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp};

/// Rewrite `(X == Y) | (X < Y)` to `X <= Y` throughout `function`.
pub fn recover_inclusive_comparisons(function: &mut Function) {
    rewrite_body(&mut function.body);
}

fn rewrite_body(body: &mut [Stmt]) {
    for statement in body.iter_mut() {
        rewrite_stmt(statement);
    }
}

fn rewrite_stmt(statement: &mut Stmt) {
    match statement {
        Stmt::Assign { src, .. }
        | Stmt::Push { value: src }
        | Stmt::IndirectGoto { target: src } => rewrite_expr(src),
        Stmt::Store { addr, src, .. } => {
            rewrite_expr(addr);
            rewrite_expr(src);
        }
        Stmt::Call { target, args, .. } => {
            rewrite_expr(target);
            for argument in args {
                rewrite_expr(argument);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                rewrite_expr(value);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            rewrite_expr(cond);
            rewrite_body(then_body);
            if let Some(else_body) = else_body {
                rewrite_body(else_body);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            rewrite_expr(cond);
            rewrite_body(body);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            rewrite_stmt(init);
            rewrite_expr(cond);
            rewrite_stmt(step);
            rewrite_body(body);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            rewrite_expr(discriminant);
            for (_, case_body) in cases.iter_mut() {
                rewrite_body(case_body);
            }
            if let Some(default) = default {
                rewrite_body(default);
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

fn rewrite_expr(expr: &mut Expr) {
    rewrite_expr_inner(expr, true);
}

/// `merge_here` is false for the one operand of an `== 0` test.
///
/// The merge is still *correct* there — it is the same disjunction — but it is
/// not an improvement, because `CmpOp` has no `>`/`>=`. Negating the recovered
/// `a <= b` can only be spelled by swapping the operands into `b < a`, and that
/// throws away the operand order the source had: `classify`'s `if (a > b)` comes
/// back as `if (b < a)`. That is measurable, not just aesthetic — recompiling
/// `b < a` emits `cmp %edi,%esi; jl` where the original binary has
/// `cmp %esi,%edi; jg`, and `branches:gcc:O2`'s recompilation byte match fell
/// from a perfect 1.00 to 0.80 when this pass merged under `== 0` as well.
/// Leaving the eager pair keeps the operand order and costs nothing: GED is
/// identical either way, because neither spelling adds or removes a branch.
fn rewrite_expr_inner(expr: &mut Expr, merge_here: bool) {
    match expr {
        Expr::Cmp { op, lhs, rhs } => {
            let inverting = *op == CmpOp::Eq;
            let lhs_is_zero = matches!(lhs.as_ref(), Expr::Const(0));
            let rhs_is_zero = matches!(rhs.as_ref(), Expr::Const(0));
            rewrite_expr_inner(lhs, !(inverting && rhs_is_zero));
            rewrite_expr_inner(rhs, !(inverting && lhs_is_zero));
        }
        Expr::Bin { lhs, rhs, .. } => {
            rewrite_expr_inner(lhs, true);
            rewrite_expr_inner(rhs, true);
        }
        Expr::Un { src, .. } => rewrite_expr(src),
        Expr::Cast { expr: inner, .. } => rewrite_expr(inner),
        Expr::Deref { addr, .. } => rewrite_expr(addr),
        Expr::Call { target, args, .. } => {
            rewrite_expr(target);
            args.iter_mut().for_each(rewrite_expr);
        }
        Expr::FunctionTableEntry { index, .. } => rewrite_expr(index),
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            rewrite_expr(cond);
            rewrite_expr(if_true);
            rewrite_expr(if_false);
        }
        Expr::WideArithmetic { args, .. } => args.iter_mut().for_each(rewrite_expr),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }

    if merge_here {
        if let Expr::Bin {
            op: BinOp::Or,
            lhs,
            rhs,
        } = expr
        {
            if let Some(merged) = merge_flag_pair(lhs, rhs).or_else(|| merge_flag_pair(rhs, lhs)) {
                *expr = merged;
            }
        }
    }

    fold_comparison_nonzero_test(expr);
}

/// `(cmp) != 0` is `cmp`.
///
/// A merged flag pair very often sits directly under the `jne` the compiler
/// emitted for the same-polarity branch, and unwrapping it here keeps the
/// recovery complete in the untyped pipeline, which has no later `const_fold`
/// run to do it. Restricted to a bare comparison, whose value is exactly 0 or 1;
/// an arbitrary truthy integer is not.
///
/// The opposite polarity is deliberately absent: `(cmp) == 0` can only be
/// spelled by swapping the comparison's operands, and this pass exists to make
/// guards read like their source, not to reverse them. `const_fold` owns that
/// rewrite and applies it to comparisons this pass never touches.
fn fold_comparison_nonzero_test(expr: &mut Expr) {
    let Expr::Cmp {
        op: CmpOp::Ne,
        lhs,
        rhs,
    } = expr
    else {
        return;
    };
    let inner = match (lhs.as_ref(), rhs.as_ref()) {
        (inner @ Expr::Cmp { .. }, Expr::Const(0)) | (Expr::Const(0), inner @ Expr::Cmp { .. }) => {
            inner.clone()
        }
        _ => return,
    };
    *expr = inner;
}

fn merge_flag_pair(equality: &Expr, less: &Expr) -> Option<Expr> {
    let Expr::Cmp {
        op: CmpOp::Eq,
        lhs: equality_lhs,
        rhs: equality_rhs,
    } = equality
    else {
        return None;
    };
    let Expr::Cmp {
        op,
        lhs: less_lhs,
        rhs: less_rhs,
    } = less
    else {
        return None;
    };
    if !same_equality_bit_view(equality_lhs, less_lhs)
        || !same_equality_bit_view(equality_rhs, less_rhs)
    {
        return None;
    }
    let op = match op {
        CmpOp::Slt => CmpOp::Sle,
        CmpOp::Ult => CmpOp::Ule,
        _ => return None,
    };
    Some(Expr::Cmp {
        op,
        // Keep the strict comparison's view: unlike equality, its signedness
        // determines the inclusive relation being recovered.
        lhs: less_lhs.clone(),
        rhs: less_rhs.clone(),
    })
}

/// Whether two integer views denote the same equality predicate.
///
/// Signed and unsigned casts of the same width are both injective mappings of
/// that width's bit patterns, so they may render different numeric values after
/// widening while leaving *equality between two operands* unchanged. Requires
/// the same cast-width chain and the same underlying expression; differing
/// widths, unmatched cast depth, and differing constants are all rejected.
fn same_equality_bit_view(lhs: &Expr, rhs: &Expr) -> bool {
    if lhs == rhs {
        return true;
    }
    match (lhs, rhs) {
        (
            Expr::Cast {
                width: lhs_width,
                expr: lhs_inner,
                ..
            },
            Expr::Cast {
                width: rhs_width,
                expr: rhs_inner,
                ..
            },
        ) if lhs_width == rhs_width => same_equality_bit_view(lhs_inner, rhs_inner),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::VReg;

    fn reg(name: &str) -> Expr {
        Expr::Reg(VReg::phys(name))
    }

    fn view(expr: Expr, signed: bool) -> Expr {
        Expr::Cast {
            signed,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed,
                width: 4,
                expr: Box::new(expr),
            }),
        }
    }

    fn cmp(op: CmpOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Cmp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn or(lhs: Expr, rhs: Expr) -> Expr {
        Expr::Bin {
            op: BinOp::Or,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn guard(cond: Expr) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond,
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
                else_body: None,
            }],
        }
    }

    fn recovered(cond: Expr) -> Expr {
        let mut function = guard(cond);
        recover_inclusive_comparisons(&mut function);
        let Stmt::If { cond, .. } = &function.body[0] else {
            panic!("guard disappeared: {:#?}", function.body);
        };
        cond.clone()
    }

    #[test]
    fn signed_flag_pair_across_cast_views_recovers_less_equal() {
        let condition = or(
            cmp(CmpOp::Eq, view(reg("x"), false), view(reg("y"), false)),
            cmp(CmpOp::Slt, view(reg("x"), true), view(reg("y"), true)),
        );
        assert_eq!(
            recovered(condition),
            cmp(CmpOp::Sle, view(reg("x"), true), view(reg("y"), true))
        );
    }

    #[test]
    fn unsigned_flag_pair_recovers_unsigned_less_equal() {
        let condition = or(
            cmp(CmpOp::Eq, view(reg("x"), false), Expr::Const(3)),
            cmp(CmpOp::Ult, view(reg("x"), false), Expr::Const(3)),
        );
        assert_eq!(
            recovered(condition),
            cmp(CmpOp::Ule, view(reg("x"), false), Expr::Const(3))
        );
    }

    #[test]
    fn a_flag_pair_under_an_inverting_zero_test_stays_eager() {
        // `!(x <= 99)` can only be spelled `99 < x`, which loses the operand
        // order the source had. The eager pair keeps it.
        let condition = cmp(
            CmpOp::Eq,
            or(
                cmp(CmpOp::Eq, view(reg("x"), false), Expr::Const(99)),
                cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(99)),
            ),
            Expr::Const(0),
        );
        assert_eq!(recovered(condition.clone()), condition);
    }

    #[test]
    fn a_flag_pair_under_a_same_polarity_zero_test_is_recovered() {
        let condition = cmp(
            CmpOp::Ne,
            or(
                cmp(CmpOp::Eq, view(reg("x"), false), Expr::Const(99)),
                cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(99)),
            ),
            Expr::Const(0),
        );
        assert_eq!(
            recovered(condition),
            cmp(CmpOp::Sle, view(reg("x"), true), Expr::Const(99))
        );
    }

    #[test]
    fn a_nested_pair_under_an_inverting_zero_test_is_still_recovered() {
        // Only the pair that IS the zero test's operand is held back; one
        // nested inside a larger expression is not.
        let inner = or(
            cmp(CmpOp::Eq, view(reg("x"), false), Expr::Const(99)),
            cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(99)),
        );
        let condition = cmp(
            CmpOp::Eq,
            Expr::Bin {
                op: BinOp::And,
                lhs: Box::new(inner),
                rhs: Box::new(reg("mask")),
            },
            Expr::Const(0),
        );
        assert_eq!(
            recovered(condition),
            cmp(
                CmpOp::Eq,
                Expr::Bin {
                    op: BinOp::And,
                    lhs: Box::new(cmp(CmpOp::Sle, view(reg("x"), true), Expr::Const(99))),
                    rhs: Box::new(reg("mask")),
                },
                Expr::Const(0),
            )
        );
    }

    #[test]
    fn mismatched_cast_depth_is_refused() {
        // `(x == 0) | ((long)((int)(x)) < 0)`: the equality is a full-width test
        // and the strict comparison a narrowed one. They agree only when the
        // high half is already known clean, which this pass cannot prove.
        let condition = or(
            cmp(CmpOp::Eq, reg("x"), Expr::Const(0)),
            cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(0)),
        );
        assert_eq!(recovered(condition.clone()), condition);
    }

    #[test]
    fn mismatched_cast_width_is_refused() {
        let narrow = Expr::Cast {
            signed: false,
            width: 4,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 2,
                expr: Box::new(reg("x")),
            }),
        };
        let condition = or(
            cmp(CmpOp::Eq, narrow, Expr::Const(0)),
            cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(0)),
        );
        assert_eq!(recovered(condition.clone()), condition);
    }

    #[test]
    fn differing_constants_are_refused() {
        let condition = or(
            cmp(CmpOp::Eq, view(reg("x"), false), Expr::Const(4294967294)),
            cmp(CmpOp::Slt, view(reg("x"), true), Expr::Const(-2)),
        );
        assert_eq!(recovered(condition.clone()), condition);
    }

    #[test]
    fn a_general_integer_disjunction_is_not_a_flag_pair() {
        let condition = or(reg("x"), reg("y"));
        assert_eq!(recovered(condition.clone()), condition);
    }

    #[test]
    fn a_non_boolean_zero_test_is_left_alone() {
        // `(x | y) == 0` is a real bitwise test, not a boolean polarity flip.
        let condition = cmp(CmpOp::Eq, or(reg("x"), reg("y")), Expr::Const(0));
        assert_eq!(recovered(condition.clone()), condition);
    }
}
