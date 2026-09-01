//! Fuse the two-comparison forms a compiler emits for one source relation.
//!
//! # The shape
//!
//! `for (i = 0; i < argc; i++)` compiles, at `-O2`, to a guard that skips the
//! loop when the trip count is not positive. The machine has no "less than or
//! equal to zero" branch, so the compiler tests the zero flag and the sign flag
//! and combines them, and lossless lifting faithfully reproduces both tests:
//!
//! ```text
//! if (((unsigned long)((unsigned int)(n)) == 0) | ((long)((int)(n)) < 0))
//! ```
//!
//! which is `n <= 0`, written as eleven tokens of flag arithmetic. Both
//! reference decompilers fold this — Ghidra 12.1.3 prints `if ((int)n < 1)`
//! and angr 9.3.3 prints `if (n > 0)` — and on a comparison of the three this
//! was the single largest readability gap in our output. It is also not
//! cosmetic: a reader who has to re-derive `n <= 0` from a disjunction of flag
//! tests is doing the decompiler's job.
//!
//! # Why this is a separate pass from `const_fold`
//!
//! The generic folder is type-independent by design. Fusing these requires
//! knowing that two *differently cast* subtrees denote the same value —
//! `(unsigned int)(n)` on one side and `(int)(n)` on the other — which is a
//! statement about how the lifter spells one machine operand, not an algebraic
//! identity. Keeping it here leaves the algebraic folder honest.
//!
//! # Soundness
//!
//! Each rule below is an equivalence over the *same* operand, and the pass
//! fires only when both sides reduce to structurally identical expressions
//! after casts are peeled. Peeling is safe here precisely because every rule
//! compares against literal zero, and zero is zero at every width and both
//! signednesses. A rule that compared against any other constant could not
//! peel a narrowing cast this way, which is why none of them do.
//!
//! Comparisons against a non-zero constant, mixed operands, and unsigned
//! relations that would need a width to be decided are all left alone.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp};

/// Fuse two-comparison guards throughout a function body.
pub fn fuse_comparisons(function: &mut Function) {
    fuse_block(&mut function.body);
}

fn fuse_block(statements: &mut Vec<Stmt>) {
    for statement in statements.iter_mut() {
        fuse_stmt(statement);
    }
}

fn fuse_stmt(statement: &mut Stmt) {
    match statement {
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            fuse_expr(cond);
            fuse_block(then_body);
            if let Some(body) = else_body.as_mut() {
                fuse_block(body);
            }
        }
        Stmt::While { cond, body } => {
            fuse_expr(cond);
            fuse_block(body);
        }
        Stmt::DoWhile { body, cond } => {
            fuse_block(body);
            fuse_expr(cond);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            fuse_stmt(init);
            fuse_expr(cond);
            fuse_stmt(step);
            fuse_block(body);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            fuse_expr(discriminant);
            for (_, body) in cases.iter_mut() {
                fuse_block(body);
            }
            if let Some(body) = default.as_mut() {
                fuse_block(body);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            fuse_block(try_body);
            for catch in catches.iter_mut() {
                fuse_block(&mut catch.body);
            }
        }
        Stmt::Assign { src, .. } => fuse_expr(src),
        Stmt::Store { addr, src, .. } => {
            fuse_expr(addr);
            fuse_expr(src);
        }
        Stmt::Call { target, args, .. } => {
            fuse_expr(target);
            for arg in args.iter_mut() {
                fuse_expr(arg);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value.as_mut() {
                fuse_expr(value);
            }
        }
        Stmt::Throw { value } | Stmt::Push { value } => fuse_expr(value),
        Stmt::IndirectGoto { target } => fuse_expr(target),
        _ => {}
    }
}

fn fuse_expr(expression: &mut Expr) {
    // Children first: an inner guard must already be fused before an outer
    // rule inspects it.
    match expression {
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fuse_expr(lhs);
            fuse_expr(rhs);
        }
        Expr::Un { src, .. } => fuse_expr(src),
        Expr::Cast { expr, .. } => fuse_expr(expr),
        _ => {}
    }
    if let Some(fused) = fused_form(expression) {
        *expression = fused;
    }
}

/// The single fused comparison equivalent to a two-comparison guard, if any.
fn fused_form(expression: &Expr) -> Option<Expr> {
    let Expr::Bin { op, lhs, rhs } = expression else {
        return None;
    };
    // `|` and `||` both appear: the lifter produces a bitwise combination of
    // two flag tests, and structuring can promote it to a logical one. Both
    // mean the same thing when each side is a 0/1-valued comparison.
    let disjunction = matches!(op, BinOp::Or | BinOp::LogicalOr);
    let conjunction = matches!(op, BinOp::And | BinOp::LogicalAnd);
    if !disjunction && !conjunction {
        return None;
    }

    let left = zero_comparison(lhs)?;
    let right = zero_comparison(rhs)?;

    // Both tests must observe the SAME VALUE AT THE SAME WIDTH. Requiring only
    // that they strip to the same expression is unsound and was measured to be
    // so: it turned eleven passing execution-differential lanes red. Given
    // 64-bit `v` holding 2^32, `v == 0` is false and `(int)v < 0` is false,
    // but the fusion `(int)v <= 0` is TRUE, because the two comparisons were
    // looking at different widths of one value.
    if !same_value(left.value, right.value) || left.width != right.width {
        return None;
    }

    // Rules are stated on the *unordered* pair, so a compiler that emits the
    // sign test first is folded identically. The second element names which
    // side's expression carries the result's signedness and width, and that
    // expression is reused VERBATIM -- casts included. Rebuilding it from the
    // stripped value is what caused the regression above.
    let (fused_op, operand) = if disjunction {
        match (left.op, right.op) {
            // (x == 0) || (x <s 0)  <=>  x <=s 0
            (CmpOp::Eq, CmpOp::Slt) => (CmpOp::Sle, right.operand),
            (CmpOp::Slt, CmpOp::Eq) => (CmpOp::Sle, left.operand),
            // (x == 0) || (x <u 0)  <=>  x <=u 0; nothing is below zero
            // unsigned, so this is just `x == 0` written uniformly.
            (CmpOp::Eq, CmpOp::Ult) => (CmpOp::Ule, right.operand),
            (CmpOp::Ult, CmpOp::Eq) => (CmpOp::Ule, left.operand),
            _ => return None,
        }
    } else {
        match (left.op, right.op) {
            // (x != 0) && (x <=s 0)  <=>  x <s 0
            (CmpOp::Ne, CmpOp::Sle) => (CmpOp::Slt, right.operand),
            (CmpOp::Sle, CmpOp::Ne) => (CmpOp::Slt, left.operand),
            _ => return None,
        }
    };

    Some(Expr::Cmp {
        op: fused_op,
        lhs: Box::new(operand.clone()),
        rhs: Box::new(Expr::Const(0)),
    })
}

/// One side of a candidate guard: `<operand> <op> 0`.
struct ZeroComparison<'a> {
    op: CmpOp,
    /// The compared expression exactly as written, casts included. This is
    /// what a fusion reuses, so the result observes the same width.
    operand: &'a Expr,
    /// The same expression with casts peeled, for operand identity.
    value: &'a Expr,
    /// The narrowest width the comparison actually observes, or `None` when
    /// no cast narrows it.
    width: Option<u8>,
}

/// Recognise `<expr> <op> 0`.
///
/// Only literal zero qualifies: see the module docs on why peeling casts for
/// the identity check is sound against zero and would not be against another
/// constant.
fn zero_comparison(expression: &Expr) -> Option<ZeroComparison<'_>> {
    let Expr::Cmp { op, lhs, rhs } = strip_casts(expression) else {
        return None;
    };
    if !is_zero(strip_casts(rhs)) {
        return None;
    }
    Some(ZeroComparison {
        op: *op,
        operand: lhs,
        value: strip_casts(lhs),
        width: observed_width(lhs),
    })
}

/// The narrowest width a cast chain exposes.
///
/// `(unsigned long)((unsigned int)(v))` observes four bytes of `v`: the outer
/// widening cannot reveal bits the inner narrowing discarded. So the innermost
/// cast decides what a comparison against zero can see, and two guards are
/// only fusable when that width agrees.
fn observed_width(expression: &Expr) -> Option<u8> {
    let mut narrowest = None;
    let mut current = expression;
    while let Expr::Cast { width, expr, .. } = current {
        narrowest = Some(narrowest.map_or(*width, |seen: u8| seen.min(*width)));
        current = expr;
    }
    narrowest
}

/// Peel cast wrappers to the underlying value.
fn strip_casts(expression: &Expr) -> &Expr {
    let mut current = expression;
    while let Expr::Cast { expr, .. } = current {
        current = expr;
    }
    current
}

fn is_zero(expression: &Expr) -> bool {
    matches!(expression, Expr::Const(0))
}

/// Whether two operands denote the same underlying value.
///
/// Structural equality after cast-peeling; width agreement is checked
/// separately by the caller. Deliberately conservative: a false negative
/// leaves an unfused guard, which is merely verbose, while a false positive
/// fuses two different values and changes what the program says.
fn same_value(left: &Expr, right: &Expr) -> bool {
    left == right
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::VReg;

    fn local(name: &str) -> Expr {
        Expr::Reg(VReg::Phys(name.to_string()))
    }

    fn cast(signed: bool, width: u8, inner: Expr) -> Expr {
        Expr::Cast {
            signed,
            width,
            expr: Box::new(inner),
        }
    }

    fn cmp(op: CmpOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Cmp {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    #[test]
    fn fuses_the_loop_guard_the_compiler_actually_emits() {
        // The motivating case, with the exact asymmetric casts seen in
        // clang -O2 output for `for (i = 0; i < n; i++)`:
        //   ((unsigned long)(unsigned int)n == 0) | ((long)(int)n < 0)
        let mut guard = bin(
            BinOp::Or,
            cmp(
                CmpOp::Eq,
                cast(false, 8, cast(false, 4, local("n"))),
                Expr::Const(0),
            ),
            cmp(
                CmpOp::Slt,
                cast(true, 8, cast(true, 4, local("n"))),
                Expr::Const(0),
            ),
        );
        fuse_expr(&mut guard);
        // The SIGNED side's expression survives verbatim, casts included: the
        // fused comparison must observe the same four bytes the sign test did.
        assert_eq!(
            guard,
            cmp(
                CmpOp::Sle,
                cast(true, 8, cast(true, 4, local("n"))),
                Expr::Const(0)
            )
        );
    }

    #[test]
    fn differing_widths_are_never_fused() {
        // The unsoundness that turned eleven execution-differential lanes red.
        // For 64-bit `v` holding 2^32: `v == 0` is false and `(int)v < 0` is
        // false, so the guard is false -- but `(int)v <= 0` is TRUE. The two
        // comparisons look at different widths of one value, so there is no
        // single comparison equivalent to them.
        let original = bin(
            BinOp::Or,
            cmp(CmpOp::Eq, local("v"), Expr::Const(0)),
            cmp(CmpOp::Slt, cast(true, 4, local("v")), Expr::Const(0)),
        );
        let mut guard = original.clone();
        fuse_expr(&mut guard);
        assert_eq!(guard, original);
    }

    #[test]
    fn operand_order_does_not_matter() {
        let mut sign_first = bin(
            BinOp::Or,
            cmp(CmpOp::Slt, local("n"), Expr::Const(0)),
            cmp(CmpOp::Eq, local("n"), Expr::Const(0)),
        );
        fuse_expr(&mut sign_first);
        assert_eq!(sign_first, cmp(CmpOp::Sle, local("n"), Expr::Const(0)));
    }

    #[test]
    fn logical_and_bitwise_disjunction_both_fuse() {
        for op in [BinOp::Or, BinOp::LogicalOr] {
            let mut guard = bin(
                op,
                cmp(CmpOp::Eq, local("n"), Expr::Const(0)),
                cmp(CmpOp::Slt, local("n"), Expr::Const(0)),
            );
            fuse_expr(&mut guard);
            assert_eq!(guard, cmp(CmpOp::Sle, local("n"), Expr::Const(0)), "{op:?}");
        }
    }

    #[test]
    fn different_operands_are_never_fused() {
        // The failure that would matter: fusing two comparisons of DIFFERENT
        // values silently changes what the program tests.
        let original = bin(
            BinOp::Or,
            cmp(CmpOp::Eq, local("a"), Expr::Const(0)),
            cmp(CmpOp::Slt, local("b"), Expr::Const(0)),
        );
        let mut guard = original.clone();
        fuse_expr(&mut guard);
        assert_eq!(guard, original);
    }

    #[test]
    fn comparison_against_a_nonzero_constant_is_left_alone() {
        // Peeling casts is only sound against zero; against 1 a narrowing cast
        // could change the comparison.
        let original = bin(
            BinOp::Or,
            cmp(CmpOp::Eq, local("n"), Expr::Const(1)),
            cmp(CmpOp::Slt, local("n"), Expr::Const(1)),
        );
        let mut guard = original.clone();
        fuse_expr(&mut guard);
        assert_eq!(guard, original);
    }

    #[test]
    fn unrecognised_operator_pairs_are_left_alone() {
        let original = bin(
            BinOp::Or,
            cmp(CmpOp::Slt, local("n"), Expr::Const(0)),
            cmp(CmpOp::Sle, local("n"), Expr::Const(0)),
        );
        let mut guard = original.clone();
        fuse_expr(&mut guard);
        assert_eq!(guard, original);
    }

    #[test]
    fn conjunction_of_nonzero_and_nonpositive_is_negative() {
        let mut guard = bin(
            BinOp::LogicalAnd,
            cmp(CmpOp::Ne, local("n"), Expr::Const(0)),
            cmp(CmpOp::Sle, local("n"), Expr::Const(0)),
        );
        fuse_expr(&mut guard);
        assert_eq!(guard, cmp(CmpOp::Slt, local("n"), Expr::Const(0)));
    }

    #[test]
    fn arithmetic_disjunction_is_not_a_guard() {
        // `a | b` over values, not comparisons, must be untouched.
        let original = bin(BinOp::Or, local("a"), local("b"));
        let mut expression = original.clone();
        fuse_expr(&mut expression);
        assert_eq!(expression, original);
    }

    #[test]
    fn a_nested_guard_is_fused_too() {
        let mut outer = bin(
            BinOp::LogicalAnd,
            local("flag"),
            bin(
                BinOp::Or,
                cmp(CmpOp::Eq, local("n"), Expr::Const(0)),
                cmp(CmpOp::Slt, local("n"), Expr::Const(0)),
            ),
        );
        fuse_expr(&mut outer);
        assert_eq!(
            outer,
            bin(
                BinOp::LogicalAnd,
                local("flag"),
                cmp(CmpOp::Sle, local("n"), Expr::Const(0))
            )
        );
    }
}
