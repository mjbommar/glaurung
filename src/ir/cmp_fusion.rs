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
use crate::ir::types_recover::{TypeHint, TypeMap};

/// Fuse two-comparison guards throughout a function body.
pub fn fuse_comparisons(function: &mut Function) {
    fuse_block(&mut function.body, None);
}

/// Fuse comparisons with the recovered value widths available to rules whose
/// safety depends on an explicit machine-width view.
pub fn fuse_comparisons_with_types(function: &mut Function, types: &TypeMap) {
    fuse_block(&mut function.body, Some(types));
}

fn fuse_block(statements: &mut Vec<Stmt>, types: Option<&TypeMap>) {
    for statement in statements.iter_mut() {
        fuse_stmt(statement, types);
    }
}

fn fuse_stmt(statement: &mut Stmt, types: Option<&TypeMap>) {
    match statement {
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            fuse_expr_with_types(cond, types);
            fuse_block(then_body, types);
            if let Some(body) = else_body.as_mut() {
                fuse_block(body, types);
            }
        }
        Stmt::While { cond, body } => {
            fuse_expr_with_types(cond, types);
            fuse_block(body, types);
        }
        Stmt::DoWhile { body, cond } => {
            fuse_block(body, types);
            fuse_expr_with_types(cond, types);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            fuse_stmt(init, types);
            fuse_expr_with_types(cond, types);
            fuse_stmt(step, types);
            fuse_block(body, types);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            fuse_expr_with_types(discriminant, types);
            for (_, body) in cases.iter_mut() {
                fuse_block(body, types);
            }
            if let Some(body) = default.as_mut() {
                fuse_block(body, types);
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            fuse_block(try_body, types);
            for catch in catches.iter_mut() {
                fuse_block(&mut catch.body, types);
            }
        }
        Stmt::Assign { src, .. } => fuse_expr_with_types(src, types),
        Stmt::Store { addr, src, .. } => {
            fuse_expr_with_types(addr, types);
            fuse_expr_with_types(src, types);
        }
        Stmt::Call { target, args, .. } => {
            fuse_expr_with_types(target, types);
            for arg in args.iter_mut() {
                fuse_expr_with_types(arg, types);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value.as_mut() {
                fuse_expr_with_types(value, types);
            }
        }
        Stmt::Throw { value } | Stmt::Push { value } => fuse_expr_with_types(value, types),
        Stmt::IndirectGoto { target } => fuse_expr_with_types(target, types),
        _ => {}
    }
}

#[cfg(test)]
fn fuse_expr(expression: &mut Expr) {
    fuse_expr_with_types(expression, None);
}

fn fuse_expr_with_types(expression: &mut Expr, types: Option<&TypeMap>) {
    // Children first: an inner guard must already be fused before an outer
    // rule inspects it.
    match expression {
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fuse_expr_with_types(lhs, types);
            fuse_expr_with_types(rhs, types);
        }
        Expr::Un { src, .. } => fuse_expr_with_types(src, types),
        Expr::Cast { expr, .. } => fuse_expr_with_types(expr, types),
        _ => {}
    }
    if let Some(fused) = fused_form(expression, types) {
        *expression = fused;
    }
}

/// The single fused comparison equivalent to a two-comparison guard, if any.
fn fused_form(expression: &Expr, types: Option<&TypeMap>) -> Option<Expr> {
    if let Some(range) = fused_unsigned_subtract_range(expression, types) {
        return Some(range);
    }
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

/// Recover `(unsigned W)(x - low) <= span` as the explicit closed range
/// `low <= (unsigned W)x && (unsigned W)x <= high`.
///
/// This is the standard compiler range idiom. It is an equivalence exactly
/// when the interval does not wrap in W bits. The cast shell is copied onto
/// both uses of `x`, so a 32-bit comparison never silently becomes a 64-bit
/// one (the historical `cmp_fusion` failure mode).
fn fused_unsigned_subtract_range(expression: &Expr, types: Option<&TypeMap>) -> Option<Expr> {
    let Expr::Cmp { op, lhs, rhs } = expression else {
        return None;
    };
    if !matches!(op, CmpOp::Ult | CmpOp::Ule) {
        return None;
    }

    // Reversed form: `limit <u (x - low)` is the complement of
    // `(x - low) <=u limit`; `limit <=u (x - low)` complements the strict
    // inside form. Compilers prefer this orientation for a rejecting guard.
    if let Some((value, low)) = subtract_range_parts(rhs) {
        if let Some(width) = unsigned_range_width(rhs, value, types) {
            if let Expr::Const(limit) = strip_casts(lhs) {
                let inside_op = match op {
                    CmpOp::Ult => CmpOp::Ule,
                    CmpOp::Ule => CmpOp::Ult,
                    _ => unreachable!(),
                };
                if let Some((low, high)) = unsigned_range_bounds(width, low, *limit, inside_op) {
                    let viewed_value = unsigned_view_with_leaf(rhs, value, width);
                    return Some(Expr::Bin {
                        op: BinOp::LogicalOr,
                        lhs: Box::new(Expr::Cmp {
                            op: CmpOp::Ult,
                            lhs: Box::new(viewed_value.clone()),
                            rhs: Box::new(Expr::Const(low)),
                        }),
                        rhs: Box::new(Expr::Cmp {
                            op: CmpOp::Ult,
                            lhs: Box::new(Expr::Const(high)),
                            rhs: Box::new(viewed_value),
                        }),
                    });
                }
            }
        }
    }

    let (value, low) = subtract_range_parts(lhs)?;
    let width = unsigned_range_width(lhs, value, types)?;
    let Expr::Const(limit) = strip_casts(rhs) else {
        return None;
    };
    let (low, high) = unsigned_range_bounds(width, low, *limit, *op)?;
    let viewed_value = unsigned_view_with_leaf(lhs, value, width);
    Some(Expr::Bin {
        op: BinOp::LogicalAnd,
        lhs: Box::new(Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(Expr::Const(low)),
            rhs: Box::new(viewed_value.clone()),
        }),
        rhs: Box::new(Expr::Cmp {
            op: CmpOp::Ule,
            lhs: Box::new(viewed_value),
            rhs: Box::new(Expr::Const(high)),
        }),
    })
}

fn subtract_range_parts(expression: &Expr) -> Option<(&Expr, i64)> {
    match strip_casts(expression) {
        Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        } => match strip_casts(rhs) {
            Expr::Const(low) if *low >= 0 => Some((lhs, *low)),
            _ => None,
        },
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => match strip_casts(rhs) {
            Expr::Const(delta) if *delta < 0 => Some((lhs, delta.checked_neg()?)),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn unsigned_range_bounds(
    width: u8,
    low: i64,
    limit: i64,
    op: CmpOp,
) -> Option<(i64, i64)> {
    if width == 0 || width > 8 || low < 0 || limit < 0 {
        return None;
    }
    let modulus = 1_i128 << (u32::from(width) * 8);
    let low = i128::from(low);
    let span = match op {
        CmpOp::Ule => i128::from(limit),
        CmpOp::Ult if limit > 0 => i128::from(limit - 1),
        _ => return None,
    };
    let high = low.checked_add(span)?;
    if low >= modulus || high >= modulus {
        return None;
    }
    Some((i64::try_from(low).ok()?, i64::try_from(high).ok()?))
}

/// Narrowest explicitly unsigned cast in a cast shell. If the narrowest view
/// is signed, the source idiom is not an unsigned modular range and declines.
fn observed_unsigned_width(expression: &Expr) -> Option<u8> {
    let mut view = None;
    let mut current = expression;
    while let Expr::Cast {
        signed,
        width,
        expr,
    } = current
    {
        if view.is_none_or(|(seen, _): (u8, bool)| *width <= seen) {
            view = Some((*width, *signed));
        }
        current = expr;
    }
    match view {
        Some((width, false)) => Some(width),
        _ => None,
    }
}

fn unsigned_range_width(shell: &Expr, value: &Expr, types: Option<&TypeMap>) -> Option<u8> {
    observed_unsigned_width(shell).or_else(|| {
        let Expr::Reg(register) = strip_casts(value) else {
            return None;
        };
        match types?.get(register)? {
            TypeHint::Int { width, .. } if width > 0 && width <= 8 => Some(width),
            TypeHint::BoolLike => Some(1),
            _ => None,
        }
    })
}

fn unsigned_view_with_leaf(shell: &Expr, leaf: &Expr, width: u8) -> Expr {
    if observed_unsigned_width(shell).is_some() {
        cast_shell_with_leaf(shell, leaf)
    } else {
        Expr::Cast {
            signed: false,
            width,
            expr: Box::new(leaf.clone()),
        }
    }
}

/// Copy only the explicit cast shell, replacing its arithmetic leaf.
fn cast_shell_with_leaf(shell: &Expr, leaf: &Expr) -> Expr {
    match shell {
        Expr::Cast {
            signed,
            width,
            expr,
        } => Expr::Cast {
            signed: *signed,
            width: *width,
            expr: Box::new(cast_shell_with_leaf(expr, leaf)),
        },
        _ => leaf.clone(),
    }
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
    fn fuses_width_stated_unsigned_subtract_range() {
        // `(uint32_t)(x - 1) <= 15` is the compiler's single-comparison
        // spelling of `1 <= x && x <= 16`. Keep the exact u32 view on both
        // replacement comparisons; widening it silently admits high bits.
        let view = |inner| cast(false, 8, cast(false, 4, inner));
        let mut guard = cmp(
            CmpOp::Ule,
            view(bin(BinOp::Sub, local("x"), Expr::Const(1))),
            cast(false, 8, Expr::Const(15)),
        );
        fuse_expr(&mut guard);
        assert_eq!(
            guard,
            bin(
                BinOp::LogicalAnd,
                cmp(CmpOp::Ule, Expr::Const(1), view(local("x"))),
                cmp(CmpOp::Ule, view(local("x")), Expr::Const(16)),
            )
        );
    }

    #[test]
    fn fuses_reversed_unsigned_subtract_as_an_outside_range() {
        let view = |inner| cast(false, 8, cast(false, 4, inner));
        let mut guard = cmp(
            CmpOp::Ult,
            Expr::Const(15),
            view(bin(BinOp::Sub, local("x"), Expr::Const(1))),
        );
        fuse_expr(&mut guard);
        assert_eq!(
            guard,
            bin(
                BinOp::LogicalOr,
                cmp(CmpOp::Ult, view(local("x")), Expr::Const(1)),
                cmp(CmpOp::Ult, Expr::Const(16), view(local("x"))),
            )
        );
    }

    #[test]
    fn typed_fusion_uses_the_authoritative_width_when_the_ast_has_no_cast() {
        let mut function = Function {
            name: "range".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: cmp(
                    CmpOp::Ult,
                    Expr::Const(15),
                    bin(BinOp::Add, local("x"), Expr::Const(-1)),
                ),
                then_body: vec![],
                else_body: None,
            }],
        };
        let mut types = TypeMap::default();
        types.upsert_public(
            VReg::phys("x"),
            TypeHint::Int {
                signed: true,
                width: 4,
            },
        );

        fuse_comparisons_with_types(&mut function, &types);

        let view = |inner| cast(false, 4, inner);
        assert_eq!(
            function.body[0],
            Stmt::If {
                cond: bin(
                    BinOp::LogicalOr,
                    cmp(CmpOp::Ult, view(local("x")), Expr::Const(1)),
                    cmp(CmpOp::Ult, Expr::Const(16), view(local("x"))),
                ),
                then_body: vec![],
                else_body: None,
            }
        );
    }

    #[test]
    fn unsigned_subtract_range_is_exhaustively_equivalent_at_8_and_16_bits() {
        for width in [1_u8, 2_u8] {
            let modulus = 1_u64 << (u32::from(width) * 8);
            let cases = [
                (0_u64, 0_u64, CmpOp::Ule),
                (1, 15, CmpOp::Ule),
                (modulus / 2, 7, CmpOp::Ule),
                (modulus - 8, 8, CmpOp::Ult),
            ];
            for (low, limit, op) in cases {
                let (_, high) = unsigned_range_bounds(
                    width,
                    i64::try_from(low).unwrap(),
                    i64::try_from(limit).unwrap(),
                    op,
                )
                .expect("selected interval does not wrap");
                for value in 0..modulus {
                    let difference = value.wrapping_sub(low) & (modulus - 1);
                    let original = match op {
                        CmpOp::Ule => difference <= limit,
                        CmpOp::Ult => difference < limit,
                        _ => unreachable!(),
                    };
                    let fused = low <= value && value <= u64::try_from(high).unwrap();
                    assert_eq!(
                        original, fused,
                        "width={width} value={value:#x} low={low:#x} limit={limit:#x} op={op:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn unsigned_subtract_range_boundaries_and_seeded_wide_values_are_equivalent() {
        for (width, low, limit) in [
            (4_u8, 1_u64, 15_u64),
            (4, 0x7fff_ff00, 0xff),
            (8, 1, 15),
            (8, 0x7fff_ffff_ffff_ff00, 0xff),
        ] {
            let (_, high) = unsigned_range_bounds(
                width,
                i64::try_from(low).unwrap(),
                i64::try_from(limit).unwrap(),
                CmpOp::Ule,
            )
            .expect("selected interval does not wrap");
            let modulus_mask = if width == 8 {
                u64::MAX
            } else {
                (1_u64 << (u32::from(width) * 8)) - 1
            };
            let mut values = vec![
                0,
                low.saturating_sub(1),
                low,
                u64::try_from(high).unwrap(),
                u64::try_from(high).unwrap().saturating_add(1) & modulus_mask,
                modulus_mask,
            ];
            let mut seed = 0x5eed_cafe_d15c_a11u64;
            for _ in 0..4096 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                values.push(seed & modulus_mask);
            }
            for value in values {
                let difference = value.wrapping_sub(low) & modulus_mask;
                let original = difference <= limit;
                let fused = low <= value && value <= u64::try_from(high).unwrap();
                assert_eq!(original, fused, "width={width} value={value:#x}");
            }
        }

        assert_eq!(
            unsigned_range_bounds(4, 0xffff_fff0, 0x20, CmpOp::Ule),
            None,
            "a wrapping interval must decline rather than become two comparisons"
        );
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
