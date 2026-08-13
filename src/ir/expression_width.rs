//! Width evidence carried explicitly by C-like AST expressions.
//!
//! This is deliberately narrower than type recovery: it answers only when an
//! expression node itself proves a storage width. Passes that need a sound
//! widening decision can share this rule instead of growing local heuristics.

use crate::ir::ast::Expr;

/// Widest byte width explicitly established by an expression.
pub(crate) fn explicit_expression_width(expression: &Expr) -> Option<u8> {
    match expression {
        Expr::Deref { size, .. }
        | Expr::Select { width: size, .. }
        | Expr::WideArithmetic { width: size, .. } => Some(*size),
        Expr::Cast { width, .. } | Expr::FloatConst { width, .. } => Some(*width),
        Expr::NumericConvert { to, .. } => Some(to.width()),
        Expr::FunctionTableEntry { pointer_size, .. } => Some(*pointer_size),
        Expr::Call { result_width, .. } => *result_width,
        Expr::Cmp { .. } => Some(1),
        Expr::Bin { lhs, rhs, .. } => explicit_expression_width(lhs)
            .into_iter()
            .chain(explicit_expression_width(rhs))
            .max(),
        Expr::Un { src, .. } => explicit_expression_width(src),
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => Some(8),
        Expr::Reg(_) | Expr::Const(_) | Expr::Unknown(_) => None,
    }
}

/// Whether an expression proves that bits above `narrow_width` can be
/// semantically significant.
///
/// A wider unsigned cast alone is not such proof: AArch64 writes to `wN`
/// routinely lower as a 32-bit value followed by zero-extension into `xN`.
/// Treating that container canonicalization as a new 64-bit lifetime causes
/// false parameter/output role splits. Arithmetic, loads, selects, and signed
/// extension at the wider width can carry meaningful high bits.
pub(crate) fn can_carry_bits_above(expression: &Expr, narrow_width: u8) -> bool {
    match expression {
        Expr::Cast {
            signed,
            width,
            expr,
        } => {
            *width > narrow_width
                && ((*signed
                    && explicit_expression_width(expr)
                        .is_some_and(|source_width| source_width <= narrow_width))
                    || can_carry_bits_above(expr, narrow_width))
        }
        // A numeric conversion states its own result type.
        Expr::NumericConvert { to, .. } => to.width() > narrow_width,
        Expr::Deref { size, .. }
        | Expr::Select { width: size, .. }
        | Expr::WideArithmetic { width: size, .. } => *size > narrow_width,
        Expr::FunctionTableEntry { pointer_size, .. } => *pointer_size > narrow_width,
        Expr::Call { .. } => {
            explicit_expression_width(expression).is_some_and(|width| width > narrow_width)
        }
        Expr::Bin { .. } | Expr::Un { .. } => {
            explicit_expression_width(expression).is_some_and(|width| width > narrow_width)
        }
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => 8 > narrow_width,
        Expr::Cmp { .. }
        | Expr::FloatConst { .. }
        | Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Unknown(_) => false,
    }
}
