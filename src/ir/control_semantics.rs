//! Shared predicates for source-level control-transfer semantics.

use crate::ir::ast::Stmt;

/// Whether `body` performs only ordinary statements before returning.
///
/// This proves that execution cannot fall through the body. Control-bearing
/// statements are rejected because moving or reasoning past them can silently
/// change which construct receives the transfer.
pub(crate) fn straight_line_return_body(body: &[Stmt]) -> bool {
    let Some((last, prefix)) = body.split_last() else {
        return false;
    };
    matches!(last, Stmt::Return { .. })
        && prefix.iter().all(|statement| {
            matches!(
                statement,
                Stmt::Assign { .. }
                    | Stmt::Store { .. }
                    | Stmt::Call { .. }
                    | Stmt::Nop
                    | Stmt::Unknown(_)
                    | Stmt::Comment(_)
                    | Stmt::Push { .. }
                    | Stmt::Pop { .. }
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;

    #[test]
    fn only_straight_line_prefixes_ending_in_return_are_terminal() {
        assert!(straight_line_return_body(&[
            Stmt::Nop,
            Stmt::Return {
                value: Some(Expr::Const(1)),
            },
        ]));
        assert!(!straight_line_return_body(&[Stmt::Nop]));
        assert!(!straight_line_return_body(&[
            Stmt::Break,
            Stmt::Return { value: None },
        ]));
    }
}
