//! Recover source-level loop forms from conservative structured AST lowering.
//!
//! The region lowerer must preserve loop-header work until later semantic passes
//! decide whether it can move.  Its safe fallback is therefore
//! `while (1) { pre; if (exit) break; body }`.  Copy propagation can eliminate a
//! pure reload-only `pre`, leaving the exit guard as the literal first statement.
//! At that point no motion or data-flow prediction is required: the guarded
//! infinite loop is exactly equivalent to `while (!exit) { body }`.
//! A2 deliberately rolls that equivalence out only for constant-bound countdowns;
//! other induction forms remain conservative until separately measured slices.

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

/// Recover the measured constant-bound countdown subset of head-tested loops.
///
/// This pass intentionally does not move, fold, or discard any statement before
/// the guard. If even one statement remains there, or the body is not the bounded
/// A2 countdown shape, the conservative form stays intact.
pub fn recover_head_tested_whiles(f: &mut Function) {
    recover_body(&mut f.body);
}

fn recover_body(stmts: &mut [Stmt]) {
    for stmt in stmts {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_body(then_body);
                if let Some(body) = else_body {
                    recover_body(body);
                }
            }
            Stmt::While { cond, body } => {
                recover_body(body);

                if !matches!(cond, crate::ir::ast::Expr::Const(1)) {
                    continue;
                }
                let Some(Stmt::If {
                    cond: exit_cond,
                    then_body,
                    else_body: None,
                }) = body.first()
                else {
                    continue;
                };
                if then_body.as_slice() != [Stmt::Break] {
                    continue;
                }
                if !is_constant_bound_countdown(exit_cond, &body[1..]) {
                    continue;
                }

                *cond = negate_cmp_expr(exit_cond.clone());
                body.remove(0);
            }
            Stmt::DoWhile { body, .. } => recover_body(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    recover_body(body);
                }
                if let Some(body) = default {
                    recover_body(body);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Label(_)
            | Stmt::Goto { .. } => {}
        }
    }
}

/// The deliberately bounded A2 shape: `i <= K` exits and the body decrements
/// that same induction variable toward the constant bound.
///
/// Other exact head guards are semantically promotable too, but rolling them
/// out together caused per-cell DecBench regressions that obscured the factorial
/// acceptance case. They remain conservative until their own measured slices.
fn is_constant_bound_countdown(exit_cond: &Expr, body: &[Stmt]) -> bool {
    let Expr::Cmp { lhs, rhs, .. } = exit_cond else {
        return false;
    };
    let Some(induction) = body.iter().find_map(countdown_target) else {
        return false;
    };

    (contains_reg(lhs, induction) || contains_reg(rhs, induction))
        && (contains_const(lhs) || contains_const(rhs))
}

fn countdown_target(stmt: &Stmt) -> Option<&VReg> {
    let (dst, src) = match stmt {
        Stmt::Assign { dst, src } => (dst, src),
        // Promoted stack locals remain Store-to-Reg nodes in the semantic AST;
        // the DecBench renderer prints them as ordinary local assignments.
        Stmt::Store {
            addr: Expr::Reg(dst),
            src,
            ..
        } => (dst, src),
        _ => return None,
    };
    let Expr::Bin {
        op: BinOp::Sub,
        lhs,
        rhs,
    } = src
    else {
        return None;
    };
    (matches!(lhs.as_ref(), Expr::Reg(read) if read == dst)
        && matches!(rhs.as_ref(), Expr::Const(step) if *step > 0))
    .then_some(dst)
}

fn contains_reg(expr: &Expr, target: &VReg) -> bool {
    match expr {
        Expr::Reg(reg) => reg == target,
        Expr::Deref { addr, .. } => contains_reg(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_reg(lhs, target) || contains_reg(rhs, target)
        }
        Expr::Un { src, .. } => contains_reg(src, target),
        Expr::Cast { expr, .. } => contains_reg(expr, target),
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(target) || index.as_ref() == Some(target)
        }
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn contains_const(expr: &Expr) -> bool {
    match expr {
        Expr::Const(_) => true,
        Expr::Deref { addr, .. } => contains_const(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_const(lhs) || contains_const(rhs)
        }
        Expr::Un { src, .. } => contains_const(src),
        Expr::Cast { expr, .. } => contains_const(expr),
        Expr::Reg(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CmpOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    #[test]
    fn a_statement_before_the_guard_blocks_promotion() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::Assign {
                    dst: reg("t"),
                    src: Expr::Reg(reg("i")),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("t"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("i"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("i"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
            ],
        };
        let mut f = Function {
            name: "protected".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn a_nontrivial_break_arm_blocks_promotion() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("done")),
                then_body: vec![Stmt::Comment("effect".into()), Stmt::Break],
                else_body: None,
            }],
        };
        let mut f = Function {
            name: "protected".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }

    #[test]
    fn an_incrementing_variable_bound_loop_stays_conservative_in_a2() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Sle,
                        lhs: Box::new(Expr::Reg(reg("n"))),
                        rhs: Box::new(Expr::Reg(reg("i"))),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("i"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("i"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
            ],
        };
        let mut f = Function {
            name: "later_slice".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(f.body, vec![original]);
    }
}
