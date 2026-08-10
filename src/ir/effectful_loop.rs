//! Recover call-driven pre-tested loops without putting effects in expressions.

use crate::ir::ast::{negate_cmp_expr, Expr, Stmt};

/// Rotate exact effectful loop headers into an initial seed and latch update.
///
/// The conservative lowerer cannot put a call in [`Expr`], so a source loop
/// such as `while ((item = next(iter)) != NULL) { consume(item); }` becomes
/// `while (1) { item = next(iter); if (item == 0) break; consume(item); }`.
/// Moving the call out without repeating it would freeze the condition. Instead
/// seed it once and clone the same call at the body's fallthrough latch. This
/// preserves the call count and order while making the head test explicit.
///
/// Only one result-producing call followed immediately by its break guard is
/// accepted. Explicit labels and gotos in the remainder fail closed because
/// they could bypass or re-enter the synthesized latch update.
pub(crate) fn rotate_effectful_call_headers(stmts: &mut Vec<Stmt>) {
    for statement in stmts.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                rotate_effectful_call_headers(then_body);
                if let Some(else_body) = else_body {
                    rotate_effectful_call_headers(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                rotate_effectful_call_headers(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    rotate_effectful_call_headers(case_body);
                }
                if let Some(default_body) = default {
                    rotate_effectful_call_headers(default_body);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                rotate_effectful_call_headers(try_body);
                for catch in catches {
                    rotate_effectful_call_headers(&mut catch.body);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < stmts.len() {
        let Some((seed, rotated)) = effectful_call_header_candidate(&stmts[index]) else {
            index += 1;
            continue;
        };
        stmts.splice(index..=index, [seed, rotated]);
        index += 2;
    }
}

fn effectful_call_header_candidate(statement: &Stmt) -> Option<(Stmt, Stmt)> {
    let Stmt::While { cond, body } = statement else {
        return None;
    };
    if !matches!(cond, Expr::Const(1)) {
        return None;
    }
    let [header @ Stmt::Call {
        dst: Some(result), ..
    }, guard, remainder @ ..] = body.as_slice()
    else {
        return None;
    };
    let Stmt::If {
        cond: exit_condition,
        then_body,
        else_body: None,
    } = guard
    else {
        return None;
    };
    if then_body.as_slice() != [Stmt::Break]
        || !exit_condition.contains_reg(result)
        || remainder.iter().any(has_explicit_loop_jump)
    {
        return None;
    }

    let mut rotated_body = remainder.to_vec();
    rotated_body.push(header.clone());
    Some((
        header.clone(),
        Stmt::While {
            cond: negate_cmp_expr(exit_condition.clone()),
            body: rotated_body,
        },
    ))
}

fn has_explicit_loop_jump(statement: &Stmt) -> bool {
    match statement {
        Stmt::Label(_) | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(has_explicit_loop_jump)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_explicit_loop_jump))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body.iter().any(has_explicit_loop_jump)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(has_explicit_loop_jump))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_explicit_loop_jump))
        }
        Stmt::TryCatch { try_body, catches } => {
            try_body.iter().any(has_explicit_loop_jump)
                || catches
                    .iter()
                    .any(|catch| catch.body.iter().any(has_explicit_loop_jump))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Function;
    use crate::ir::types::{CmpOp, VReg};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn iterator_call() -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0x2000,
                name: "iter_next".into(),
            },
            args: vec![Expr::Reg(reg("iter"))],
            dst: Some(reg("item")),
            call_spec: None,
        }
    }

    fn exit_guard() -> Stmt {
        Stmt::If {
            cond: Expr::Cmp {
                op: CmpOp::Eq,
                lhs: Box::new(Expr::Reg(reg("item"))),
                rhs: Box::new(Expr::Const(0)),
            },
            then_body: vec![Stmt::Break],
            else_body: None,
        }
    }

    #[test]
    fn rotates_without_losing_an_iteration() {
        let next = iterator_call();
        let consume = Stmt::Call {
            target: Expr::Named {
                va: 0x3000,
                name: "consume".into(),
            },
            args: vec![Expr::Reg(reg("item"))],
            dst: None,
            call_spec: None,
        };
        let mut function = Function {
            name: "drain".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![next.clone(), exit_guard(), consume.clone()],
            }],
        };

        rotate_effectful_call_headers(&mut function.body);

        assert_eq!(
            function.body,
            vec![
                next.clone(),
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Ne,
                        lhs: Box::new(Expr::Reg(reg("item"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    body: vec![consume, next],
                },
            ]
        );
    }

    #[test]
    fn explicit_goto_in_the_remainder_fails_closed() {
        let original = Stmt::While {
            cond: Expr::Const(1),
            body: vec![iterator_call(), exit_guard(), Stmt::Goto { target: 0x4000 }],
        };
        let mut body = vec![original.clone()];

        rotate_effectful_call_headers(&mut body);

        assert_eq!(body, vec![original]);
    }
}
