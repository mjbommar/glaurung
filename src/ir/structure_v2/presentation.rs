//! Provenance-preserving lexical cleanup for verified structure-v2 output.

use crate::ir::ast::{Function, Stmt};

/// Remove lexical `else` nesting after an arm that returns on every path.
///
/// This runs only for selected structure-v2 output and only after region
/// adaptation has fixed block ownership and joins. It changes no condition,
/// transfer, or statement order: `if (c) return; else body` becomes
/// `if (c) return; body`.
pub(crate) fn flatten_terminal_elses(function: &mut Function) {
    flatten_in_body(&mut function.body);
}

fn returns_on_all_paths(body: &[Stmt]) -> bool {
    let Some(last) = body.last() else {
        return false;
    };
    match last.semantic() {
        Stmt::Return { .. } => true,
        Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => returns_on_all_paths(then_body) && returns_on_all_paths(else_body),
        _ => false,
    }
}

fn flatten_in_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement.semantic_mut() {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                flatten_in_body(then_body);
                if let Some(else_body) = else_body {
                    flatten_in_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::DoWhile { body, .. } => {
                flatten_in_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    flatten_in_body(case);
                }
                if let Some(default) = default {
                    flatten_in_body(default);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                flatten_in_body(try_body);
                for catch in catches {
                    flatten_in_body(&mut catch.body);
                }
            }
            Stmt::Origin { .. }
            | Stmt::Assign { .. }
            | Stmt::Store { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Continue
            | Stmt::IndirectGoto { .. }
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Push { .. }
            | Stmt::Pop { .. } => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let qualifies = matches!(
            body[index].semantic(),
            Stmt::If {
                then_body,
                else_body: Some(_),
                ..
            } if returns_on_all_paths(then_body)
        );
        if !qualifies {
            index += 1;
            continue;
        }
        let statement = std::mem::replace(&mut body[index], Stmt::Nop);
        let (semantic, origins) = statement.into_semantic_with_origins();
        let Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } = semantic
        else {
            unreachable!("shape checked above")
        };
        body[index] = Stmt::If {
            cond,
            then_body,
            else_body: None,
        }
        .with_optional_origins(origins);
        let inserted = else_body.len();
        body.splice(index + 1..index + 1, else_body);
        index += inserted + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, OriginSet};

    #[test]
    fn terminal_then_arm_becomes_an_attributed_early_return() {
        let owner = OriginSet::one(0x1010);
        let mut function = Function {
            name: "early".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
                else_body: Some(vec![Stmt::Assign {
                    dst: crate::ir::types::VReg::phys("result"),
                    src: Expr::Const(2),
                }]),
            }
            .with_origins(owner.clone())],
        };

        flatten_terminal_elses(&mut function);

        assert_eq!(function.body.len(), 2);
        assert_eq!(function.body[0].origins(), Some(&owner));
        assert!(matches!(
            function.body[0].semantic(),
            Stmt::If {
                else_body: None,
                ..
            }
        ));
        assert!(matches!(function.body[1].semantic(), Stmt::Assign { .. }));
    }

    #[test]
    fn partially_returning_then_arm_keeps_its_else() {
        let mut function = Function {
            name: "partial".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![Stmt::If {
                    cond: Expr::Const(2),
                    then_body: vec![Stmt::Return { value: None }],
                    else_body: None,
                }],
                else_body: Some(vec![Stmt::Return { value: None }]),
            }],
        };

        flatten_terminal_elses(&mut function);

        assert!(matches!(
            function.body[0].semantic(),
            Stmt::If {
                else_body: Some(_),
                ..
            }
        ));
    }
}
