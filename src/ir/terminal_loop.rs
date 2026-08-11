//! Recover terminal machine self-branches as source-level infinite loops.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};

/// Recover exact terminal `label; goto label` tails.
pub fn recover_terminal_self_loops(function: &mut Function) {
    let mut incoming = HashMap::new();
    count_gotos(&function.body, &mut incoming);
    recover_in_body(&mut function.body, &incoming);
}

fn recover_in_body(body: &mut Vec<Stmt>, incoming: &HashMap<u64, usize>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_in_body(then_body, incoming);
                if let Some(else_body) = else_body {
                    recover_in_body(else_body, incoming);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                recover_in_body(body, incoming);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    recover_in_body(case_body, incoming);
                }
                if let Some(default_body) = default {
                    recover_in_body(default_body, incoming);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_in_body(try_body, incoming);
                for catch in catches {
                    recover_in_body(&mut catch.body, incoming);
                }
            }
            _ => {}
        }
    }

    let Some((Stmt::Label(label), Stmt::Goto { target })) = body
        .len()
        .checked_sub(2)
        .map(|index| (&body[index], &body[index + 1]))
    else {
        return;
    };
    if label != target {
        return;
    }
    let loop_statement = Stmt::While {
        cond: Expr::Const(1),
        body: Vec::new(),
    };
    let terminal = body.len() - 1;
    if incoming.get(target).copied() == Some(1) {
        body.splice(terminal - 1..=terminal, [loop_statement]);
    } else {
        body[terminal] = loop_statement;
    }
}

fn count_gotos(body: &[Stmt], incoming: &mut HashMap<u64, usize>) {
    for statement in body {
        match statement {
            Stmt::Goto { target } => *incoming.entry(*target).or_default() += 1,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                count_gotos(then_body, incoming);
                if let Some(else_body) = else_body {
                    count_gotos(else_body, incoming);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                count_gotos(body, incoming);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    count_gotos(case_body, incoming);
                }
                if let Some(default_body) = default {
                    count_gotos(default_body, incoming);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                count_gotos(try_body, incoming);
                for catch in catches {
                    count_gotos(&catch.body, incoming);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::VReg;

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "terminal_loop".into(),
            entry_va: 0x1000,
            body,
        }
    }

    #[test]
    fn exact_unreferenced_terminal_self_branch_becomes_an_infinite_loop() {
        let mut function = function(vec![Stmt::Label(0x1010), Stmt::Goto { target: 0x1010 }]);

        recover_terminal_self_loops(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![],
            }]
        );
    }

    #[test]
    fn terminal_self_branch_is_recovered_inside_a_conditional_arm() {
        let mut function = function(vec![Stmt::If {
            cond: Expr::Reg(VReg::phys("flag")),
            then_body: vec![Stmt::Label(0x1020), Stmt::Goto { target: 0x1020 }],
            else_body: None,
        }]);

        recover_terminal_self_loops(&mut function);

        assert!(matches!(
            function.body.as_slice(),
            [Stmt::If { then_body, .. }]
                if matches!(
                    then_body.as_slice(),
                    [Stmt::While { cond: Expr::Const(1), body }]
                        if body.is_empty()
                )
        ));
    }

    #[test]
    fn nonterminal_self_branch_is_left_unchanged() {
        let original = vec![
            Stmt::Label(0x1030),
            Stmt::Goto { target: 0x1030 },
            Stmt::Label(0x1040),
        ];
        let mut function = function(original.clone());

        recover_terminal_self_loops(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn terminal_jump_to_a_different_label_is_left_unchanged() {
        let original = vec![Stmt::Label(0x1050), Stmt::Goto { target: 0x1060 }];
        let mut function = function(original.clone());

        recover_terminal_self_loops(&mut function);

        assert_eq!(function.body, original);
    }

    #[test]
    fn forward_skip_composes_into_a_guarded_call_before_the_loop() {
        let work = Stmt::Assign {
            dst: VReg::phys("started"),
            src: Expr::Const(1),
        };
        let mut function = function(vec![
            Stmt::If {
                cond: Expr::Cmp {
                    op: crate::ir::types::CmpOp::Ne,
                    lhs: Box::new(Expr::Reg(VReg::phys("state"))),
                    rhs: Box::new(Expr::Const(1)),
                },
                then_body: vec![Stmt::Goto { target: 0x1070 }],
                else_body: None,
            },
            work.clone(),
            Stmt::Label(0x1070),
            Stmt::Goto { target: 0x1070 },
        ]);

        recover_terminal_self_loops(&mut function);
        crate::ir::label_prune::recover_forward_exit_regions(&mut function);

        assert!(matches!(
            function.body.as_slice(),
            [
                Stmt::If {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Eq,
                        lhs,
                        rhs,
                    },
                    then_body,
                    else_body: None,
                },
                Stmt::While { cond: Expr::Const(1), body },
            ] if lhs.as_ref() == &Expr::Reg(VReg::phys("state"))
                && rhs.as_ref() == &Expr::Const(1)
                && then_body == &[work]
                && body.is_empty()
        ));
    }
}
