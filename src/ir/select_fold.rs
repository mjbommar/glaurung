//! Collapse structurally proven assignment diamonds into pure selects.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Collapse terminal return-value diamonds whose arms assign the returned register.
pub fn collapse_assignment_diamonds(function: &mut Function) {
    let Some(returned) = terminal_return_register(&function.body) else {
        return;
    };
    collapse_body(&mut function.body, &returned, false);
}

fn terminal_return_register(body: &[Stmt]) -> Option<VReg> {
    body.iter()
        .rev()
        .find(|statement| !matches!(statement, Stmt::Comment(_) | Stmt::Nop))
        .and_then(|statement| match statement {
            Stmt::Return {
                value: Some(Expr::Reg(returned)),
            } => Some(returned.clone()),
            _ => None,
        })
}

fn collapse_body(body: &mut Vec<Stmt>, returned: &VReg, may_feed_parent: bool) {
    let mut created = Vec::new();
    for (index, statement) in body.iter_mut().enumerate() {
        let original = statement.clone();
        if collapse_statement(statement, returned) {
            created.push((index, original));
        }
    }
    settle_created_selects(body, created, may_feed_parent);
}

fn settle_created_selects(
    body: &mut Vec<Stmt>,
    created: Vec<(usize, Stmt)>,
    may_feed_parent: bool,
) {
    for (index, original) in created.into_iter().rev() {
        if fold_created_select_return(body, index) {
            continue;
        }
        if may_feed_parent
            && body.len() == 1
            && index == 0
            && matches!(
                body.first(),
                Some(Stmt::Assign {
                    src: Expr::Select { .. },
                    ..
                })
            )
        {
            continue;
        }
        body[index] = original;
    }
}

fn fold_created_select_return(body: &mut Vec<Stmt>, index: usize) -> bool {
    let (destination, selected) = match body.get(index) {
        Some(Stmt::Assign {
            dst,
            src: selected @ Expr::Select { .. },
        }) => (dst.clone(), selected.clone()),
        _ => return false,
    };
    let mut return_index = index + 1;
    while matches!(body.get(return_index), Some(Stmt::Comment(_) | Stmt::Nop)) {
        return_index += 1;
    }
    let Some(Stmt::Return {
        value: Some(Expr::Reg(returned)),
    }) = body.get(return_index)
    else {
        return false;
    };
    if returned != &destination {
        return false;
    }
    body[return_index] = Stmt::Return {
        value: Some(selected),
    };
    body.remove(index);
    true
}

fn collapse_statement(statement: &mut Stmt, returned: &VReg) -> bool {
    let original = statement.clone();
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            collapse_body(then_body, returned, true);
            if let Some(else_body) = else_body {
                collapse_body(else_body, returned, true);
            }
        }
        _ => {}
    }

    let replacement = match statement {
        Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } => {
            let [Stmt::Assign {
                dst: then_dst,
                src: then_src,
            }] = then_body.as_slice()
            else {
                return false;
            };
            let [Stmt::Assign {
                dst: else_dst,
                src: else_src,
            }] = else_body.as_slice()
            else {
                return false;
            };
            if then_dst != else_dst || then_dst != returned {
                return false;
            }
            Some(Stmt::Assign {
                dst: then_dst.clone(),
                src: Expr::Select {
                    cond: Box::new(cond.clone()),
                    if_true: Box::new(then_src.clone()),
                    if_false: Box::new(else_src.clone()),
                    width: select_width(then_src, else_src),
                },
            })
        }
        _ => None,
    };
    if let Some(replacement) = replacement {
        *statement = replacement;
        true
    } else {
        *statement = original;
        false
    }
}

fn select_width(if_true: &Expr, if_false: &Expr) -> u8 {
    expression_width(if_true)
        .into_iter()
        .chain(expression_width(if_false))
        .max()
        .unwrap_or(8)
}

fn expression_width(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Deref { size, .. } | Expr::Select { width: size, .. } => Some(*size),
        Expr::Cast { width, .. } => Some(*width),
        Expr::Cmp { .. } => Some(1),
        Expr::Bin { lhs, rhs, .. } => expression_width(lhs)
            .into_iter()
            .chain(expression_width(rhs))
            .max(),
        Expr::Un { src, .. } => expression_width(src),
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => Some(8),
        Expr::Reg(_) | Expr::Const(_) | Expr::Unknown(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Stmt};
    use crate::ir::types::VReg;

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn assign(dst: &str, src: Expr) -> Stmt {
        Stmt::Assign { dst: reg(dst), src }
    }

    fn return_reg(name: &str) -> Stmt {
        Stmt::Return {
            value: Some(Expr::Reg(reg(name))),
        }
    }

    fn function(body: Vec<Stmt>) -> Function {
        Function {
            name: "diamond".into(),
            entry_va: 0x1000,
            body,
        }
    }

    #[test]
    fn nested_same_destination_diamonds_collapse_bottom_up() {
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("outer")),
                then_body: vec![Stmt::If {
                    cond: Expr::Reg(reg("inner")),
                    then_body: vec![assign("result", Expr::Reg(reg("inner_yes")))],
                    else_body: Some(vec![assign("result", Expr::Reg(reg("inner_no")))]),
                }],
                else_body: Some(vec![assign("result", Expr::Reg(reg("outer_no")))]),
            },
            return_reg("result"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Return {
                    value: Some(Expr::Select {
                        if_true,
                        if_false,
                        ..
                    })
                }] if matches!(if_true.as_ref(), Expr::Select { .. })
                    && matches!(if_false.as_ref(), Expr::Reg(r) if r == &reg("outer_no"))
            ),
            "both return-value diamonds must collapse into the return: {:?}",
            f.body
        );
    }

    #[test]
    fn different_destinations_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("left", Expr::Const(1))],
            else_body: Some(vec![assign("right", Expr::Const(2))]),
        };
        let terminal_return = return_reg("left");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }

    #[test]
    fn a_created_select_feeding_the_return_folds_through_comments() {
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("cond")),
                then_body: vec![assign("result", Expr::Const(1))],
                else_body: Some(vec![assign("result", Expr::Const(2))]),
            },
            Stmt::Comment("epilogue".into()),
            return_reg("result"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [
                    Stmt::Comment(_),
                    Stmt::Return {
                        value: Some(Expr::Select { .. })
                    }
                ]
            ),
            "the diamond-created return value must become one expression: {:?}",
            f.body
        );
    }

    #[test]
    fn a_non_return_diamond_keeps_its_existing_control_flow_shape() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("scratch", Expr::Const(1))],
            else_body: Some(vec![assign("scratch", Expr::Const(2))]),
        };
        let mut f = function(vec![
            original.clone(),
            Stmt::Return {
                value: Some(Expr::Reg(reg("result"))),
            },
        ]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body.first(), Some(&original));
    }

    #[test]
    fn an_overwritten_return_register_diamond_keeps_its_shape() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: Some(vec![assign("result", Expr::Const(2))]),
        };
        let overwrite = assign("result", Expr::Const(3));
        let terminal_return = return_reg("result");
        let mut f = function(vec![
            original.clone(),
            overwrite.clone(),
            terminal_return.clone(),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, overwrite, terminal_return]);
    }

    #[test]
    fn multi_statement_arms_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![
                assign("side", Expr::Const(1)),
                assign("result", Expr::Const(2)),
            ],
            else_body: Some(vec![assign("result", Expr::Const(3))]),
        };
        let terminal_return = return_reg("result");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }

    #[test]
    fn one_armed_conditionals_do_not_collapse() {
        let original = Stmt::If {
            cond: Expr::Reg(reg("cond")),
            then_body: vec![assign("result", Expr::Const(1))],
            else_body: None,
        };
        let terminal_return = return_reg("result");
        let mut f = function(vec![original.clone(), terminal_return.clone()]);

        collapse_assignment_diamonds(&mut f);

        assert_eq!(f.body, vec![original, terminal_return]);
    }
}
