//! Collapse structurally proven assignment diamonds into pure selects.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Collapse exact two-arm, same-destination assignment diamonds.
///
/// `Expr::Select` preserves lazy arm evaluation, so this identity is valid for
/// arbitrary value expressions. Stores are accepted only for promoted stack
/// locals: moving a genuine pointer-address calculation out of an arm could
/// change faults or other address dependencies.
pub fn collapse_assignment_diamonds(function: &mut Function) {
    collapse_body(&mut function.body);
}

fn collapse_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collapse_body(then_body);
                if let Some(else_body) = else_body {
                    collapse_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collapse_body(body)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collapse_body(case_body);
                }
                if let Some(default) = default {
                    collapse_body(default);
                }
            }
            _ => {}
        }
        if let Some(replacement) = select_from_diamond(statement) {
            *statement = replacement;
        }
    }

    for index in (0..body.len()).rev() {
        let _ = fold_created_select_return(body, index);
    }
}

fn fold_created_select_return(body: &mut Vec<Stmt>, index: usize) -> bool {
    let (destination, selected) = match body.get(index) {
        Some(Stmt::Assign {
            dst,
            src: selected @ Expr::Select { .. },
        }) => (dst.clone(), selected.clone()),
        Some(Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            src: selected @ Expr::Select { .. },
            ..
        }) if is_promoted_local(name) => (dst.clone(), selected.clone()),
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

fn select_from_diamond(statement: &Stmt) -> Option<Stmt> {
    match statement {
        Stmt::If {
            cond,
            then_body,
            else_body: Some(else_body),
        } => {
            let [then_statement] = then_body.as_slice() else {
                return None;
            };
            let [else_statement] = else_body.as_slice() else {
                return None;
            };
            match (
                assignment_value(then_statement),
                assignment_value(else_statement),
            ) {
                (
                    Some(AssignmentValue::Register(then_dst, then_src)),
                    Some(AssignmentValue::Register(else_dst, else_src)),
                ) if then_dst == else_dst => Some(Stmt::Assign {
                    dst: then_dst.clone(),
                    src: make_select(cond, then_src, else_src),
                }),
                (
                    Some(AssignmentValue::PromotedLocal(then_dst, then_src, then_size)),
                    Some(AssignmentValue::PromotedLocal(else_dst, else_src, else_size)),
                ) if then_dst == else_dst && then_size == else_size => Some(Stmt::Store {
                    addr: Expr::Reg(then_dst.clone()),
                    src: make_select(cond, then_src, else_src),
                    size: then_size,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

enum AssignmentValue<'a> {
    Register(&'a VReg, &'a Expr),
    PromotedLocal(&'a VReg, &'a Expr, u8),
}

fn assignment_value(statement: &Stmt) -> Option<AssignmentValue<'_>> {
    match statement {
        Stmt::Assign { dst, src } => Some(AssignmentValue::Register(dst, src)),
        Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            src,
            size,
        } if is_promoted_local(name) => Some(AssignmentValue::PromotedLocal(dst, src, *size)),
        _ => None,
    }
}

fn is_promoted_local(name: &str) -> bool {
    name.starts_with("local_") || name.starts_with("stack_")
}

fn make_select(cond: &Expr, if_true: &Expr, if_false: &Expr) -> Expr {
    Expr::Select {
        cond: Box::new(cond.clone()),
        if_true: Box::new(if_true.clone()),
        if_false: Box::new(if_false.clone()),
        width: select_width(if_true, if_false),
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
    fn a_non_return_assignment_diamond_becomes_a_select() {
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

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Assign {
                    dst,
                    src: Expr::Select { .. },
                }) if dst == &reg("scratch")
            ),
            "nonterminal value diamonds are still exact selects: {:?}",
            f.body
        );
    }

    #[test]
    fn promoted_local_assignment_diamond_becomes_a_nonterminal_select() {
        let local = reg("local_2c");
        let store = |value| Stmt::Store {
            addr: Expr::Reg(local.clone()),
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = function(vec![
            Stmt::If {
                cond: Expr::Reg(reg("is_b")),
                then_body: vec![store(2)],
                else_body: Some(vec![store(0)]),
            },
            Stmt::Store {
                addr: Expr::Reg(reg("local_state")),
                src: Expr::Reg(local.clone()),
                size: 4,
            },
            return_reg("local_state"),
        ]);

        collapse_assignment_diamonds(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Store {
                    addr: Expr::Reg(destination),
                    src: Expr::Select { .. },
                    size: 4,
                }) if destination == &local
            ),
            "same-local stores should become one lazy value select: {:?}",
            f.body
        );
    }

    #[test]
    fn an_overwritten_diamond_can_collapse_before_later_dse() {
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

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Assign {
                dst,
                src: Expr::Select { .. }
            }) if dst == &reg("result")
        ));
        assert_eq!(f.body[1..], [overwrite, terminal_return]);
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
