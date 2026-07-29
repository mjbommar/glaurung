//! Recover source-level loop forms from conservative structured AST lowering.
//!
//! The region lowerer must preserve loop-header work until later semantic passes
//! decide whether it can move.  Its safe fallback is therefore
//! `while (1) { pre; if (exit) break; body }`.  Copy propagation can eliminate a
//! pure reload-only `pre`, leaving the exit guard as the literal first statement.
//! At that point no motion or data-flow prediction is required: the guarded
//! infinite loop is exactly equivalent to `while (!exit) { body }`. This needs
//! no induction-variable guess: the guard is already the literal first statement
//! and its arm is exactly one `break`, so no work is moved or discarded.

use crate::ir::ast::{negate_cmp_expr, Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

/// Recover exact head-tested loops from their conservative guarded form.
///
/// This pass intentionally does not move, fold, or discard any statement before
/// the guard. If even one statement remains there, the conservative form stays
/// intact.
pub fn recover_head_tested_whiles(f: &mut Function) {
    recover_body(&mut f.body);
}

/// Promote a narrow, structurally exact counted-loop shape to `Stmt::For`.
///
/// The first A3 slice accepts only an adjacent initializer, a head guard (either
/// direct or the conservative `if (exit) break` form), and one unconditional
/// unit-increment tail iterator for the same variable. Returns and structured
/// switches are safe in the body: a return exits the function, and a switch's
/// implicit breaks do not bypass the loop iterator. Bodies containing an explicit
/// loop-level `break`, `goto`, or nested loop remain conservative: until
/// `continue` is represented explicitly, such control can bypass the tail
/// iterator and cannot safely become C `continue` semantics.
pub fn promote_for_loops(f: &mut Function) {
    promote_for_body(&mut f.body);
}

fn promote_for_body(stmts: &mut Vec<Stmt>) {
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                promote_for_body(then_body);
                if let Some(body) = else_body {
                    promote_for_body(body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => promote_for_body(body),
            Stmt::For { body, .. } => promote_for_body(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    promote_for_body(body);
                }
                if let Some(body) = default {
                    promote_for_body(body);
                }
            }
            _ => {}
        }
    }

    let mut index = 1;
    while index < stmts.len() {
        let Some(promoted) = for_candidate(&stmts[index - 1], &stmts[index]) else {
            index += 1;
            continue;
        };
        stmts.splice(index - 1..=index, [promoted]);
    }
}

fn for_candidate(init: &Stmt, loop_stmt: &Stmt) -> Option<Stmt> {
    let init_target = assigned_target(init)?;
    let Stmt::While { cond, body } = loop_stmt else {
        return None;
    };

    let (loop_cond, loop_body) = if matches!(cond, Expr::Const(1)) {
        let Stmt::If {
            cond: exit_cond,
            then_body,
            else_body: None,
        } = body.first()?
        else {
            return None;
        };
        if then_body.as_slice() != [Stmt::Break] {
            return None;
        }
        (negate_cmp_expr(exit_cond.clone()), &body[1..])
    } else {
        (cond.clone(), body.as_slice())
    };

    let (step, core_body) = loop_body.split_last()?;
    let step_target = assigned_target(step)?;
    if step_target != init_target
        || !is_unit_increment(step, step_target)
        || !contains_reg(&loop_cond, init_target)
        || core_body.iter().any(has_iterator_bypass)
    {
        return None;
    }

    Some(Stmt::For {
        init: Box::new(init.clone()),
        cond: loop_cond,
        step: Box::new(step.clone()),
        body: core_body.to_vec(),
    })
}

fn is_unit_increment(stmt: &Stmt, target: &VReg) -> bool {
    let src = match stmt {
        Stmt::Assign { src, .. } | Stmt::Store { src, .. } => src,
        _ => return false,
    };
    // Width-changing ops are part of the update's machine semantics and remain
    // intact in the `for` step. They should not hide the exact underlying
    // `i + 1` identity from shape recognition.
    fn without_casts(mut expr: &Expr) -> &Expr {
        while let Expr::Cast { expr: inner, .. } = expr {
            expr = inner;
        }
        expr
    }
    let src = without_casts(src);
    matches!(
        src,
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } if matches!(without_casts(lhs), Expr::Reg(read) if read == target)
            && matches!(rhs.as_ref(), Expr::Const(1))
    )
}

fn assigned_target(stmt: &Stmt) -> Option<&VReg> {
    match stmt {
        Stmt::Assign { dst, .. } => Some(dst),
        Stmt::Store {
            addr: Expr::Reg(dst @ VReg::Phys(name)),
            ..
        } if name.starts_with("local_") || name.starts_with("stack_") => Some(dst),
        _ => None,
    }
}

fn has_iterator_bypass(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Goto { .. } | Stmt::Break => true,
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(has_iterator_bypass)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_iterator_bypass))
        }
        Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } => true,
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(has_iterator_bypass))
                || default
                    .as_ref()
                    .is_some_and(|body| body.iter().any(has_iterator_bypass))
        }
        _ => false,
    }
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
                *cond = negate_cmp_expr(exit_cond.clone());
                body.remove(0);
            }
            Stmt::For { body, .. } => recover_body(body),
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
            | Stmt::IndirectGoto { .. }
            | Stmt::Goto { .. } => {}
        }
    }
}

fn contains_reg(expr: &Expr, target: &VReg) -> bool {
    match expr {
        Expr::Reg(reg) => reg == target,
        Expr::StackAddr { object, .. } => object == target,
        Expr::Deref { addr, .. } => contains_reg(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_reg(lhs, target) || contains_reg(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            contains_reg(cond, target)
                || contains_reg(if_true, target)
                || contains_reg(if_false, target)
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
    fn exact_first_exit_guard_recovers_incrementing_variable_bound_while() {
        let step = Stmt::Assign {
            dst: reg("i"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
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
                step.clone(),
            ],
        };
        let mut f = Function {
            name: "later_slice".into(),
            entry_va: 0,
            body: vec![original.clone()],
        };

        recover_head_tested_whiles(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("i"))),
                    rhs: Box::new(Expr::Reg(reg("n"))),
                },
                body: vec![step],
            }]
        );
    }

    #[test]
    fn promotes_a_guarded_counted_loop_with_adjacent_initializer() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let work = Stmt::Assign {
            dst: reg("sum"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("sum"))),
                rhs: Box::new(Expr::Reg(induction.clone())),
            },
        };
        let mut f = Function {
            name: "counted".into(),
            entry_va: 0,
            body: vec![
                init.clone(),
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Sle,
                                lhs: Box::new(Expr::Reg(reg("n"))),
                                rhs: Box::new(Expr::Reg(induction.clone())),
                            },
                            then_body: vec![Stmt::Break],
                            else_body: None,
                        },
                        work.clone(),
                        step.clone(),
                    ],
                },
            ],
        };

        promote_for_loops(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(induction)),
                    rhs: Box::new(Expr::Reg(reg("n"))),
                },
                step: Box::new(step),
                body: vec![work],
            }]
        );
    }

    #[test]
    fn promotes_counted_loop_with_switch_and_early_return() {
        let induction = reg("local_i");
        let init = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Const(0),
            size: 4,
        };
        let step = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
            size: 4,
        };
        let switch = Stmt::Switch {
            discriminant: Expr::Reg(reg("state")),
            cases: vec![
                (Some(0), vec![Stmt::Nop]),
                (
                    Some(1),
                    vec![Stmt::Return {
                        value: Some(Expr::Const(1)),
                    }],
                ),
            ],
            default: None,
        };
        let condition = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(induction.clone())),
            rhs: Box::new(Expr::Reg(reg("n"))),
        };
        let mut function = Function {
            name: "fsm".to_string(),
            entry_va: 0,
            body: vec![
                init.clone(),
                Stmt::While {
                    cond: condition.clone(),
                    body: vec![switch.clone(), step.clone()],
                },
            ],
        };

        promote_for_loops(&mut function);

        assert_eq!(
            function.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond: condition,
                step: Box::new(step),
                body: vec![switch],
            }]
        );
    }

    #[test]
    fn explicit_width_casts_do_not_hide_a_unit_increment() {
        let induction = reg("local_i");
        let step = Stmt::Store {
            addr: Expr::Reg(induction.clone()),
            src: Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Cast {
                    signed: false,
                    width: 4,
                    expr: Box::new(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(induction.clone())),
                        rhs: Box::new(Expr::Const(1)),
                    }),
                }),
            },
            size: 4,
        };

        assert!(is_unit_increment(&step, &induction));
    }

    #[test]
    fn operand_width_casts_do_not_hide_a_unit_increment() {
        let induction = reg("local_i");
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Cast {
                    signed: false,
                    width: 8,
                    expr: Box::new(Expr::Cast {
                        signed: false,
                        width: 4,
                        expr: Box::new(Expr::Reg(induction.clone())),
                    }),
                }),
                rhs: Box::new(Expr::Const(1)),
            },
        };

        assert!(is_unit_increment(&step, &induction));
    }

    #[test]
    fn a_memory_store_is_not_an_induction_variable_assignment() {
        let pointer = reg("ptr");
        let init = Stmt::Store {
            addr: Expr::Reg(pointer.clone()),
            src: Expr::Const(0),
            size: 4,
        };
        let step = Stmt::Store {
            addr: Expr::Reg(pointer.clone()),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(pointer.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
            size: 4,
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Reg(pointer)),
                rhs: Box::new(Expr::Reg(reg("end"))),
            },
            body: vec![step],
        };
        let mut f = Function {
            name: "memory_store".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn a_body_goto_that_can_bypass_the_iterator_blocks_promotion() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Reg(induction)),
                rhs: Box::new(Expr::Reg(reg("n"))),
            },
            body: vec![
                Stmt::If {
                    cond: Expr::Reg(reg("skip")),
                    then_body: vec![Stmt::Goto { target: 0x1000 }],
                    else_body: None,
                },
                step,
            ],
        };
        let mut f = Function {
            name: "continue_like_goto".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn a_decrementing_source_while_stays_a_while_in_the_first_a3_slice() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(10),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let original_loop = Stmt::While {
            cond: Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(0)),
                rhs: Box::new(Expr::Reg(induction)),
            },
            body: vec![step],
        };
        let mut f = Function {
            name: "source_while".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop.clone()],
        };

        promote_for_loops(&mut f);

        assert_eq!(f.body, vec![init, original_loop]);
    }

    #[test]
    fn right_handed_accumulator_does_not_block_exact_for_recovery() {
        let induction = reg("i");
        let init = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: induction.clone(),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction.clone())),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let cond = Expr::Cmp {
            op: CmpOp::Slt,
            lhs: Box::new(Expr::Reg(induction.clone())),
            rhs: Box::new(Expr::Reg(reg("n"))),
        };
        let update = Stmt::Assign {
            dst: reg("sum"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(induction)),
                rhs: Box::new(Expr::Reg(reg("sum"))),
            },
        };
        let original_loop = Stmt::While {
            cond: cond.clone(),
            body: vec![update.clone(), step.clone()],
        };
        let mut f = Function {
            name: "right_handed".into(),
            entry_va: 0,
            body: vec![init.clone(), original_loop],
        };
        promote_for_loops(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::For {
                init: Box::new(init),
                cond,
                step: Box::new(step),
                body: vec![update],
            }]
        );
    }
}
