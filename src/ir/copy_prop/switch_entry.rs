//! Carry a dominating straight-line alias into the arms of a switch.
//!
//! The general walkers in the parent clear the environment at every
//! control-flow boundary, a switch included, because an arm is reached by an
//! edge. That is right in general and costs real quality in one specific place:
//! a compiler range guard sits in front of most jump tables, and once the
//! structuring passes remove it the discriminant's straight-line alias
//! (`t10 = local_3`) dies at the `switch` and every arm reloads it.
//!
//! This pass exists for exactly that shape, and its scope is deliberately
//! narrow. It seeds arms only from the *immediately dominating* linear prefix;
//! any other control flow in that prefix clears the set; and every loop -- in
//! the prefix, in an arm, or nested inside one -- is a hard barrier, because a
//! source that looks constant at loop entry may be updated by the body and is
//! therefore not invariant on later iterations.
//!
//! It runs late, after the guard removal it depends on, and cleans up after
//! itself with [`super::dead::eliminate_dead_copies`].

use crate::ir::ast::{Function, Stmt};

use super::dead::eliminate_dead_copies;
use super::env::{invalidate, is_pure_copyable, is_self_ref, Copies};
use super::subst::{subst, subst_store_addr};

/// Carry a straight-line pure alias into a following structured switch.
///
/// This deliberately narrow late-pipeline transform exists for switches whose
/// compiler range guard has just been removed. It never carries an alias into
/// or through a loop: a source that looks constant at loop entry may be updated
/// by the body and therefore is not invariant on later iterations.
pub fn propagate_switch_entry_copies(f: &mut Function) {
    if propagate_switch_entries_in_body(&mut f.body) {
        while eliminate_dead_copies(&mut f.body) {}
    }
}

/// Find switches in `body` and seed only their arms with aliases established by
/// the immediately dominating straight-line prefix. Other control flow clears
/// the environment; nested bodies are searched independently.
fn propagate_switch_entries_in_body(body: &mut [Stmt]) -> bool {
    let mut copies = Copies::new();
    let mut changed = false;
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                let mut resolved = src.clone();
                subst(&mut resolved, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(&resolved) && !is_self_ref(dst, &resolved) {
                    copies.insert(dst.clone(), resolved);
                }
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                changed |= !copies.is_empty();
                subst(discriminant, &copies);
                for (_, case_body) in cases {
                    propagate_switch_arm(case_body, &copies);
                }
                if let Some(default_body) = default {
                    propagate_switch_arm(default_body, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= propagate_switch_entries_in_body(then_body);
                if let Some(else_body) = else_body {
                    changed |= propagate_switch_entries_in_body(else_body);
                }
                copies.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                changed |= propagate_switch_entries_in_body(body);
                copies.clear();
            }
            Stmt::Comment(_) | Stmt::Nop => {}
            Stmt::Store { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Unknown(_) => copies.clear(),
            Stmt::Throw { .. } | Stmt::TryCatch { .. } => copies.clear(),
        }
    }
    changed
}

/// Apply switch-entry aliases within one arm. Nested branches inherit them,
/// while every loop is a hard barrier so no entry snapshot is mistaken for a
/// loop invariant.
fn propagate_switch_arm(body: &mut [Stmt], incoming: &Copies) {
    let mut copies = incoming.clone();
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(src) && !is_self_ref(dst, src) {
                    copies.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                subst_store_addr(addr, &copies);
                subst(src, &copies);
                copies.clear();
            }
            Stmt::Push { value } => {
                subst(value, &copies);
                copies.clear();
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    subst(value, &copies);
                }
            }
            Stmt::Pop { .. } => copies.clear(),
            Stmt::Call { target, args, .. } => {
                subst(target, &copies);
                for arg in args {
                    subst(arg, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                let incoming = copies.clone();
                propagate_switch_arm(then_body, &incoming);
                if let Some(else_body) = else_body {
                    propagate_switch_arm(else_body, &incoming);
                }
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                let incoming = copies.clone();
                for (_, case_body) in cases {
                    propagate_switch_arm(case_body, &incoming);
                }
                if let Some(default_body) = default {
                    propagate_switch_arm(default_body, &incoming);
                }
                copies.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                let _ = propagate_switch_entries_in_body(body);
                copies.clear();
            }
            Stmt::IndirectGoto { target } => {
                subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } | Stmt::Continue => copies.clear(),
            Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::Expr;
    use crate::ir::types::{BinOp, CmpOp, VReg};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn pure_prefix_copy_reaches_switch_arms_until_its_source_changes() {
        // Optimized switch lowering often snapshots an argument into a scratch
        // immediately before dispatch.  Every case is dominated by that copy,
        // so the alias is valid on entry to every arm.  An arm that overwrites
        // the source must still invalidate it before a later use.
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg2")),
                },
                Stmt::Switch {
                    discriminant: Expr::Reg(reg("arg0")),
                    cases: vec![
                        (
                            Some(0),
                            vec![Stmt::Return {
                                value: Some(Expr::Bin {
                                    op: BinOp::Add,
                                    lhs: Box::new(Expr::Reg(reg("var0"))),
                                    rhs: Box::new(Expr::Reg(reg("arg1"))),
                                }),
                            }],
                        ),
                        (
                            Some(1),
                            vec![
                                Stmt::Assign {
                                    dst: reg("arg2"),
                                    src: Expr::Const(7),
                                },
                                Stmt::Return {
                                    value: Some(Expr::Reg(reg("var0"))),
                                },
                            ],
                        ),
                    ],
                    default: None,
                },
            ],
        };

        propagate_switch_entry_copies(&mut f);

        assert!(
            matches!(
                &f.body[1],
                Stmt::Switch { cases, .. }
                    if matches!(
                        &cases[0].1[0],
                        Stmt::Return {
                            value: Some(Expr::Bin { lhs, .. })
                        } if matches!(lhs.as_ref(), Expr::Reg(source) if source == &reg("arg2"))
                    )
                    && matches!(
                        &cases[1].1[1],
                        Stmt::Return { value: Some(Expr::Reg(source)) }
                            if source == &reg("var0")
                    )
            ),
            "the incoming alias should reach an arm but stop at a source write: {:?}",
            f.body
        );
    }

    #[test]
    fn late_switch_copy_propagation_does_not_freeze_loop_carried_condition() {
        let mut f = Function {
            name: "find_first_set".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("var0"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    body: vec![Stmt::Assign {
                        dst: reg("var0"),
                        src: Expr::Bin {
                            op: BinOp::Shr,
                            lhs: Box::new(Expr::Reg(reg("var0"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }],
                },
            ],
        };

        let before = f.clone();
        propagate_switch_entry_copies(&mut f);

        assert_eq!(f, before, "a loop entry copy is not a loop invariant");
    }

    #[test]
    fn late_switch_copy_propagation_leaves_switchless_functions_untouched() {
        let mut f = Function {
            name: "unrelated".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("dead_scratch"),
                src: Expr::Const(1),
            }],
        };

        let before = f.clone();
        propagate_switch_entry_copies(&mut f);

        assert_eq!(f, before, "the late pass is switch-specific");
    }
}
