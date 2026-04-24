//! Re-materialise the lifted push/pop idioms.
//!
//! The x86 lifter decomposes `push rax` into a pair:
//!
//! ```text
//!   rsp = rsp - 8;
//!   store [rsp] = rax;
//! ```
//!
//! After stack-local promotion rewrites `[rsp]` into `%stack_top`, that pair
//! reads as:
//!
//! ```text
//!   %rsp = %rsp - 8;
//!   store %stack_top = %rax;
//! ```
//!
//! This pass recognises that shape and collapses it back into `Stmt::Push`,
//! which the printer renders as a single `push %rax;` line. The mirror for
//! `pop %X` matches:
//!
//! ```text
//!   %X = %stack_top;    (i.e. the stack-local load)
//!   %rsp = %rsp + 8;
//! ```
//!
//! The pass must run *after* [`super::stack_locals::promote_stack_locals`]
//! (which produces the `%stack_top` alias) and after
//! [`super::naming::apply_role_names`] (which preserves `stack_*` names).

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, VReg};

/// Run the pass in place over `f`'s body and every nested arm.
pub fn rematerialise_stack_ops(f: &mut Function) {
    rematerialise_body(&mut f.body);
    drop_epilogue_rsp_adjust(&mut f.body);
}

/// Remove a trailing `%rsp = %rsp + N;` that sits immediately before a
/// `Stmt::Return`. The adjustment is a callee-side bookkeeping write with
/// no visible effect in decompiled C-level output. Also handles the same
/// pattern when the return sits inside an arm.
fn drop_epilogue_rsp_adjust(body: &mut Vec<Stmt>) {
    // Recurse first so inner arms are simplified independently.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_epilogue_rsp_adjust(then_body);
                if let Some(eb) = else_body {
                    drop_epilogue_rsp_adjust(eb);
                }
            }
            Stmt::While { body, .. } => drop_epilogue_rsp_adjust(body),
            _ => {}
        }
    }
    // Walk backwards and drop qualifying `rsp += N;` stmts that sit
    // immediately before a Return.
    let mut i = body.len();
    while i >= 2 {
        i -= 1;
        if matches!(&body[i], Stmt::Return { .. }) {
            if i >= 1 && is_rsp_add_width(&body[i - 1]) {
                body.remove(i - 1);
                i = i.saturating_sub(1);
            }
        }
    }
}

fn rematerialise_body(body: &mut Vec<Stmt>) {
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                rematerialise_body(then_body);
                if let Some(eb) = else_body {
                    rematerialise_body(eb);
                }
            }
            Stmt::While { body, .. } => rematerialise_body(body),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        // Push: `rsp = rsp - N;` then `store %stack_top = X;`.
        if is_rsp_sub_width(&body[i]) {
            if let Stmt::Store {
                addr: Expr::Reg(slot),
                src,
            } = &body[i + 1]
            {
                if is_stack_top(slot) {
                    let value = src.clone();
                    body.remove(i + 1);
                    body[i] = Stmt::Push { value };
                    i += 1;
                    continue;
                }
            }
        }
        // Pop: `%X = %stack_top;` then `rsp = rsp + N;`.
        if let Stmt::Assign {
            dst,
            src: Expr::Reg(slot),
        } = &body[i]
        {
            if is_stack_top(slot) && is_phys_reg(dst) {
                if is_rsp_add_width(&body[i + 1]) {
                    let target = dst.clone();
                    body.remove(i + 1);
                    body[i] = Stmt::Pop { target };
                    i += 1;
                    continue;
                }
            }
        }
        i += 1;
    }
}

fn is_phys_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(_))
}

fn is_stack_top(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "stack_top")
}

fn is_stack_ptr(v: &VReg) -> bool {
    matches!(v, VReg::Phys(n) if n == "rsp" || n == "esp" || n == "sp")
}

/// `Stmt::Assign { dst: rsp, src: Bin { Sub, Reg(rsp), Const(N) } }` with N>0.
fn is_rsp_sub_width(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Assign {
            dst,
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            },
        } if is_stack_ptr(dst)
            && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
            && matches!(rhs.as_ref(), Expr::Const(n) if *n > 0)
    )
}

/// `Stmt::Assign { dst: rsp, src: Bin { Add, Reg(rsp), Const(N) } }` with N>0.
fn is_rsp_add_width(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Assign {
            dst,
            src: Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            },
        } if is_stack_ptr(dst)
            && matches!(lhs.as_ref(), Expr::Reg(r) if r == dst)
            && matches!(rhs.as_ref(), Expr::Const(n) if *n > 0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn rsp_sub(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }
    fn rsp_add(n: i64) -> Stmt {
        Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(n)),
            },
        }
    }

    #[test]
    fn push_pair_collapses_to_push_stmt() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_sub(8),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_top")),
                    src: Expr::Reg(reg("rbp")),
                },
            ],
        };
        rematerialise_stack_ops(&mut f);
        assert_eq!(f.body.len(), 1);
        match &f.body[0] {
            Stmt::Push { value } => assert_eq!(*value, Expr::Reg(reg("rbp"))),
            other => panic!("expected Push, got {:?}", other),
        }
    }

    #[test]
    fn pop_pair_collapses_to_pop_stmt() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_top")),
                },
                rsp_add(8),
            ],
        };
        rematerialise_stack_ops(&mut f);
        assert_eq!(f.body.len(), 1);
        match &f.body[0] {
            Stmt::Pop { target } => assert_eq!(*target, reg("rbp")),
            other => panic!("expected Pop, got {:?}", other),
        }
    }

    #[test]
    fn non_matching_rsp_stores_are_untouched() {
        // `rsp = rsp - 8;` alone (no following store) must stay.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![rsp_sub(8), Stmt::Nop],
        };
        let orig = f.clone();
        rematerialise_stack_ops(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn store_to_other_slot_does_not_collapse() {
        // `rsp -= 8; store %stack_5 = X` — not stack_top, so no push.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_sub(8),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_5")),
                    src: Expr::Reg(reg("rbp")),
                },
            ],
        };
        let orig = f.clone();
        rematerialise_stack_ops(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn pop_followed_by_other_rsp_op_does_not_collapse() {
        // `%rbp = %stack_top; %rsp = %rsp - 8;` (sub not add) — not a pop.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_top")),
                },
                rsp_sub(8),
            ],
        };
        let orig = f.clone();
        rematerialise_stack_ops(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn trailing_rsp_adjust_before_return_is_dropped() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(32),
                Stmt::Return { value: None },
            ],
        };
        rematerialise_stack_ops(&mut f);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Return { .. }));
    }

    #[test]
    fn trailing_rsp_adjust_inside_if_arm_is_dropped() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![rsp_add(16), Stmt::Return { value: None }],
                else_body: None,
            }],
        };
        rematerialise_stack_ops(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[0] {
            assert_eq!(then_body.len(), 1);
            assert!(matches!(&then_body[0], Stmt::Return { .. }));
        } else {
            panic!("expected If");
        }
    }

    #[test]
    fn rsp_adjust_not_before_return_survives() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![rsp_add(16), Stmt::Nop],
        };
        let orig = f.clone();
        rematerialise_stack_ops(&mut f);
        assert_eq!(f, orig);
    }

    #[test]
    fn collapse_recurses_into_nested_if_bodies() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Const(1),
                then_body: vec![
                    rsp_sub(8),
                    Stmt::Store {
                        addr: Expr::Reg(reg("stack_top")),
                        src: Expr::Reg(reg("r12")),
                    },
                ],
                else_body: None,
            }],
        };
        rematerialise_stack_ops(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[0] {
            assert_eq!(then_body.len(), 1);
            assert!(matches!(&then_body[0], Stmt::Push { .. }));
        }
    }
}
