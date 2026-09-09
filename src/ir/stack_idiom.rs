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

use crate::ir::ast::{Expr, Function, OriginSet, Stmt};
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
        match s.semantic_mut() {
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
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => drop_epilogue_rsp_adjust(body),
            Stmt::For { body, .. } => drop_epilogue_rsp_adjust(body),
            _ => {}
        }
    }
    // Walk backwards and drop qualifying `rsp += N;` stmts that sit
    // immediately before a Return.
    let mut i = body.len();
    while i > 0 {
        i -= 1;
        if matches!(body[i].semantic(), Stmt::Return { .. }) {
            while i > 0 && is_rsp_add_width(&body[i - 1]) {
                body.remove(i - 1);
                i -= 1;
            }
        }
    }
}

fn rematerialise_body(body: &mut Vec<Stmt>) {
    for s in body.iter_mut() {
        match s.semantic_mut() {
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
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => rematerialise_body(body),
            Stmt::For { body, .. } => rematerialise_body(body),
            _ => {}
        }
    }

    let mut i = 0;
    while i + 1 < body.len() {
        // Push: `rsp = rsp - N;` then `store %stack_top = X;`.
        if is_rsp_sub_width(&body[i]) {
            if let Stmt::Store { addr, src, .. } = body[i + 1].semantic() {
                if let Expr::Reg(slot) = addr.semantic() {
                    if is_stack_top(slot) {
                        let mut value = src.clone();
                        if let Some(origins) = body[i + 1].origins() {
                            value.merge_origins(origins);
                        }
                        let origins = origins_of(&body[i..=i + 1]);
                        body.remove(i + 1);
                        body[i] = Stmt::Push { value }
                            .with_optional_origins((!origins.is_empty()).then_some(origins));
                        i += 1;
                        continue;
                    }
                }
            }
        }
        // Pop: `%X = %stack_top;` then `rsp = rsp + N;`.
        if let Stmt::Assign { dst, src } = body[i].semantic() {
            if let Expr::Reg(slot) = src.semantic() {
                if is_stack_top(slot) && is_phys_reg(dst) {
                    if is_rsp_add_width(&body[i + 1]) {
                        let target = dst.clone();
                        let origins = origins_of(&body[i..=i + 1]);
                        body.remove(i + 1);
                        body[i] = Stmt::Pop { target }
                            .with_optional_origins((!origins.is_empty()).then_some(origins));
                        i += 1;
                        continue;
                    }
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
        s.semantic(),
        Stmt::Assign {
            dst,
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs,
                rhs,
            },
        } if is_stack_ptr(dst)
            && matches!(lhs.semantic(), Expr::Reg(r) if r == dst)
            && matches!(rhs.semantic(), Expr::Const(n) if *n > 0)
    )
}

/// `Stmt::Assign { dst: rsp, src: Bin { Add, Reg(rsp), Const(N) } }` with N>0.
fn is_rsp_add_width(s: &Stmt) -> bool {
    matches!(
        s.semantic(),
        Stmt::Assign {
            dst,
            src: Expr::Bin {
                op: BinOp::Add,
                lhs,
                rhs,
            },
        } if is_stack_ptr(dst)
            && matches!(lhs.semantic(), Expr::Reg(r) if r == dst)
            && matches!(rhs.semantic(), Expr::Const(n) if *n > 0)
    )
}

fn origins_of(statements: &[Stmt]) -> OriginSet {
    statements
        .iter()
        .filter_map(Stmt::origins)
        .fold(OriginSet::empty(), |origins, next| origins.union(next))
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
                    size: 8,
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
    fn attributed_push_pair_unions_instruction_origins() {
        let source_owner = OriginSet::one(0x0ffc);
        let store_owner = OriginSet::one(0x1004);
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_sub(8).with_origins(OriginSet::one(0x1000)),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_top")),
                    src: Expr::Reg(reg("rbp")).with_origins(source_owner.clone()),
                    size: 8,
                }
                .with_origins(store_owner.clone()),
            ],
        };

        rematerialise_stack_ops(&mut f);

        assert_eq!(f.body.len(), 1);
        let Stmt::Push { value } = f.body[0].semantic() else {
            panic!("expected attributed push: {:#?}", f.body)
        };
        assert!(matches!(value.semantic(), Expr::Reg(register) if register == &reg("rbp")));
        assert_eq!(value.origins(), Some(&source_owner.union(&store_owner)));
        assert_eq!(
            f.body[0].origins().expect("push origins").addresses(),
            &[0x1000, 0x1004]
        );
    }

    #[test]
    fn attributed_stack_operands_still_rematerialize_push_and_drop_epilogue_adjustment() {
        let owner = OriginSet::one(0x1000);
        let attributed_adjustment = |op| Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op,
                lhs: Box::new(Expr::Reg(reg("rsp")).with_origins(owner.clone())),
                rhs: Box::new(Expr::Const(8).with_origins(owner.clone())),
            },
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                attributed_adjustment(BinOp::Sub),
                Stmt::Store {
                    addr: Expr::Reg(reg("stack_top")).with_origins(owner.clone()),
                    src: Expr::Reg(reg("rbp")),
                    size: 8,
                },
                attributed_adjustment(BinOp::Add),
                Stmt::Return { value: None },
            ],
        };

        rematerialise_stack_ops(&mut f);

        assert_eq!(f.body.len(), 2, "stack bookkeeping survived: {:#?}", f.body);
        assert!(matches!(f.body[0].semantic(), Stmt::Push { .. }));
        assert!(matches!(f.body[1].semantic(), Stmt::Return { .. }));
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
                    size: 8,
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
            body: vec![rsp_add(32), Stmt::Return { value: None }],
        };
        rematerialise_stack_ops(&mut f);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Return { .. }));
    }

    #[test]
    fn complete_trailing_rsp_adjust_run_before_return_is_dropped() {
        // Omit-frame-pointer functions can restore several callee-saved
        // registers with adjacent pops.  Once dead restore loads have been
        // removed, each pop leaves one machine-only `rsp += 8` spelling.  The
        // complete adjacent run, not merely its final member, belongs to the
        // epilogue and must disappear from source-level C.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                rsp_add(8),
                rsp_add(8),
                rsp_add(8),
                rsp_add(8),
                Stmt::Return { value: None },
            ],
        };

        rematerialise_stack_ops(&mut f);

        assert_eq!(f.body, vec![Stmt::Return { value: None }]);
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
                        size: 8,
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
