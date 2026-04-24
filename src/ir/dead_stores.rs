//! Intra-body dead-store elimination.
//!
//! A store (`Stmt::Assign { dst: D, ... }`) is dead when the value written to
//! `D` is never read before the next write to `D` — or before the end of the
//! body. This pass conservatively removes such stores inside a single
//! `Vec<Stmt>`, recursing into If/While arms.
//!
//! Scope (v1):
//!
//! * We walk forward within a body. For each assignment to some register
//!   `D`, we scan forward: if we see a read of `D` first, the store is
//!   **live**; if we see another write to `D` (or a `Stmt::Call` that
//!   writes `D` by convention) with no prior read, the store is **dead**
//!   and we delete it.
//! * Stmt::Call is treated as reading every regisdt listed in its `args`
//!   (already explicit in the AST) and — for the current architecture's
//!   return-value register — as *writing* it. That is enough to collapse
//!   the common `%ret = 0; call foo(); %ret = 0; call bar();` shape.
//! * We never cross a nested If/While boundary. Any read inside such a
//!   nested body flushes our analysis for that variable (we conservatively
//!   treat the store as live).
//! * We never remove flag-VReg writes — those are handled by the dedicated
//!   `dce` pass which already understands their locality.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

/// Run dead-store elimination for the given calling convention.
pub fn eliminate_dead_stores(f: &mut Function, cc: CallConv) {
    let ret_regs = return_reg_aliases(cc);
    eliminate_body(&mut f.body, &ret_regs);
}

fn return_reg_aliases(cc: CallConv) -> Vec<&'static str> {
    match cc {
        CallConv::SysVAmd64 => vec!["rax", "eax", "ax", "al", "ret"],
        CallConv::Aarch64 => vec!["x0", "w0", "arg0", "ret"],
    }
}

fn eliminate_body(body: &mut Vec<Stmt>, ret_regs: &[&str]) {
    // Recurse first so inner bodies drive their own analyses.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                eliminate_body(then_body, ret_regs);
                if let Some(eb) = else_body {
                    eliminate_body(eb, ret_regs);
                }
            }
            Stmt::While { body, .. } => eliminate_body(body, ret_regs),
            _ => {}
        }
    }

    // Pre-pass: drop ABI-bookkeeping zero stores to frame-/link-registers
    // that are never read elsewhere in the body. These are emitted by glibc's
    // `_start` to establish a sentinel frame and are always dead from the
    // visible-C semantics view.
    drop_unread_abi_zeros(body);

    let mut i = 0;
    while i < body.len() {
        // Drop `%X = %X` self-assigns unconditionally — they have no
        // side effect and appear after naming collapses two aliases onto
        // the same role-name (e.g. `%edi` and `%rdi` both becoming `%arg0`).
        if matches!(
            &body[i],
            Stmt::Assign { dst, src: Expr::Reg(r) } if dst == r
        ) {
            body.remove(i);
            continue;
        }
        let dst = match &body[i] {
            Stmt::Assign { dst, .. } => match dst {
                // Only regular register writes are considered. Flag writes
                // are handled elsewhere.
                VReg::Phys(_) | VReg::Temp(_) => dst.clone(),
                VReg::Flag(_) => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        if is_dead_from(body, i + 1, &dst, ret_regs) {
            body.remove(i);
            continue;
        }
        i += 1;
    }
}

/// True when the register `dst` is demonstrably overwritten before any
/// read, starting at index `start` in `body`.
fn is_dead_from(body: &[Stmt], start: usize, dst: &VReg, ret_regs: &[&str]) -> bool {
    for j in start..body.len() {
        let s = &body[j];

        // Any read of dst in this statement means the earlier store is
        // live — stop and report "not dead."
        if stmt_reads(s, dst) {
            return false;
        }

        // An assignment that overwrites dst without reading it first kills
        // the earlier store.
        if let Stmt::Assign { dst: d2, .. } = s {
            if d2 == dst {
                return true;
            }
        }

        // A call in the body is treated as writing the return register.
        if matches!(s, Stmt::Call { .. }) {
            if let VReg::Phys(name) = dst {
                if ret_regs.iter().any(|r| r == name) {
                    return true;
                }
            }
        }

        // Nested If / While bodies are opaque — if the variable is read
        // anywhere inside, we have to keep the store. If it's written
        // inside without being read, we *don't* claim death (the write may
        // be on only one path).
        if contains_nested_read(s, dst) {
            return false;
        }

        // Control-flow sinks — if we hit Return / Goto, further reads are
        // off-limits for our intra-body analysis, so we treat the store as
        // live to be safe (except Return whose value obviously reads some
        // reg already covered by `stmt_reads`).
        if matches!(s, Stmt::Return { .. } | Stmt::Goto { .. }) {
            return false;
        }
    }
    // End-of-body: conservatively assume the value may escape.
    false
}

/// Names of frame- and link-registers (and their aliases after naming) for
/// which a top-level `%X = 0;` is ABI bookkeeping when unread.
const ABI_BOOKKEEPING_REGS: &[&str] = &[
    "fp", "lr", "x29", "x30", "w29", "w30", "rbp", "ebp",
];

fn drop_unread_abi_zeros(body: &mut Vec<Stmt>) {
    // Collect the offsets of qualifying stmts, then decide for each one
    // whether the register is ever read in the remaining body. We scan each
    // candidate against the full body in-place; no need to worry about
    // earlier removals invalidating later indices since we process back-to-
    // front.
    let candidates: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match s {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src: Expr::Const(0),
            } if ABI_BOOKKEEPING_REGS.iter().any(|r| r == name) => Some(i),
            _ => None,
        })
        .collect();
    let mut to_drop: Vec<usize> = Vec::new();
    for &i in &candidates {
        let name = if let Stmt::Assign { dst: VReg::Phys(n), .. } = &body[i] {
            n.clone()
        } else {
            continue;
        };
        let reg = VReg::Phys(name);
        // Is the register read anywhere else in the body (ignoring the
        // store itself)?
        let any_read = body
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .any(|(_, s)| stmt_reads(s, &reg));
        if !any_read {
            to_drop.push(i);
        }
    }
    // Drop back-to-front so indices stay valid.
    for i in to_drop.into_iter().rev() {
        body.remove(i);
    }
}

fn stmt_reads(s: &Stmt, dst: &VReg) -> bool {
    match s {
        Stmt::Assign { src, .. } => expr_reads(src, dst),
        Stmt::Store { addr, src } => expr_reads(addr, dst) || expr_reads(src, dst),
        Stmt::Call { target, args } => {
            expr_reads(target, dst) || args.iter().any(|a| expr_reads(a, dst))
        }
        Stmt::Return { value } => value.as_ref().is_some_and(|e| expr_reads(e, dst)),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_reads(cond, dst)
                || then_body.iter().any(|s| stmt_reads(s, dst))
                || else_body
                    .as_ref()
                    .is_some_and(|eb| eb.iter().any(|s| stmt_reads(s, dst)))
        }
        Stmt::While { cond, body } => {
            expr_reads(cond, dst) || body.iter().any(|s| stmt_reads(s, dst))
        }
        Stmt::Push { value } => expr_reads(value, dst),
        Stmt::Pop { target: t } => t == dst,
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
    }
}

fn contains_nested_read(s: &Stmt, dst: &VReg) -> bool {
    match s {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(|s| stmt_reads(s, dst))
                || else_body
                    .as_ref()
                    .is_some_and(|eb| eb.iter().any(|s| stmt_reads(s, dst)))
        }
        Stmt::While { body, .. } => body.iter().any(|s| stmt_reads(s, dst)),
        _ => false,
    }
}

fn expr_reads(e: &Expr, dst: &VReg) -> bool {
    match e {
        Expr::Reg(r) => r == dst,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } => base.as_ref() == Some(dst) || index.as_ref() == Some(dst),
        Expr::Deref { addr, .. } => expr_reads(addr, dst),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads(lhs, dst) || expr_reads(rhs, dst)
        }
        Expr::Un { src, .. } => expr_reads(src, dst),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn assign_overwritten_without_read_is_removed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(2),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(2));
        }
    }

    #[test]
    fn read_between_assigns_keeps_both_alive() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Reg(reg("rax")),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(2),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 3, "both rax stores must survive");
    }

    #[test]
    fn ret_assign_before_call_is_dead() {
        // %ret = 0; call foo(...); — the call clobbers ret.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1, "dead ret store should be removed");
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn ret_assign_before_call_that_reads_ret_survives() {
        // %ret = 0; call foo(%ret); — ret is read by the call, so survive.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: vec![Expr::Reg(reg("ret"))],
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn non_return_reg_before_call_survives() {
        // %rbx = 0; call foo(); — call doesn't clobber rbx, so keep it.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn repeated_pre_call_ret_zeros_all_collapse() {
        // The actual c2_demo shape: %ret = 0; call A(); %ret = 0; call B();
        // Both %ret assignments are dead.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "A".into(),
                    },
                    args: Vec::new(),
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "B".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
        assert!(matches!(&f.body[1], Stmt::Call { .. }));
    }

    #[test]
    fn nested_if_read_blocks_elimination() {
        // %rax = 0; if (cond) { use %rax } %rax = 1;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(0),
                },
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Call {
                        target: Expr::Named {
                            va: 0,
                            name: "foo".into(),
                        },
                        args: vec![Expr::Reg(reg("rax"))],
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 3, "inner read must preserve the outer store");
    }

    #[test]
    fn self_assign_is_removed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rax")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn assign_to_different_reg_is_preserved_even_if_other_side_is_same_name() {
        // `%rax = %rbx` must stay — only exact-identity self-assigns collapse.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: Expr::Reg(reg("rbx")),
            }],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
    }

    #[test]
    fn abi_fp_zero_with_no_read_is_dropped() {
        let mut f = Function {
            name: "_start".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: reg("lr"),
                    src: Expr::Const(0),
                },
                Stmt::Return { value: None },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Return { .. }));
    }

    #[test]
    fn abi_fp_zero_with_a_read_survives() {
        // If fp is read later, the zero store is real and must stay.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: vec![Expr::Reg(reg("fp"))],
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn aarch64_ret_alias_x0_is_clobbered_by_call() {
        // Aarch64: x0 is both arg0 and ret. After role naming arg0 is the
        // conventional alias. The AArch64 return-reg list includes `ret`,
        // `arg0`, and `x0`/`w0` — so an `arg0 = 0; call foo();` pair is
        // eliminated on AArch64 too.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("arg0"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
    }
}
