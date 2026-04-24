//! Reconstruct call arguments by folding the immediately-preceding
//! argument-register assignments into each `Stmt::Call`.
//!
//! The pass is intentionally conservative: it only folds an assignment when
//!
//! 1. the assignment's destination is a calling-convention argument
//!    register (x86-64 SysV: rdi/rsi/rdx/rcx/r8/r9; AArch64: x0..x7), and
//! 2. that register is not read between the assignment and the call, and
//! 3. no intervening statement has a side effect we can't reason about
//!    (calls, stores are treated as a barrier to keep the transformation
//!    semantically safe).
//!
//! A 32-bit sub-register write (e.g. `%esi = 0`) also counts as writing the
//! corresponding 64-bit arg register because on x86-64 the upper 32 bits of
//! every GPR are zeroed by a 32-bit write.
//!
//! After running, `call foo` becomes `call foo(arg0, arg1, …)` with args
//! populated in calling-convention order.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Calling-convention argument registers in positional order. We include the
/// common 32-/8-bit sub-register names so a `%edi = ...` write is recognised
/// as writing the same logical parameter slot as `%rdi = ...`.
const X86_64_ARG_SLOTS: &[&[&str]] = &[
    &["rdi", "edi", "di", "dil"],
    &["rsi", "esi", "si", "sil"],
    &["rdx", "edx", "dx", "dl"],
    &["rcx", "ecx", "cx", "cl"],
    &["r8", "r8d", "r8w", "r8b"],
    &["r9", "r9d", "r9w", "r9b"],
];

const AARCH64_ARG_SLOTS: &[&[&str]] = &[
    &["x0", "w0"],
    &["x1", "w1"],
    &["x2", "w2"],
    &["x3", "w3"],
    &["x4", "w4"],
    &["x5", "w5"],
    &["x6", "w6"],
    &["x7", "w7"],
];

fn slot_of(arch: CallConv, name: &str) -> Option<usize> {
    let slots = match arch {
        CallConv::SysVAmd64 => X86_64_ARG_SLOTS,
        CallConv::Aarch64 => AARCH64_ARG_SLOTS,
    };
    slots.iter().position(|names| names.contains(&name))
}

fn all_slot_names(arch: CallConv) -> Vec<&'static str> {
    let slots = match arch {
        CallConv::SysVAmd64 => X86_64_ARG_SLOTS,
        CallConv::Aarch64 => AARCH64_ARG_SLOTS,
    };
    slots.iter().flat_map(|s| s.iter().copied()).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    SysVAmd64,
    Aarch64,
}

/// Run argument reconstruction on `f` using the given calling convention.
pub fn reconstruct_args(f: &mut Function, arch: CallConv) {
    fold_body(&mut f.body, arch);
}

fn fold_body(body: &mut Vec<Stmt>, arch: CallConv) {
    // Recurse into nested bodies first so we don't miss calls inside arms.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_body(then_body, arch);
                if let Some(eb) = else_body {
                    fold_body(eb, arch);
                }
            }
            Stmt::While { body, .. } => fold_body(body, arch),
            _ => {}
        }
    }

    // Find calls and walk backward from each to collect args.
    let mut call_positions: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(i, s)| if matches!(s, Stmt::Call { .. }) { Some(i) } else { None })
        .collect();

    // Process right-to-left so earlier indices stay stable as we remove
    // preceding arg assignments for a later call first.
    call_positions.reverse();
    for call_idx in call_positions {
        fold_one_call(body, call_idx, arch);
    }
}

fn fold_one_call(body: &mut Vec<Stmt>, call_idx: usize, arch: CallConv) {
    // Map slot → (stmt_index, expression) for assignments we will eat.
    let mut found: Vec<Option<(usize, Expr)>> = vec![None; match arch {
        CallConv::SysVAmd64 => X86_64_ARG_SLOTS.len(),
        CallConv::Aarch64 => AARCH64_ARG_SLOTS.len(),
    }];

    // Walk backwards from the call.
    let mut i = call_idx;
    while i > 0 {
        i -= 1;
        let stop = matches!(&body[i], Stmt::Call { .. }) || matches!(&body[i], Stmt::Store { .. });
        if let Stmt::Assign { dst, src } = &body[i] {
            if let VReg::Phys(name) = dst {
                if let Some(slot) = slot_of(arch, name.as_str()) {
                    if found[slot].is_none() {
                        // Before claiming this slot, make sure no already-
                        // captured arg expression reads this register. If
                        // one does, folding this assignment would leave a
                        // dangling reference in the higher slot's expr.
                        let would_dangle = found.iter().any(|f| {
                            f.as_ref().is_some_and(|(_, e)| reads_reg_in_expr(e, dst))
                        });
                        if !would_dangle {
                            found[slot] = Some((i, src.clone()));
                        }
                        continue;
                    }
                    // Second assignment to the same slot before the call —
                    // the later (earlier-indexed) one is live, so bail out.
                    break;
                }
            }
        }
        if stop {
            break;
        }
        // Also bail if any slot we've already claimed is read by this stmt
        // (its def-to-call window must be clean).
        let names: Vec<&str> = all_slot_names(arch);
        for slot in 0..found.len() {
            if found[slot].is_none() {
                continue;
            }
            // Check if any register in this slot is read here.
            for &n in &names {
                if slot_of(arch, n) != Some(slot) {
                    continue;
                }
                let target = VReg::Phys(n.to_string());
                if reads_reg_in_stmt(&body[i], &target) {
                    // Unsafe to fold — drop the slot and downstream args.
                    found[slot] = None;
                }
            }
        }
    }

    // Determine the maximum contiguous prefix of filled slots. We only
    // include slot N if slots 0..N-1 were also assigned; a gap means the
    // function probably doesn't use that argument, so trimming at the first
    // gap is the safe choice.
    let mut args_out: Vec<Expr> = Vec::new();
    let mut used_stmt_indices: Vec<usize> = Vec::new();
    for slot in &found {
        match slot {
            Some((stmt_idx, expr)) => {
                args_out.push(expr.clone());
                used_stmt_indices.push(*stmt_idx);
            }
            None => break,
        }
    }

    if args_out.is_empty() {
        return;
    }

    // Splice the args in.
    if let Stmt::Call { args, .. } = &mut body[call_idx] {
        *args = args_out;
    }

    // Remove the folded assigns. Sort descending to keep call_idx valid.
    used_stmt_indices.sort_by(|a, b| b.cmp(a));
    for idx in used_stmt_indices {
        body.remove(idx);
    }
}

fn reads_reg_in_expr(e: &Expr, target: &VReg) -> bool {
    match e {
        Expr::Reg(r) => r == target,
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } => {
            base.as_ref() == Some(target) || index.as_ref() == Some(target)
        }
        Expr::Deref { addr, .. } => reads_reg_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            reads_reg_in_expr(lhs, target) || reads_reg_in_expr(rhs, target)
        }
        Expr::Un { src, .. } => reads_reg_in_expr(src, target),
    }
}

fn reads_reg_in_stmt(s: &Stmt, target: &VReg) -> bool {
    match s {
        Stmt::Assign { src, .. } => reads_reg_in_expr(src, target),
        Stmt::Store { addr, src } => {
            reads_reg_in_expr(addr, target) || reads_reg_in_expr(src, target)
        }
        Stmt::Call {
            target: t,
            args,
        } => reads_reg_in_expr(t, target) || args.iter().any(|a| reads_reg_in_expr(a, target)),
        Stmt::Return { value } => value.as_ref().is_some_and(|e| reads_reg_in_expr(e, target)),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            reads_reg_in_expr(cond, target)
                || then_body.iter().any(|s| reads_reg_in_stmt(s, target))
                || else_body
                    .as_ref()
                    .is_some_and(|eb| eb.iter().any(|s| reads_reg_in_stmt(s, target)))
        }
        Stmt::While { cond, body } => {
            reads_reg_in_expr(cond, target)
                || body.iter().any(|s| reads_reg_in_stmt(s, target))
        }
        Stmt::Push { value } => reads_reg_in_expr(value, target),
        Stmt::Pop { target: t } => t == target,
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    fn assign(dst: &str, value: i64) -> Stmt {
        Stmt::Assign {
            dst: reg(dst),
            src: Expr::Const(value),
        }
    }

    #[test]
    fn folds_first_arg_before_direct_call() {
        // %rdi = 0x13d0 ; call main
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 0x13d0),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "main".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1, "assign not absorbed: {:?}", f.body);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(0x13d0));
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    #[test]
    fn folds_multiple_args_in_conventional_order() {
        // %rdi = 1 ; %rsi = 2 ; %rdx = 3 ; call foo
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rsi", 2),
                assign("rdx", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 3);
            assert_eq!(args[0], Expr::Const(1));
            assert_eq!(args[1], Expr::Const(2));
            assert_eq!(args[2], Expr::Const(3));
        }
    }

    #[test]
    fn stops_at_first_gap_in_arg_sequence() {
        // %rdi = 1 ; %rdx = 3 ; call foo  — only rdi folds (rsi is missing).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rdx", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // rdx assign must stay; rdi is folded.
        assert_eq!(f.body.len(), 2, "unexpected shape: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdx")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(1));
        }
    }

    #[test]
    fn fold_does_not_cross_intervening_call() {
        // %rdi = 1 ; call other ; call foo  — rdi must not fold into `foo`
        // because `other` clobbers it (we conservatively treat any call
        // between def and use as a barrier).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "other".into(),
                    },
                    args: Vec::new(),
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
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // `other` still has its rdi fold (legitimate); `foo` gets none.
        if let Stmt::Call { args, .. } = &f.body[f.body.len() - 1] {
            assert!(args.is_empty(), "foo() shouldn't have args: {:?}", f.body);
        }
    }

    #[test]
    fn sub_register_write_counts_as_arg_write() {
        // %edi = 0x2a ; call foo — %edi writes rdi's slot on x86-64.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("edi"),
                    src: Expr::Const(42),
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
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], Expr::Const(42));
        }
    }

    #[test]
    fn aarch64_folds_x0_argument() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Const(7),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args[0], Expr::Const(7));
        }
    }

    #[test]
    fn read_of_arg_reg_between_def_and_call_blocks_fold() {
        // %rdi = 1 ; %rsi = rdi + 2 ; call foo — rdi is read between the
        // assignment and the call, so folding it would move its value out
        // of sequence. Leave rdi's assign alone; rsi still folds.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                Stmt::Assign {
                    dst: reg("rsi"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rdi"))),
                        rhs: Box::new(Expr::Const(2)),
                    },
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
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // Since rdi can't fold, the slot-0 is empty, so nothing folds at all
        // (args are contiguous prefix).
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi")));
    }
}
