//! Reconstruct call arguments by folding the immediately-preceding
//! argument-register assignments into each `Stmt::Call`.
//!
//! The pass is intentionally conservative: it only folds an assignment when
//!
//! 1. the assignment's destination is a calling-convention argument
//!    register (x86-64 SysV: rdi/rsi/rdx/rcx/r8/r9; Windows x64:
//!    rcx/rdx/r8/r9; AArch64: x0..x7), and
//! 2. that register is not read between the assignment and the call, and
//! 3. no intervening statement has a side effect we can't reason about
//!    (calls are treated as a barrier to keep the transformation
//!    semantically safe).
//!
//! If a later slot was explicitly set but an earlier slot was never written
//! since the previous call boundary, the pass fills that earlier slot from
//! the function's incoming argument register. This covers common forwarding
//! shapes such as Win64 `rdx = 256; call strnlen`, where `rcx` still carries
//! the function's incoming first parameter.
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
const X86_64_SYSV_ARG_SLOTS: &[&[&str]] = &[
    &["rdi", "edi", "di", "dil"],
    &["rsi", "esi", "si", "sil"],
    &["rdx", "edx", "dx", "dl"],
    &["rcx", "ecx", "cx", "cl"],
    &["r8", "r8d", "r8w", "r8b"],
    &["r9", "r9d", "r9w", "r9b"],
];

const X86_64_WIN64_ARG_SLOTS: &[&[&str]] = &[
    &["rcx", "ecx", "cx", "cl"],
    &["rdx", "edx", "dx", "dl"],
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    SysVAmd64,
    Win64,
    Aarch64,
}

fn arg_slots(arch: CallConv) -> &'static [&'static [&'static str]] {
    match arch {
        CallConv::SysVAmd64 => X86_64_SYSV_ARG_SLOTS,
        CallConv::Win64 => X86_64_WIN64_ARG_SLOTS,
        CallConv::Aarch64 => AARCH64_ARG_SLOTS,
    }
}

fn slot_of(arch: CallConv, name: &str) -> Option<usize> {
    arg_slots(arch)
        .iter()
        .position(|names| names.contains(&name))
}

fn incoming_arg_expr(arch: CallConv, slot: usize) -> Option<Expr> {
    arg_slots(arch)
        .get(slot)
        .and_then(|names| names.first())
        .map(|name| Expr::Reg(VReg::Phys((*name).to_string())))
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
        .filter_map(|(i, s)| {
            if matches!(s, Stmt::Call { .. }) {
                Some(i)
            } else {
                None
            }
        })
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
    let mut found: Vec<Option<(usize, Expr)>> = vec![None; arg_slots(arch).len()];
    let mut read_between: Vec<bool> = vec![false; arg_slots(arch).len()];
    let mut blocked_incoming: Vec<bool> = vec![false; arg_slots(arch).len()];

    // Walk backwards from the call.
    let mut i = call_idx;
    while i > 0 {
        i -= 1;
        let stop = matches!(&body[i], Stmt::Call { .. });
        if let Stmt::Assign { dst, src } = &body[i] {
            if let VReg::Phys(name) = dst {
                if let Some(slot) = slot_of(arch, name.as_str()) {
                    if found[slot].is_none() {
                        // Before claiming this slot, make sure no already-
                        // captured arg expression reads this register. If
                        // one does, folding this assignment would leave a
                        // dangling reference in the higher slot's expr.
                        let would_dangle = found
                            .iter()
                            .any(|f| f.as_ref().is_some_and(|(_, e)| reads_reg_in_expr(e, dst)));
                        if !would_dangle && !read_between[slot] {
                            found[slot] = Some((i, src.clone()));
                        } else {
                            blocked_incoming[slot] = true;
                        }
                        mark_arg_reads_in_expr(src, arch, &mut read_between);
                        continue;
                    }
                    // Second assignment to the same slot before the call —
                    // the later (earlier-indexed) one is live, so bail out.
                    break;
                }
            }
            mark_arg_reads_in_expr(src, arch, &mut read_between);
        } else {
            mark_arg_reads_in_stmt(&body[i], arch, &mut read_between);
            mark_arg_writes_in_stmt(&body[i], arch, &mut blocked_incoming);
        }
        if stop {
            break;
        }
    }

    // Determine the maximum contiguous prefix of filled slots. We only
    // include slot N if slots 0..N-1 were also assigned; a gap means the
    // function probably doesn't use that argument, so trimming at the first
    // gap is the safe choice.
    let mut args_out: Vec<Expr> = Vec::new();
    let mut used_stmt_indices: Vec<usize> = Vec::new();
    let Some(last_filled_slot) = found.iter().rposition(Option::is_some) else {
        return;
    };
    for slot_idx in 0..=last_filled_slot {
        match &found[slot_idx] {
            Some((stmt_idx, expr)) => {
                args_out.push(expr.clone());
                used_stmt_indices.push(*stmt_idx);
            }
            None if args_out.is_empty() && !blocked_incoming[slot_idx] => {
                let Some(expr) = incoming_arg_expr(arch, slot_idx) else {
                    break;
                };
                args_out.push(expr);
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

fn mark_slot_write(reg: &VReg, arch: CallConv, blocked_incoming: &mut [bool]) {
    let VReg::Phys(name) = reg else {
        return;
    };
    if let Some(slot) = slot_of(arch, name.as_str()) {
        if let Some(blocked) = blocked_incoming.get_mut(slot) {
            *blocked = true;
        }
    }
}

fn mark_slot_read(reg: &VReg, arch: CallConv, read_between: &mut [bool]) {
    let VReg::Phys(name) = reg else {
        return;
    };
    if let Some(slot) = slot_of(arch, name.as_str()) {
        if let Some(read) = read_between.get_mut(slot) {
            *read = true;
        }
    }
}

fn mark_arg_reads_in_expr(e: &Expr, arch: CallConv, read_between: &mut [bool]) {
    match e {
        Expr::Reg(r) => mark_slot_read(r, arch, read_between),
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(base) = base {
                mark_slot_read(base, arch, read_between);
            }
            if let Some(index) = index {
                mark_slot_read(index, arch, read_between);
            }
        }
        Expr::Deref { addr, .. } => mark_arg_reads_in_expr(addr, arch, read_between),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            mark_arg_reads_in_expr(lhs, arch, read_between);
            mark_arg_reads_in_expr(rhs, arch, read_between);
        }
        Expr::Un { src, .. } => mark_arg_reads_in_expr(src, arch, read_between),
    }
}

fn mark_arg_reads_in_stmt(s: &Stmt, arch: CallConv, read_between: &mut [bool]) {
    match s {
        Stmt::Assign { src, .. } => mark_arg_reads_in_expr(src, arch, read_between),
        Stmt::Store { addr, src } => {
            mark_arg_reads_in_expr(addr, arch, read_between);
            mark_arg_reads_in_expr(src, arch, read_between);
        }
        Stmt::Call { target, args } => {
            mark_arg_reads_in_expr(target, arch, read_between);
            for arg in args {
                mark_arg_reads_in_expr(arg, arch, read_between);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                mark_arg_reads_in_expr(value, arch, read_between);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            mark_arg_reads_in_expr(cond, arch, read_between);
            for stmt in then_body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
            if let Some(else_body) = else_body {
                for stmt in else_body {
                    mark_arg_reads_in_stmt(stmt, arch, read_between);
                }
            }
        }
        Stmt::While { cond, body } => {
            mark_arg_reads_in_expr(cond, arch, read_between);
            for stmt in body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
        }
        Stmt::Push { value } => mark_arg_reads_in_expr(value, arch, read_between),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            mark_arg_reads_in_expr(discriminant, arch, read_between);
            for (_case, body) in cases {
                for stmt in body {
                    mark_arg_reads_in_stmt(stmt, arch, read_between);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    mark_arg_reads_in_stmt(stmt, arch, read_between);
                }
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

fn mark_arg_writes_in_stmt(s: &Stmt, arch: CallConv, blocked_incoming: &mut [bool]) {
    match s {
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            mark_slot_write(dst, arch, blocked_incoming);
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            for stmt in then_body {
                mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
            }
            if let Some(else_body) = else_body {
                for stmt in else_body {
                    mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                }
            }
        }
        Stmt::While { body, .. } => {
            for stmt in body {
                mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for (_case, body) in cases {
                for stmt in body {
                    mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                }
            }
        }
        Stmt::Store { .. }
        | Stmt::Call { .. }
        | Stmt::Return { .. }
        | Stmt::Push { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
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
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(target) || index.as_ref() == Some(target)
        }
        Expr::Deref { addr, .. } => reads_reg_in_expr(addr, target),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            reads_reg_in_expr(lhs, target) || reads_reg_in_expr(rhs, target)
        }
        Expr::Un { src, .. } => reads_reg_in_expr(src, target),
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
    fn win64_folds_rcx_rdx_r8_r9_in_windows_order() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                assign("rdx", 2),
                assign("r8", 3),
                assign("r9", 4),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(
                args,
                &vec![
                    Expr::Const(1),
                    Expr::Const(2),
                    Expr::Const(3),
                    Expr::Const(4)
                ]
            );
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    #[test]
    fn win64_does_not_treat_rdi_as_first_argument() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdi", 1),
                assign("rcx", 2),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args, &vec![Expr::Const(2)]);
        } else {
            panic!("expected Call, got {:?}", f.body[1]);
        }
    }

    #[test]
    fn win64_folds_args_across_unrelated_stores() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rax"))),
                        rhs: Box::new(Expr::Const(40)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rax")),
                        index: None,
                        scale: 1,
                        disp: 0x14,
                        segment: None,
                    },
                    src: Expr::Reg(reg("rbx")),
                },
                assign("r8", 3),
                assign("rdx", 256),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rax")),
                        index: None,
                        scale: 1,
                        disp: 0x18,
                        segment: None,
                    },
                    src: Expr::Reg(reg("r11")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strcpy_s".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert_eq!(f.body.len(), 3, "only unrelated stores and call remain");
        assert!(matches!(f.body[0], Stmt::Store { .. }));
        assert!(matches!(f.body[1], Stmt::Store { .. }));
        if let Stmt::Call { args, .. } = &f.body[2] {
            assert_eq!(args.len(), 3);
            assert_eq!(
                args[0],
                Expr::Bin {
                    op: crate::ir::types::BinOp::Add,
                    lhs: Box::new(Expr::Reg(reg("rax"))),
                    rhs: Box::new(Expr::Const(40)),
                }
            );
            assert_eq!(args[1], Expr::Const(256));
            assert_eq!(args[2], Expr::Const(3));
        } else {
            panic!("expected Call, got {:?}", f.body[2]);
        }
    }

    #[test]
    fn win64_fills_leading_incoming_arg_when_later_slot_is_set() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdx", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args, &vec![Expr::Reg(reg("rcx")), Expr::Const(256)]);
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    #[test]
    fn win64_does_not_fill_internal_argument_gap() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                assign("r8", 3),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("r8")));
        if let Stmt::Call { args, .. } = &f.body[1] {
            assert_eq!(args, &vec![Expr::Const(1)]);
        } else {
            panic!("expected Call, got {:?}", f.body[1]);
        }
    }

    #[test]
    fn win64_does_not_fold_arg_read_by_intervening_store() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rcx", 1),
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rcx")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(99),
                },
                assign("rdx", 2),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::Win64);

        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rcx")));
        assert!(matches!(&f.body[2], Stmt::Assign { dst, .. } if dst == &reg("rdx")));
        if let Stmt::Call { args, .. } = &f.body[3] {
            assert!(args.is_empty(), "call args should not fold: {:?}", f.body);
        } else {
            panic!("expected Call, got {:?}", f.body[3]);
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
