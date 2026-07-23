//! Role-based register renaming for the decompiled AST.
//!
//! After the earlier passes (lower → reconstruct → DCE → name-resolve →
//! call-arg → strings-fold) the body of a function still talks in raw
//! machine-register names (`%rax`, `%rdi`, `%x0`). That is faithful but not
//! legible — a human reader has to remember the calling convention to
//! understand which register means "argument 0" and which means "return
//! value". This pass rewrites those physical registers to role-based
//! names within the scope of a single function:
//!
//! * Return-value register → `ret`
//! * Argument-passing register N -> `argN` (rdi/rcx/x0 -> `arg0`,
//!   rsi/rdx/x1 -> `arg1`, ...)
//! * Stack-frame registers (`rsp`, `ebp`, `sp`, `x29`, …) keep their names —
//!   renaming them to `stack` would lose information.
//! * Any other GPR that still appears after earlier folding gets a stable
//!   `varN` alias assigned in first-appearance order.
//!
//! The rename is purely cosmetic — it does not alter the semantics of the
//! AST. `Expr::Reg(VReg::Phys("rdi"))` becomes `Expr::Reg(VReg::Phys("arg0"))`,
//! which the printer then shows as `%arg0`.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::VReg;

const STACK_KEEPERS: &[&str] = &[
    "rsp", "esp", "sp", "rbp", "ebp", "bp", "x29", "w29", "fp", "x30", "w30", "lr",
];

fn return_reg_aliases(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
        CallConv::Arm => &["r0"],
    }
}

fn arg_slot_tables(cc: CallConv) -> &'static [&'static [&'static str]] {
    match cc {
        CallConv::SysVAmd64 => &[
            &["rdi", "edi", "di", "dil"],
            &["rsi", "esi", "si", "sil"],
            &["rdx", "edx", "dx", "dl"],
            &["rcx", "ecx", "cx", "cl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Win64 => &[
            &["rcx", "ecx", "cx", "cl"],
            &["rdx", "edx", "dx", "dl"],
            &["r8", "r8d", "r8w", "r8b"],
            &["r9", "r9d", "r9w", "r9b"],
        ],
        CallConv::Aarch64 => &[
            &["x0", "w0"],
            &["x1", "w1"],
            &["x2", "w2"],
            &["x3", "w3"],
            &["x4", "w4"],
            &["x5", "w5"],
            &["x6", "w6"],
            &["x7", "w7"],
        ],
        CallConv::Arm => &[&["r0"], &["r1"], &["r2"], &["r3"]],
    }
}

/// Rename registers in `f` according to the given calling convention.
pub fn apply_role_names(f: &mut Function, cc: CallConv) {
    // Build the role map: raw name → friendly name. We build it up-front so
    // that every substitution is consistent across the function.
    let mut role: HashMap<String, String> = HashMap::new();

    // Only arg-passing registers that are genuine *live-in parameters* become
    // `argN`. A register in an argument slot that is written before it is ever
    // read is just scratch reuse of that ABI register (e.g. `cl` as a variable
    // shift count reuses `rcx`, the 4th SysV arg slot) and must NOT inflate the
    // recovered arity — it falls through to a `varN` alias below.
    let param_slots = live_in_arg_slots(&f.body, cc);
    // On AArch64 x0 serves as both arg0 and return value. We prefer `arg0`
    // because in a called function it's more often referenced as the input
    // than as the output slot.
    for (slot_idx, names) in arg_slot_tables(cc).iter().enumerate() {
        if !param_slots.contains(&slot_idx) {
            continue;
        }
        for name in *names {
            role.entry(name.to_string())
                .or_insert_with(|| format!("arg{}", slot_idx));
        }
    }
    for name in return_reg_aliases(cc) {
        // `ret` only wins if no arg-slot already claimed the name (x0 case
        // above keeps `arg0`).
        role.entry(name.to_string())
            .or_insert_with(|| "ret".to_string());
    }

    // Assign stable `varN` aliases for other physical registers in order of
    // first appearance. We walk the body in reading order.
    let mut counter = 0usize;
    let mut assign_var = |name: &str, role: &mut HashMap<String, String>| {
        if STACK_KEEPERS.contains(&name) {
            return;
        }
        // Names already allocated by the stack-slot promotion pass
        // (`stack_0`, `local_0`, `stack_top`) are meaningful — don't
        // rewrite them to generic varN.
        if name.starts_with("stack_") || name.starts_with("local_") {
            return;
        }
        if role.contains_key(name) {
            return;
        }
        let n = counter;
        counter += 1;
        role.insert(name.to_string(), format!("var{}", n));
    };
    for name in collect_first_appearance_phys(&f.body) {
        assign_var(&name, &mut role);
    }

    rewrite_body(&mut f.body, &role);
}

/// Slot indices (into [`arg_slot_tables`]) that behave like genuine live-in
/// parameters: some alias of the slot is **read before** any alias is
/// **written**, scanning the body in linear (approximate execution) order.
///
/// A register written before its first read is scratch reuse of that ABI slot,
/// not an incoming argument, so its slot is excluded — this is what stops
/// scratch uses of `rcx`/`rdx`/... from inflating the recovered function arity.
/// The prologue of an `-O0` function spills each real parameter first thing
/// (`mov [rbp-x], edi`), i.e. reads it, so real parameters are reliably
/// classified as live-in by this first-touch scan.
fn live_in_arg_slots(body: &[Stmt], cc: CallConv) -> std::collections::HashSet<usize> {
    let mut slot_of: HashMap<&str, usize> = HashMap::new();
    for (i, names) in arg_slot_tables(cc).iter().enumerate() {
        for n in *names {
            slot_of.insert(n, i);
        }
    }
    // slot -> is_param (true = first touch was a read). First touch wins.
    let mut decided: HashMap<usize, bool> = HashMap::new();
    for s in body {
        walk_stmt_rw(s, &mut |name, is_write| {
            if let Some(&slot) = slot_of.get(name) {
                decided.entry(slot).or_insert(!is_write);
            }
        });
    }
    decided
        .into_iter()
        .filter_map(|(slot, is_param)| is_param.then_some(slot))
        .collect()
}

/// Walk a statement emitting `(register_name, is_write)` events in execution
/// order: the reads of a statement are reported before its write. Memory stores
/// write memory, not a register, so their operands are all reads.
fn walk_stmt_rw(s: &Stmt, cb: &mut impl FnMut(&str, bool)) {
    match s {
        Stmt::Assign { dst, src } => {
            walk_expr_phys(src, &mut |n| cb(n, false));
            if let VReg::Phys(n) = dst {
                cb(n, true);
            }
        }
        Stmt::Store { addr, src } => {
            walk_expr_phys(addr, &mut |n| cb(n, false));
            walk_expr_phys(src, &mut |n| cb(n, false));
        }
        Stmt::Call { target, args } => {
            walk_expr_phys(target, &mut |n| cb(n, false));
            for a in args {
                walk_expr_phys(a, &mut |n| cb(n, false));
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                walk_expr_phys(e, &mut |n| cb(n, false));
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            walk_expr_phys(cond, &mut |n| cb(n, false));
            for s in then_body {
                walk_stmt_rw(s, cb);
            }
            if let Some(eb) = else_body {
                for s in eb {
                    walk_stmt_rw(s, cb);
                }
            }
        }
        Stmt::While { cond, body } => {
            walk_expr_phys(cond, &mut |n| cb(n, false));
            for s in body {
                walk_stmt_rw(s, cb);
            }
        }
        Stmt::Push { value } => walk_expr_phys(value, &mut |n| cb(n, false)),
        Stmt::Pop { target } => {
            if let VReg::Phys(n) = target {
                cb(n, true);
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            walk_expr_phys(discriminant, &mut |n| cb(n, false));
            for (_, body) in cases {
                for s in body {
                    walk_stmt_rw(s, cb);
                }
            }
            if let Some(b) = default {
                for s in b {
                    walk_stmt_rw(s, cb);
                }
            }
        }
        Stmt::Goto { .. } | Stmt::Label(_) | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
    }
}

fn collect_first_appearance_phys(body: &[Stmt]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in body {
        walk_stmt_phys(s, &mut |name| {
            if seen.insert(name.to_string()) {
                out.push(name.to_string());
            }
        });
    }
    out
}

fn walk_stmt_phys(s: &Stmt, cb: &mut impl FnMut(&str)) {
    match s {
        Stmt::Assign { dst, src } => {
            if let VReg::Phys(n) = dst {
                cb(n);
            }
            walk_expr_phys(src, cb);
        }
        Stmt::Store { addr, src } => {
            walk_expr_phys(addr, cb);
            walk_expr_phys(src, cb);
        }
        Stmt::Call { target, args } => {
            walk_expr_phys(target, cb);
            for a in args {
                walk_expr_phys(a, cb);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                walk_expr_phys(e, cb);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            walk_expr_phys(cond, cb);
            for s in then_body {
                walk_stmt_phys(s, cb);
            }
            if let Some(eb) = else_body {
                for s in eb {
                    walk_stmt_phys(s, cb);
                }
            }
        }
        Stmt::While { cond, body } => {
            walk_expr_phys(cond, cb);
            for s in body {
                walk_stmt_phys(s, cb);
            }
        }
        Stmt::Push { value } => walk_expr_phys(value, cb),
        Stmt::Pop { target } => {
            if let VReg::Phys(n) = target {
                cb(n);
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            walk_expr_phys(discriminant, cb);
            for (_, body) in cases {
                for s in body {
                    walk_stmt_phys(s, cb);
                }
            }
            if let Some(b) = default {
                for s in b {
                    walk_stmt_phys(s, cb);
                }
            }
        }
        Stmt::Goto { .. } | Stmt::Label(_) | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
    }
}

fn walk_expr_phys(e: &Expr, cb: &mut impl FnMut(&str)) {
    match e {
        Expr::Reg(VReg::Phys(n)) => cb(n),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(VReg::Phys(n)) = base {
                cb(n);
            }
            if let Some(VReg::Phys(n)) = index {
                cb(n);
            }
        }
        Expr::Deref { addr, .. } => walk_expr_phys(addr, cb),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            walk_expr_phys(lhs, cb);
            walk_expr_phys(rhs, cb);
        }
        Expr::Un { src, .. } => walk_expr_phys(src, cb),
    }
}

fn rename_vreg(v: &mut VReg, role: &HashMap<String, String>) {
    if let VReg::Phys(n) = v {
        if let Some(alias) = role.get(n) {
            *n = alias.clone();
        }
    }
}

fn rewrite_expr(e: &mut Expr, role: &HashMap<String, String>) {
    match e {
        Expr::Reg(v) => rename_vreg(v, role),
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(v) = base {
                rename_vreg(v, role);
            }
            if let Some(v) = index {
                rename_vreg(v, role);
            }
        }
        Expr::Deref { addr, .. } => rewrite_expr(addr, role),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            rewrite_expr(lhs, role);
            rewrite_expr(rhs, role);
        }
        Expr::Un { src, .. } => rewrite_expr(src, role),
    }
}

fn rewrite_body(body: &mut [Stmt], role: &HashMap<String, String>) {
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                rename_vreg(dst, role);
                rewrite_expr(src, role);
            }
            Stmt::Store { addr, src } => {
                rewrite_expr(addr, role);
                rewrite_expr(src, role);
            }
            Stmt::Call { target, args } => {
                rewrite_expr(target, role);
                for a in args {
                    rewrite_expr(a, role);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    rewrite_expr(e, role);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                rewrite_expr(cond, role);
                rewrite_body(then_body, role);
                if let Some(eb) = else_body {
                    rewrite_body(eb, role);
                }
            }
            Stmt::While { cond, body } => {
                rewrite_expr(cond, role);
                rewrite_body(body, role);
            }
            Stmt::Push { value } => rewrite_expr(value, role),
            Stmt::Pop { target } => rename_vreg(target, role),
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                rewrite_expr(discriminant, role);
                for (_, body) in cases.iter_mut() {
                    rewrite_body(body, role);
                }
                if let Some(b) = default {
                    rewrite_body(b, role);
                }
            }
            Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{render, Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn sysv_rdi_becomes_arg0_and_rax_becomes_ret() {
        // rdi is READ (a genuine live-in parameter) before rax is set as the
        // return value.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rdi")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%ret = %arg0;"), "got: {}", text);
        assert!(text.contains("return %ret;"), "got: {}", text);
        assert!(!text.contains("%rdi"));
        assert!(!text.contains("%rax"));
    }

    #[test]
    fn scratch_arg_register_written_first_is_not_a_param() {
        // rcx (SysV 4th arg slot) is written before any read -> it is scratch,
        // not `arg3`; it must become a `varN` local so the recovered arity is
        // not inflated. rdi *is* read first, so it is the sole parameter.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x2000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Const(32),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Bin {
                        op: crate::ir::types::BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("rdi"))),
                        rhs: Box::new(Expr::Reg(reg("rcx"))),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%arg0"), "rdi should be arg0: {}", text);
        assert!(
            !text.contains("arg3") && !text.contains("arg1") && !text.contains("arg2"),
            "scratch rcx must not become an arg slot: {}",
            text
        );
        assert!(!text.contains("%rcx"), "rcx should be aliased away: {}", text);
    }

    #[test]
    fn stack_registers_keep_their_names() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rsp"),
                src: Expr::Bin {
                    op: crate::ir::types::BinOp::Sub,
                    lhs: Box::new(Expr::Reg(reg("rsp"))),
                    rhs: Box::new(Expr::Const(8)),
                },
            }],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%rsp"), "got: {}", text);
    }

    #[test]
    fn unclaimed_gprs_get_stable_varn_aliases() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("r12"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("r13"),
                    src: Expr::Reg(reg("r12")),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%var0 = 1;"), "got: {}", text);
        assert!(text.contains("%var1 = %var0;"), "got: {}", text);
    }

    #[test]
    fn aarch64_x0_stays_arg0() {
        // x0 is read (live-in parameter); on AArch64 arg0 wins over the
        // ret-alias for the shared x0 register.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Return {
                value: Some(Expr::Reg(reg("x0"))),
            }],
        };
        apply_role_names(&mut f, CallConv::Aarch64);
        let text = render(&f);
        assert!(text.contains("return %arg0;"), "got: {}", text);
    }

    #[test]
    fn call_arg_expression_is_also_renamed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "puts".into(),
                },
                args: vec![Expr::Reg(reg("rdi"))],
            }],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("call puts(%arg0);"), "got: {}", text);
    }

    #[test]
    fn win64_rcx_becomes_arg0_and_rdi_becomes_var() {
        // rcx (Win64 arg0) is read first -> arg0; rdi is not a Win64 arg slot
        // and is written -> a var local.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rcx")),
                },
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Const(2),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::Win64);
        let text = render(&f);
        assert!(text.contains("%ret = %arg0;"), "got: {}", text);
        assert!(text.contains("%var0 = 2;"), "got: {}", text);
        assert!(text.contains("return %ret;"), "got: {}", text);
    }
}
