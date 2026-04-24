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
//! * Argument-passing register N → `argN` (rdi/x0 → `arg0`, rsi/x1 → `arg1`,
//!   …)
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
    "rsp", "esp", "sp",
    "rbp", "ebp", "bp",
    "x29", "w29", "fp",
    "x30", "w30", "lr",
];

fn return_reg_aliases(cc: CallConv) -> &'static [&'static str] {
    match cc {
        CallConv::SysVAmd64 => &["rax", "eax", "ax", "al"],
        CallConv::Aarch64 => &["x0", "w0"],
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
    }
}

/// Rename registers in `f` according to the given calling convention.
pub fn apply_role_names(f: &mut Function, cc: CallConv) {
    // Build the role map: raw name → friendly name. We build it up-front so
    // that every substitution is consistent across the function.
    let mut role: HashMap<String, String> = HashMap::new();

    // On AArch64 x0 serves as both arg0 and return value. We prefer `arg0`
    // because in a called function it's more often referenced as the input
    // than as the output slot.
    for (slot_idx, names) in arg_slot_tables(cc).iter().enumerate() {
        for name in *names {
            role.entry(name.to_string())
                .or_insert_with(|| format!("arg{}", slot_idx));
        }
    }
    for name in return_reg_aliases(cc) {
        // `ret` only wins if no arg-slot already claimed the name (x0 case
        // above keeps `arg0`).
        role.entry(name.to_string()).or_insert_with(|| "ret".to_string());
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
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

fn walk_expr_phys(e: &Expr, cb: &mut impl FnMut(&str)) {
    match e {
        Expr::Reg(VReg::Phys(n)) => cb(n),
        Expr::Reg(_) | Expr::Const(_) | Expr::Addr(_) | Expr::Named { .. } | Expr::StringLit { .. } | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } => {
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
        Expr::Const(_) | Expr::Addr(_) | Expr::Named { .. } | Expr::StringLit { .. } | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } => {
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
        let mut f = Function {
            name: "f".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rdi"),
                    src: Expr::Const(1),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        apply_role_names(&mut f, CallConv::SysVAmd64);
        let text = render(&f);
        assert!(text.contains("%arg0 = 1;"), "got: {}", text);
        assert!(text.contains("return %ret;"), "got: {}", text);
        assert!(!text.contains("%rdi"));
        assert!(!text.contains("%rax"));
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
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("x0"),
                src: Expr::Const(42),
            }],
        };
        apply_role_names(&mut f, CallConv::Aarch64);
        let text = render(&f);
        assert!(text.contains("%arg0 = 42;"), "got: {}", text);
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
}
