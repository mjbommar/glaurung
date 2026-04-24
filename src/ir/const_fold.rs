//! Algebraic identity folding over the AST.
//!
//! Rewrites common compiler idioms that obscure the real semantics:
//!
//! | Before           | After |
//! |------------------|-------|
//! | `(X ^ X)`        | `0`   |
//! | `(X - X)`        | `0`   |
//! | `(X & X)`        | `X`   |
//! | `(X \| X)`       | `X`   |
//! | `(X + 0)`        | `X`   |
//! | `(0 + X)`        | `X`   |
//! | `(X - 0)`        | `X`   |
//! | `(X * 1)`        | `X`   |
//! | `(1 * X)`        | `X`   |
//! | `(X * 0)`        | `0`   |
//! | `(X & 0)`        | `0`   |
//! | `(X & -1)`       | `X`   |
//! | `(X \| 0)`       | `X`   |
//! | `(c1 op c2)`     | folded constant when the op is safe |
//!
//! The pass is purely syntactic — it doesn't require any dataflow info —
//! and recurses bottom-up so nested patterns collapse in one walk.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::BinOp;

/// Rewrite `f`'s body in place, folding the patterns above.
pub fn fold_constants(f: &mut Function) {
    fold_body(&mut f.body);
}

fn fold_body(body: &mut [Stmt]) {
    for s in body.iter_mut() {
        match s {
            Stmt::Assign { src, .. } => fold_expr(src),
            Stmt::Store { addr, src } => {
                fold_expr(addr);
                fold_expr(src);
            }
            Stmt::Call { target, args } => {
                fold_expr(target);
                for a in args {
                    fold_expr(a);
                }
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    fold_expr(e);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond);
                fold_body(then_body);
                if let Some(eb) = else_body {
                    fold_body(eb);
                }
            }
            Stmt::While { cond, body } => {
                fold_expr(cond);
                fold_body(body);
            }
            Stmt::Push { value } => fold_expr(value),
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn fold_expr(e: &mut Expr) {
    // Recurse first — bottom-up folding composes naturally.
    match e {
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs);
            fold_expr(rhs);
        }
        Expr::Un { src, .. } => fold_expr(src),
        Expr::Deref { addr, .. } => fold_expr(addr),
        _ => {}
    }

    // Now try to collapse the current node.
    if let Expr::Bin { op, lhs, rhs } = e {
        let op = *op;
        // Same-operand identities (X op X).
        if lhs == rhs {
            match op {
                BinOp::Xor | BinOp::Sub => {
                    *e = Expr::Const(0);
                    return;
                }
                BinOp::And | BinOp::Or => {
                    // (X & X) == X; replace with X.
                    let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                    *e = x;
                    return;
                }
                _ => {}
            }
        }

        // Constant-with-anything identities.
        if let Expr::Const(0) = **rhs {
            match op {
                BinOp::Add | BinOp::Sub | BinOp::Or | BinOp::Xor | BinOp::Shl | BinOp::Shr | BinOp::Sar => {
                    let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                    *e = x;
                    return;
                }
                BinOp::Mul | BinOp::And => {
                    *e = Expr::Const(0);
                    return;
                }
            }
        }
        if let Expr::Const(0) = **lhs {
            if matches!(op, BinOp::Add | BinOp::Or | BinOp::Xor) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if matches!(op, BinOp::Mul | BinOp::And) {
                *e = Expr::Const(0);
                return;
            }
        }
        if let Expr::Const(1) = **rhs {
            if matches!(op, BinOp::Mul) {
                let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
        }
        if let Expr::Const(1) = **lhs {
            if matches!(op, BinOp::Mul) {
                let x = std::mem::replace(rhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
        }
        if let Expr::Const(-1) = **rhs {
            if matches!(op, BinOp::And) {
                let x = std::mem::replace(lhs.as_mut(), Expr::Const(0));
                *e = x;
                return;
            }
            if matches!(op, BinOp::Or) {
                *e = Expr::Const(-1);
                return;
            }
        }

        // Const × Const fold.
        if let (Expr::Const(a), Expr::Const(b)) = (lhs.as_ref(), rhs.as_ref()) {
            let (a, b) = (*a, *b);
            let folded = match op {
                BinOp::Add => a.wrapping_add(b),
                BinOp::Sub => a.wrapping_sub(b),
                BinOp::Mul => a.wrapping_mul(b),
                BinOp::And => a & b,
                BinOp::Or => a | b,
                BinOp::Xor => a ^ b,
                BinOp::Shl => {
                    if (0..64).contains(&b) {
                        a.wrapping_shl(b as u32)
                    } else {
                        return;
                    }
                }
                BinOp::Shr => {
                    if (0..64).contains(&b) {
                        ((a as u64) >> (b as u32)) as i64
                    } else {
                        return;
                    }
                }
                BinOp::Sar => {
                    if (0..64).contains(&b) {
                        a.wrapping_shr(b as u32)
                    } else {
                        return;
                    }
                }
            };
            *e = Expr::Const(folded);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};
    use crate::ir::types::VReg;

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }
    fn bin(op: BinOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::Bin {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    fn one_stmt(src: Expr) -> Function {
        Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src,
            }],
        }
    }

    #[test]
    fn xor_self_collapses_to_zero() {
        let mut f = one_stmt(bin(
            BinOp::Xor,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn sub_self_collapses_to_zero() {
        let mut f = one_stmt(bin(
            BinOp::Sub,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn and_self_collapses_to_operand() {
        let mut f = one_stmt(bin(
            BinOp::And,
            Expr::Reg(reg("rax")),
            Expr::Reg(reg("rax")),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn add_zero_collapses_to_operand() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Reg(reg("rbx")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rbx")));
        }
    }

    #[test]
    fn mul_one_left_and_right_collapse() {
        let mut f = one_stmt(bin(BinOp::Mul, Expr::Const(1), Expr::Reg(reg("rcx"))));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
        let mut g = one_stmt(bin(BinOp::Mul, Expr::Reg(reg("rcx")), Expr::Const(1)));
        fold_constants(&mut g);
        if let Stmt::Assign { src, .. } = &g.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
    }

    #[test]
    fn mul_zero_and_and_zero_collapse_to_zero() {
        let mut f = one_stmt(bin(BinOp::Mul, Expr::Reg(reg("rcx")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
        let mut g = one_stmt(bin(BinOp::And, Expr::Reg(reg("rcx")), Expr::Const(0)));
        fold_constants(&mut g);
        if let Stmt::Assign { src, .. } = &g.body[0] {
            assert_eq!(*src, Expr::Const(0));
        }
    }

    #[test]
    fn and_minus_one_collapses_to_operand() {
        let mut f = one_stmt(bin(BinOp::And, Expr::Reg(reg("rcx")), Expr::Const(-1)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rcx")));
        }
    }

    #[test]
    fn const_times_const_folds() {
        let mut f = one_stmt(bin(BinOp::Add, Expr::Const(2), Expr::Const(3)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(5));
        }
    }

    #[test]
    fn nested_xor_self_inside_larger_expression() {
        // (rax + (rcx ^ rcx))  →  (rax + 0)  →  rax
        let mut f = one_stmt(bin(
            BinOp::Add,
            Expr::Reg(reg("rax")),
            bin(BinOp::Xor, Expr::Reg(reg("rcx")), Expr::Reg(reg("rcx"))),
        ));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn shift_by_zero_is_identity() {
        let mut f = one_stmt(bin(BinOp::Shl, Expr::Reg(reg("rax")), Expr::Const(0)));
        fold_constants(&mut f);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Reg(reg("rax")));
        }
    }

    #[test]
    fn real_binary_end_to_end() {
        // Compose with the full pipeline; we just want to confirm the fold
        // runs to fixed point without panicking on a real function body.
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::ast::{lower, render};
        use crate::ir::expr_reconstruct::reconstruct;
        use crate::ir::lift_function::lift_function_from_bytes;
        use crate::ir::ssa::compute_ssa;
        use crate::ir::structure::recover;

        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 2,
                max_blocks: 64,
                max_instructions: 1000,
                timeout_ms: 500,
            },
        );
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                let mut ast = lower(&lf, &r, f.name.clone());
                reconstruct(&mut ast);
                fold_constants(&mut ast);
                let text = render(&ast);
                // xor-self idioms are pervasive in compiler-emitted prologues;
                // we can't assert the exact count, but the output should no
                // longer contain a plain `(%X ^ %X)` for any X.
                assert!(
                    !text.contains("= (%ret ^ %ret);"),
                    "xor-self survived fold: {}",
                    text
                );
            }
        }
    }
}
