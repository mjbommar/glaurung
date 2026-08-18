//! How many times is a name read?
//!
//! Several of the parent pass's proofs are counting arguments rather than
//! dataflow ones: a non-pure expression may be folded into its use when the
//! destination has exactly one whole-function read, an adjacent guard may
//! consume a value when that guard is its only reader, and a dead copy may be
//! deleted when nothing reads its destination at all.
//!
//! [`count_reg_uses`] answers the question for one expression and one name;
//! [`count_reads_expr`], [`count_reads_stmt`] and [`count_reads_body`] build the
//! whole-body read histogram the parent consults.
//!
//! These functions only read: nothing here mutates the AST. They are also the
//! place the read/write asymmetry of the AST is encoded — an `Assign`
//! destination and the bare promoted local of a `Store local_x = value` are
//! *writes*, and must not be counted as reads.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::{is_promoted_local_reg, VReg};

pub(super) fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
    match e {
        Expr::Reg(r) => (r == target) as usize,
        Expr::StackAddr { object, .. } => (object == target) as usize,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => 0,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            (base.as_ref() == Some(target)) as usize + (index.as_ref() == Some(target)) as usize
        }
        Expr::Deref { addr, .. } => count_reg_uses(addr, target),
        Expr::Call {
            target: call_target,
            args,
            ..
        } => {
            count_reg_uses(call_target, target)
                + args
                    .iter()
                    .map(|argument| count_reg_uses(argument, target))
                    .sum::<usize>()
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reg_uses(lhs, target) + count_reg_uses(rhs, target)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reg_uses(cond, target)
                + count_reg_uses(if_true, target)
                + count_reg_uses(if_false, target)
        }
        Expr::Un { src, .. } => count_reg_uses(src, target),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => count_reg_uses(expr, target),
        Expr::FunctionTableEntry { index, .. } => count_reg_uses(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reg_uses(argument, target))
            .sum(),
    }
}

pub(super) fn count_reads_expr(e: &Expr, reads: &mut HashMap<VReg, usize>) {
    match e {
        Expr::Reg(r) => *reads.entry(r.clone()).or_insert(0) += 1,
        Expr::StackAddr { object, .. } => *reads.entry(object.clone()).or_insert(0) += 1,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(r) = base {
                *reads.entry(r.clone()).or_insert(0) += 1;
            }
            if let Some(r) = index {
                *reads.entry(r.clone()).or_insert(0) += 1;
            }
        }
        Expr::Deref { addr, .. } => count_reads_expr(addr, reads),
        Expr::Call { target, args, .. } => {
            count_reads_expr(target, reads);
            for argument in args {
                count_reads_expr(argument, reads);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            count_reads_expr(lhs, reads);
            count_reads_expr(rhs, reads);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            count_reads_expr(cond, reads);
            count_reads_expr(if_true, reads);
            count_reads_expr(if_false, reads);
        }
        Expr::Un { src, .. } => count_reads_expr(src, reads),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            count_reads_expr(expr, reads)
        }
        Expr::FunctionTableEntry { index, .. } => count_reads_expr(index, reads),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                count_reads_expr(argument, reads);
            }
        }
    }
}

pub(super) fn count_reads_stmt(s: &Stmt, reads: &mut HashMap<VReg, usize>) {
    match s {
        Stmt::IndirectGoto { target } => count_reads_expr(target, reads),
        // The destination of an Assign is a WRITE, not a read.
        Stmt::Assign { src, .. } => count_reads_expr(src, reads),
        Stmt::Store { addr, src, .. } => {
            // `Store local_x = value` is how promoted scalar assignment is
            // encoded. Its bare local is a destination, not a pointer read.
            if !matches!(addr, Expr::Reg(dst) if is_promoted_local_reg(dst)) {
                count_reads_expr(addr, reads);
            }
            count_reads_expr(src, reads);
        }
        Stmt::Call { target, args, .. } => {
            count_reads_expr(target, reads);
            for a in args {
                count_reads_expr(a, reads);
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                count_reads_expr(e, reads);
            }
        }
        Stmt::Push { value } => count_reads_expr(value, reads),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_reads_expr(cond, reads);
            count_reads_body(then_body, reads);
            if let Some(eb) = else_body {
                count_reads_body(eb, reads);
            }
        }
        Stmt::While { cond, body } => {
            count_reads_expr(cond, reads);
            count_reads_body(body, reads);
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            count_reads_stmt(init, reads);
            count_reads_expr(cond, reads);
            count_reads_body(body, reads);
            count_reads_stmt(step, reads);
        }
        Stmt::DoWhile { body, cond } => {
            count_reads_body(body, reads);
            count_reads_expr(cond, reads);
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            count_reads_expr(discriminant, reads);
            for (_, b) in cases {
                count_reads_body(b, reads);
            }
            if let Some(b) = default {
                count_reads_body(b, reads);
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => {}
    }
}

pub(super) fn count_reads_body(body: &[Stmt], reads: &mut HashMap<VReg, usize>) {
    for s in body {
        count_reads_stmt(s, reads);
    }
}
