//! How many times is a name read?
//!
//! Several of the parent pass's proofs are counting arguments rather than
//! dataflow ones: a non-pure expression may be folded into its use when the
//! destination has exactly one whole-function read, an adjacent guard may
//! consume a value when that guard is its only reader, and a dead copy may be
//! deleted when nothing reads its destination at all.
//!
//! [`count_reg_uses`] answers the question for one expression and one name,
//! [`expr_reads_reg`] answers it as a yes/no, and [`count_reads_stmt`] /
//! [`count_reads_body`] build the whole-body read histogram the parent
//! consults.
//!
//! All four, plus [`super::alias::contains_reg`], are one traversal — the
//! `visit_*_reads` walkers below — specialised by a closure. They used to be
//! separate copies of the same match, which is how the read/write asymmetry
//! documented in the next paragraph could drift between "which names does this
//! read" and "how many times does it read this one name". A single walker makes
//! that impossible, and lets the callers that only need a yes/no answer stop at
//! the first hit instead of counting every occurrence.
//!
//! These functions only read: nothing here mutates the AST. They are also the
//! place the read/write asymmetry of the AST is encoded — an `Assign`
//! destination and the bare promoted local of a `Store local_x = value` are
//! *writes*, and must not be counted as reads.

use super::hash::RegMap;
use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::{is_promoted_local_reg, VReg};

/// Visit every register `e` READS, in source order.
///
/// The visitor returns `false` to abandon the walk; `visit_expr_reads` then
/// returns `false` too, so a caller asking a yes/no question does not pay for
/// the rest of the expression.
pub(super) fn visit_expr_reads<F: FnMut(&VReg) -> bool>(e: &Expr, visit: &mut F) -> bool {
    match e {
        Expr::Reg(r) => visit(r),
        Expr::StackAddr { object, .. } => visit(object),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => true,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(r) = base {
                if !visit(r) {
                    return false;
                }
            }
            if let Some(r) = index {
                if !visit(r) {
                    return false;
                }
            }
            true
        }
        Expr::Deref { addr, .. } => visit_expr_reads(addr, visit),
        Expr::Call { target, args, .. } => {
            if !visit_expr_reads(target, visit) {
                return false;
            }
            for argument in args {
                if !visit_expr_reads(argument, visit) {
                    return false;
                }
            }
            true
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            visit_expr_reads(lhs, visit) && visit_expr_reads(rhs, visit)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            visit_expr_reads(cond, visit)
                && visit_expr_reads(if_true, visit)
                && visit_expr_reads(if_false, visit)
        }
        Expr::Un { src, .. } => visit_expr_reads(src, visit),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            visit_expr_reads(expr, visit)
        }
        Expr::FunctionTableEntry { index, .. } => visit_expr_reads(index, visit),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                if !visit_expr_reads(argument, visit) {
                    return false;
                }
            }
            true
        }
    }
}

/// [`visit_expr_reads`] over one statement, including any nested body.
pub(super) fn visit_stmt_reads<F: FnMut(&VReg) -> bool>(s: &Stmt, visit: &mut F) -> bool {
    match s {
        Stmt::IndirectGoto { target } => visit_expr_reads(target, visit),
        // The destination of an Assign is a WRITE, not a read.
        Stmt::Assign { src, .. } => visit_expr_reads(src, visit),
        Stmt::Store { addr, src, .. } => {
            // `Store local_x = value` is how promoted scalar assignment is
            // encoded. Its bare local is a destination, not a pointer read.
            if !matches!(addr, Expr::Reg(dst) if is_promoted_local_reg(dst))
                && !visit_expr_reads(addr, visit)
            {
                return false;
            }
            visit_expr_reads(src, visit)
        }
        Stmt::Call { target, args, .. } => {
            if !visit_expr_reads(target, visit) {
                return false;
            }
            for a in args {
                if !visit_expr_reads(a, visit) {
                    return false;
                }
            }
            true
        }
        Stmt::Return { value } => match value {
            Some(e) => visit_expr_reads(e, visit),
            None => true,
        },
        Stmt::Push { value } => visit_expr_reads(value, visit),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            if !visit_expr_reads(cond, visit) || !visit_body_reads(then_body, visit) {
                return false;
            }
            match else_body {
                Some(eb) => visit_body_reads(eb, visit),
                None => true,
            }
        }
        Stmt::While { cond, body } => {
            visit_expr_reads(cond, visit) && visit_body_reads(body, visit)
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            visit_stmt_reads(init, visit)
                && visit_expr_reads(cond, visit)
                && visit_body_reads(body, visit)
                && visit_stmt_reads(step, visit)
        }
        Stmt::DoWhile { body, cond } => {
            visit_body_reads(body, visit) && visit_expr_reads(cond, visit)
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            if !visit_expr_reads(discriminant, visit) {
                return false;
            }
            for (_, b) in cases {
                if !visit_body_reads(b, visit) {
                    return false;
                }
            }
            match default {
                Some(b) => visit_body_reads(b, visit),
                None => true,
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => true,
    }
}

/// [`visit_stmt_reads`] over a statement list.
pub(super) fn visit_body_reads<F: FnMut(&VReg) -> bool>(body: &[Stmt], visit: &mut F) -> bool {
    for s in body {
        if !visit_stmt_reads(s, visit) {
            return false;
        }
    }
    true
}

/// Add one read of `r` to the histogram.
///
/// `entry(r.clone())` cloned the key on every *occurrence*; a `VReg::Phys` owns
/// a `String`, so a name read ten times paid ten allocations for one entry.
/// Clone only when the name is new.
fn bump(reads: &mut RegMap<usize>, r: &VReg) {
    if let Some(count) = reads.get_mut(r) {
        *count += 1;
    } else {
        reads.insert(r.clone(), 1);
    }
}

pub(super) fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
    let mut uses = 0;
    visit_expr_reads(e, &mut |r| {
        if r == target {
            uses += 1;
        }
        true
    });
    uses
}

/// Whether `e` reads `target` at all. Stops at the first occurrence.
pub(super) fn expr_reads_reg(e: &Expr, target: &VReg) -> bool {
    let mut found = false;
    visit_expr_reads(e, &mut |r| {
        if r == target {
            found = true;
        }
        !found
    });
    found
}

pub(super) fn count_reads_stmt(s: &Stmt, reads: &mut RegMap<usize>) {
    visit_stmt_reads(s, &mut |r| {
        bump(reads, r);
        true
    });
}

pub(super) fn count_reads_body(body: &[Stmt], reads: &mut RegMap<usize>) {
    visit_body_reads(body, &mut |r| {
        bump(reads, r);
        true
    });
}
