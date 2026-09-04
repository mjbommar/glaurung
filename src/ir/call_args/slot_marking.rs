//! Argument-slot liveness marking: which ABI argument registers a statement
//! writes, and which it reads, along the path into a call.
//!
//! Folding an argument setup into its call is only sound when the register it
//! targets is neither read nor rewritten between the two points. These markers
//! are the two halves of that proof, run as a backward scan over the statements
//! preceding a `Stmt::Call`:
//!
//! * the *read* markers ([`mark_arg_reads_in_expr`], [`mark_arg_reads_in_stmt`])
//!   set a slot when anything between the assignment and the call observes it,
//!   which forbids moving the definition forward past that use.
//! * the *write* markers ([`mark_arg_writes_in_stmt`]) set a slot when the
//!   incoming value is clobbered, which forbids filling that slot from the
//!   function's own incoming parameter register.
//!
//! Both recurse structurally through nested bodies, and both fail closed:
//! a shape they do not understand marks the slot rather than leaving it clear.
//! `Stmt::Call` clobbers every argument slot at once, since every one of them
//! is caller-saved.
//!
//! [`body_falls_through`] is what keeps the write scan from being a plain
//! syntactic walk — only branch arms that can reach the following statement are
//! on the path into the call. It is local to this module; `stack_locals` has an
//! independent function of the same name answering a different question.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{slot_of, CallConv};

pub(super) fn mark_slot_write(reg: &VReg, arch: CallConv, blocked_incoming: &mut [bool]) {
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

pub(super) fn mark_arg_reads_in_expr(e: &Expr, arch: CallConv, read_between: &mut [bool]) {
    match e {
        Expr::Reg(r) => mark_slot_read(r, arch, read_between),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
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
        Expr::Call { target, args, .. } => {
            mark_arg_reads_in_expr(target, arch, read_between);
            for argument in args {
                mark_arg_reads_in_expr(argument, arch, read_between);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            mark_arg_reads_in_expr(lhs, arch, read_between);
            mark_arg_reads_in_expr(rhs, arch, read_between);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            mark_arg_reads_in_expr(cond, arch, read_between);
            mark_arg_reads_in_expr(if_true, arch, read_between);
            mark_arg_reads_in_expr(if_false, arch, read_between);
        }
        Expr::Un { src, .. } => mark_arg_reads_in_expr(src, arch, read_between),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            mark_arg_reads_in_expr(expr, arch, read_between)
        }
        Expr::FunctionTableEntry { index, .. } => mark_arg_reads_in_expr(index, arch, read_between),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                mark_arg_reads_in_expr(argument, arch, read_between);
            }
        }
    }
}

pub(super) fn mark_arg_reads_in_stmt(s: &Stmt, arch: CallConv, read_between: &mut [bool]) {
    match s {
        Stmt::IndirectGoto { target } => mark_arg_reads_in_expr(target, arch, read_between),
        Stmt::Assign { src, .. } => mark_arg_reads_in_expr(src, arch, read_between),
        Stmt::Store { addr, src, .. } => {
            mark_arg_reads_in_expr(addr, arch, read_between);
            mark_arg_reads_in_expr(src, arch, read_between);
        }
        Stmt::Call { target, args, .. } => {
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
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            mark_arg_reads_in_stmt(init, arch, read_between);
            mark_arg_reads_in_expr(cond, arch, read_between);
            for stmt in body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
            mark_arg_reads_in_stmt(step, arch, read_between);
        }
        Stmt::DoWhile { body, cond } => {
            for stmt in body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
            mark_arg_reads_in_expr(cond, arch, read_between);
        }
        Stmt::Push { value } | Stmt::Throw { value } => {
            mark_arg_reads_in_expr(value, arch, read_between)
        }
        Stmt::TryCatch { try_body, catches } => {
            for stmt in try_body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
            for catch in catches {
                for stmt in &catch.body {
                    mark_arg_reads_in_stmt(stmt, arch, read_between);
                }
            }
        }
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
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

/// Can control reach the statement *after* `body` by running off its end?
///
/// A branch arm that always returns, throws, or transfers away is not on the
/// path into the statement that follows it, so the argument registers it writes
/// cannot reach a later call. The backward call scan already stops dead at
/// `Stmt::Label` — a potential join — so the absence of a label between such an
/// arm and the call means falling through is the ONLY way in. That is what
/// makes this lexical test a reaching-definition argument rather than a guess.
///
/// `Stmt::Break` is deliberately excluded even though it also leaves the arm:
/// inside a `Stmt::Switch` case, a break lands exactly on the switch's own
/// successor, so it does not prove the following statement is skipped.
///
/// Fail-closed: anything not proven to leave counts as falling through.
fn body_falls_through(body: &[Stmt]) -> bool {
    match body.last() {
        Some(
            Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. },
        ) => false,
        Some(Stmt::If {
            then_body,
            else_body: Some(else_body),
            ..
        }) => body_falls_through(then_body) || body_falls_through(else_body),
        _ => true,
    }
}

pub(super) fn mark_arg_writes_in_stmt(s: &Stmt, arch: CallConv, blocked_incoming: &mut [bool]) {
    match s {
        // A computed transfer writes no argument slot.
        Stmt::IndirectGoto { .. } => {}
        // Every ABI argument register is caller-clobbered. A top-level call is
        // also a backward-scan barrier; this arm matters for calls nested in a
        // structured branch/loop before the call currently being recovered.
        Stmt::Call { .. } => blocked_incoming.fill(true),
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            mark_slot_write(dst, arch, blocked_incoming);
        }
        // Only the arms that can fall through are on the path into whatever
        // follows this branch. See `body_falls_through`.
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            if body_falls_through(then_body) {
                for stmt in then_body {
                    mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                }
            }
            if let Some(else_body) = else_body {
                if body_falls_through(else_body) {
                    for stmt in else_body {
                        mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                    }
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for stmt in body {
                mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            mark_arg_writes_in_stmt(init, arch, blocked_incoming);
            for stmt in body {
                mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
            }
            mark_arg_writes_in_stmt(step, arch, blocked_incoming);
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
        Stmt::TryCatch { try_body, catches } => {
            for stmt in try_body {
                mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
            }
            for catch in catches {
                for stmt in &catch.body {
                    mark_arg_writes_in_stmt(stmt, arch, blocked_incoming);
                }
            }
        }
        Stmt::Store { .. }
        | Stmt::Return { .. }
        | Stmt::Push { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. } => {}
    }
}
