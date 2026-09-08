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
use crate::ir::value_number::ValueIdentities;

use super::{slot_of, CallConv};

pub(super) fn mark_slot_write_with_identities(
    reg: &VReg,
    arch: CallConv,
    blocked_incoming: &mut [bool],
    identities: Option<&ValueIdentities>,
) {
    match argument_slot_of_register(reg, arch, identities) {
        Some(Some(slot)) => {
            if let Some(blocked) = blocked_incoming.get_mut(slot) {
                *blocked = true;
            }
        }
        Some(None) => {}
        None => blocked_incoming.fill(true),
    }
}

fn mark_slot_read(
    reg: &VReg,
    arch: CallConv,
    read_between: &mut [bool],
    identities: Option<&ValueIdentities>,
) {
    match argument_slot_of_register(reg, arch, identities) {
        Some(Some(slot)) => {
            if let Some(read) = read_between.get_mut(slot) {
                *read = true;
            }
        }
        Some(None) => {}
        None => read_between.fill(true),
    }
}

fn argument_slot_of_register(
    reg: &VReg,
    arch: CallConv,
    identities: Option<&ValueIdentities>,
) -> Option<Option<usize>> {
    let name = match identities {
        Some(identities) => {
            let Some(candidates) = identities.candidates(reg) else {
                return Some(None);
            };
            let classifications = candidates
                .iter()
                .map(|identity| match &identity.base {
                    VReg::Phys(name) => slot_of(arch, name),
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<_>>();
            if classifications.len() != 1 {
                return None;
            }
            return classifications.first().copied();
        }
        None => {
            let VReg::Phys(name) = reg else {
                return Some(None);
            };
            name.as_str()
        }
    };
    Some(slot_of(arch, name))
}

pub(super) fn mark_arg_reads_in_expr_with_identities(
    e: &Expr,
    arch: CallConv,
    read_between: &mut [bool],
    identities: Option<&ValueIdentities>,
) {
    match e {
        Expr::Origin { expr, .. } => {
            mark_arg_reads_in_expr_with_identities(expr, arch, read_between, identities)
        }
        Expr::Reg(r) => mark_slot_read(r, arch, read_between, identities),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            if let Some(base) = base {
                mark_slot_read(base, arch, read_between, identities);
            }
            if let Some(index) = index {
                mark_slot_read(index, arch, read_between, identities);
            }
        }
        Expr::Deref { addr, .. } => {
            mark_arg_reads_in_expr_with_identities(addr, arch, read_between, identities)
        }
        Expr::Call { target, args, .. } => {
            mark_arg_reads_in_expr_with_identities(target, arch, read_between, identities);
            for argument in args {
                mark_arg_reads_in_expr_with_identities(argument, arch, read_between, identities);
            }
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            mark_arg_reads_in_expr_with_identities(lhs, arch, read_between, identities);
            mark_arg_reads_in_expr_with_identities(rhs, arch, read_between, identities);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            mark_arg_reads_in_expr_with_identities(cond, arch, read_between, identities);
            mark_arg_reads_in_expr_with_identities(if_true, arch, read_between, identities);
            mark_arg_reads_in_expr_with_identities(if_false, arch, read_between, identities);
        }
        Expr::Un { src, .. } => {
            mark_arg_reads_in_expr_with_identities(src, arch, read_between, identities)
        }
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            mark_arg_reads_in_expr_with_identities(expr, arch, read_between, identities)
        }
        Expr::FunctionTableEntry { index, .. } => {
            mark_arg_reads_in_expr_with_identities(index, arch, read_between, identities)
        }
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                mark_arg_reads_in_expr_with_identities(argument, arch, read_between, identities);
            }
        }
    }
}

pub(super) fn mark_arg_reads_in_stmt_with_identities(
    s: &Stmt,
    arch: CallConv,
    read_between: &mut [bool],
    identities: Option<&ValueIdentities>,
) {
    match s {
        Stmt::Origin { stmt, .. } => {
            mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities)
        }
        Stmt::IndirectGoto { target } => {
            mark_arg_reads_in_expr_with_identities(target, arch, read_between, identities)
        }
        Stmt::Assign { src, .. } => {
            mark_arg_reads_in_expr_with_identities(src, arch, read_between, identities)
        }
        Stmt::Store { addr, src, .. } => {
            mark_arg_reads_in_expr_with_identities(addr, arch, read_between, identities);
            mark_arg_reads_in_expr_with_identities(src, arch, read_between, identities);
        }
        Stmt::Call { target, args, .. } => {
            mark_arg_reads_in_expr_with_identities(target, arch, read_between, identities);
            for arg in args {
                mark_arg_reads_in_expr_with_identities(arg, arch, read_between, identities);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                mark_arg_reads_in_expr_with_identities(value, arch, read_between, identities);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            mark_arg_reads_in_expr_with_identities(cond, arch, read_between, identities);
            for stmt in then_body {
                mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
            }
            if let Some(else_body) = else_body {
                for stmt in else_body {
                    mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
                }
            }
        }
        Stmt::While { cond, body } => {
            mark_arg_reads_in_expr_with_identities(cond, arch, read_between, identities);
            for stmt in body {
                mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            mark_arg_reads_in_stmt_with_identities(init, arch, read_between, identities);
            mark_arg_reads_in_expr_with_identities(cond, arch, read_between, identities);
            for stmt in body {
                mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
            }
            mark_arg_reads_in_stmt_with_identities(step, arch, read_between, identities);
        }
        Stmt::DoWhile { body, cond } => {
            for stmt in body {
                mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
            }
            mark_arg_reads_in_expr_with_identities(cond, arch, read_between, identities);
        }
        Stmt::Push { value } | Stmt::Throw { value } => {
            mark_arg_reads_in_expr_with_identities(value, arch, read_between, identities)
        }
        Stmt::TryCatch { try_body, catches } => {
            for stmt in try_body {
                mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
            }
            for catch in catches {
                for stmt in &catch.body {
                    mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
                }
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            mark_arg_reads_in_expr_with_identities(discriminant, arch, read_between, identities);
            for (_case, body) in cases {
                for stmt in body {
                    mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    mark_arg_reads_in_stmt_with_identities(stmt, arch, read_between, identities);
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
        Some(Stmt::Origin { stmt, .. }) => body_falls_through(std::slice::from_ref(stmt)),
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

pub(super) fn mark_arg_writes_in_stmt_with_identities(
    s: &Stmt,
    arch: CallConv,
    blocked_incoming: &mut [bool],
    identities: Option<&ValueIdentities>,
) {
    match s {
        Stmt::Origin { stmt, .. } => {
            mark_arg_writes_in_stmt_with_identities(stmt, arch, blocked_incoming, identities)
        }
        // A computed transfer writes no argument slot.
        Stmt::IndirectGoto { .. } => {}
        // Every ABI argument register is caller-clobbered. A top-level call is
        // also a backward-scan barrier; this arm matters for calls nested in a
        // structured branch/loop before the call currently being recovered.
        Stmt::Call { .. } => blocked_incoming.fill(true),
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            mark_slot_write_with_identities(dst, arch, blocked_incoming, identities);
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
                    mark_arg_writes_in_stmt_with_identities(
                        stmt,
                        arch,
                        blocked_incoming,
                        identities,
                    );
                }
            }
            if let Some(else_body) = else_body {
                if body_falls_through(else_body) {
                    for stmt in else_body {
                        mark_arg_writes_in_stmt_with_identities(
                            stmt,
                            arch,
                            blocked_incoming,
                            identities,
                        );
                    }
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for stmt in body {
                mark_arg_writes_in_stmt_with_identities(stmt, arch, blocked_incoming, identities);
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            mark_arg_writes_in_stmt_with_identities(init, arch, blocked_incoming, identities);
            for stmt in body {
                mark_arg_writes_in_stmt_with_identities(stmt, arch, blocked_incoming, identities);
            }
            mark_arg_writes_in_stmt_with_identities(step, arch, blocked_incoming, identities);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_case, body) in cases {
                for stmt in body {
                    mark_arg_writes_in_stmt_with_identities(
                        stmt,
                        arch,
                        blocked_incoming,
                        identities,
                    );
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    mark_arg_writes_in_stmt_with_identities(
                        stmt,
                        arch,
                        blocked_incoming,
                        identities,
                    );
                }
            }
        }
        Stmt::TryCatch { try_body, catches } => {
            for stmt in try_body {
                mark_arg_writes_in_stmt_with_identities(stmt, arch, blocked_incoming, identities);
            }
            for catch in catches {
                for stmt in &catch.body {
                    mark_arg_writes_in_stmt_with_identities(
                        stmt,
                        arch,
                        blocked_incoming,
                        identities,
                    );
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
