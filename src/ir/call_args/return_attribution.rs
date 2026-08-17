//! Attaching a call's result to the call that produced it.
//!
//! The ABI clobbers the return register on every call; only some calls have
//! their result CONSUMED by the source. Printing `ret = f(..)` asserts the
//! second fact, so this pass answers it separately, by asking whether the return
//! register is read before anything overwrites it. Everything here exists to
//! support that one question: the read/write walk over statements and
//! expressions is a local, conservative liveness probe, not a general dataflow
//! facility — a nested body counts as an opaque read.
//!
//! The register itself stays in the parent as `return_reg`: [`super::tail_calls`]
//! needs the same answer for the value a tail call forwards.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{return_reg, ssa_base, CallConv};

/// Is the return register read after the call at `call_idx`, before anything
/// overwrites it? Nested bodies are treated as opaque reads (conservative): if a
/// branch might read it, the result is consumed.
pub(super) fn return_value_is_read(body: &[Stmt], call_idx: usize, ret: &str) -> bool {
    return_value_read_before_write(body, call_idx, ret).unwrap_or(true)
}

/// Whether `ret` is explicitly read or overwritten after a call. `None`
/// means the structured body ended without either event.
fn return_value_read_before_write(body: &[Stmt], call_idx: usize, ret: &str) -> Option<bool> {
    for s in &body[call_idx + 1..] {
        let mut reads = false;
        let mut writes = false;
        walk_stmt_regs(s, ret, &mut reads, &mut writes);
        if reads {
            return Some(true);
        }
        if writes {
            return Some(false);
        }
    }
    None
}

fn expr_reads_storage(expr: &Expr, storage: &str) -> bool {
    let register_matches =
        |register: &VReg| matches!(register, VReg::Phys(name) if ssa_base(name) == storage);
    match expr {
        Expr::Reg(register) => register_matches(register),
        Expr::StackAddr { object, .. } => register_matches(object),
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref().is_some_and(register_matches)
                || index.as_ref().is_some_and(register_matches)
        }
        Expr::Deref { addr, .. } => expr_reads_storage(addr, storage),
        Expr::Call { target, args, .. } => {
            expr_reads_storage(target, storage)
                || args
                    .iter()
                    .any(|argument| expr_reads_storage(argument, storage))
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads_storage(lhs, storage) || expr_reads_storage(rhs, storage)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            expr_reads_storage(cond, storage)
                || expr_reads_storage(if_true, storage)
                || expr_reads_storage(if_false, storage)
        }
        Expr::Un { src, .. } => expr_reads_storage(src, storage),
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
            expr_reads_storage(expr, storage)
        }
        Expr::FunctionTableEntry { index, .. } => expr_reads_storage(index, storage),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .any(|argument| expr_reads_storage(argument, storage)),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

/// Note reads and writes of `name` in `s`. A statement with a nested body reports a
/// read if the name appears anywhere inside it, so a conditional consumer counts.
fn walk_stmt_regs(s: &Stmt, name: &str, reads: &mut bool, writes: &mut bool) {
    let mut expr_reads = |e: &Expr| {
        if expr_reads_storage(e, name) {
            *reads = true;
        }
    };
    match s {
        Stmt::Assign { dst, src } => {
            expr_reads(src);
            if matches!(dst, VReg::Phys(n) if ssa_base(n) == name) {
                *writes = true;
            }
        }
        Stmt::Store { addr, src, .. } => {
            expr_reads(addr);
            expr_reads(src);
        }
        Stmt::Call {
            target, args, dst, ..
        } => {
            expr_reads(target);
            for a in args {
                expr_reads(a);
            }
            // A later call clobbers the register whether or not it took the value.
            if dst.is_none() || matches!(dst, Some(VReg::Phys(n)) if ssa_base(n) == name) {
                *writes = true;
            }
        }
        Stmt::Return { value } => {
            if let Some(e) = value {
                expr_reads(e);
            }
        }
        Stmt::Push { value } => expr_reads(value),
        Stmt::Pop { target } => {
            if matches!(target, VReg::Phys(n) if ssa_base(n) == name) {
                *writes = true;
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_reads(cond);
            for b in then_body.iter().chain(else_body.iter().flatten()) {
                walk_stmt_regs(b, name, reads, writes);
            }
        }
        Stmt::While { cond, body } => {
            expr_reads(cond);
            for b in body {
                walk_stmt_regs(b, name, reads, writes);
            }
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            expr_reads(cond);
            walk_stmt_regs(init, name, reads, writes);
            for stmt in body {
                walk_stmt_regs(stmt, name, reads, writes);
            }
            walk_stmt_regs(step, name, reads, writes);
        }
        Stmt::DoWhile { body, cond } => {
            // This walk only accumulates whether a read/write occurs anywhere;
            // visit the condition first to release the closure's borrow before
            // recursing into the body.
            expr_reads(cond);
            for b in body {
                walk_stmt_regs(b, name, reads, writes);
            }
        }
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expr_reads(discriminant);
            for b in cases
                .iter()
                .flat_map(|(_, b)| b)
                .chain(default.iter().flatten())
            {
                walk_stmt_regs(b, name, reads, writes);
            }
        }
        _ => {}
    }
}

/// Record, on a call whose result is USED, where that result lands.
///
/// A call produces a value; until this ran, the AST had no way to say so, and the
/// emitted C dropped the result on the floor — `fib` called itself and then used the
/// ARGUMENT in place of the returned value. The destination is the ABI's return
/// register, so the naming pass turns it into `ret` alongside every other use of that
/// register and the renderer can print `ret = f(...)`.
///
/// Two different facts must not be conflated here:
///
/// * the ABI **clobbers** the return register on every call, used or not. That is a
///   property of the machine and belongs in the value model (`def_uses`/SSA), where a
///   post-call read must not see the pre-call value;
/// * the **source consumed** the result. That is a property of this program, and it
///   is the only one that justifies printing an assignment.
///
/// A first version set the destination unconditionally, which asserted the second
/// fact everywhere the first held: `void`-returning calls rendered as `ret = puts(..)`,
/// claiming a result the source never took. So the destination is attached only when
/// the register is actually read before being overwritten.
///
/// The scan errs toward attaching it: falling off the end of the enclosing block is
/// treated as consumed, because control continues somewhere this walk cannot see, and
/// the costs are asymmetric — a spurious assignment is dead code a later pass can
/// drop, while a missing one makes the reader take a stale value.
pub(super) fn attribute_call_results(body: &mut Vec<Stmt>, arch: CallConv) {
    let ret = return_reg(arch);
    let consumed: Vec<Option<&'static str>> = (0..body.len())
        .map(|i| {
            if !matches!(&body[i], Stmt::Call { dst: None, .. }) {
                return None;
            }
            if arch == CallConv::ArmHardFloat {
                for candidate in ["s0", "d0", "r0"] {
                    if return_value_read_before_write(body, i, candidate) == Some(true) {
                        return Some(candidate);
                    }
                }
            }
            return_value_is_read(body, i, ret).then_some(ret)
        })
        .collect();
    for (i, s) in body.iter_mut().enumerate() {
        match s {
            Stmt::Call { dst, .. } => {
                if dst.is_none() {
                    if let Some(result) = consumed[i] {
                        *dst = Some(VReg::phys(result));
                    }
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                attribute_call_results(then_body, arch);
                if let Some(eb) = else_body {
                    attribute_call_results(eb, arch);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                attribute_call_results(body, arch)
            }
            Stmt::For { body, .. } => attribute_call_results(body, arch),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    attribute_call_results(b, arch);
                }
                if let Some(b) = default {
                    attribute_call_results(b, arch);
                }
            }
            _ => {}
        }
    }
}
