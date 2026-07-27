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

/// Which calling convention a function obeys. The register facts that follow from
/// it live in [`crate::ir::abi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    SysVAmd64,
    Win64,
    Aarch64,
    /// ARM32 AAPCS (r0-r3 args, r0 return).
    Arm,
}

/// Argument slots come from [`crate::ir::abi`], which owns them. They were
/// previously written out here AND in `value_number`, and the copies drifted in a
/// way no test could see: this one matched names literally while the other had
/// already renamed registers to `canon#version`, so `rdi#3` matched nothing and
/// every call on that path silently lost all of its arguments.
fn arg_slots(arch: CallConv) -> &'static [&'static [&'static str]] {
    crate::ir::abi::argument_slots(arch)
}

/// The calling-convention slot a register name denotes, if any.
///
/// The name may be SSA-VERSIONED. The decbench pipeline value-numbers the LLIR
/// before lowering (`value_number` renames a register to `canon#version`), so an
/// argument arrives here as `rdi#3`. Matching the slot table against the literal
/// string found nothing and every call on that path silently lost all of its
/// arguments — `signed_step(x)` rendered as `signed_step()`. The register-style
/// path does not value-number, which is exactly why the same function showed its
/// arguments there and hid the bug.
fn slot_of(arch: CallConv, name: &str) -> Option<usize> {
    crate::ir::abi::argument_slot_of(arch, name)
}

fn ssa_base(name: &str) -> &str {
    crate::ir::abi::ssa_base(name)
}

/// An expression naming the function's INCOMING value in `slot`, as that value is
/// actually spelled in `body`.
///
/// The bare canonical name is wrong on a value-numbered body. The decbench
/// pipeline renames registers to `canon#version`, so injecting `rdi` referenced a
/// register the body never defines — it survived naming as a scratch `varN` and
/// produced `__stack_chk_fail(var24)`, an argument reading nothing, in a callee
/// that takes no arguments at all.
///
/// The incoming value is the LOWEST version of the slot's register present in the
/// body: later versions are definitions made inside the function. When the slot's
/// register does not appear at all there is no incoming value to name and no
/// argument is invented.
fn incoming_arg_expr(arch: CallConv, slot: usize, body: &[Stmt]) -> Option<Expr> {
    let names = arg_slots(arch).get(slot)?;
    // Is this body value-numbered at all? On the un-numbered path the incoming
    // register is implicit — it legitimately appears nowhere — and the bare
    // canonical name is the right reference, as it always was.
    let mut versioned_anywhere = false;
    let mut best: Option<(u32, String)> = None;
    let mut visit = |n: &str| {
        let Some((_, v)) = n.split_once('#') else {
            return;
        };
        versioned_anywhere = true;
        if !names.contains(&ssa_base(n)) {
            return;
        }
        if let Ok(v) = v.parse::<u32>() {
            if best.as_ref().is_none_or(|(bv, _)| v < *bv) {
                best = Some((v, n.to_string()));
            }
        }
    };
    walk_body_reg_names(body, &mut visit);
    if !versioned_anywhere {
        return names
            .first()
            .map(|n| Expr::Reg(VReg::Phys((*n).to_string())));
    }
    // VALUE-NUMBERED: decline. Naming the live-in version requires knowing which
    // version `value_number` treats as live-in, and this pass cannot see that.
    // Guessing the lowest version present is wrong — in `cpp_virtual_dispatch` the
    // only `rdi` in the body is a scratch use that nothing defines, so the guess
    // produced `__stack_chk_fail(var24)`: an argument reading an undefined value,
    // handed to a callee that takes none.
    //
    // Declining costs the Win64 forwarding recovery on this path only, where it
    // was inventing wrong arguments anyway; the register path keeps it. Doing it
    // properly means threading the live-in version out of `value_number` — see the
    // AbiDescriptor consolidation.
    let _ = best;
    None
}

/// Call `f` with every register name mentioned anywhere in `body`.
fn walk_body_reg_names(body: &[Stmt], f: &mut impl FnMut(&str)) {
    fn expr(e: &Expr, f: &mut impl FnMut(&str)) {
        match e {
            Expr::Reg(VReg::Phys(n)) => f(n),
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                expr(lhs, f);
                expr(rhs, f);
            }
            Expr::Un { src, .. } => expr(src, f),
            Expr::Cast { expr: e, .. } => expr(e, f),
            Expr::Deref { addr, .. } => expr(addr, f),
            _ => {}
        }
    }
    for s in body {
        match s {
            Stmt::Assign { dst, src } => {
                if let VReg::Phys(n) = dst {
                    f(n);
                }
                expr(src, f);
            }
            Stmt::Store { addr, src, .. } => {
                expr(addr, f);
                expr(src, f);
            }
            Stmt::Call { target, args, dst } => {
                expr(target, f);
                for a in args {
                    expr(a, f);
                }
                if let Some(VReg::Phys(n)) = dst {
                    f(n);
                }
            }
            Stmt::Return { value: Some(e) } => expr(e, f),
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                expr(cond, f);
                walk_body_reg_names(then_body, f);
                if let Some(b) = else_body {
                    walk_body_reg_names(b, f);
                }
            }
            Stmt::While { cond, body } => {
                expr(cond, f);
                walk_body_reg_names(body, f);
            }
            Stmt::DoWhile { body, cond } => {
                walk_body_reg_names(body, f);
                expr(cond, f);
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                expr(discriminant, f);
                for (_, b) in cases {
                    walk_body_reg_names(b, f);
                }
                if let Some(b) = default {
                    walk_body_reg_names(b, f);
                }
            }
            Stmt::Push { value } => expr(value, f),
            _ => {}
        }
    }
}

/// Run argument reconstruction on `f` using the given calling convention.
pub fn reconstruct_args(f: &mut Function, arch: CallConv) {
    reconstruct_args_with_params(f, arch, &std::collections::HashSet::new())
}

/// As [`reconstruct_args`], but told which argument slots hold THIS function's
/// own incoming parameters (`value_number::live_in_arg_slots_llir`).
///
/// The backfill below invents an argument from the incoming register when an
/// earlier slot was never written. That is only sound when the register actually
/// carries a parameter. Without the set it fired on `__stack_chk_fail` — a void
/// callee — and produced `__stack_chk_fail(var24)` reading a value nothing ever
/// defines, which the definition verifier duly reported.
pub fn reconstruct_args_with_params(
    f: &mut Function,
    arch: CallConv,
    param_slots: &std::collections::HashSet<usize>,
) {
    fold_body(&mut f.body, arch, param_slots);
    attribute_call_results(&mut f.body, arch);
}

/// The register a callee leaves its return value in.
fn return_reg(arch: CallConv) -> &'static str {
    crate::ir::abi::return_register(arch)
}

/// Is the return register read after the call at `call_idx`, before anything
/// overwrites it? Nested bodies are treated as opaque reads (conservative): if a
/// branch might read it, the result is consumed.
fn return_value_is_read(body: &[Stmt], call_idx: usize, ret: &str) -> bool {
    for s in &body[call_idx + 1..] {
        let mut reads = false;
        let mut writes = false;
        walk_stmt_regs(s, ret, &mut reads, &mut writes);
        if reads {
            return true;
        }
        if writes {
            return false;
        }
    }
    // Fell off the end of this block: control continues where this walk cannot see.
    true
}

/// Note reads and writes of `name` in `s`. A statement with a nested body reports a
/// read if the name appears anywhere inside it, so a conditional consumer counts.
fn walk_stmt_regs(s: &Stmt, name: &str, reads: &mut bool, writes: &mut bool) {
    let mut expr_reads = |e: &Expr| {
        if reads_reg_in_expr(e, &VReg::phys(name)) {
            *reads = true;
        }
    };
    match s {
        Stmt::Assign { dst, src } => {
            expr_reads(src);
            if matches!(dst, VReg::Phys(n) if n == name) {
                *writes = true;
            }
        }
        Stmt::Store { addr, src, .. } => {
            expr_reads(addr);
            expr_reads(src);
        }
        Stmt::Call { target, args, dst } => {
            expr_reads(target);
            for a in args {
                expr_reads(a);
            }
            // A later call clobbers the register whether or not it took the value.
            if dst.is_none() || matches!(dst, Some(VReg::Phys(n)) if n == name) {
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
            if matches!(target, VReg::Phys(n) if n == name) {
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
fn attribute_call_results(body: &mut Vec<Stmt>, arch: CallConv) {
    let ret = return_reg(arch);
    let consumed: Vec<bool> = (0..body.len())
        .map(|i| {
            matches!(&body[i], Stmt::Call { dst: None, .. }) && return_value_is_read(body, i, ret)
        })
        .collect();
    for (i, s) in body.iter_mut().enumerate() {
        match s {
            Stmt::Call { dst, .. } => {
                if dst.is_none() && consumed[i] {
                    *dst = Some(VReg::phys(ret));
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

fn fold_body(body: &mut Vec<Stmt>, arch: CallConv, param_slots: &std::collections::HashSet<usize>) {
    // Recurse into nested bodies first so we don't miss calls inside arms.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_body(then_body, arch, param_slots);
                if let Some(eb) = else_body {
                    fold_body(eb, arch, param_slots);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                fold_body(body, arch, param_slots)
            }
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
        fold_one_call(body, call_idx, arch, param_slots);
    }
}

fn fold_one_call(
    body: &mut Vec<Stmt>,
    call_idx: usize,
    arch: CallConv,
    param_slots: &std::collections::HashSet<usize>,
) {
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
            // Backfill an unwritten earlier slot from the incoming register —
            // but only when that slot really is one of THIS function's
            // parameters. Otherwise the "argument" is a register nothing defined,
            // and a void callee acquires one out of thin air
            // (`__stack_chk_fail(var24)`).
            None if args_out.is_empty()
                && !blocked_incoming[slot_idx]
                && param_slots.contains(&slot_idx) =>
            {
                let Some(expr) = incoming_arg_expr(arch, slot_idx, body) else {
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
        Expr::Cast { expr, .. } => mark_arg_reads_in_expr(expr, arch, read_between),
    }
}

fn mark_arg_reads_in_stmt(s: &Stmt, arch: CallConv, read_between: &mut [bool]) {
    match s {
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
        Stmt::DoWhile { body, cond } => {
            for stmt in body {
                mark_arg_reads_in_stmt(stmt, arch, read_between);
            }
            mark_arg_reads_in_expr(cond, arch, read_between);
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
        | Stmt::Break
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
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
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
        | Stmt::Break
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
        Expr::Cast { expr, .. } => reads_reg_in_expr(expr, target),
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
                    dst: None,
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
                    dst: None,
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
                    dst: None,
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
                    dst: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
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
                    dst: None,
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
                    dst: None,
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
                    dst: None,
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
                    dst: None,
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
                    size: 8,
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
                    size: 8,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strcpy_s".into(),
                    },
                    args: Vec::new(),
                    dst: None,
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
                    dst: None,
                },
            ],
        };
        // The premise of the backfill is that `rcx` still carries the function's
        // OWN incoming first parameter, so slot 0 must be declared as such.
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());

        assert_eq!(f.body.len(), 1);
        if let Stmt::Call { args, .. } = &f.body[0] {
            assert_eq!(args, &vec![Expr::Reg(reg("rcx")), Expr::Const(256)]);
        } else {
            panic!("expected Call, got {:?}", f.body[0]);
        }
    }

    /// The same shape in a function that has NO first parameter must not invent
    /// one. This is how `__stack_chk_fail`, which takes nothing, acquired
    /// `__stack_chk_fail(var24)` — an argument reading a register nothing defines.
    #[test]
    fn no_incoming_argument_is_invented_when_the_slot_is_not_a_parameter() {
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
                    dst: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &Default::default());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args.iter().any(|a| *a == Expr::Reg(reg("rcx"))),
            "invented an incoming argument for a slot that is not a parameter: {args:?}"
        );
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
                    dst: None,
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
                    size: 8,
                },
                assign("rdx", 2),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
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
                    dst: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        // Since rdi can't fold, the slot-0 is empty, so nothing folds at all
        // (args are contiguous prefix).
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rdi")));
    }

    fn call_to(name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0x2000,
                name: name.into(),
            },
            args: vec![],
            dst: None,
        }
    }

    fn dst_of(s: &Stmt) -> &Option<VReg> {
        match s {
            Stmt::Call { dst, .. } => dst,
            other => panic!("expected a call, got {other:?}"),
        }
    }

    #[test]
    fn a_consumed_call_result_records_where_it_lands() {
        // A call PRODUCES a value. Until the AST could say so, the emitted C dropped
        // it: `fib` called itself and then used the ARGUMENT where the returned value
        // belonged.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("g"),
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn a_result_nobody_reads_is_not_an_assignment() {
        // The ABI clobbers the return register on EVERY call — that belongs in the
        // value model. Printing `ret = puts(..)` claims something else: that the
        // source took the result. Here the register is overwritten before any read.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("puts"),
                Stmt::Assign {
                    dst: VReg::phys("rax"),
                    src: Expr::Const(0),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), None);
    }

    #[test]
    fn a_later_call_clobbers_the_register_so_the_earlier_result_is_unread() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("first"),
                call_to("second"),
                Stmt::Return {
                    value: Some(Expr::Reg(VReg::phys("rax"))),
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), None, "first result is never read");
        assert_eq!(
            *dst_of(&f.body[1]),
            Some(VReg::phys("rax")),
            "second result is returned"
        );
    }

    #[test]
    fn a_conditional_reader_counts_as_consuming_the_result() {
        // The scan errs toward attaching the destination: a spurious assignment is
        // dead code, a missing one makes the reader take a stale value.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                call_to("g"),
                Stmt::If {
                    cond: Expr::Reg(VReg::phys("rdi")),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(VReg::phys("rax"))),
                    }],
                    else_body: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn a_call_at_the_end_of_a_block_is_treated_as_consumed() {
        // Control continues where this walk cannot see.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![call_to("g")],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        assert_eq!(*dst_of(&f.body[0]), Some(VReg::phys("rax")));
    }

    #[test]
    fn the_result_register_follows_the_abi() {
        for (cc, reg_name) in [
            (CallConv::SysVAmd64, "rax"),
            (CallConv::Win64, "rax"),
            (CallConv::Aarch64, "x0"),
            (CallConv::Arm, "r0"),
        ] {
            let mut f = Function {
                name: "f".into(),
                entry_va: 0,
                body: vec![Stmt::Call {
                    target: Expr::Addr(0x2000),
                    args: vec![],
                    dst: None,
                }],
            };
            // A call at the end of a block counts as consumed, so this exercises the
            // ABI's choice of register rather than the liveness scan.
            reconstruct_args(&mut f, cc);
            match &f.body[0] {
                Stmt::Call { dst, .. } => assert_eq!(*dst, Some(VReg::phys(reg_name)), "{cc:?}"),
                other => panic!("expected a call, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_call_inside_a_branch_is_attributed_too() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(VReg::phys("rdi")),
                then_body: vec![Stmt::Call {
                    target: Expr::Addr(0x2000),
                    args: vec![],
                    dst: None,
                }],
                else_body: None,
            }],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        match &f.body[0] {
            Stmt::If { then_body, .. } => match &then_body[0] {
                Stmt::Call { dst, .. } => assert_eq!(*dst, Some(VReg::phys("rax"))),
                other => panic!("expected a call, got {other:?}"),
            },
            other => panic!("expected an if, got {other:?}"),
        }
    }

    /// The decbench pipeline value-numbers the LLIR before lowering, so an
    /// argument register arrives as `rdi#3`, not `rdi`. Matching the slot table
    /// against the literal name found NOTHING, and every call on that path lost
    /// all of its arguments: `signed_step(x)` rendered as `signed_step()`.
    ///
    /// The register-style path does not value-number, which is why the same
    /// function showed the argument there and hid the bug.
    #[test]
    fn an_ssa_versioned_argument_register_still_names_its_slot() {
        assert_eq!(slot_of(CallConv::SysVAmd64, "rdi"), Some(0));
        assert_eq!(slot_of(CallConv::SysVAmd64, "rdi#3"), Some(0));
        assert_eq!(slot_of(CallConv::SysVAmd64, "esi#12"), Some(1));
        assert_eq!(slot_of(CallConv::Aarch64, "x2#1"), Some(2));
        // A non-argument register is still not an argument register.
        assert_eq!(slot_of(CallConv::SysVAmd64, "rbx#2"), None);
    }

    /// End to end over the pass: a value-numbered argument write folds into the
    /// call just as an unversioned one does.
    #[test]
    fn a_value_numbered_argument_write_folds_into_the_call() {
        let mut f = Function {
            name: "caller".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rdi#4"),
                    src: Expr::Const(7),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "callee".to_string(),
                    },
                    args: vec![],
                    dst: None,
                },
            ],
        };
        reconstruct_args(&mut f, CallConv::SysVAmd64);
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert_eq!(args, vec![Expr::Const(7)], "body was:\n{:#?}", f.body);
    }

    /// On a VALUE-NUMBERED body the incoming value has a version, and only a
    /// version the body mentions may be referenced. Injecting the bare `rdi` gave
    /// `__stack_chk_fail(var24)` — an argument reading a register nothing defines,
    /// in a callee that takes none.
    #[test]
    fn no_bare_register_is_injected_into_a_value_numbered_body() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                assign("rdx#7", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args
                .iter()
                .any(|a| matches!(a, Expr::Reg(VReg::Phys(n)) if n == "rcx")),
            "injected an unversioned register into a value-numbered body: {args:?}"
        );
    }

    /// A value-numbered body declines the backfill entirely: the live-in version is
    /// not knowable here, and guessing produced an argument that read nothing.
    #[test]
    fn a_value_numbered_body_declines_the_incoming_backfill() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("scratch"),
                    src: Expr::Reg(reg("rcx#1")),
                },
                assign("rdx#7", 256),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "strnlen".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                },
            ],
        };
        reconstruct_args_with_params(&mut f, CallConv::Win64, &[0].into_iter().collect());
        let args = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Call { args, .. } => Some(args.clone()),
                _ => None,
            })
            .expect("the call must survive");
        assert!(
            !args
                .iter()
                .any(|a| matches!(a, Expr::Reg(VReg::Phys(n)) if ssa_base(n) == "rcx")),
            "the backfill must not fire on a value-numbered body: {args:?}"
        );
    }
}
