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
use crate::ir::types::{BinOp, VReg};

/// Which calling convention a function obeys. The register facts that follow from
/// it live in [`crate::ir::abi`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConv {
    SysVAmd64,
    Win64,
    /// 32-bit x86 cdecl: stack arguments, EAX return value.
    Cdecl32,
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

/// Recover a terminal jump through a resolved import slot as the source-level
/// tail call it implements.
///
/// This is intentionally narrower than generic indirect-call recovery. Only
/// `IndirectGoto(Deref(Named(...)))` qualifies: name resolution proved the memory
/// slot is a GOT/IAT-style symbol. Register/vtable/jump-table targets remain
/// `IndirectGoto`, preserving the explicit unrecovered-control-flow warning.
///
/// A tail transfer does not return to this machine frame, but its C meaning is
/// `return callee(...)`. We express that as adjacent Call + Return nodes so the
/// existing argument/result reconstruction and renderer can retain normal value
/// identity. When no argument register was set up locally, the jump forwards the
/// complete ABI register state. Logical `argN` names record that fact without
/// guessing a source prototype or a callee arity.
pub fn recover_resolved_tail_calls(f: &mut Function, arch: CallConv) {
    recover_tail_calls_in_body(&mut f.body, arch);
}

/// Recover a direct jump whose target is a named entry outside the current AST
/// as a source-level tail call.
///
/// Authoritative function ranges deliberately keep PLT stubs and neighboring
/// functions out of the lifted LLIR. The terminal machine jump therefore has
/// no local `Label`, but the binary address map still proves which callable
/// entry it targets. Converting only that exact combination avoids both a
/// dangling `goto` and the old workaround of importing the callee's basic
/// blocks into the caller.
pub fn recover_resolved_direct_tail_calls(
    f: &mut Function,
    arch: CallConv,
    names: &std::collections::HashMap<u64, String>,
) {
    let mut local_labels = std::collections::HashSet::new();
    collect_labels(&f.body, &mut local_labels);
    recover_direct_tail_calls_in_body(&mut f.body, arch, names, &local_labels);
}

fn collect_labels(body: &[Stmt], labels: &mut std::collections::HashSet<u64>) {
    for statement in body {
        match statement {
            Stmt::Label(va) => {
                labels.insert(*va);
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                collect_labels(then_body, labels);
                if let Some(else_body) = else_body {
                    collect_labels(else_body, labels);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                collect_labels(body, labels)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    collect_labels(case, labels);
                }
                if let Some(default) = default {
                    collect_labels(default, labels);
                }
            }
            _ => {}
        }
    }
}

fn recover_direct_tail_calls_in_body(
    body: &mut Vec<Stmt>,
    arch: CallConv,
    names: &std::collections::HashMap<u64, String>,
    local_labels: &std::collections::HashSet<u64>,
) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_direct_tail_calls_in_body(then_body, arch, names, local_labels);
                if let Some(else_body) = else_body {
                    recover_direct_tail_calls_in_body(else_body, arch, names, local_labels);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                recover_direct_tail_calls_in_body(body, arch, names, local_labels)
            }
            Stmt::For { body, .. } => {
                recover_direct_tail_calls_in_body(body, arch, names, local_labels)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_direct_tail_calls_in_body(case, arch, names, local_labels);
                }
                if let Some(default) = default {
                    recover_direct_tail_calls_in_body(default, arch, names, local_labels);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let callee = match &body[index] {
            Stmt::Goto { target } if !local_labels.contains(target) => {
                names.get(target).map(|name| Expr::Named {
                    va: *target,
                    name: name.clone(),
                })
            }
            _ => None,
        };
        let Some(callee) = callee else {
            index += 1;
            continue;
        };

        let has_local_setup = body[..index]
            .iter()
            .any(|statement| statement_writes_argument_slot(statement, arch));
        let args = if has_local_setup {
            Vec::new()
        } else {
            (0..arg_slots(arch).len())
                .map(|slot| Expr::Reg(VReg::phys(format!("arg{slot}"))))
                .collect()
        };
        body[index] = Stmt::Call {
            target: callee,
            args,
            dst: None,
            call_spec: None,
        };
        body.insert(
            index + 1,
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys(return_reg(arch)))),
            },
        );
        index += 2;
    }
}

fn recover_tail_calls_in_body(body: &mut Vec<Stmt>, arch: CallConv) {
    for stmt in body.iter_mut() {
        match stmt {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_tail_calls_in_body(then_body, arch);
                if let Some(else_body) = else_body {
                    recover_tail_calls_in_body(else_body, arch);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                recover_tail_calls_in_body(body, arch)
            }
            Stmt::For { body, .. } => recover_tail_calls_in_body(body, arch),
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_tail_calls_in_body(case, arch);
                }
                if let Some(default) = default {
                    recover_tail_calls_in_body(default, arch);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < body.len() {
        let callee = match &body[index] {
            Stmt::IndirectGoto {
                target: Expr::Deref { addr, .. },
            } => match addr.as_ref() {
                Expr::Named { .. } => Some((**addr).clone()),
                _ => None,
            },
            _ => None,
        };
        let Some(callee) = callee else {
            index += 1;
            continue;
        };

        let has_local_setup = body[..index]
            .iter()
            .any(|stmt| statement_writes_argument_slot(stmt, arch));
        let args = if has_local_setup {
            Vec::new()
        } else {
            (0..arg_slots(arch).len())
                .map(|slot| Expr::Reg(VReg::phys(format!("arg{slot}"))))
                .collect()
        };
        body[index] = Stmt::Call {
            target: callee,
            args,
            dst: None,
            call_spec: None,
        };
        body.insert(
            index + 1,
            Stmt::Return {
                value: Some(Expr::Reg(VReg::phys(return_reg(arch)))),
            },
        );
        index += 2;
    }
}

fn statement_writes_argument_slot(stmt: &Stmt, arch: CallConv) -> bool {
    match stmt {
        Stmt::Assign { dst, .. } | Stmt::Pop { target: dst } => {
            matches!(dst, VReg::Phys(name) if slot_of(arch, name).is_some())
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .iter()
                .any(|stmt| statement_writes_argument_slot(stmt, arch))
                || else_body.as_ref().is_some_and(|body| {
                    body.iter()
                        .any(|stmt| statement_writes_argument_slot(stmt, arch))
                })
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => body
            .iter()
            .any(|stmt| statement_writes_argument_slot(stmt, arch)),
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| {
                body.iter()
                    .any(|stmt| statement_writes_argument_slot(stmt, arch))
            }) || default.as_ref().is_some_and(|body| {
                body.iter()
                    .any(|stmt| statement_writes_argument_slot(stmt, arch))
            })
        }
        _ => false,
    }
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
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                expr(cond, f);
                expr(if_true, f);
                expr(if_false, f);
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
            Stmt::Call {
                target, args, dst, ..
            } => {
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
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                walk_body_reg_names(std::slice::from_ref(init.as_ref()), f);
                expr(cond, f);
                walk_body_reg_names(body, f);
                walk_body_reg_names(std::slice::from_ref(step.as_ref()), f);
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
        Stmt::Call {
            target, args, dst, ..
        } => {
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
            Stmt::For { body, .. } => fold_body(body, arch, param_slots),
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
    if arch == CallConv::Cdecl32 {
        fold_one_cdecl32_call(body, call_idx);
        return;
    }
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
                    // An older SSA definition may feed the captured value for
                    // this same architectural slot. Clang emits this for width
                    // normalisation (`rdx#1 = 0; rdx#2 = zext rdx#1`), with flag
                    // bookkeeping sometimes between the two definitions.
                    // Follow that exact definition edge instead of treating the
                    // SSA values as unrelated clobbers and abandoning every
                    // earlier argument slot.
                    if let Some((_, captured)) = &mut found[slot] {
                        if reads_reg_in_expr(captured, dst) {
                            // Pure normalisation can be stated directly in the
                            // call argument. Memory reads stay statement-rooted:
                            // moving a load across an intervening store would
                            // change its value, so the argument keeps referring
                            // to that SSA definition instead.
                            if is_pure_arg_normalisation(src) {
                                // `reads_reg_in_expr` also sees VReg-only address
                                // components (`Lea`, `PdbFieldAddr`, `StackAddr`).
                                // A non-register source cannot be substituted into
                                // those fields, by design. In that case the older
                                // definition remains in the body and the captured
                                // argument keeps its exact reaching reference.
                                let _ = substitute_exact_reg(captured, dst, src);
                            }
                            mark_arg_reads_in_expr(src, arch, &mut read_between);
                            continue;
                        }
                    }
                    // A genuinely unrelated second assignment to the same slot
                    // remains a boundary: the later value is live at the call.
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

/// Replace an exact SSA register use inside an ordinary value expression.
///
/// Address components remain VRegs by construction, so they are only rewritten
/// when the replacement is another bare register. `StackAddr` is storage
/// identity and intentionally does not participate in scalar substitution.
fn substitute_exact_reg(expr: &mut Expr, target: &VReg, replacement: &Expr) -> bool {
    match expr {
        Expr::Reg(reg) if reg == target => {
            *expr = replacement.clone();
            true
        }
        Expr::Reg(_) | Expr::StackAddr { .. } => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            let Expr::Reg(replacement) = replacement else {
                return false;
            };
            let mut changed = false;
            if base.as_ref() == Some(target) {
                *base = Some(replacement.clone());
                changed = true;
            }
            if index.as_ref() == Some(target) {
                *index = Some(replacement.clone());
                changed = true;
            }
            changed
        }
        Expr::Deref { addr, .. } => substitute_exact_reg(addr, target, replacement),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            let left = substitute_exact_reg(lhs, target, replacement);
            let right = substitute_exact_reg(rhs, target, replacement);
            left || right
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            let cond = substitute_exact_reg(cond, target, replacement);
            let if_true = substitute_exact_reg(if_true, target, replacement);
            let if_false = substitute_exact_reg(if_false, target, replacement);
            cond || if_true || if_false
        }
        Expr::Un { src, .. } => substitute_exact_reg(src, target, replacement),
        Expr::Cast { expr, .. } => substitute_exact_reg(expr, target, replacement),
        Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
    }
}

fn is_pure_arg_normalisation(expr: &Expr) -> bool {
    match expr {
        Expr::Deref { .. } | Expr::Unknown(_) => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            is_pure_arg_normalisation(lhs) && is_pure_arg_normalisation(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            is_pure_arg_normalisation(cond)
                && is_pure_arg_normalisation(if_true)
                && is_pure_arg_normalisation(if_false)
        }
        Expr::Un { src, .. } => is_pure_arg_normalisation(src),
        Expr::Cast { expr, .. } => is_pure_arg_normalisation(expr),
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => true,
    }
}

/// Recover 32-bit cdecl arguments from stores into the outgoing ESP area.
///
/// A typical caller emits `mov [esp], a0; mov [esp+4], a1; call f`. These are
/// not register assignments, so the register-ABI reconstruction above sees no
/// arguments at all. Walk backward only to the nearest call/stack adjustment or
/// control-flow boundary, retain the latest store at each non-negative offset,
/// and accept an exactly contiguous layout beginning at `[esp]`.
fn fold_one_cdecl32_call(body: &mut Vec<Stmt>, call_idx: usize) {
    let mut by_offset: std::collections::BTreeMap<i64, (usize, Expr, u8)> =
        std::collections::BTreeMap::new();
    let mut pushed_args = Vec::new();
    let mut used = Vec::new();
    let mut cursor = call_idx;
    while cursor > 0 {
        let i = cursor - 1;
        match &body[i] {
            Stmt::Call { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Return { .. }
            | Stmt::If { .. }
            | Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::Switch { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. } => break,
            Stmt::Assign {
                dst: VReg::Phys(frame),
                src: Expr::Reg(VReg::Phys(stack)),
            } if matches!(frame.as_str(), "ebp" | "rbp")
                && matches!(stack.as_str(), "esp" | "rsp") =>
            {
                break;
            }
            Stmt::Assign {
                dst: VReg::Phys(name),
                ..
            } if name == "esp" || name == "rsp" => break,
            Stmt::Store {
                addr:
                    Expr::Lea {
                        base: Some(VReg::Phys(base)),
                        index: None,
                        disp,
                        ..
                    },
                src,
                size,
            } if matches!(base.as_str(), "esp" | "rsp") && *disp >= 0 && *size > 0 => {
                // Iced lowers `push X` to `sp -= width; [sp] = X`. Walking
                // backward encounters cdecl's right-to-left pushes in source
                // argument order: arg0, arg1, ... . Absorb both halves of each
                // pair, but stop at an unrelated stack adjustment (alignment,
                // local allocation, or cleanup) rather than guessing across it.
                if *disp == 0
                    && i > 0
                    && stack_pointer_sub_width(&body[i - 1]) == Some(i64::from(*size))
                {
                    pushed_args.push(src.clone());
                    used.extend([i, i - 1]);
                    cursor = i - 1;
                    continue;
                }
                if pushed_args.is_empty() {
                    by_offset
                        .entry(*disp)
                        .or_insert_with(|| (i, src.clone(), *size));
                } else {
                    break;
                }
            }
            _ => {}
        }
        cursor = i;
    }

    let args = if pushed_args.is_empty() {
        let mut args = Vec::new();
        let mut expected_offset = 0i64;
        for (offset, (stmt_idx, value, size)) in by_offset {
            if offset != expected_offset {
                break;
            }
            args.push(value);
            used.push(stmt_idx);
            let slot_size = i64::from(size).max(4);
            expected_offset = expected_offset.saturating_add((slot_size + 3) & !3);
        }
        args
    } else {
        pushed_args
    };
    if args.is_empty() {
        return;
    }

    if let Stmt::Call {
        args: call_args, ..
    } = &mut body[call_idx]
    {
        *call_args = args;
    }
    used.sort_unstable_by(|left, right| right.cmp(left));
    for stmt_idx in used {
        body.remove(stmt_idx);
    }
}

/// Width of `esp/rsp = esp/rsp - N`, if this is exactly a stack allocation.
fn stack_pointer_sub_width(stmt: &Stmt) -> Option<i64> {
    let Stmt::Assign {
        dst: VReg::Phys(dst),
        src: Expr::Bin {
            op: BinOp::Sub,
            lhs,
            rhs,
        },
    } = stmt
    else {
        return None;
    };
    if !matches!(dst.as_str(), "esp" | "rsp")
        || !matches!(lhs.as_ref(), Expr::Reg(VReg::Phys(src)) if src == dst)
    {
        return None;
    }
    match rhs.as_ref() {
        Expr::Const(width) if *width > 0 => Some(*width),
        _ => None,
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
        Expr::Cast { expr, .. } => mark_arg_reads_in_expr(expr, arch, read_between),
    }
}

fn mark_arg_reads_in_stmt(s: &Stmt, arch: CallConv, read_between: &mut [bool]) {
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
        // A computed transfer writes no argument slot.
        Stmt::IndirectGoto { .. } => {}
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
        Expr::StackAddr { object, .. } => object == target,
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
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            reads_reg_in_expr(cond, target)
                || reads_reg_in_expr(if_true, target)
                || reads_reg_in_expr(if_false, target)
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

    fn got_tail(name: &str, va: u64) -> Stmt {
        Stmt::IndirectGoto {
            target: Expr::Deref {
                addr: Box::new(Expr::Named {
                    va,
                    name: name.to_string(),
                }),
                size: 8,
            },
        }
    }

    #[test]
    fn resolved_got_tail_jump_becomes_a_call_and_return() {
        let mut f = Function {
            name: "reverse".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("r8#1"),
                    src: Expr::Reg(reg("rdi#0")),
                },
                Stmt::Assign {
                    dst: reg("rax#1"),
                    src: Expr::Reg(reg("rsi#0")),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Reg(reg("rcx#0")),
                },
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rdx#0")),
                },
                Stmt::Assign {
                    dst: reg("rcx#1"),
                    src: Expr::Reg(reg("r8#1")),
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Reg(reg("rax#1")),
                },
                got_tail("sum_arg4", 0x4000),
            ],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);
        reconstruct_args_with_params(
            &mut f,
            CallConv::SysVAmd64,
            &[0, 1, 2, 3].into_iter().collect(),
        );

        let (target, args, dst) = f
            .body
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Call {
                    target, args, dst, ..
                } => Some((target, args, dst)),
                _ => None,
            })
            .expect("the resolved terminal transfer must become a call");
        assert!(matches!(target, Expr::Named { name, .. } if name == "sum_arg4"));
        assert_eq!(
            args,
            &vec![
                Expr::Reg(reg("rcx#0")),
                Expr::Reg(reg("rdx#0")),
                Expr::Reg(reg("rax#1")),
                Expr::Reg(reg("r8#1")),
            ]
        );
        assert_eq!(dst, &Some(reg("rax")));
        assert!(matches!(
            f.body.last(),
            Some(Stmt::Return {
                value: Some(Expr::Reg(VReg::Phys(name)))
            }) if name == "rax"
        ));
    }

    #[test]
    fn untouched_tail_jump_forwards_the_complete_abi_register_state() {
        let mut f = Function {
            name: "forward".into(),
            entry_va: 0,
            body: vec![got_tail("sum_arg6", 0x4008)],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { target, args, .. } = &f.body[0] else {
            panic!("expected recovered call, got {:#?}", f.body);
        };
        assert!(matches!(target, Expr::Named { name, .. } if name == "sum_arg6"));
        assert_eq!(
            args,
            &(0..6)
                .map(|slot| Expr::Reg(reg(&format!("arg{slot}"))))
                .collect::<Vec<_>>()
        );
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn unresolved_direct_jump_to_a_named_external_entry_becomes_a_tail_call() {
        let mut f = Function {
            name: "forward_sum6".into(),
            entry_va: 0x17b0,
            body: vec![Stmt::Goto { target: 0x1070 }],
        };
        let names = [(0x1070, "sum_arg6@plt".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        let Stmt::Call { target, args, .. } = &f.body[0] else {
            panic!("expected recovered direct tail call, got {:#?}", f.body);
        };
        assert!(matches!(target, Expr::Named { va: 0x1070, name } if name == "sum_arg6@plt"));
        assert_eq!(
            args,
            &(0..6)
                .map(|slot| Expr::Reg(reg(&format!("arg{slot}"))))
                .collect::<Vec<_>>()
        );
        assert!(matches!(f.body[1], Stmt::Return { .. }));
    }

    #[test]
    fn direct_jump_with_an_in_function_label_stays_a_goto() {
        let mut f = Function {
            name: "loop".into(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Goto { target: 0x1070 },
                Stmt::Label(0x1070),
                Stmt::Return { value: None },
            ],
        };
        let names = [(0x1070, "other_symbol".to_string())].into_iter().collect();

        recover_resolved_direct_tail_calls(&mut f, CallConv::SysVAmd64, &names);

        assert!(matches!(f.body[0], Stmt::Goto { target: 0x1070 }));
    }

    #[test]
    fn unresolved_computed_jump_is_not_relabelled_as_a_call() {
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0,
            body: vec![Stmt::IndirectGoto {
                target: Expr::Reg(reg("rax")),
            }],
        };

        recover_resolved_tail_calls(&mut f, CallConv::SysVAmd64);
        assert!(matches!(f.body.as_slice(), [Stmt::IndirectGoto { .. }]));
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
                    call_spec: None,
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
                    call_spec: None,
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
    fn cdecl32_folds_contiguous_outgoing_stack_stores() {
        let stack_store = |disp, value| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("esp")),
                index: None,
                scale: 1,
                disp,
                segment: None,
            },
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                stack_store(8, 30),
                stack_store(4, 20),
                stack_store(0, 10),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "callee".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(
            f.body.len(),
            1,
            "stack setup was not absorbed: {:#?}",
            f.body
        );
        assert!(matches!(
            &f.body[0],
            Stmt::Call { args, .. }
                if args == &vec![Expr::Const(10), Expr::Const(20), Expr::Const(30)]
        ));
    }

    #[test]
    fn cdecl32_folds_right_to_left_push_lowering() {
        let push_pair = |value| {
            [
                Stmt::Assign {
                    dst: reg("rsp"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rsp"))),
                        rhs: Box::new(Expr::Const(4)),
                    },
                },
                Stmt::Store {
                    addr: Expr::Lea {
                        base: Some(reg("rsp")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                    src: Expr::Const(value),
                    size: 4,
                },
            ]
        };
        let mut body = Vec::new();
        body.extend(push_pair(30));
        body.extend(push_pair(20));
        body.extend(push_pair(10));
        body.push(Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: "callee".into(),
            },
            args: Vec::new(),
            dst: None,
            call_spec: None,
        });
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body,
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert_eq!(
            f.body.len(),
            1,
            "push setup was not absorbed: {:#?}",
            f.body
        );
        assert!(matches!(
            &f.body[0],
            Stmt::Call { args, .. }
                if args == &vec![Expr::Const(10), Expr::Const(20), Expr::Const(30)]
        ));
    }

    #[test]
    fn cdecl32_does_not_absorb_frame_prologue_as_an_argument() {
        let stack_sub = || Stmt::Assign {
            dst: reg("rsp"),
            src: Expr::Bin {
                op: BinOp::Sub,
                lhs: Box::new(Expr::Reg(reg("rsp"))),
                rhs: Box::new(Expr::Const(4)),
            },
        };
        let stack_store = |value| Stmt::Store {
            addr: Expr::Lea {
                base: Some(reg("rsp")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            },
            src: Expr::Const(value),
            size: 4,
        };
        let mut f = Function {
            name: "caller".into(),
            entry_va: 0,
            body: vec![
                stack_sub(),
                stack_store(99),
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("rsp")),
                },
                stack_sub(),
                stack_store(20),
                stack_sub(),
                stack_store(10),
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "callee".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };

        reconstruct_args(&mut f, CallConv::Cdecl32);

        assert!(matches!(
            f.body.last(),
            Some(Stmt::Call { args, .. })
                if args == &vec![Expr::Const(10), Expr::Const(20)]
        ));
        assert!(f.body.iter().any(|stmt| matches!(
            stmt,
            Stmt::Assign { dst: VReg::Phys(name), .. } if name == "rbp"
        )));
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
                    call_spec: None,
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
                    call_spec: None,
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
            call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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
                    call_spec: None,
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

    #[test]
    fn ssa_normalisation_chain_of_one_argument_does_not_hide_earlier_slots() {
        // Clang -O0 commonly zeroes edx and then emits the architectural
        // zero-extension as a second SSA definition immediately before a call.
        // Treating that as an unrelated second write stopped the entire backward
        // scan and lost this, arg1, and arg3 as well as the zero argument.
        let mut f = Function {
            name: "clang_ctor_call".to_string(),
            entry_va: 0x1000,
            body: vec![
                Stmt::Assign {
                    dst: reg("rsi#1"),
                    src: Expr::Reg(reg("rsi#0")),
                },
                Stmt::Assign {
                    dst: reg("rcx#1"),
                    src: Expr::Reg(reg("rcx#0")),
                },
                Stmt::Assign {
                    dst: reg("rdi#1"),
                    src: Expr::Bin {
                        op: BinOp::Sub,
                        lhs: Box::new(Expr::Reg(reg("rbp"))),
                        rhs: Box::new(Expr::Const(32)),
                    },
                },
                Stmt::Assign {
                    dst: reg("rdx#1"),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: reg("rdx#2"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Reg(reg("rdx#1"))),
                    },
                },
                call_to("ctor"),
            ],
        };

        reconstruct_args(&mut f, CallConv::SysVAmd64);

        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {:#?}", f.body);
        };
        assert_eq!(
            args.len(),
            4,
            "all contiguous ABI slots must survive: {f:#?}"
        );
        assert_eq!(
            args[2],
            Expr::Cast {
                signed: false,
                width: 8,
                expr: Box::new(Expr::Const(0)),
            }
        );
    }

    #[test]
    fn nonsubstitutable_address_dependency_stays_statement_rooted() {
        // ARM address formation can reuse one ABI slot through two SSA
        // definitions. The later argument expression reads the older value as
        // a LEA component, but substituting an arithmetic expression into that
        // VReg-only component is intentionally unsupported. That is not an
        // invariant failure: keep the older definition and let the call
        // argument continue to reference it.
        let older = Stmt::Assign {
            dst: reg("r0#1"),
            src: Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(reg("r4#1"))),
                rhs: Box::new(Expr::Const(4)),
            },
        };
        let mut f = Function {
            name: "arm_address_arg".to_string(),
            entry_va: 0x1000,
            body: vec![
                older.clone(),
                Stmt::Assign {
                    dst: reg("r0#2"),
                    src: Expr::Lea {
                        base: Some(reg("r0#1")),
                        index: None,
                        scale: 1,
                        disp: 0,
                        segment: None,
                    },
                },
                call_to("callee"),
            ],
        };

        reconstruct_args(&mut f, CallConv::Arm);

        assert_eq!(f.body.first(), Some(&older));
        let Stmt::Call { args, .. } = f.body.last().expect("call must survive") else {
            panic!("expected call: {:#?}", f.body)
        };
        assert_eq!(
            args,
            &[Expr::Lea {
                base: Some(reg("r0#1")),
                index: None,
                scale: 1,
                disp: 0,
                segment: None,
            }]
        );
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
                    call_spec: None,
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
                    call_spec: None,
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
