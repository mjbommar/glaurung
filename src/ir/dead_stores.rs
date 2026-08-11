//! Intra-body dead-store elimination.
//!
//! A store (`Stmt::Assign { dst: D, ... }`) is dead when the value written to
//! `D` is never read before the next write to `D` — or before the end of the
//! body. This pass conservatively removes such stores inside a single
//! `Vec<Stmt>`, recursing into If/While arms.
//!
//! Scope (v1):
//!
//! * We walk forward within a body. For each assignment to some register
//!   `D`, we scan forward: if we see a read of `D` first, the store is
//!   **live**; if we see another write to `D` (or a `Stmt::Call` that
//!   writes `D` by convention) with no prior read, the store is **dead**
//!   and we delete it.
//! * Stmt::Call is treated as reading every regisdt listed in its `args`
//!   (already explicit in the AST) and — for the current architecture's
//!   return-value register — as *writing* it. That is enough to collapse
//!   the common `%ret = 0; call foo(); %ret = 0; call bar();` shape.
//! * We never cross a nested If/While boundary. Any read inside such a
//!   nested body flushes our analysis for that variable (we conservatively
//!   treat the store as live).
//! * We never remove flag-VReg writes — those are handled by the dedicated
//!   `dce` pass which already understands their locality.

use std::collections::HashSet;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};

/// Run dead-store elimination for the given calling convention.
pub fn eliminate_dead_stores(f: &mut Function, cc: CallConv) {
    let ret_regs = return_reg_aliases(cc);
    eliminate_body(&mut f.body, &ret_regs);
}

fn return_reg_aliases(cc: CallConv) -> Vec<&'static str> {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => vec!["rax", "eax", "ax", "al", "ret"],
        CallConv::Cdecl32 => vec!["rax", "eax", "ax", "al", "ret"],
        CallConv::Aarch64 => vec!["x0", "w0", "arg0", "ret"],
        CallConv::Arm | CallConv::ArmHardFloat => vec!["r0", "s0", "d0", "arg0", "ret"],
    }
}

fn eliminate_body(body: &mut Vec<Stmt>, ret_regs: &[&str]) {
    // Recurse first so inner bodies drive their own analyses.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                eliminate_body(then_body, ret_regs);
                if let Some(eb) = else_body {
                    eliminate_body(eb, ret_regs);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => eliminate_body(body, ret_regs),
            Stmt::For { body, .. } => eliminate_body(body, ret_regs),
            _ => {}
        }
    }

    // Pre-pass: drop ABI-bookkeeping zero stores to frame-/link-registers
    // that are never read elsewhere in the body. These are emitted by glibc's
    // `_start` to establish a sentinel frame and are always dead from the
    // visible-C semantics view.
    drop_unread_abi_zeros(body);

    let mut i = 0;
    while i < body.len() {
        // Drop `%X = %X` self-assigns unconditionally — they have no
        // side effect and appear after naming collapses two aliases onto
        // the same role-name (e.g. `%edi` and `%rdi` both becoming `%arg0`).
        if matches!(
            &body[i],
            Stmt::Assign { dst, src: Expr::Reg(r) } if dst == r
        ) {
            body.remove(i);
            continue;
        }
        let dst = match &body[i] {
            Stmt::Assign { dst, src } => match dst {
                // Only regular register writes are considered. Flag writes
                // are handled elsewhere.
                VReg::Phys(_) | VReg::Temp(_) if !src.contains_call() => dst.clone(),
                VReg::Phys(_) | VReg::Temp(_) => {
                    i += 1;
                    continue;
                }
                VReg::Flag(_) | VReg::FlagValue { .. } => {
                    i += 1;
                    continue;
                }
            },
            _ => {
                i += 1;
                continue;
            }
        };
        if is_dead_from(body, i + 1, &dst, ret_regs) {
            body.remove(i);
            continue;
        }
        i += 1;
    }
}

/// True when the register `dst` is demonstrably overwritten before any
/// read, starting at index `start` in `body`.
fn is_dead_from(body: &[Stmt], start: usize, dst: &VReg, ret_regs: &[&str]) -> bool {
    for j in start..body.len() {
        let s = &body[j];

        // Any read of dst in this statement means the earlier store is
        // live — stop and report "not dead."
        if stmt_reads(s, dst) {
            return false;
        }

        // An assignment that overwrites dst without reading it first kills
        // the earlier store.
        if let Stmt::Assign { dst: d2, .. } = s {
            if d2 == dst {
                return true;
            }
        }

        // A call in the body is treated as writing the return register.
        if matches!(s, Stmt::Call { .. }) {
            if let VReg::Phys(name) = dst {
                if ret_regs.iter().any(|r| r == name) {
                    return true;
                }
            }
        }

        // Nested If / While bodies are opaque — if the variable is read
        // anywhere inside, we have to keep the store. If it's written
        // inside without being read, we *don't* claim death (the write may
        // be on only one path).
        if contains_nested_read(s, dst) || contains_nested_exit(s) {
            return false;
        }

        // Control-flow sinks — if we hit Return / Goto, further reads are
        // off-limits for our intra-body analysis, so we treat the store as
        // live to be safe (except Return whose value obviously reads some
        // reg already covered by `stmt_reads`).
        if matches!(
            s,
            Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Break
        ) {
            return false;
        }
    }
    // End-of-body: conservatively assume the value may escape.
    false
}

/// Names of frame- and link-registers (and their aliases after naming) for
/// which a top-level `%X = 0;` is ABI bookkeeping when unread.
const ABI_BOOKKEEPING_REGS: &[&str] = &["fp", "lr", "x29", "x30", "w29", "w30", "rbp", "ebp"];

fn drop_unread_abi_zeros(body: &mut Vec<Stmt>) {
    // Collect the offsets of qualifying stmts, then decide for each one
    // whether the register is ever read in the remaining body. We scan each
    // candidate against the full body in-place; no need to worry about
    // earlier removals invalidating later indices since we process back-to-
    // front.
    let candidates: Vec<usize> = body
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match s {
            Stmt::Assign {
                dst: VReg::Phys(name),
                src: Expr::Const(0),
            } if ABI_BOOKKEEPING_REGS.iter().any(|r| r == name) => Some(i),
            _ => None,
        })
        .collect();
    let mut to_drop: Vec<usize> = Vec::new();
    for &i in &candidates {
        let name = if let Stmt::Assign {
            dst: VReg::Phys(n), ..
        } = &body[i]
        {
            n.clone()
        } else {
            continue;
        };
        let reg = VReg::Phys(name);
        // Is the register read anywhere else in the body (ignoring the
        // store itself)?
        let any_read = body
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .any(|(_, s)| stmt_reads(s, &reg));
        if !any_read {
            to_drop.push(i);
        }
    }
    // Drop back-to-front so indices stay valid.
    for i in to_drop.into_iter().rev() {
        body.remove(i);
    }
}

/// Remove callee-saved register spills that nothing in the function reads.
///
/// A function entry emits one store per callee-saved register it uses:
///
/// ```text
///     stack_0 = var0;      // push rbx
///     stack_1 = var1;      // push r12
///     stack_2 = rbp;       // push rbp
/// ```
///
/// These are machine-frame bookkeeping, not source-level state. The ABI
/// guarantees the epilogue restores each one, so nothing in the function ever
/// reads the slot, and the source they came from has no corresponding
/// statement. They were the last surviving source of raw register names in
/// rendered output — `rsp`, `rbp`, `sp`, `lr` and `fp` accounted for every
/// register token Glaurung emitted, against zero for Ghidra, angr and RetDec.
///
/// The proof required is deliberately strong: the slot must not be *read
/// anywhere* in the body, which also rules out a slot whose address escaped,
/// and the stored value must be a bare register so deleting the statement
/// cannot discard a computation. [`eliminate_dead_stores`] cannot make this
/// call itself — it walks forward and stops at the first nested `If`, and these
/// stores sit above all of a function's control flow.
pub fn prune_callee_saved_spills(f: &mut Function, cc: CallConv) {
    // A promoted spill appears in either spelling depending on how far stack
    // promotion got: `Assign` when the slot became a plain local, `Store` when
    // it is still addressed. Both render identically as `stack_2 = rbp;`, so
    // matching only one silently left half the spills in place.
    let spilled_slot = |stmt: &Stmt| -> Option<VReg> {
        match stmt {
            Stmt::Assign {
                dst,
                src: Expr::Reg(source),
            } if is_saved_frame_slot(dst)
                || is_arm_saved_register_local(dst, source, cc)
                || is_x86_saved_register_local(dst, source, cc) =>
            {
                Some(dst.clone())
            }
            Stmt::Store {
                addr: Expr::Reg(slot),
                src: Expr::Reg(source),
                ..
            } if is_saved_frame_slot(slot)
                || is_arm_saved_register_local(slot, source, cc)
                || is_x86_saved_register_local(slot, source, cc) =>
            {
                Some(slot.clone())
            }
            _ => None,
        }
    };

    // A slot restored by the epilogue reads back into the register it came
    // from (`rbp = stack_2`), so the spill is not dead on its own — the pair
    // has to go together, and only when the restored value is itself unused.
    // That is the whole callee-save idiom: save at entry, restore at exit,
    // never observe it in between.
    let restore_of = |stmt: &Stmt, slot: &VReg| -> Option<VReg> {
        match stmt {
            Stmt::Assign {
                dst,
                src: Expr::Reg(src),
            } if src == slot => Some(dst.clone()),
            _ => None,
        }
    };

    let candidates: Vec<VReg> = f.body.iter().filter_map(spilled_slot).collect();
    let mut doomed_slots: Vec<VReg> = Vec::new();
    for slot in candidates {
        // Every statement that mentions the slot, other than its own spill.
        let readers: Vec<&Stmt> = f
            .body
            .iter()
            .filter(|s| spilled_slot(s).as_ref() != Some(&slot))
            .filter(|s| stmt_reads(s, &slot))
            .collect();
        let dead = match readers.as_slice() {
            // Never observed at all: the spill alone is dead.
            [] => true,
            // Observed exactly once, by a restore whose result nothing reads.
            [only] => match restore_of(only, &slot) {
                // The spill and the restore both mention the register — the
                // spill reads it, the restore writes it. Neither counts as an
                // observation of the restored value, so both are excluded.
                // Before SSA renaming they share one name, which is exactly the
                // shape the unit tests pin.
                Some(restored) => !f
                    .body
                    .iter()
                    .filter(|s| {
                        restore_of(s, &slot).is_none() && spilled_slot(s).as_ref() != Some(&slot)
                    })
                    .any(|s| stmt_reads(s, &restored)),
                None => false,
            },
            _ => false,
        };
        if dead {
            doomed_slots.push(slot);
        }
    }
    if !doomed_slots.is_empty() {
        f.body.retain(|stmt| {
            if spilled_slot(stmt).is_some_and(|slot| doomed_slots.contains(&slot)) {
                return false;
            }
            !doomed_slots
                .iter()
                .any(|slot| restore_of(stmt, slot).is_some())
        });
    }

    prune_orphaned_stack_pointer_arithmetic(f);
}

/// Remove writes to a promoted local object whose value and address never escape.
///
/// Stack promotion can conservatively group callee-save slots into an addressed
/// byte object before machine-frame cleanup runs. Once later preparation has
/// removed the matching epilogue, those field writes are ordinary dead local
/// stores. The proof here is storage-based: every remaining mention of the
/// object must be the destination address of one such store.
pub fn prune_unobserved_promoted_object_stores(f: &mut Function) {
    fn field_store_base(statement: &Stmt) -> Option<&VReg> {
        let Stmt::Store { addr, src, .. } = statement else {
            return None;
        };
        let Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } = addr
        else {
            return None;
        };
        let object = match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::StackAddr { object, .. }, Expr::Const(_))
            | (Expr::Const(_), Expr::StackAddr { object, .. }) => object,
            _ => return None,
        };
        let VReg::Phys(name) = object else {
            return None;
        };
        if !(name.starts_with("local_") || name.starts_with("stack_")) || expr_reads(src, object) {
            return None;
        }
        Some(object)
    }

    let candidates = f
        .body
        .iter()
        .filter_map(field_store_base)
        .cloned()
        .collect::<HashSet<_>>();
    let doomed = candidates
        .into_iter()
        .filter(|object| {
            !f.body.iter().any(|statement| {
                field_store_base(statement) != Some(object) && stmt_reads(statement, object)
            })
        })
        .collect::<HashSet<_>>();
    if doomed.is_empty() {
        return;
    }
    f.body.retain(|statement| {
        !field_store_base(statement).is_some_and(|object| doomed.contains(object))
    });
}

/// Drop stack-pointer adjustments that nothing observes.
///
/// `push X` lifts to `rsp = rsp - 8; store [rsp] = X`. Once the spill above is
/// removed the decrement is orphaned, and a function that saved four registers
/// renders four bare `rsp = (rsp - 8);` lines that correspond to nothing in the
/// source — `rsp` alone accounted for 80 of the remaining register tokens.
///
/// Removal is only safe when the stack pointer is *never read for anything
/// else*. If any local is addressed relative to it, or it reaches a call or a
/// return value, every adjustment stays: the frame is then real storage, and
/// silently deleting the arithmetic would move every local.
fn prune_orphaned_stack_pointer_arithmetic(f: &mut Function) {
    let is_sp_adjust = |stmt: &Stmt| -> Option<VReg> {
        let Stmt::Assign {
            dst,
            src: Expr::Bin { op, lhs, rhs },
        } = stmt
        else {
            return None;
        };
        if !matches!(op, BinOp::Add | BinOp::Sub) {
            return None;
        }
        // `sp = sp ± constant`, and nothing else.
        match (lhs.as_ref(), rhs.as_ref()) {
            (Expr::Reg(base), Expr::Const(_)) if base == dst && is_stack_pointer(dst) => {
                Some(dst.clone())
            }
            _ => None,
        }
    };

    let pointers: Vec<VReg> = {
        let mut seen: Vec<VReg> = Vec::new();
        for stmt in &f.body {
            if let Some(p) = is_sp_adjust(stmt) {
                if !seen.contains(&p) {
                    seen.push(p);
                }
            }
        }
        seen
    };
    let doomed: Vec<VReg> = pointers
        .into_iter()
        .filter(|p| {
            !f.body
                .iter()
                .filter(|s| is_sp_adjust(s).as_ref() != Some(p))
                .any(|s| stmt_reads(s, p))
        })
        .collect();
    if doomed.is_empty() {
        return;
    }
    f.body
        .retain(|stmt| !is_sp_adjust(stmt).is_some_and(|p| doomed.contains(&p)));
}

fn is_stack_pointer(v: &VReg) -> bool {
    matches!(v, VReg::Phys(name) if matches!(name.as_str(), "rsp" | "esp" | "sp"))
}

/// A promoted stack slot, which is where a register spill lands after
/// `stack_locals` promotion. `stack_top` is excluded: it names the frame
/// boundary rather than a storage location.
fn is_saved_frame_slot(v: &VReg) -> bool {
    matches!(v, VReg::Phys(name) if name.starts_with("stack_") && name != "stack_top")
}

/// Whether a promoted `local_*` is the entry-stack save of ARM machine state.
///
/// Stack coordinates deliberately name storage below the entry SP `local_*`.
/// That is normally source-local territory, but Thumb leaf prologues put the
/// `push {r7}` save at exactly `entry_sp - 4` and may omit LR entirely.  The
/// corresponding restore is represented through `stack_top`, so the ordinary
/// spill/restore pairing cannot see the shared slot name.  Restricting this
/// exception to the ARM calling conventions, entry SSA versions, and the
/// architectural callee-save/return-address registers keeps an arbitrary
/// `local_4 = r0` source spill outside the machine-frame cleanup.
fn is_arm_saved_register_local(slot: &VReg, source: &VReg, cc: CallConv) -> bool {
    if !matches!(cc, CallConv::Arm | CallConv::ArmHardFloat) {
        return false;
    }
    let VReg::Phys(slot_name) = slot else {
        return false;
    };
    let VReg::Phys(source_name) = source else {
        return false;
    };
    if !slot_name.starts_with("local_") {
        return false;
    }
    let (base, version) = source_name
        .split_once('#')
        .map_or((source_name.as_str(), None), |(base, version)| {
            (base, Some(version))
        });
    if !matches!(version, None | Some("0")) {
        return false;
    }
    if matches!(base, "fp" | "lr" | "r14") {
        return true;
    }
    base.strip_prefix('r')
        .and_then(|index| index.parse::<u8>().ok())
        .is_some_and(|index| (4..=11).contains(&index))
}

/// Whether a promoted `local_*` is an x86 entry-stack callee save.
///
/// With frame-pointer omission, pushes land below the function-entry SP and
/// therefore use the same `local_*` coordinate family as source locals.  The
/// incoming value of an ABI-nonvolatile register is nevertheless machine state,
/// not a source parameter.  Restrict this exception to the unversioned/SSA-zero
/// entry value; a later definition held in the same architectural register is
/// ordinary recovered program state and must remain visible.
fn is_x86_saved_register_local(slot: &VReg, source: &VReg, cc: CallConv) -> bool {
    if !matches!(
        cc,
        CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32
    ) {
        return false;
    }
    let VReg::Phys(slot_name) = slot else {
        return false;
    };
    let VReg::Phys(source_name) = source else {
        return false;
    };
    if !slot_name.starts_with("local_") {
        return false;
    }
    let (base, version) = source_name
        .split_once('#')
        .map_or((source_name.as_str(), None), |(base, version)| {
            (base, Some(version))
        });
    matches!(version, None | Some("0"))
        && matches!(base, "rbx" | "rbp" | "r12" | "r13" | "r14" | "r15")
}

pub(crate) fn stmt_reads(s: &Stmt, dst: &VReg) -> bool {
    match s {
        Stmt::Assign { src, .. } => expr_reads(src, dst),
        Stmt::Store { addr, src, .. } => expr_reads(addr, dst) || expr_reads(src, dst),
        Stmt::Call { target, args, .. } => {
            expr_reads(target, dst) || args.iter().any(|a| expr_reads(a, dst))
        }
        Stmt::Return { value } => value.as_ref().is_some_and(|e| expr_reads(e, dst)),
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            expr_reads(cond, dst)
                || then_body.iter().any(|s| stmt_reads(s, dst))
                || else_body
                    .as_ref()
                    .is_some_and(|eb| eb.iter().any(|s| stmt_reads(s, dst)))
        }
        Stmt::While { cond, body } => {
            expr_reads(cond, dst) || body.iter().any(|s| stmt_reads(s, dst))
        }
        Stmt::For {
            init,
            cond,
            step,
            body,
        } => {
            stmt_reads(init, dst)
                || expr_reads(cond, dst)
                || body.iter().any(|s| stmt_reads(s, dst))
                || stmt_reads(step, dst)
        }
        Stmt::DoWhile { body, cond } => {
            body.iter().any(|s| stmt_reads(s, dst)) || expr_reads(cond, dst)
        }
        Stmt::Push { value } => expr_reads(value, dst),
        Stmt::Pop { target: t } => t == dst,
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            expr_reads(discriminant, dst)
                || cases
                    .iter()
                    .any(|(_, body)| body.iter().any(|s| stmt_reads(s, dst)))
                || default
                    .as_ref()
                    .is_some_and(|b| b.iter().any(|s| stmt_reads(s, dst)))
        }
        Stmt::IndirectGoto { target } => expr_reads(target, dst),
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_)
        | Stmt::Throw { .. }
        | Stmt::TryCatch { .. } => false,
    }
}

fn contains_nested_read(s: &Stmt, dst: &VReg) -> bool {
    match s {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(|s| stmt_reads(s, dst))
                || else_body
                    .as_ref()
                    .is_some_and(|eb| eb.iter().any(|s| stmt_reads(s, dst)))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.iter().any(|s| stmt_reads(s, dst))
        }
        Stmt::For {
            init, step, body, ..
        } => {
            stmt_reads(init, dst)
                || body.iter().any(|s| stmt_reads(s, dst))
                || stmt_reads(step, dst)
        }
        _ => false,
    }
}

/// Whether a nested structured statement can leave the current sequential
/// path before a later overwrite. Such an exit makes the earlier value live on
/// at least one path, even when the nested body does not itself read it.
fn contains_nested_exit(statement: &Stmt) -> bool {
    fn body_exits(body: &[Stmt]) -> bool {
        body.iter().any(|statement| match statement {
            Stmt::Return { .. } | Stmt::Goto { .. } | Stmt::IndirectGoto { .. } | Stmt::Break => {
                true
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                body_exits(then_body)
                    || else_body
                        .as_ref()
                        .is_some_and(|else_body| body_exits(else_body))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                body_exits(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases.iter().any(|(_, body)| body_exits(body))
                    || default.as_ref().is_some_and(|body| body_exits(body))
            }
            _ => false,
        })
    }

    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_exits(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|else_body| body_exits(else_body))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            body_exits(body)
        }
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| body_exits(body))
                || default.as_ref().is_some_and(|body| body_exits(body))
        }
        _ => false,
    }
}

fn expr_reads(e: &Expr, dst: &VReg) -> bool {
    match e {
        Expr::Reg(r) => r == dst,
        Expr::StackAddr { object, .. } => object == dst,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => false,
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            base.as_ref() == Some(dst) || index.as_ref() == Some(dst)
        }
        Expr::Deref { addr, .. } => expr_reads(addr, dst),
        Expr::Call { target, args, .. } => {
            expr_reads(target, dst) || args.iter().any(|argument| expr_reads(argument, dst))
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            expr_reads(lhs, dst) || expr_reads(rhs, dst)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => expr_reads(cond, dst) || expr_reads(if_true, dst) || expr_reads(if_false, dst),
        Expr::Un { src, .. } => expr_reads(src, dst),
        Expr::Cast { expr, .. } => expr_reads(expr, dst),
        Expr::FunctionTableEntry { index, .. } => expr_reads(index, dst),
        Expr::WideArithmetic { args, .. } => args.iter().any(|argument| expr_reads(argument, dst)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Expr, Function, Stmt};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn assign_overwritten_without_read_is_removed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(2),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        if let Stmt::Assign { src, .. } = &f.body[0] {
            assert_eq!(*src, Expr::Const(2));
        }
    }

    #[test]
    fn overwritten_call_expression_keeps_its_effect() {
        let mut function = Function {
            name: "effectful_assignment".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Call {
                        target: Box::new(Expr::Named {
                            va: 0x2000,
                            name: "write_event".into(),
                        }),
                        args: Vec::new(),
                        call_spec: None,
                        result_width: Some(8),
                    },
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(2),
                },
            ],
        };

        eliminate_dead_stores(&mut function, CallConv::SysVAmd64);

        assert_eq!(function.body.len(), 2);
        assert!(matches!(
            &function.body[0],
            Stmt::Assign {
                src: Expr::Call { .. },
                ..
            }
        ));
    }

    #[test]
    fn read_between_assigns_keeps_both_alive() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Reg(reg("rax")),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(2),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 3, "both rax stores must survive");
    }

    #[test]
    fn ret_assign_before_call_is_dead() {
        // %ret = 0; call foo(...); — the call clobbers ret.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
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
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1, "dead ret store should be removed");
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn ret_assign_before_call_that_reads_ret_survives() {
        // %ret = 0; call foo(%ret); — ret is read by the call, so survive.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: vec![Expr::Reg(reg("ret"))],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn non_return_reg_before_call_survives() {
        // %rbx = 0; call foo(); — call doesn't clobber rbx, so keep it.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rbx"),
                    src: Expr::Const(0),
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
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn repeated_pre_call_ret_zeros_all_collapse() {
        // The actual c2_demo shape: %ret = 0; call A(); %ret = 0; call B();
        // Both %ret assignments are dead.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "A".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "B".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2);
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
        assert!(matches!(&f.body[1], Stmt::Call { .. }));
    }

    #[test]
    fn nested_if_read_blocks_elimination() {
        // %rax = 0; if (cond) { use %rax } %rax = 1;
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(0),
                },
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Call {
                        target: Expr::Named {
                            va: 0,
                            name: "foo".into(),
                        },
                        args: vec![Expr::Reg(reg("rax"))],
                        dst: None,
                        call_spec: None,
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 3, "inner read must preserve the outer store");
    }

    #[test]
    fn loop_value_before_conditional_break_is_not_dead() {
        // The first assignment reaches the return when the loop breaks before
        // the later overwrite. Treating a nested `break` as transparent made
        // the recovered `sum_until_zero` return an uninitialised variable for
        // an array whose first element is zero.
        let mut f = Function {
            name: "sum_until_zero".into(),
            entry_va: 0,
            body: vec![
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::Assign {
                            dst: reg("result"),
                            src: Expr::Reg(reg("sum")),
                        },
                        Stmt::If {
                            cond: Expr::Reg(reg("is_zero")),
                            then_body: vec![Stmt::Break],
                            else_body: None,
                        },
                        Stmt::Assign {
                            dst: reg("result"),
                            src: Expr::Reg(reg("updated")),
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("result"))),
                },
            ],
        };

        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);

        let Stmt::While { body, .. } = &f.body[0] else {
            panic!("expected loop, got {:#?}", f.body);
        };
        assert!(matches!(
            body.first(),
            Some(Stmt::Assign { dst, .. }) if dst == &reg("result")
        ));
    }

    #[test]
    fn self_assign_is_removed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("rax")),
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
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
    }

    #[test]
    fn assign_to_different_reg_is_preserved_even_if_other_side_is_same_name() {
        // `%rax = %rbx` must stay — only exact-identity self-assigns collapse.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("rax"),
                src: Expr::Reg(reg("rbx")),
            }],
        };
        eliminate_dead_stores(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 1);
    }

    #[test]
    fn abi_fp_zero_with_no_read_is_dropped() {
        let mut f = Function {
            name: "_start".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Const(0),
                },
                Stmt::Assign {
                    dst: reg("lr"),
                    src: Expr::Const(0),
                },
                Stmt::Return { value: None },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
        assert!(matches!(&f.body[0], Stmt::Return { .. }));
    }

    #[test]
    fn abi_fp_zero_with_a_read_survives() {
        // If fp is read later, the zero store is real and must stay.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("fp"),
                    src: Expr::Const(0),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "foo".into(),
                    },
                    args: vec![Expr::Reg(reg("fp"))],
                    dst: None,
                    call_spec: None,
                },
            ],
        };
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 2);
    }

    #[test]
    fn aarch64_ret_alias_x0_is_clobbered_by_call() {
        // Aarch64: x0 is both arg0 and ret. After role naming arg0 is the
        // conventional alias. The AArch64 return-reg list includes `ret`,
        // `arg0`, and `x0`/`w0` — so an `arg0 = 0; call foo();` pair is
        // eliminated on AArch64 too.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("arg0"),
                    src: Expr::Const(0),
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
        eliminate_dead_stores(&mut f, CallConv::Aarch64);
        assert_eq!(f.body.len(), 1);
    }

    /// A callee-saved spill/restore pair is machine bookkeeping and must go.
    ///
    /// `stack_2 = rbp` at entry with `rbp = stack_2` at exit is what `push rbp`
    /// / `pop rbp` becomes. Neither statement exists in the source, and the
    /// restored value is never observed — the ABI just requires the register to
    /// be intact for the caller.
    #[test]
    fn callee_saved_spill_and_restore_pair_is_removed() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("stack_2"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Const(1),
                },
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_2")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rax"))),
                },
            ],
        };
        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);
        assert_eq!(f.body.len(), 2, "spill/restore pair survived: {:?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("rax")));
    }

    /// A Thumb leaf function can save only r7, without lr.  Stack-coordinate
    /// recovery names that entry-SP-minus-four slot `local_4`, not `stack_0`:
    /// it is below the caller's entry stack pointer even though its semantic
    /// owner is the machine frame.  The value is restored through `stack_top`,
    /// so the save slot itself has no reader and must not survive as a fake C
    /// local.
    #[test]
    fn unread_arm_frame_register_save_in_local_slot_is_removed() {
        let mut f = Function {
            name: "thumb_leaf".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("r7")),
                },
                Stmt::Assign {
                    dst: reg("result"),
                    src: Expr::Const(7),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("result"))),
                },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::Arm);

        assert_eq!(f.body.len(), 2, "leaf r7 save survived: {:#?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Assign { dst, .. } if dst == &reg("result")));
    }

    /// A non-leaf Thumb function saves the incoming link register below the
    /// entry SP before its first call.  Stack-coordinate recovery names that
    /// exact machine slot `local_4`; retaining it invents both a C local and an
    /// undefined source input named `lr`.
    #[test]
    fn unread_arm_entry_lr_save_in_local_slot_is_removed() {
        let mut f = Function {
            name: "thumb_non_leaf".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("lr")),
                },
                Stmt::Call {
                    target: Expr::Named {
                        va: 0x2000,
                        name: "callee".into(),
                    },
                    args: Vec::new(),
                    dst: None,
                    call_spec: None,
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::ArmHardFloat);

        assert_eq!(f.body.len(), 2, "entry LR save survived: {:#?}", f.body);
        assert!(matches!(&f.body[0], Stmt::Call { .. }));
    }

    /// A later SSA definition held in a core register is ordinary recovered
    /// program state, not the incoming return address.  The machine-frame
    /// exception must be entry-version specific just like its x86 counterpart.
    #[test]
    fn defined_arm_register_value_in_local_slot_is_kept() {
        let mut f = Function {
            name: "source_local".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("r7#3")),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::Arm);

        assert_eq!(f.body.len(), 2, "defined ARM value was deleted");
    }

    /// Register spelling alone is not enough evidence: an x86 function may
    /// contain a recovered source variable named `r7`, and ARM frame policy
    /// must never run under a different calling convention.
    #[test]
    fn arm_spelling_in_non_arm_function_is_kept() {
        let mut f = Function {
            name: "cross_arch_name".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("r7")),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);

        assert_eq!(f.body.len(), 2, "ARM policy crossed architectures");
    }

    /// Omit-frame-pointer x86 stack-clash frames save nonvolatile registers
    /// below the entry SP, so stack promotion names each save `local_*` rather
    /// than `stack_*`.  The source values are ABI state, not C inputs; retaining
    /// them renders undefined `varN` reads even when the matching restore is
    /// present and dead.
    #[test]
    fn x86_entry_callee_save_in_local_slot_is_removed() {
        let mut f = Function {
            name: "stack_clash_frame".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_8"),
                    src: Expr::Reg(reg("r15")),
                },
                Stmt::Assign {
                    dst: reg("r15#5"),
                    src: Expr::Reg(reg("local_8")),
                },
                Stmt::Return {
                    value: Some(Expr::Const(7)),
                },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(Expr::Const(7))
            }]
        );
    }

    /// A later SSA definition stored in a local is ordinary recovered state,
    /// even when it occupies a callee-saved machine register.  Only the entry
    /// value has machine-frame provenance.
    #[test]
    fn defined_x86_callee_saved_value_in_local_slot_is_kept() {
        let mut f = Function {
            name: "source_local".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_8"),
                    src: Expr::Reg(reg("r15#3")),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);

        assert_eq!(f.body.len(), 2, "defined source value was deleted");
    }

    /// ARM also spells its call-clobbered scratch register `r12`.  The x86
    /// nonvolatile set contains a different architectural `r12`, so register
    /// spelling alone is not sufficient proof that a promoted local is a
    /// machine-frame save.
    #[test]
    fn arm_r12_local_is_not_treated_as_an_x86_callee_save() {
        let mut f = Function {
            name: "arm_source_local".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("r12")),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::Arm);

        assert_eq!(
            f.body.len(),
            2,
            "ARM scratch value was deleted as x86 state"
        );
    }

    /// A source value stored in an otherwise similarly named local is not
    /// machine-frame evidence.  The ARM fix must key off the saved-register
    /// provenance rather than deleting arbitrary unread source locals.
    #[test]
    fn unread_non_frame_value_in_local_slot_is_kept() {
        let mut f = Function {
            name: "source_local".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_4"),
                    src: Expr::Reg(reg("r0")),
                },
                Stmt::Return { value: None },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::Arm);

        assert_eq!(
            f.body.len(),
            2,
            "source local was mistaken for a frame save"
        );
    }

    /// If the restored register IS observed, the pair is real state and must
    /// stay — removing it would delete a value the function goes on to use.
    #[test]
    fn spill_whose_restored_value_is_used_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("stack_2"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Assign {
                    dst: reg("rbp"),
                    src: Expr::Reg(reg("stack_2")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rbp"))),
                },
            ],
        };
        let before = f.body.len();
        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);
        assert_eq!(
            f.body.len(),
            before,
            "removed a spill whose value is returned"
        );
    }

    /// A slot read by something other than its restore is live storage, not a
    /// register save.
    #[test]
    fn slot_read_by_ordinary_code_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("stack_2"),
                    src: Expr::Reg(reg("rbp")),
                },
                Stmt::Assign {
                    dst: reg("rax"),
                    src: Expr::Reg(reg("stack_2")),
                },
                Stmt::Assign {
                    dst: reg("rcx"),
                    src: Expr::Reg(reg("rax")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("rcx"))),
                },
            ],
        };
        let before = f.body.len();
        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);
        assert_eq!(
            f.body.len(),
            before,
            "removed a spill that ordinary code reads"
        );
    }

    #[test]
    fn unobserved_promoted_object_field_stores_are_removed() {
        let field = |offset| Expr::Bin {
            op: BinOp::Add,
            lhs: Box::new(Expr::StackAddr {
                object: reg("local_10"),
                size: 16,
            }),
            rhs: Box::new(Expr::Const(offset)),
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: field(8),
                    src: Expr::Reg(reg("var0")),
                    size: 4,
                },
                Stmt::Store {
                    addr: field(12),
                    src: Expr::Reg(reg("lr")),
                    size: 4,
                },
                Stmt::Return { value: None },
            ],
        };

        prune_unobserved_promoted_object_stores(&mut f);

        assert_eq!(f.body, vec![Stmt::Return { value: None }]);
    }

    #[test]
    fn observed_promoted_object_field_store_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::StackAddr {
                            object: reg("local_10"),
                            size: 16,
                        }),
                        rhs: Box::new(Expr::Const(8)),
                    },
                    src: Expr::Reg(reg("var0")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_10"))),
                },
            ],
        };

        prune_unobserved_promoted_object_stores(&mut f);

        assert_eq!(f.body.len(), 2);
    }
}
