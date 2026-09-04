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
    prune_adjacent_overwritten_promoted_stores(f);
}

/// Remove a pure promoted-stack write immediately shadowed by an equal-width write.
///
/// `push rax; mov [rsp], rcx` is a common clang-cl spelling for reserving one
/// stack word and then homing the first Win64 parameter. Stack promotion turns
/// it into `store local_8 = ret; store local_8 = arg0`. The first value is not
/// source state and no instruction observes it. Keep this proof deliberately
/// local: comments and nops may separate the writes, but control flow, a size
/// change, a self-dependent overwrite, or an observable first expression all
/// decline the deletion.
fn prune_adjacent_overwritten_promoted_stores(function: &mut Function) {
    fn discardable_source(expression: &Expr) -> bool {
        match expression {
            Expr::Reg(_)
            | Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::StackAddr { .. }
            | Expr::Named { .. }
            | Expr::StringLit { .. } => true,
            Expr::Un { src, .. }
            | Expr::Cast { expr: src, .. }
            | Expr::NumericConvert { expr: src, .. } => discardable_source(src),
            Expr::Lea { .. } | Expr::PdbFieldAddr { .. } => true,
            Expr::Bin { .. }
            | Expr::Cmp { .. }
            | Expr::Select { .. }
            | Expr::WideArithmetic { .. }
            | Expr::Deref { .. }
            | Expr::Call { .. }
            | Expr::FunctionTableEntry { .. }
            | Expr::Unknown(_) => false,
        }
    }

    fn promoted_store(statement: &Stmt) -> Option<(&VReg, &Expr, u8)> {
        let Stmt::Store {
            addr: Expr::Reg(slot),
            src,
            size,
        } = statement
        else {
            return None;
        };
        matches!(slot, VReg::Phys(name)
            if name.starts_with("local_") || name.starts_with("stack_"))
        .then_some((slot, src, *size))
    }

    fn prune(body: &mut Vec<Stmt>) {
        for statement in body.iter_mut() {
            match statement {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    prune(then_body);
                    if let Some(else_body) = else_body {
                        prune(else_body);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                    prune(body);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case) in cases {
                        prune(case);
                    }
                    if let Some(default) = default {
                        prune(default);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    prune(try_body);
                    for catch in catches {
                        prune(&mut catch.body);
                    }
                }
                _ => {}
            }
        }

        loop {
            let mut removed = None;
            for first in 0..body.len().saturating_sub(1) {
                let Some((slot, source, width)) = promoted_store(&body[first]) else {
                    continue;
                };
                if !discardable_source(source) {
                    continue;
                }
                let Some(second) = (first + 1..body.len())
                    .find(|index| !matches!(body[*index], Stmt::Comment(_) | Stmt::Nop))
                else {
                    continue;
                };
                let Some((next_slot, next_source, next_width)) = promoted_store(&body[second])
                else {
                    continue;
                };
                if slot == next_slot && width == next_width && !next_source.contains_reg(slot) {
                    removed = Some(first);
                    break;
                }
            }
            let Some(index) = removed else {
                break;
            };
            body.remove(index);
        }
    }

    prune(&mut function.body);
}

/// Discard the destination identity of an effectful call when the function
/// never reads that value.
///
/// The call itself is retained: this is not dead-code elimination of an
/// effect, only removal of an invented source temporary for an ignored ABI
/// result.  The proof is deliberately whole-function and conservative. If any
/// statement reads the same identity, every call defining it remains intact;
/// distinguishing those definitions requires reaching-definition evidence.
pub fn drop_globally_unused_call_results(f: &mut Function) {
    fn collect(body: &[Stmt], out: &mut HashSet<VReg>) {
        for statement in body {
            match statement {
                Stmt::Call { dst: Some(dst), .. } => {
                    out.insert(dst.clone());
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    collect(then_body, out);
                    if let Some(else_body) = else_body {
                        collect(else_body, out);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => collect(body, out),
                Stmt::For {
                    init, step, body, ..
                } => {
                    collect(std::slice::from_ref(init.as_ref()), out);
                    collect(body, out);
                    collect(std::slice::from_ref(step.as_ref()), out);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, body) in cases {
                        collect(body, out);
                    }
                    if let Some(default) = default {
                        collect(default, out);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    collect(try_body, out);
                    for catch in catches {
                        collect(&catch.body, out);
                    }
                }
                _ => {}
            }
        }
    }

    fn clear(body: &mut [Stmt], unused: &HashSet<VReg>) {
        for statement in body {
            match statement {
                Stmt::Call { dst, .. } if dst.as_ref().is_some_and(|dst| unused.contains(dst)) => {
                    *dst = None;
                }
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    clear(then_body, unused);
                    if let Some(else_body) = else_body {
                        clear(else_body, unused);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => clear(body, unused),
                Stmt::For {
                    init, step, body, ..
                } => {
                    clear(std::slice::from_mut(init.as_mut()), unused);
                    clear(body, unused);
                    clear(std::slice::from_mut(step.as_mut()), unused);
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, body) in cases {
                        clear(body, unused);
                    }
                    if let Some(default) = default {
                        clear(default, unused);
                    }
                }
                Stmt::TryCatch { try_body, catches } => {
                    clear(try_body, unused);
                    for catch in catches {
                        clear(&mut catch.body, unused);
                    }
                }
                _ => {}
            }
        }
    }

    let mut candidates = HashSet::new();
    collect(&f.body, &mut candidates);
    let unused = candidates
        .into_iter()
        .filter(|candidate| {
            !f.body
                .iter()
                .any(|statement| stmt_reads(statement, candidate))
        })
        .collect::<HashSet<_>>();
    clear(&mut f.body, &unused);
}

fn return_reg_aliases(cc: CallConv) -> Vec<&'static str> {
    match cc {
        CallConv::SysVAmd64 | CallConv::Win64 => vec!["rax", "eax", "ax", "al", "ret"],
        CallConv::Cdecl32 => vec!["rax", "eax", "ax", "al", "ret"],
        // `d0`/`s0` are the scalar views of AAPCS64's `v0` float result. Without
        // them the write that produces a float return looked dead.
        CallConv::Aarch64 => vec!["x0", "w0", "d0", "s0", "arg0", "ret"],
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
    prune_callee_saved_spills_with_scope(f, cc, false);
}

/// Remove otherwise-dead callee saves nested by an experimental region tree.
///
/// Unlike [`prune_callee_saved_spills`], this walks structured bodies. Callers
/// must opt in only when the selected region has independent verification;
/// register-looking nested assignments are not sufficient global provenance.
pub fn prune_callee_saved_spills_nested(f: &mut Function, cc: CallConv) {
    prune_callee_saved_spills_with_scope(f, cc, true);
}

fn prune_callee_saved_spills_with_scope(f: &mut Function, cc: CallConv, recursive: bool) {
    fn visit_statements(body: &[Stmt], recursive: bool, visit: &mut impl FnMut(&Stmt)) {
        for statement in body {
            visit(statement);
            if !recursive {
                continue;
            }
            match statement {
                Stmt::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    visit_statements(then_body, true, visit);
                    if let Some(else_body) = else_body {
                        visit_statements(else_body, true, visit);
                    }
                }
                Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                    visit_statements(body, true, visit);
                }
                Stmt::For {
                    init, step, body, ..
                } => {
                    visit(init.as_ref());
                    visit_statements(body, true, visit);
                    visit(step.as_ref());
                }
                Stmt::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        visit_statements(case_body, true, visit);
                    }
                    if let Some(default_body) = default {
                        visit_statements(default_body, true, visit);
                    }
                }
                Stmt::TryCatch {
                    try_body, catches, ..
                } => {
                    visit_statements(try_body, true, visit);
                    for catch in catches {
                        visit_statements(&catch.body, true, visit);
                    }
                }
                _ => {}
            }
        }
    }

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

    let mut candidates = Vec::new();
    visit_statements(&f.body, recursive, &mut |statement| {
        if let Some(slot) = spilled_slot(statement) {
            if !candidates.contains(&slot) {
                candidates.push(slot);
            }
        }
    });
    let mut doomed_slots: Vec<VReg> = Vec::new();
    for slot in candidates {
        // Every statement that mentions the slot, other than its own spill.
        let mut reader_count = 0usize;
        let mut sole_restore = None;
        visit_statements(&f.body, recursive, &mut |statement| {
            let reads_slot = if recursive {
                stmt_reads_direct(statement, &slot)
            } else {
                stmt_reads(statement, &slot)
            };
            if spilled_slot(statement).as_ref() == Some(&slot) || !reads_slot {
                return;
            }
            reader_count += 1;
            sole_restore = restore_of(statement, &slot);
        });
        let dead = match reader_count {
            // Never observed at all: the spill alone is dead.
            0 => true,
            // Observed exactly once, by a restore whose result nothing reads.
            1 => match sole_restore {
                // The spill and the restore both mention the register — the
                // spill reads it, the restore writes it. Neither counts as an
                // observation of the restored value, so both are excluded.
                // Before SSA renaming they share one name, which is exactly the
                // shape the unit tests pin.
                Some(restored) => {
                    let mut observed = false;
                    visit_statements(&f.body, recursive, &mut |statement| {
                        if restore_of(statement, &slot).is_none()
                            && spilled_slot(statement).as_ref() != Some(&slot)
                            && if recursive {
                                stmt_reads_direct(statement, &restored)
                            } else {
                                stmt_reads(statement, &restored)
                            }
                        {
                            observed = true;
                        }
                    });
                    !observed
                }
                None => false,
            },
            _ => false,
        };
        if dead {
            doomed_slots.push(slot);
        }
    }
    if !doomed_slots.is_empty() {
        fn prune_body(
            body: &mut Vec<Stmt>,
            recursive: bool,
            doomed_slots: &[VReg],
            spilled_slot: &impl Fn(&Stmt) -> Option<VReg>,
            restore_of: &impl Fn(&Stmt, &VReg) -> Option<VReg>,
        ) {
            if recursive {
                for statement in body.iter_mut() {
                    match statement {
                        Stmt::If {
                            then_body,
                            else_body,
                            ..
                        } => {
                            prune_body(then_body, true, doomed_slots, spilled_slot, restore_of);
                            if let Some(else_body) = else_body {
                                prune_body(else_body, true, doomed_slots, spilled_slot, restore_of);
                            }
                        }
                        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                            prune_body(body, true, doomed_slots, spilled_slot, restore_of);
                        }
                        Stmt::For {
                            init, step, body, ..
                        } => {
                            if removable(init.as_ref(), doomed_slots, spilled_slot, restore_of) {
                                **init = Stmt::Nop;
                            }
                            prune_body(body, true, doomed_slots, spilled_slot, restore_of);
                            if removable(step.as_ref(), doomed_slots, spilled_slot, restore_of) {
                                **step = Stmt::Nop;
                            }
                        }
                        Stmt::Switch { cases, default, .. } => {
                            for (_, case_body) in cases {
                                prune_body(case_body, true, doomed_slots, spilled_slot, restore_of);
                            }
                            if let Some(default_body) = default {
                                prune_body(
                                    default_body,
                                    true,
                                    doomed_slots,
                                    spilled_slot,
                                    restore_of,
                                );
                            }
                        }
                        Stmt::TryCatch {
                            try_body, catches, ..
                        } => {
                            prune_body(try_body, true, doomed_slots, spilled_slot, restore_of);
                            for catch in catches {
                                prune_body(
                                    &mut catch.body,
                                    true,
                                    doomed_slots,
                                    spilled_slot,
                                    restore_of,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            body.retain(|statement| !removable(statement, doomed_slots, spilled_slot, restore_of));
        }

        fn removable(
            statement: &Stmt,
            doomed_slots: &[VReg],
            spilled_slot: &impl Fn(&Stmt) -> Option<VReg>,
            restore_of: &impl Fn(&Stmt, &VReg) -> Option<VReg>,
        ) -> bool {
            spilled_slot(statement).is_some_and(|slot| doomed_slots.contains(&slot))
                || doomed_slots
                    .iter()
                    .any(|slot| restore_of(statement, slot).is_some())
        }

        prune_body(
            &mut f.body,
            recursive,
            &doomed_slots,
            &spilled_slot,
            &restore_of,
        );
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

/// Reads owned by this statement node, excluding reads in nested bodies.
///
/// Recursive AST walks must use this view; pairing it with [`stmt_reads`]
/// would count the same nested restore once for every enclosing control node.
fn stmt_reads_direct(statement: &Stmt, register: &VReg) -> bool {
    match statement {
        Stmt::Assign { src, .. } => expr_reads(src, register),
        Stmt::Store { addr, src, .. } => expr_reads(addr, register) || expr_reads(src, register),
        Stmt::Call { target, args, .. } => {
            expr_reads(target, register) || args.iter().any(|arg| expr_reads(arg, register))
        }
        Stmt::Return { value } => value
            .as_ref()
            .is_some_and(|value| expr_reads(value, register)),
        Stmt::Throw { value } => expr_reads(value, register),
        Stmt::If { cond, .. }
        | Stmt::While { cond, .. }
        | Stmt::DoWhile { cond, .. }
        | Stmt::For { cond, .. } => expr_reads(cond, register),
        Stmt::Switch { discriminant, .. } => expr_reads(discriminant, register),
        Stmt::Push { value } => expr_reads(value, register),
        Stmt::IndirectGoto { target } => expr_reads(target, register),
        Stmt::Pop { target } => target == register,
        Stmt::TryCatch { .. }
        | Stmt::Label(_)
        | Stmt::Goto { .. }
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
    }
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
        Stmt::Throw { value } => expr_reads(value, dst),
        Stmt::TryCatch { try_body, catches } => {
            try_body.iter().any(|statement| stmt_reads(statement, dst))
                || catches.iter().any(|catch| {
                    catch
                        .body
                        .iter()
                        .any(|statement| stmt_reads(statement, dst))
                })
        }
        Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break
        | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => false,
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
        Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => expr_reads(expr, dst),
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
    fn globally_unused_call_result_becomes_an_effect_only_call() {
        let mut f = Function {
            name: "main".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "puts".into(),
                    },
                    args: vec![Expr::StringLit {
                        value: "Hello, World!".into(),
                    }],
                    dst: Some(reg("var0")),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Const(0)),
                },
            ],
        };

        drop_globally_unused_call_results(&mut f);

        assert!(matches!(f.body.first(), Some(Stmt::Call { dst: None, .. })));
        assert!(matches!(f.body.last(), Some(Stmt::Return { .. })));
    }

    #[test]
    fn read_call_result_keeps_its_destination() {
        let result = reg("var0");
        let mut f = Function {
            name: "wrapper".into(),
            entry_va: 0,
            body: vec![
                Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "puts".into(),
                    },
                    args: Vec::new(),
                    dst: Some(result.clone()),
                    call_spec: None,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(result)),
                },
            ],
        };

        drop_globally_unused_call_results(&mut f);

        assert!(matches!(
            f.body.first(),
            Some(Stmt::Call { dst: Some(_), .. })
        ));
    }

    #[test]
    fn call_result_read_inside_try_body_keeps_its_destination() {
        let result = reg("call_result");
        let mut function = Function {
            name: "exceptional_wrapper".into(),
            entry_va: 0,
            body: vec![Stmt::TryCatch {
                try_body: vec![
                    Stmt::Call {
                        target: Expr::Named {
                            va: 0,
                            name: "may_throw".into(),
                        },
                        args: Vec::new(),
                        dst: Some(result.clone()),
                        call_spec: None,
                    },
                    Stmt::Return {
                        value: Some(Expr::Reg(result)),
                    },
                ],
                catches: Vec::new(),
            }],
        };

        drop_globally_unused_call_results(&mut function);

        let Stmt::TryCatch { try_body, .. } = &function.body[0] else {
            panic!("expected the try body")
        };
        assert!(matches!(
            try_body.first(),
            Some(Stmt::Call { dst: Some(_), .. })
        ));
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

    /// A structured early-return guard can place the machine prologue inside
    /// an `else` arm. Callee-save cleanup must follow the AST rather than only
    /// scanning the function's top-level statement list.
    #[test]
    fn nested_x86_entry_callee_save_is_removed_by_explicit_recursive_pass() {
        let mut f = Function {
            name: "guarded_frame".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("guard")),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }],
                else_body: Some(vec![
                    Stmt::Assign {
                        dst: reg("local_8"),
                        src: Expr::Reg(reg("r15")),
                    },
                    Stmt::Return {
                        value: Some(Expr::Const(7)),
                    },
                ]),
            }],
        };

        prune_callee_saved_spills_nested(&mut f, CallConv::SysVAmd64);

        let Stmt::If {
            else_body: Some(else_body),
            ..
        } = &f.body[0]
        else {
            panic!("guarded frame shape changed: {:#?}", f.body);
        };
        assert_eq!(
            else_body,
            &vec![Stmt::Return {
                value: Some(Expr::Const(7))
            }]
        );
    }

    /// Production's historical pass is deliberately top-level-only. A nested
    /// register-looking assignment is not enough evidence by itself to erase
    /// it across the full corpus; the shadow structurer opts into the stronger
    /// recursive cleanup only after independent output verification.
    #[test]
    fn default_callee_save_pass_preserves_nested_assignments() {
        let nested_save = Stmt::Assign {
            dst: reg("local_8"),
            src: Expr::Reg(reg("r15")),
        };
        let mut f = Function {
            name: "guarded_frame".into(),
            entry_va: 0,
            body: vec![Stmt::If {
                cond: Expr::Reg(reg("guard")),
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(-1)),
                }],
                else_body: Some(vec![
                    nested_save.clone(),
                    Stmt::Return {
                        value: Some(Expr::Const(7)),
                    },
                ]),
            }],
        };

        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);

        let Stmt::If {
            else_body: Some(else_body),
            ..
        } = &f.body[0]
        else {
            panic!("guarded frame shape changed: {:#?}", f.body);
        };
        assert_eq!(else_body.first(), Some(&nested_save));
    }

    /// The historical top-level pass still treats a read inside structured
    /// control flow as a real observation of a top-level spill. Its scan is
    /// shallow only for candidate discovery and removal, not for liveness.
    #[test]
    fn default_callee_save_pass_sees_nested_reads_of_top_level_spills() {
        let spill = Stmt::Assign {
            dst: reg("local_8"),
            src: Expr::Reg(reg("r15")),
        };
        let mut f = Function {
            name: "nested_read".into(),
            entry_va: 0,
            body: vec![
                spill.clone(),
                Stmt::If {
                    cond: Expr::Reg(reg("guard")),
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(reg("local_8"))),
                    }],
                    else_body: Some(vec![Stmt::Return {
                        value: Some(Expr::Const(7)),
                    }]),
                },
            ],
        };

        prune_callee_saved_spills(&mut f, CallConv::SysVAmd64);

        assert_eq!(f.body.first(), Some(&spill));
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

    #[test]
    fn adjacent_promoted_store_overwrite_drops_the_unobserved_push_value() {
        let slot = VReg::phys("local_8");
        let mut function = Function {
            name: "record_value".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(slot.clone()),
                    src: Expr::Reg(VReg::phys("ret")),
                    size: 8,
                },
                Stmt::Comment("instruction boundary".into()),
                Stmt::Store {
                    addr: Expr::Reg(slot.clone()),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: VReg::phys("ret"),
                    src: Expr::Reg(slot),
                },
            ],
        };

        prune_adjacent_overwritten_promoted_stores(&mut function);

        assert_eq!(function.body.len(), 3);
        assert!(matches!(
            &function.body[1],
            Stmt::Store {
                src: Expr::Reg(source),
                ..
            } if source == &VReg::phys("arg0")
        ));
    }

    #[test]
    fn promoted_store_overwrite_keeps_observable_or_self_dependent_values() {
        let slot = VReg::phys("local_8");
        let effect = Expr::Call {
            target: Box::new(Expr::Named {
                va: 0x2000,
                name: "effect".into(),
            }),
            args: Vec::new(),
            result_width: Some(8),
            call_spec: None,
        };
        for (first, second) in [
            (effect, Expr::Reg(VReg::phys("arg0"))),
            (Expr::Const(0), Expr::Reg(slot.clone())),
        ] {
            let mut function = Function {
                name: "keep".into(),
                entry_va: 0,
                body: vec![
                    Stmt::Store {
                        addr: Expr::Reg(slot.clone()),
                        src: first,
                        size: 8,
                    },
                    Stmt::Store {
                        addr: Expr::Reg(slot.clone()),
                        src: second,
                        size: 8,
                    },
                ],
            };

            prune_adjacent_overwritten_promoted_stores(&mut function);

            assert_eq!(function.body.len(), 2);
        }
    }

    #[test]
    fn promoted_store_overwrite_keeps_mismatched_widths() {
        let slot = VReg::phys("local_8");
        let mut function = Function {
            name: "keep_partial_write".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(slot.clone()),
                    src: Expr::Const(0),
                    size: 8,
                },
                Stmt::Store {
                    addr: Expr::Reg(slot),
                    src: Expr::Reg(VReg::phys("arg0")),
                    size: 4,
                },
            ],
        };

        prune_adjacent_overwritten_promoted_stores(&mut function);

        assert_eq!(function.body.len(), 2);
    }
}
