//! Copy propagation + dead-copy elimination on the structured AST.
//!
//! `-O0` code (and our own lifting) is full of short-lived copies: every switch
//! comparison reloads its discriminant into a scratch register
//! (`t10 = local_3; if (t10 == K)`), and the loop-condition setup copies locals
//! into temporaries (`ret = local_c; t11 = local_4; while (ret < t11)`). Left
//! alone these copies survive into the rendered C as extra statements, which
//! inflates the control-flow graph the GED metric compares against ground truth
//! and clutters the output.
//!
//! This pass performs conservative, within-linear-run copy propagation: a copy
//! `A = <pure>` (a register/local/constant source) is substituted into later
//! uses of `A` until `A` or the source is overwritten. Copies do not cross
//! control-flow edges (the active set is cleared at `if`/`while`/`switch`,
//! labels, gotos, and calls), so the transform is sound without dataflow
//! analysis. A follow-up dead-copy elimination drops register copies whose
//! destination is then never read.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

/// Run copy propagation then dead-copy elimination over `f`'s body.
pub fn propagate_copies(f: &mut Function) {
    // Global read counts. With SSA value-numbering upstream every scratch value
    // is single-def, so a value read exactly once can have its defining
    // *expression* propagated to that one use without duplicating any work — this
    // reassembles a split address computation (`t = i*4; p = base + t; *p`) into
    // `*(base + i*4)` and removes the scratch locals value-numbering created.
    //
    // Recount after every DCE round. Machine flag calculations often add a
    // second, ultimately dead read of an address/load temporary. The first DCE
    // round removes that flag chain; only a fresh count can then see that the
    // useful read is unique and fold the expression. This is the same fixpoint
    // contract as ordinary SSA simplification, bounded here to keep it cheap.
    let mut reads: HashMap<VReg, usize> = HashMap::new();
    count_reads_body(&f.body, &mut reads);
    propagate_run_counted(&mut f.body, &reads);
    propagate_run(&mut f.body);
    for _ in 0..8 {
        if !eliminate_dead_copies(&mut f.body) {
            break;
        }
        let mut reads: HashMap<VReg, usize> = HashMap::new();
        count_reads_body(&f.body, &mut reads);
        propagate_run_counted(&mut f.body, &reads);
    }
    // Copy propagation exposes local dead stores (`ret = local_c; ret =
    // (local_c >> 1)` — the first write is overwritten before any read once the
    // reload was folded away). Remove those within each straight-line run.
    dead_store_runs(&mut f.body);
}

/// Carry a straight-line pure alias into a following structured switch.
///
/// This deliberately narrow late-pipeline transform exists for switches whose
/// compiler range guard has just been removed. It never carries an alias into
/// or through a loop: a source that looks constant at loop entry may be updated
/// by the body and therefore is not invariant on later iterations.
pub fn propagate_switch_entry_copies(f: &mut Function) {
    if propagate_switch_entries_in_body(&mut f.body) {
        while eliminate_dead_copies(&mut f.body) {}
    }
}

/// Inline an adjacent, one-use promoted-stack value temporary. Select diamonds
/// create the common store form; stack promotion also exposes boolean return
/// temporaries as ordinary assignments.
///
/// Promoted locals are mutable variables rather than SSA values, so the general
/// copy environment must not carry them into a loop condition or across a
/// control-flow edge. This deliberately narrower transform accepts only:
///
/// `local_tmp = narrow_value; <next linear statement reads local_tmp once>`
///
/// A stored value must already fit its stack write width, the expression may
/// not read memory or contain an unknown, and the local must have exactly one
/// read in the entire structured function. Those constraints preserve the
/// store's truncation and evaluation point while removing compiler-only storage.
pub fn propagate_adjacent_promoted_values(f: &mut Function) {
    loop {
        if !fold_one_adjacent_promoted_value(&mut f.body) {
            break;
        }
    }
}

/// Inline a physical/scratch value definition into its immediately following,
/// sole eager guard use.
///
/// Explicit machine-width lifting can produce
/// `ret = zext(load); if ((ret & mask) == 0) break;`. The physical role name is
/// not globally SSA, so ordinary counted propagation correctly refuses it. This
/// local def-use proof needs no global SSA claim: only comments may intervene,
/// the guard is the value's sole read in the whole function, neither arm nor the
/// remaining linear body reads it, and no conditional [`Expr::Select`] can defer
/// the moved load. The whole-function count matters for loop-carried values: a
/// guard definition may also reach a read after the loop. Under these constraints
/// the expression stays at the same observable evaluation point while the
/// loop-form pass gets the source-level guard back.
pub fn propagate_adjacent_guard_values(f: &mut Function) {
    loop {
        let mut reads = HashMap::new();
        count_reads_body(&f.body, &mut reads);
        if !fold_one_adjacent_guard_value(&mut f.body, &reads) {
            break;
        }
    }
}

fn fold_one_adjacent_guard_value(body: &mut Vec<Stmt>, reads: &HashMap<VReg, usize>) -> bool {
    for statement in body.iter_mut() {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_one_adjacent_guard_value(then_body, reads)
                    || else_body
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_guard_value(body, reads))
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_one_adjacent_guard_value(body, reads)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| fold_one_adjacent_guard_value(body, reads))
                    || default
                        .as_mut()
                        .is_some_and(|body| fold_one_adjacent_guard_value(body, reads))
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }

    for index in 0..body.len().saturating_sub(1) {
        let Some((dst, source)) = (match &body[index] {
            Stmt::Assign { dst, src }
                if is_scratch_reg(dst)
                    && !is_promoted_local_reg(dst)
                    && reads.get(dst).copied() == Some(1)
                    && !contains_reg(src, dst)
                    && !contains_unknown(src)
                    && !contains_select(src) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(guard_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };
        let Stmt::If {
            cond,
            then_body,
            else_body,
        } = &body[guard_index]
        else {
            continue;
        };
        if contains_select(cond) || count_reg_uses(cond, &dst) != 1 {
            continue;
        }
        let mut other_reads = HashMap::new();
        count_reads_body(then_body, &mut other_reads);
        if let Some(else_body) = else_body {
            count_reads_body(else_body, &mut other_reads);
        }
        count_reads_body(&body[guard_index + 1..], &mut other_reads);
        if other_reads.get(&dst).copied().unwrap_or(0) != 0 {
            continue;
        }

        let Stmt::If { cond, .. } = &mut body[guard_index] else {
            unreachable!()
        };
        subst(cond, &HashMap::from([(dst, source)]));
        body.remove(index);
        return true;
    }
    false
}

fn fold_one_adjacent_promoted_value(body: &mut Vec<Stmt>) -> bool {
    for index in 0..body.len().saturating_sub(1) {
        let candidate = match &body[index] {
            Stmt::Assign { dst, src }
                if is_promoted_local_reg(dst)
                    && is_deferable_promoted_value(src)
                    && !contains_reg(src, dst)
                    && promoted_value_width(src).is_some() =>
            {
                Some((dst.clone(), src.clone()))
            }
            Stmt::Store {
                addr: Expr::Reg(dst),
                src,
                size,
            } if is_promoted_local_reg(dst)
                && is_deferable_promoted_value(src)
                && !contains_reg(src, dst)
                && promoted_value_width(src).is_some_and(|width| width <= *size) =>
            {
                Some((dst.clone(), src.clone()))
            }
            _ => None,
        };
        let Some((dst, selected)) = candidate else {
            continue;
        };

        let Some(next_index) = (index + 1..body.len())
            .find(|next| !matches!(body[*next], Stmt::Comment(_) | Stmt::Nop))
        else {
            continue;
        };

        let mut next_reads = HashMap::new();
        count_reads_stmt(&body[next_index], &mut next_reads);
        if next_reads.get(&dst).copied().unwrap_or(0) != 1 {
            continue;
        }
        let mut later_reads = HashMap::new();
        count_reads_body(&body[next_index + 1..], &mut later_reads);
        if later_reads.get(&dst).copied().unwrap_or(0) != 0 {
            // Another use in this same structured run still observes the
            // definition. Other cases/arms live in a different Vec and do not
            // block an exact local def-use fold.
            continue;
        }

        let substituted = match &mut body[next_index] {
            Stmt::Assign { src, .. } | Stmt::Store { src, .. } => {
                let copies = HashMap::from([(dst, selected)]);
                subst(src, &copies);
                true
            }
            Stmt::Return { value: Some(value) } | Stmt::Push { value } => {
                let copies = HashMap::from([(dst, selected)]);
                subst(value, &copies);
                true
            }
            _ => false,
        };
        if substituted {
            body.remove(index);
            return true;
        }
    }

    for statement in body {
        let changed = match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                fold_one_adjacent_promoted_value(then_body)
                    || else_body
                        .as_mut()
                        .is_some_and(fold_one_adjacent_promoted_value)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                fold_one_adjacent_promoted_value(body)
            }
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|(_, body)| fold_one_adjacent_promoted_value(body))
                    || default
                        .as_mut()
                        .is_some_and(fold_one_adjacent_promoted_value)
            }
            _ => false,
        };
        if changed {
            return true;
        }
    }
    false
}

fn promoted_value_width(e: &Expr) -> Option<u8> {
    match e {
        Expr::Const(value) if (0..=127).contains(value) => Some(1),
        Expr::Cmp { .. } => Some(1),
        Expr::Select { width, .. } if *width > 0 => Some(*width),
        Expr::Cast { width, .. } if *width > 0 => Some(*width),
        _ => None,
    }
}

/// Is `e` safe to record as a copy source and duplicate into use sites? Only
/// pure, stable values: a register/local reference, a constant, or a resolved
/// address/name. Memory loads (`Deref`) and arithmetic are excluded — their
/// value can change or their operands be clobbered before the use.
fn is_pure_copyable(e: &Expr) -> bool {
    match e {
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. } => true,
        // Integer view changes are pure, cheap, and retain the source register
        // in the expression, so the ordinary invalidation rule still removes
        // the alias if that source is overwritten. Treating the view as a copy
        // prevents a machine-width SSA value from becoming a fake mutable C
        // variable merely because it has more than one use.
        Expr::Cast { expr, .. } => is_pure_copyable(expr),
        _ => false,
    }
}

/// A promoted stack slot is represented as a store whose bare-register address
/// is the source variable itself (`Store local_x = value`). It is assignment
/// semantics, not an indirect write through a pointer named `local_x`.
fn is_promoted_local_reg(v: &VReg) -> bool {
    matches!(v, VReg::Phys(name) if name.starts_with("local_") || name.starts_with("stack_"))
}

/// Expressions whose evaluation may be moved from a promoted temporary store
/// to its sole later use. AST expressions have no calls or writes; memory loads
/// are still excluded because an intervening store could alias them, and an
/// unknown expression must remain rooted where the lifter placed it.
fn is_deferable_promoted_value(e: &Expr) -> bool {
    !contains_deref(e) && !contains_unknown(e)
}

type Copies = HashMap<VReg, Expr>;

/// Invalidate every copy whose destination *is* `written`, or whose source
/// *reads* `written` (its recorded value is now stale).
fn invalidate(copies: &mut Copies, written: &VReg) {
    copies.retain(|dst, src| dst != written && !contains_reg(src, written));
}

fn propagate_run(stmts: &mut [Stmt]) -> Copies {
    let mut copies: Copies = HashMap::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(src) && !is_self_ref(dst, src) {
                    copies.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                subst(addr, &copies);
                subst(src, &copies);
                // A store to a bare promoted local writes that variable.
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
            }
            Stmt::Push { value } => subst(value, &copies),
            Stmt::Return { value } => {
                if let Some(e) = value {
                    subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args, .. } => {
                subst(target, &copies);
                for a in args.iter_mut() {
                    subst(a, &copies);
                }
                // A call clobbers caller-saved registers — drop everything.
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                propagate_run(then_body);
                if let Some(eb) = else_body {
                    propagate_run(eb);
                }
                copies.clear();
            }
            Stmt::While { cond, body } => {
                subst(cond, &copies);
                propagate_run(body);
                copies.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                propagate_run(std::slice::from_mut(init.as_mut()));
                subst(cond, &copies);
                propagate_run(body);
                propagate_run(std::slice::from_mut(step.as_mut()));
                copies.clear();
            }
            Stmt::DoWhile { body, cond } => {
                // Unlike a pre-tested loop, the condition observes the tail of
                // the body on every iteration.  Carry only the body's final
                // straight-line copies into it; any branch, call, or other
                // control-flow boundary clears that set conservatively.
                let tail_copies = propagate_run(body);
                subst(cond, &tail_copies);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run(body);
                }
                if let Some(b) = default {
                    propagate_run(b);
                }
                copies.clear();
            }
            // Control-flow boundaries: a label may be a join target and a goto
            // leaves the run — clear so nothing propagates across the edge.
            // Substitute THEN end the run: the dispatch reads its target, so a
            // copy that reaches it has to be applied before the barrier.
            Stmt::IndirectGoto { target } => {
                subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
    copies
}

/// Find switches in `body` and seed only their arms with aliases established by
/// the immediately dominating straight-line prefix. Other control flow clears
/// the environment; nested bodies are searched independently.
fn propagate_switch_entries_in_body(body: &mut [Stmt]) -> bool {
    let mut copies: Copies = HashMap::new();
    let mut changed = false;
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                let mut resolved = src.clone();
                subst(&mut resolved, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(&resolved) && !is_self_ref(dst, &resolved) {
                    copies.insert(dst.clone(), resolved);
                }
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                changed |= !copies.is_empty();
                subst(discriminant, &copies);
                for (_, case_body) in cases {
                    propagate_switch_arm(case_body, &copies);
                }
                if let Some(default_body) = default {
                    propagate_switch_arm(default_body, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= propagate_switch_entries_in_body(then_body);
                if let Some(else_body) = else_body {
                    changed |= propagate_switch_entries_in_body(else_body);
                }
                copies.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                changed |= propagate_switch_entries_in_body(body);
                copies.clear();
            }
            Stmt::Comment(_) | Stmt::Nop => {}
            Stmt::Store { .. }
            | Stmt::Push { .. }
            | Stmt::Pop { .. }
            | Stmt::Call { .. }
            | Stmt::Return { .. }
            | Stmt::IndirectGoto { .. }
            | Stmt::Label(_)
            | Stmt::Goto { .. }
            | Stmt::Break
            | Stmt::Unknown(_) => copies.clear(),
        }
    }
    changed
}

/// Apply switch-entry aliases within one arm. Nested branches inherit them,
/// while every loop is a hard barrier so no entry snapshot is mistaken for a
/// loop invariant.
fn propagate_switch_arm(body: &mut [Stmt], incoming: &Copies) {
    let mut copies = incoming.clone();
    for statement in body {
        match statement {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if is_pure_copyable(src) && !is_self_ref(dst, src) {
                    copies.insert(dst.clone(), src.clone());
                }
            }
            Stmt::Store { addr, src, .. } => {
                subst(addr, &copies);
                subst(src, &copies);
                copies.clear();
            }
            Stmt::Push { value } => {
                subst(value, &copies);
                copies.clear();
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    subst(value, &copies);
                }
            }
            Stmt::Pop { .. } => copies.clear(),
            Stmt::Call { target, args, .. } => {
                subst(target, &copies);
                for arg in args {
                    subst(arg, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                let incoming = copies.clone();
                propagate_switch_arm(then_body, &incoming);
                if let Some(else_body) = else_body {
                    propagate_switch_arm(else_body, &incoming);
                }
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                let incoming = copies.clone();
                for (_, case_body) in cases {
                    propagate_switch_arm(case_body, &incoming);
                }
                if let Some(default_body) = default {
                    propagate_switch_arm(default_body, &incoming);
                }
                copies.clear();
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                let _ = propagate_switch_entries_in_body(body);
                copies.clear();
            }
            Stmt::IndirectGoto { target } => {
                subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
}

fn is_self_ref(dst: &VReg, src: &Expr) -> bool {
    matches!(src, Expr::Reg(r) if r == dst)
}

/// Like [`propagate_run`], but also propagates a *non-pure* expression whose
/// scratch destination is read exactly once in the whole body — safe because
/// value-numbering makes each such destination single-def, so folding it in
/// duplicates no computation. Copies still do not cross control-flow edges.
fn propagate_run_counted(stmts: &mut [Stmt], reads: &HashMap<VReg, usize>) -> Copies {
    let mut copies: Copies = HashMap::new();
    for s in stmts.iter_mut() {
        match s {
            Stmt::Assign { dst, src } => {
                subst(src, &copies);
                invalidate(&mut copies, dst);
                if !is_self_ref(dst, src) {
                    let record = is_pure_copyable(src)
                        || (is_scratch_reg(dst)
                            && reads.get(dst).copied().unwrap_or(0) == 1
                            // A 128-bit load cannot be represented by the
                            // scalar expression that would replace this use.
                            // Keep its value identity so the C backend can
                            // materialize a full-width temporary and preserve
                            // load-before-store ordering across sibling XMM
                            // moves.
                            && !matches!(src, Expr::Deref { size: 16, .. })
                            && !matches!(src, Expr::Unknown(_)));
                    if record {
                        copies.insert(dst.clone(), src.clone());
                    }
                }
            }
            Stmt::Store { addr, src, .. } => {
                subst(addr, &copies);
                subst(src, &copies);
                if let Expr::Reg(r) = addr {
                    invalidate(&mut copies, r);
                }
                // The store may alias a pending single-use load; folding that
                // load past this point would read the post-store value.
                invalidate_loads(&mut copies);
            }
            Stmt::Push { value } => {
                subst(value, &copies);
                invalidate_loads(&mut copies);
            }
            Stmt::Return { value } => {
                if let Some(e) = value {
                    subst(e, &copies);
                }
            }
            Stmt::Pop { target } => invalidate(&mut copies, target),
            Stmt::Call { target, args, .. } => {
                subst(target, &copies);
                for a in args.iter_mut() {
                    subst(a, &copies);
                }
                copies.clear();
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                subst(cond, &copies);
                propagate_run_counted(then_body, reads);
                if let Some(eb) = else_body {
                    propagate_run_counted(eb, reads);
                }
                copies.clear();
            }
            Stmt::While { cond, body } => {
                subst(cond, &copies);
                propagate_run_counted(body, reads);
                copies.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                propagate_run_counted(std::slice::from_mut(init.as_mut()), reads);
                subst(cond, &copies);
                propagate_run_counted(body, reads);
                propagate_run_counted(std::slice::from_mut(step.as_mut()), reads);
                copies.clear();
            }
            Stmt::DoWhile { body, cond } => {
                let tail_copies = propagate_run_counted(body, reads);
                subst(cond, &tail_copies);
                copies.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                subst(discriminant, &copies);
                for (_, body) in cases.iter_mut() {
                    propagate_run_counted(body, reads);
                }
                if let Some(b) = default {
                    propagate_run_counted(b, reads);
                }
                copies.clear();
            }
            // Substitute THEN end the run: the dispatch reads its target, so a
            // copy that reaches it has to be applied before the barrier.
            Stmt::IndirectGoto { target } => {
                subst(target, &copies);
                copies.clear();
            }
            Stmt::Label(_) | Stmt::Goto { .. } => copies.clear(),
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
    }
    copies
}

/// Within each straight-line run, drop a scratch-register write that is
/// overwritten by a later write before any intervening read (a dead store).
/// Conservative: resets at every control-flow boundary and only removes writes
/// whose source is side-effect-free.
fn dead_store_runs(body: &mut Vec<Stmt>) {
    // last_write[reg] = index of the most recent not-yet-consumed removable
    // write to `reg` in this run.
    let mut last_write: HashMap<VReg, usize> = HashMap::new();
    let mut dead: Vec<usize> = Vec::new();
    for (i, s) in body.iter().enumerate() {
        match s {
            Stmt::Assign { dst, src } => {
                // Reads in `src` consume any pending write of those regs.
                let mut r: HashMap<VReg, usize> = HashMap::new();
                count_reads_expr(src, &mut r);
                for reg in r.keys() {
                    last_write.remove(reg);
                }
                // This write shadows a pending one to `dst` with no read between.
                if let Some(prev) = last_write.remove(dst) {
                    dead.push(prev);
                }
                if is_pure_copyable(src) && is_scratch_reg(dst) && !is_self_ref(dst, src) {
                    last_write.insert(dst.clone(), i);
                }
            }
            other => {
                // Any read anywhere consumes pending writes; be safe and clear
                // on anything that isn't a pure Assign (stores, calls, control
                // flow, returns all either read or branch).
                let mut r: HashMap<VReg, usize> = HashMap::new();
                count_reads_stmt(other, &mut r);
                for reg in r.keys() {
                    last_write.remove(reg);
                }
                if !matches!(other, Stmt::Nop | Stmt::Comment(_)) {
                    last_write.clear();
                }
            }
        }
    }
    if !dead.is_empty() {
        let dead: std::collections::HashSet<usize> = dead.into_iter().collect();
        let mut i = 0;
        body.retain(|_| {
            let keep = !dead.contains(&i);
            i += 1;
            keep
        });
    }
    // Recurse into nested bodies.
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                dead_store_runs(then_body);
                if let Some(eb) = else_body {
                    dead_store_runs(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => dead_store_runs(body),
            Stmt::For { body, .. } => dead_store_runs(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    dead_store_runs(b);
                }
                if let Some(b) = default {
                    dead_store_runs(b);
                }
            }
            _ => {}
        }
    }
}

/// Remove register copies (`A = <pure>`) whose destination is never read in the
/// whole body. Returns whether anything was removed. Promoted stack locals
/// (`local_*`/`stack_*`) are left to the dedicated dead-store pass; here we only
/// clean scratch registers/temporaries the copy-prop just made dead.
fn eliminate_dead_copies(body: &mut Vec<Stmt>) -> bool {
    // Count reads of every register across the whole (nested) body.
    let mut reads: HashMap<VReg, usize> = HashMap::new();
    count_reads_body(body, &mut reads);
    remove_dead(body, &reads)
}

fn remove_dead(body: &mut Vec<Stmt>, reads: &HashMap<VReg, usize>) -> bool {
    let mut changed = false;
    body.retain(|s| {
        // Every `Assign` source is side-effect-free (registers, constants,
        // arithmetic, loads — never a call), so a scratch destination that is
        // never read is dead and safe to drop, whatever the source shape.
        if let Stmt::Assign { dst, .. } = s {
            if is_scratch_reg(dst) && reads.get(dst).copied().unwrap_or(0) == 0 {
                changed = true;
                return false;
            }
        }
        true
    });
    for s in body.iter_mut() {
        match s {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= remove_dead(then_body, reads);
                if let Some(eb) = else_body {
                    changed |= remove_dead(eb, reads);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                changed |= remove_dead(body, reads)
            }
            Stmt::For { body, .. } => changed |= remove_dead(body, reads),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    changed |= remove_dead(b, reads);
                }
                if let Some(b) = default {
                    changed |= remove_dead(b, reads);
                }
            }
            _ => {}
        }
    }
    changed
}

/// A register we're willing to delete a dead copy to: physical scratch/role
/// registers, temporaries, and SSA-versioned predicate values, but NOT promoted
/// stack locals (owned by dead-store elimination) or unversioned architectural
/// flag names. A poisoned predicate is separately excluded from propagation.
fn is_scratch_reg(v: &VReg) -> bool {
    match v {
        VReg::Temp(_) => true,
        VReg::Phys(n) => !n.starts_with("local_") && !n.starts_with("stack_"),
        VReg::FlagValue { .. } => true,
        VReg::Flag(_) => false,
    }
}

// --- expression/statement read-counting and substitution ---------------------

fn contains_reg(e: &Expr, target: &VReg) -> bool {
    count_reg_uses(e, target) > 0
}

/// True if `e` reads memory (contains a `Deref`). A recorded copy whose source
/// reads memory must be dropped at any intervening store/push, since the store
/// may alias the loaded location — folding the load past it would read the
/// post-store value.
fn contains_deref(e: &Expr) -> bool {
    match e {
        Expr::Deref { .. } | Expr::FunctionTableEntry { .. } => true,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_deref(lhs) || contains_deref(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => contains_deref(cond) || contains_deref(if_true) || contains_deref(if_false),
        Expr::Un { src, .. } => contains_deref(src),
        Expr::Cast { expr, .. } => contains_deref(expr),
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_deref),
    }
}

fn contains_unknown(e: &Expr) -> bool {
    match e {
        Expr::Unknown(_) => true,
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
        Expr::Deref { addr, .. } => contains_unknown(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_unknown(lhs) || contains_unknown(rhs)
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => contains_unknown(cond) || contains_unknown(if_true) || contains_unknown(if_false),
        Expr::Un { src, .. } => contains_unknown(src),
        Expr::Cast { expr, .. } => contains_unknown(expr),
        Expr::FunctionTableEntry { index, .. } => contains_unknown(index),
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_unknown),
    }
}

fn contains_select(e: &Expr) -> bool {
    match e {
        Expr::Select { .. } => true,
        Expr::Deref { addr, .. }
        | Expr::Un { src: addr, .. }
        | Expr::Cast { expr: addr, .. }
        | Expr::FunctionTableEntry { index: addr, .. } => contains_select(addr),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            contains_select(lhs) || contains_select(rhs)
        }
        Expr::WideArithmetic { args, .. } => args.iter().any(contains_select),
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_)
        | Expr::Reg(_)
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. } => false,
    }
}

/// Drop every recorded copy whose source reads memory (a pending load that a
/// store/push could alias).
fn invalidate_loads(copies: &mut Copies) {
    copies.retain(|_, src| !contains_deref(src));
}

fn count_reg_uses(e: &Expr, target: &VReg) -> usize {
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
        Expr::Cast { expr, .. } => count_reg_uses(expr, target),
        Expr::FunctionTableEntry { index, .. } => count_reg_uses(index, target),
        Expr::WideArithmetic { args, .. } => args
            .iter()
            .map(|argument| count_reg_uses(argument, target))
            .sum(),
    }
}

fn count_reads_expr(e: &Expr, reads: &mut HashMap<VReg, usize>) {
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
        Expr::Cast { expr, .. } => count_reads_expr(expr, reads),
        Expr::FunctionTableEntry { index, .. } => count_reads_expr(index, reads),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                count_reads_expr(argument, reads);
            }
        }
    }
}

fn count_reads_stmt(s: &Stmt, reads: &mut HashMap<VReg, usize>) {
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
        | Stmt::Comment(_) => {}
    }
}

fn count_reads_body(body: &[Stmt], reads: &mut HashMap<VReg, usize>) {
    for s in body {
        count_reads_stmt(s, reads);
    }
}

/// Substitute every active copy `dst -> src` into `e`.
fn subst(e: &mut Expr, copies: &Copies) {
    if copies.is_empty() {
        return;
    }
    // Lea stores base/index as VRegs for the machine IR. Once a single-use
    // index is reconstructed as a real expression (for example the signed
    // extension of a loop counter), keeping that VReg-only container would
    // strand an otherwise dead scratch. Expand the address to ordinary Bin
    // arithmetic when either component has a non-register replacement.
    let expanded_lea = expand_lea_with_copies(e, copies);
    if let Some(expanded) = expanded_lea {
        *e = expanded;
        subst(e, copies);
        return;
    }
    // A trivial `Lea` — base only, no index, zero displacement — denotes exactly
    // its base register. When that base has a recorded copy (which for a single-
    // use address is an arithmetic expression, not a bare register), fold the
    // whole `Lea` to the copied value. This is what lets a reassembled address
    // (`p = base + i*4`) inline into its `*p` use, since an `Lea` base/index slot
    // must otherwise stay a register.
    let trivial_lea_repl = match e {
        Expr::Lea {
            base: Some(r),
            index: None,
            disp,
            ..
        } if *disp == 0 => copies.get(r).cloned(),
        _ => None,
    };
    if let Some(repl) = trivial_lea_repl {
        *e = repl;
        subst(e, copies); // substitute within the inlined expression too
        return;
    }
    match e {
        Expr::Reg(r) => {
            if let Some(src) = copies.get(r) {
                *e = src.clone();
            }
        }
        // A stack object's identity is stable storage, not a scalar value to
        // replace from the copy environment.
        Expr::StackAddr { .. } => {}
        Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::Unknown(_) => {}
        Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
            // Only substitute when the replacement is itself a bare register
            // (an Lea base/index must stay a register).
            if let Some(r) = base {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    *base = Some(nr.clone());
                }
            }
            if let Some(r) = index {
                if let Some(Expr::Reg(nr)) = copies.get(r) {
                    *index = Some(nr.clone());
                }
            }
        }
        Expr::Deref { addr, .. } => subst(addr, copies),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            subst(lhs, copies);
            subst(rhs, copies);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            subst(cond, copies);
            subst(if_true, copies);
            subst(if_false, copies);
        }
        Expr::Un { src, .. } => subst(src, copies),
        Expr::Cast { expr, .. } => subst(expr, copies),
        Expr::FunctionTableEntry { index, .. } => subst(index, copies),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                subst(argument, copies);
            }
        }
    }
}

fn expand_lea_with_copies(e: &Expr, copies: &Copies) -> Option<Expr> {
    let Expr::Lea {
        base,
        index,
        scale,
        disp,
        segment: None,
    } = e
    else {
        return None;
    };
    let replacement = |reg: &VReg| {
        copies
            .get(reg)
            .cloned()
            .unwrap_or_else(|| Expr::Reg(reg.clone()))
    };
    let needs_expansion = base
        .iter()
        .chain(index.iter())
        .any(|reg| matches!(copies.get(reg), Some(expr) if !matches!(expr, Expr::Reg(_))));
    if !needs_expansion {
        return None;
    }

    let mut terms = Vec::new();
    if let Some(base) = base {
        terms.push(replacement(base));
    }
    if let Some(index) = index {
        let index = replacement(index);
        terms.push(if *scale > 1 {
            Expr::Bin {
                op: crate::ir::types::BinOp::Mul,
                lhs: Box::new(index),
                rhs: Box::new(Expr::Const(i64::from(*scale))),
            }
        } else {
            index
        });
    }
    if *disp != 0 || terms.is_empty() {
        terms.push(Expr::Const(*disp));
    }
    Some(
        terms
            .into_iter()
            .reduce(|lhs, rhs| Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
            .expect("a Lea expansion always has at least one address term"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{Function, Stmt};
    use crate::ir::types::{BinOp, CmpOp};

    fn reg(n: &str) -> VReg {
        VReg::phys(n)
    }

    #[test]
    fn pure_prefix_copy_reaches_switch_arms_until_its_source_changes() {
        // Optimized switch lowering often snapshots an argument into a scratch
        // immediately before dispatch.  Every case is dominated by that copy,
        // so the alias is valid on entry to every arm.  An arm that overwrites
        // the source must still invalidate it before a later use.
        let mut f = Function {
            name: "dispatch".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg2")),
                },
                Stmt::Switch {
                    discriminant: Expr::Reg(reg("arg0")),
                    cases: vec![
                        (
                            Some(0),
                            vec![Stmt::Return {
                                value: Some(Expr::Bin {
                                    op: BinOp::Add,
                                    lhs: Box::new(Expr::Reg(reg("var0"))),
                                    rhs: Box::new(Expr::Reg(reg("arg1"))),
                                }),
                            }],
                        ),
                        (
                            Some(1),
                            vec![
                                Stmt::Assign {
                                    dst: reg("arg2"),
                                    src: Expr::Const(7),
                                },
                                Stmt::Return {
                                    value: Some(Expr::Reg(reg("var0"))),
                                },
                            ],
                        ),
                    ],
                    default: None,
                },
            ],
        };

        propagate_switch_entry_copies(&mut f);

        assert!(
            matches!(
                &f.body[1],
                Stmt::Switch { cases, .. }
                    if matches!(
                        &cases[0].1[0],
                        Stmt::Return {
                            value: Some(Expr::Bin { lhs, .. })
                        } if matches!(lhs.as_ref(), Expr::Reg(source) if source == &reg("arg2"))
                    )
                    && matches!(
                        &cases[1].1[1],
                        Stmt::Return { value: Some(Expr::Reg(source)) }
                            if source == &reg("var0")
                    )
            ),
            "the incoming alias should reach an arm but stop at a source write: {:?}",
            f.body
        );
    }

    #[test]
    fn late_switch_copy_propagation_does_not_freeze_loop_carried_condition() {
        let mut f = Function {
            name: "find_first_set".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: Expr::Reg(reg("arg0")),
                },
                Stmt::While {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("var0"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    body: vec![Stmt::Assign {
                        dst: reg("var0"),
                        src: Expr::Bin {
                            op: BinOp::Shr,
                            lhs: Box::new(Expr::Reg(reg("var0"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    }],
                },
            ],
        };

        let before = f.clone();
        propagate_switch_entry_copies(&mut f);

        assert_eq!(f, before, "a loop entry copy is not a loop invariant");
    }

    #[test]
    fn late_switch_copy_propagation_leaves_switchless_functions_untouched() {
        let mut f = Function {
            name: "unrelated".into(),
            entry_va: 0,
            body: vec![Stmt::Assign {
                dst: reg("dead_scratch"),
                src: Expr::Const(1),
            }],
        };

        let before = f.clone();
        propagate_switch_entry_copies(&mut f);

        assert_eq!(f, before, "the late pass is switch-specific");
    }

    #[test]
    fn single_use_address_folds_into_deref_inside_loop() {
        // var5 = arg0 + (local_4 * 4); s = s + *var5   (var5 scratch, single-use)
        // Expected: var5 folds into the deref -> s = s + *(arg0 + local_4*4).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Reg(reg("local_4"))),
                    rhs: Box::new(Expr::Reg(reg("arg1"))),
                },
                body: vec![
                    Stmt::Assign {
                        dst: reg("var5"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("arg0"))),
                            rhs: Box::new(Expr::Bin {
                                op: BinOp::Mul,
                                lhs: Box::new(Expr::Reg(reg("local_4"))),
                                rhs: Box::new(Expr::Const(4)),
                            }),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("local_8"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("local_8"))),
                            // The lifter wraps the deref address in a trivial Lea
                            // (base only) — the real shape the fold must see through.
                            rhs: Box::new(Expr::Deref {
                                addr: Box::new(Expr::Lea {
                                    base: Some(reg("var5")),
                                    index: None,
                                    scale: 1,
                                    disp: 0,
                                    segment: None,
                                }),
                                size: 4,
                            }),
                        },
                    },
                ],
            }],
        };
        propagate_copies(&mut f);
        let dump = format!("{:?}", f.body);
        assert!(
            !dump.contains("var5"),
            "var5 should have folded into its single use, got:\n{}",
            dump
        );
    }

    #[test]
    fn nontrivial_lea_inlines_a_single_use_computed_index() {
        // Clang -O0 materialises the sign-extended loop index in a scratch and
        // then addresses `base + scratch`. Keeping Lea's index as VReg-only
        // strands that scratch in source C; expanding the address lets the
        // typed Cast travel to the byte load.
        let mut f = Function {
            name: "index".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var_index"),
                    src: Expr::Cast {
                        signed: true,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: true,
                            width: 4,
                            expr: Box::new(Expr::Reg(reg("local_i"))),
                        }),
                    },
                },
                Stmt::Assign {
                    dst: reg("value"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(reg("arg0")),
                            index: Some(reg("var_index")),
                            scale: 1,
                            disp: 0,
                            segment: None,
                        }),
                        size: 1,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("value"))),
                },
            ],
        };

        propagate_copies(&mut f);

        let dump = format!("{:?}", f.body);
        assert!(
            !dump.contains("var_index"),
            "index scratch survived: {dump}"
        );
        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Return {
                    value: Some(Expr::Deref { addr, size: 1 })
                }] if matches!(
                    addr.as_ref(),
                    Expr::Bin {
                        op: BinOp::Add,
                        lhs,
                        rhs,
                    } if matches!(lhs.as_ref(), Expr::Reg(r) if r == &reg("arg0"))
                        && matches!(rhs.as_ref(), Expr::Cast { width: 8, .. })
                )
            ),
            "computed index should be explicit address arithmetic: {:?}",
            f.body
        );
    }

    #[test]
    fn newly_single_use_address_and_load_fold_after_dead_flag_cleanup() {
        // Real GCC -O0 array loops compute flags for the address arithmetic and
        // loaded value even though the subsequent branch never reads them.  On
        // the first read-count pass those dead flag temporaries make `var3` and
        // `var6` look multi-use.  Once DCE removes the flag chain, propagation
        // must reconsider the surviving one-use address/load chain rather than
        // strand it in the emitted C.
        let mut f = Function {
            name: "sum_array_shape".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: reg("var3"),
                        src: Expr::Bin {
                            op: BinOp::Mul,
                            lhs: Box::new(Expr::Reg(reg("local_4"))),
                            rhs: Box::new(Expr::Const(4)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("dead_addr_sign"),
                        src: Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("var3"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("var5"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("arg0"))),
                            rhs: Box::new(Expr::Reg(reg("var3"))),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("var6"),
                        src: Expr::Deref {
                            addr: Box::new(Expr::Reg(reg("var5"))),
                            size: 4,
                        },
                    },
                    Stmt::Assign {
                        dst: reg("dead_load_sign"),
                        src: Expr::Cmp {
                            op: CmpOp::Slt,
                            lhs: Box::new(Expr::Reg(reg("var6"))),
                            rhs: Box::new(Expr::Const(0)),
                        },
                    },
                    Stmt::Assign {
                        dst: reg("local_8"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("local_8"))),
                            rhs: Box::new(Expr::Reg(reg("var6"))),
                        },
                    },
                ],
            }],
        };

        propagate_copies(&mut f);
        let dump = format!("{:?}", f.body);
        for dead in ["var3", "var5", "var6", "dead_addr_sign", "dead_load_sign"] {
            assert!(
                !dump.contains(dead),
                "{dead} should disappear after propagation/DCE reaches a fixpoint:\n{dump}"
            );
        }
        assert!(dump.contains("Deref") && dump.contains("Mul"), "{dump}");
    }

    #[test]
    fn reload_temp_is_propagated_and_removed() {
        // t10 = local_3; zf = (t10 == 7); return zf
        // t10 folds into the comparison (reading local_3); zf, read once, folds
        // into the return -> `return (local_3 == 7)`.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t10"),
                    src: Expr::Reg(reg("local_3")),
                },
                Stmt::Assign {
                    dst: reg("zf"),
                    src: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("t10"))),
                        rhs: Box::new(Expr::Const(7)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("zf"))),
                },
            ],
        };
        propagate_copies(&mut f);
        assert_eq!(f.body.len(), 1, "temps should be folded away: {:?}", f.body);
        match &f.body[0] {
            Stmt::Return {
                value: Some(Expr::Cmp { lhs, .. }),
            } => assert_eq!(**lhs, Expr::Reg(reg("local_3"))),
            other => panic!("expected folded `return (local_3 == 7)`, got {:?}", other),
        }
    }

    #[test]
    fn single_use_select_folds_into_its_only_consumer() {
        let selected = reg("var0");
        let mut f = Function {
            name: "select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: selected.clone(),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("cond"))),
                        if_true: Box::new(Expr::Reg(reg("yes"))),
                        if_false: Box::new(Expr::Reg(reg("no"))),
                        width: 8,
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(selected)),
                        rhs: Box::new(Expr::Const(1)),
                    }),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            matches!(
                f.body.as_slice(),
                [Stmt::Return {
                    value: Some(Expr::Bin { lhs, .. })
                }] if matches!(lhs.as_ref(), Expr::Select { .. })
            ),
            "a single-use select should stay a value while losing its scratch: {:?}",
            f.body
        );
    }

    #[test]
    fn do_while_condition_observes_tail_copy() {
        // The latch comparison is evaluated after the body.  A reload emitted
        // at the body tail therefore reaches the condition and must fold there;
        // leaving it as a separate wide scratch lets later width recovery change
        // a signed `local_c > 0` into an unsigned comparison.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![Stmt::DoWhile {
                body: vec![Stmt::Assign {
                    dst: reg("t10"),
                    src: Expr::Reg(reg("local_c")),
                }],
                cond: Expr::Cmp {
                    op: CmpOp::Slt,
                    lhs: Box::new(Expr::Const(0)),
                    rhs: Box::new(Expr::Reg(reg("t10"))),
                },
            }],
        };

        propagate_copies(&mut f);

        let Stmt::DoWhile { body, cond } = &f.body[0] else {
            panic!("expected do-while, got {:?}", f.body[0]);
        };
        assert!(
            body.is_empty(),
            "folded latch reload must be dead: {body:?}"
        );
        assert_eq!(
            *cond,
            Expr::Cmp {
                op: CmpOp::Slt,
                lhs: Box::new(Expr::Const(0)),
                rhs: Box::new(Expr::Reg(reg("local_c"))),
            }
        );
    }

    #[test]
    fn single_use_load_not_folded_across_store() {
        // t = *p; *q = 5; return t
        // Even though `t` is read exactly once, its defining load must NOT be
        // folded past the store (the store may alias `p`). The load stays put.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t0"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("p"))),
                        size: 8,
                    },
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("q")),
                    src: Expr::Const(5),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("t0"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The load must survive as its own statement (t0 = *p), read by the
        // return — it must not have been substituted into the return expression.
        assert!(
            f.body.iter().any(|s| matches!(
                s,
                Stmt::Assign { dst, src: Expr::Deref { .. } } if *dst == reg("t0")
            )),
            "load must not be folded across the store: {:?}",
            f.body
        );
        assert!(
            matches!(f.body.last(), Some(Stmt::Return { value: Some(Expr::Reg(r)) }) if *r == reg("t0")),
            "return must still read the loaded temp, not the moved load: {:?}",
            f.body
        );
    }

    #[test]
    fn copy_invalidated_when_source_overwritten() {
        // ret = local_c; local_c = local_c + 1; x = ret
        // The `x = ret` must NOT become `x = local_c` (local_c changed).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_c")),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Reg(reg("local_c"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("x"),
                    src: Expr::Reg(reg("ret")),
                },
                // Keep `x` live so it isn't dead-eliminated; we want to inspect it.
                Stmt::Return {
                    value: Some(Expr::Reg(reg("x"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The returned value must be `ret` (which captured local_c *before* the
        // store), never the post-store `local_c`. That's the invalidation
        // invariant: the stale copy was not propagated across the write.
        let ret_val = f
            .body
            .iter()
            .find_map(|s| match s {
                Stmt::Return { value } => value.clone(),
                _ => None,
            })
            .expect("a return");
        assert_eq!(
            ret_val,
            Expr::Reg(reg("ret")),
            "return must use captured `ret`, not the overwritten local_c"
        );
    }

    #[test]
    fn pure_register_view_propagates_to_multiple_linear_uses() {
        let view = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 4,
                expr: Box::new(Expr::Reg(reg("arg0"))),
            }),
        };
        let mut f = Function {
            name: "views".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("var0"),
                    src: view.clone(),
                },
                Stmt::Store {
                    addr: Expr::Addr(0x4000),
                    src: Expr::Reg(reg("var0")),
                    size: 8,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var0"))),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            !format!("{f:?}").contains("var0"),
            "a pure view alias should not survive as a fake source variable: {f:#?}"
        );
        let Stmt::Store { src, .. } = &f.body[0] else {
            panic!("expected the first consumer")
        };
        assert!(format!("{src:?}").contains("arg0"));
        assert!(matches!(
            &f.body[1],
            Stmt::Return { value: Some(value) } if value == &view
        ));
    }

    #[test]
    fn overwritten_scratch_write_is_dead_store_eliminated() {
        // ret = local_c; ret = (local_c >> 1); return ret
        // The first write is overwritten before any read -> dead, removed.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Bin {
                        op: BinOp::Shr,
                        lhs: Box::new(Expr::Reg(reg("local_c"))),
                        rhs: Box::new(Expr::Const(1)),
                    },
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The dead first write is removed and the shift (read once by the return)
        // folds into it -> `return (local_c >> 1)`.
        assert_eq!(
            f.body.len(),
            1,
            "dead write removed + shift folded: {:?}",
            f.body
        );
        assert!(
            matches!(
                &f.body[0],
                Stmt::Return {
                    value: Some(Expr::Bin { op: BinOp::Shr, .. })
                }
            ),
            "surviving statement must be the folded return: {:?}",
            f.body[0]
        );
    }

    #[test]
    fn write_read_before_overwrite_is_kept() {
        // ret = local_c; x = ret; ret = 5; return x  -> first write is READ, kept.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Reg(reg("local_c")),
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_9")),
                    src: Expr::Reg(reg("ret")),
                    size: 8,
                },
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Const(5),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("ret"))),
                },
            ],
        };
        propagate_copies(&mut f);
        // The store consumes the first `ret`, so it must not be eliminated; the
        // store keeps a value derived from local_c.
        assert!(
            f.body.iter().any(|s| matches!(s, Stmt::Store { .. })),
            "store must remain: {:?}",
            f.body
        );
    }

    #[test]
    fn copies_do_not_cross_control_flow() {
        // t = local_0; if (...) { store local_5 = t }  -> the copy is cleared at
        // the `if`, so the store inside the branch keeps `t` (NOT local_0).
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("t"),
                    src: Expr::Reg(reg("local_0")),
                },
                Stmt::If {
                    cond: Expr::Reg(reg("zf")),
                    then_body: vec![Stmt::Store {
                        addr: Expr::Reg(reg("local_5")),
                        src: Expr::Reg(reg("t")),
                        size: 8,
                    }],
                    else_body: None,
                },
            ],
        };
        propagate_copies(&mut f);
        if let Stmt::If { then_body, .. } = &f.body[1] {
            assert_eq!(
                then_body[0],
                Stmt::Store {
                    addr: Expr::Reg(reg("local_5")),
                    src: Expr::Reg(reg("t")),
                    size: 8,
                },
                "copy must not cross the if boundary"
            );
        } else {
            panic!("expected if");
        }
    }

    #[test]
    fn single_use_promoted_local_select_folds_into_next_assignment() {
        // A stack-slot assignment diamond has already become one lazy Select:
        // local_tmp = cond ? 1 : 2; local_state = local_tmp. The intermediate
        // promoted slot is compiler storage, not source-level state.
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(reg("cond"))),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Const(2)),
            width: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_tmp")),
                    src: selected.clone(),
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("local_state")),
                    src: Expr::Reg(reg("local_tmp")),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_state"))),
                },
            ],
        };

        propagate_copies(&mut f);

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f.body,
            vec![Stmt::Return {
                value: Some(selected),
            }],
            "the one-use promoted temporary chain should disappear"
        );
    }

    #[test]
    fn adjacent_boolean_promoted_local_folds_into_return() {
        let predicate = Expr::Cmp {
            op: CmpOp::Eq,
            lhs: Box::new(Expr::Reg(reg("state"))),
            rhs: Box::new(Expr::Const(3)),
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_result"),
                    src: predicate.clone(),
                },
                Stmt::Comment("epilogue".into()),
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_result"))),
                },
            ],
        };

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f.body,
            vec![
                Stmt::Comment("epilogue".into()),
                Stmt::Return {
                    value: Some(predicate),
                },
            ]
        );
    }

    #[test]
    fn adjacent_physical_load_folds_into_its_only_eager_guard_use() {
        // x86-64 `movzx eax, byte ptr [base+index]; test eax,eax` now carries
        // the architectural zero-extension explicitly. After role naming the
        // destination is the physical `ret` role rather than an SSA Temp, but
        // the immediately following guard is still its one reaching use. Keep
        // the load at the same evaluation point while exposing the loop guard.
        let loaded = Expr::Cast {
            signed: false,
            width: 8,
            expr: Box::new(Expr::Cast {
                signed: false,
                width: 1,
                expr: Box::new(Expr::Deref {
                    addr: Box::new(Expr::Reg(reg("cursor"))),
                    size: 1,
                }),
            }),
        };
        let mut f = Function {
            name: "str_len".into(),
            entry_va: 0,
            body: vec![Stmt::While {
                cond: Expr::Const(1),
                body: vec![
                    Stmt::Assign {
                        dst: reg("ret"),
                        src: loaded.clone(),
                    },
                    Stmt::If {
                        cond: Expr::Cmp {
                            op: CmpOp::Eq,
                            lhs: Box::new(Expr::Bin {
                                op: BinOp::And,
                                lhs: Box::new(Expr::Reg(reg("ret"))),
                                rhs: Box::new(Expr::Const(255)),
                            }),
                            rhs: Box::new(Expr::Const(0)),
                        },
                        then_body: vec![Stmt::Break],
                        else_body: None,
                    },
                    Stmt::Assign {
                        dst: reg("cursor"),
                        src: Expr::Bin {
                            op: BinOp::Add,
                            lhs: Box::new(Expr::Reg(reg("cursor"))),
                            rhs: Box::new(Expr::Const(1)),
                        },
                    },
                ],
            }],
        };

        propagate_adjacent_guard_values(&mut f);

        let Stmt::While { body, .. } = &f.body[0] else {
            panic!("expected loop")
        };
        assert_eq!(
            body.len(),
            2,
            "the physical scratch definition should disappear"
        );
        let Stmt::If { cond, .. } = &body[0] else {
            panic!("the reconstructed guard must remain first")
        };
        let dump = format!("{cond:?}");
        assert!(
            dump.contains("Deref"),
            "the load must move into the guard: {dump}"
        );
        assert!(
            !dump.contains("ret"),
            "the scratch read must be replaced: {dump}"
        );
    }

    #[test]
    fn adjacent_physical_guard_value_with_an_arm_read_is_kept() {
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("cursor"))),
                        size: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("ret"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Reg(reg("ret"))),
                    }],
                    else_body: None,
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_guard_values(&mut f);

        assert_eq!(
            f, expected,
            "a second reaching read must keep the definition"
        );
    }

    #[test]
    fn loop_header_value_read_after_the_loop_is_kept() {
        // `while_reload_header` uses the last loaded element both to decide
        // whether to leave the loop and in the joined return. Moving the load
        // into the loop condition would make that joined read undefined.
        let mut f = Function {
            name: "while_reload_header".into(),
            entry_va: 0,
            body: vec![
                Stmt::While {
                    cond: Expr::Const(1),
                    body: vec![
                        Stmt::Assign {
                            dst: reg("var3"),
                            src: Expr::Deref {
                                addr: Box::new(Expr::Reg(reg("cursor"))),
                                size: 4,
                            },
                        },
                        Stmt::If {
                            cond: Expr::Cmp {
                                op: CmpOp::Ne,
                                lhs: Box::new(Expr::Bin {
                                    op: BinOp::And,
                                    lhs: Box::new(Expr::Reg(reg("var3"))),
                                    rhs: Box::new(Expr::Const(1)),
                                }),
                                rhs: Box::new(Expr::Const(0)),
                            },
                            then_body: vec![Stmt::Break],
                            else_body: None,
                        },
                    ],
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("var3"))),
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_guard_values(&mut f);

        assert_eq!(
            f, expected,
            "a joined post-loop read must keep the reaching loop definition"
        );
    }

    #[test]
    fn adjacent_physical_value_is_not_moved_across_select_evaluation() {
        let mut source_select = Function {
            name: "source_select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("choose_load"))),
                        if_true: Box::new(Expr::Deref {
                            addr: Box::new(Expr::Reg(reg("cursor"))),
                            size: 1,
                        }),
                        if_false: Box::new(Expr::Const(0)),
                        width: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(Expr::Reg(reg("ret"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
            ],
        };
        let expected_source = source_select.clone();

        propagate_adjacent_guard_values(&mut source_select);

        assert_eq!(
            source_select, expected_source,
            "a select source must retain its original conditional evaluation"
        );

        let mut guard_select = Function {
            name: "guard_select".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("ret"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("cursor"))),
                        size: 1,
                    },
                },
                Stmt::If {
                    cond: Expr::Select {
                        cond: Box::new(Expr::Reg(reg("skip_read"))),
                        if_true: Box::new(Expr::Const(1)),
                        if_false: Box::new(Expr::Reg(reg("ret"))),
                        width: 1,
                    },
                    then_body: vec![Stmt::Break],
                    else_body: None,
                },
            ],
        };
        let expected_guard = guard_select.clone();

        propagate_adjacent_guard_values(&mut guard_select);

        assert_eq!(
            guard_select, expected_guard,
            "a select guard must not make an eager load conditional"
        );
    }

    #[test]
    fn adjacent_promoted_value_with_a_second_read_is_kept() {
        let selected = Expr::Select {
            cond: Box::new(Expr::Reg(reg("cond"))),
            if_true: Box::new(Expr::Const(1)),
            if_false: Box::new(Expr::Const(2)),
            width: 4,
        };
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: reg("local_tmp"),
                    src: selected,
                },
                Stmt::Assign {
                    dst: reg("first"),
                    src: Expr::Reg(reg("local_tmp")),
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_tmp"))),
                },
            ],
        };
        let expected = f.clone();

        propagate_adjacent_promoted_values(&mut f);

        assert_eq!(
            f, expected,
            "a later read still needs the rooted definition"
        );
    }

    #[test]
    fn promoted_local_load_is_not_deferred_into_a_later_use() {
        // Even a one-use promoted local must keep a memory load at its original
        // evaluation point: the intervening store may alias it.
        let mut f = Function {
            name: "f".into(),
            entry_va: 0,
            body: vec![
                Stmt::Store {
                    addr: Expr::Reg(reg("local_tmp")),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Reg(reg("p"))),
                        size: 4,
                    },
                    size: 4,
                },
                Stmt::Store {
                    addr: Expr::Reg(reg("q")),
                    src: Expr::Const(9),
                    size: 4,
                },
                Stmt::Return {
                    value: Some(Expr::Reg(reg("local_tmp"))),
                },
            ],
        };

        propagate_copies(&mut f);

        assert!(
            matches!(
                f.body.first(),
                Some(Stmt::Store {
                    addr: Expr::Reg(dst),
                    src: Expr::Deref { .. },
                    ..
                }) if dst == &reg("local_tmp")
            ),
            "the load must remain rooted before the aliasing store: {:?}",
            f.body
        );
        assert!(
            matches!(
                f.body.last(),
                Some(Stmt::Return {
                    value: Some(Expr::Reg(value))
                }) if value == &reg("local_tmp")
            ),
            "the return must still read the rooted promoted local: {:?}",
            f.body
        );
    }
}
