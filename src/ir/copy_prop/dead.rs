//! Delete a write nothing observes.
//!
//! Copy propagation does not remove anything by itself: it rewrites uses and
//! leaves the definitions standing. Two different proofs then retire those
//! definitions, and they are different proofs over different scopes:
//!
//! * [`dead_store_runs`] is a *local* argument. Within one straight-line run, a
//!   write to a scratch register that a later write shadows with no read
//!   between is dead. It resets at every control-flow boundary and only removes
//!   writes whose source is side-effect-free.
//! * [`eliminate_dead_copies`] is a *whole-body* counting argument. A scratch
//!   destination that the entire nested body never reads is dead, whatever the
//!   control flow between definition and end.
//!
//! Neither is copy propagation, and neither owns promoted stack locals
//! (`local_*`/`stack_*`) -- those belong to the dedicated stack dead-store pass.
//! What both must keep is an assignment whose source can still be *observed*
//! even when its destination is not: a lazy `Select` may contain a
//! value-producing call, and dropping it would drop the call.

use crate::ir::ast::Stmt;

use super::alias::is_scratch_reg;
use super::env::{is_pure_copyable, is_self_ref};
use super::hash::RegMap;
use super::reads::{count_reads_body, visit_expr_reads};

/// Within each straight-line run, drop a scratch-register write that is
/// overwritten by a later write before any intervening read (a dead store).
/// Conservative: resets at every control-flow boundary and only removes writes
/// whose source is side-effect-free.
pub(super) fn dead_store_runs(body: &mut Vec<Stmt>) -> bool {
    // last_write[reg] = index of the most recent not-yet-consumed removable
    // write to `reg` in this run.
    let mut last_write: RegMap<usize> = RegMap::default();
    let mut dead: Vec<usize> = Vec::new();
    for (i, s) in body.iter().enumerate() {
        match s {
            Stmt::Assign { dst, src } => {
                // Reads in `src` consume any pending write of those regs. The
                // histogram this used to build was thrown away after its keys
                // were walked, so visit the names directly — and only while
                // there is a pending write for one of them to consume.
                if !last_write.is_empty() {
                    visit_expr_reads(src, &mut |reg| {
                        last_write.remove(reg);
                        true
                    });
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
                //
                // The read scan that used to stand here was dead work in both
                // directions. `count_reads_stmt` descends into the WHOLE nested
                // body of an `If`/`While`/`For`/`Switch`, so a function whose
                // top level is one `if` re-walked the entire function at that
                // statement — and the `clear()` below then discarded every
                // removal it had just made. The only statements that survive
                // the clear are `Nop` and `Comment`, and neither reads a
                // register, so their removals were no-ops too.
                if !matches!(other, Stmt::Nop | Stmt::Comment(_)) {
                    last_write.clear();
                }
            }
        }
    }
    let mut removed = !dead.is_empty();
    if removed {
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
                removed |= dead_store_runs(then_body);
                if let Some(eb) = else_body {
                    removed |= dead_store_runs(eb);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                removed |= dead_store_runs(body);
            }
            Stmt::For { body, .. } => removed |= dead_store_runs(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, b) in cases.iter_mut() {
                    removed |= dead_store_runs(b);
                }
                if let Some(b) = default {
                    removed |= dead_store_runs(b);
                }
            }
            _ => {}
        }
    }
    removed
}

/// Remove register copies (`A = <pure>`) whose destination is never read in the
/// whole body. Returns whether anything was removed. Promoted stack locals
/// (`local_*`/`stack_*`) are left to the dedicated dead-store pass; here we only
/// clean scratch registers/temporaries the copy-prop just made dead.
pub(super) fn eliminate_dead_copies(body: &mut Vec<Stmt>) -> bool {
    // Count reads of every register across the whole (nested) body.
    let mut reads: RegMap<usize> = RegMap::default();
    count_reads_body(body, &mut reads);
    remove_dead(body, &reads)
}

fn remove_dead(body: &mut Vec<Stmt>, reads: &RegMap<usize>) -> bool {
    let mut changed = false;
    body.retain(|s| {
        // A lazy select may contain a value-producing call. Preserve that
        // effect even when the scratch result is never read; all other current
        // assignment sources are removable when their destination is dead.
        if let Stmt::Assign { dst, src } = s {
            if is_scratch_reg(dst)
                && reads.get(dst).copied().unwrap_or(0) == 0
                && !src.contains_call()
            {
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
