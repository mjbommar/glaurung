//! What the enclosing scope already proved about each ABI argument slot.
//!
//! The backward call scan in `super::fold_one_call` is deliberately local: it
//! walks one structured statement list and stops at every join. `EnclosingSlots`
//! is the only thing that crosses that boundary, and it crosses in both
//! directions -- carrying a proven incoming value inward so a call in a branch
//! arm can still name the function's own parameter, and carrying an enclosing
//! clobber inward so that naming is never a guess.
//!
//! Every constructor here is a `&self` derivation, so a nested body gets its own
//! value and cannot disturb the enclosing one.

use crate::ir::ast::{Expr, Stmt};
use crate::ir::types::VReg;

use super::{arg_slots, mark_arg_writes_in_stmt, slot_of, CallConv};

/// What the statements OUTSIDE the body being folded already prove about each
/// ABI argument slot.
///
/// The backward call scan is deliberately local: it walks one structured
/// statement list and stops at every join. That is sound for what it deletes,
/// but it also made the enclosing scope invisible, in both directions:
///
/// * an untouched incoming parameter used by a call inside a branch arm had no
///   witness in that arm, so `incoming_arg_expr` declined and the whole
///   argument list was dropped — the ABI prefix rule discards every recovered
///   slot once a lower one is missing; and
/// * conversely nothing carried an enclosing CLOBBER inward, so authorizing the
///   live-in from the whole function would have been a guess.
///
/// Carrying both together is what makes the live-in usable: `live_ins` supplies
/// the function's spelling, `blocked` proves it still reaches.
#[derive(Clone)]
pub(super) struct EnclosingSlots {
    /// A proven value entering a slot at the top of this body (loop-carried).
    pub(super) overrides: Vec<Option<Expr>>,
    /// The slot was written, clobbered, or joined on the way into this body, so
    /// the function-entry value no longer reaches it.
    pub(super) blocked: Vec<bool>,
    /// How this function spells each of its own live-in argument registers.
    pub(super) live_ins: Vec<Option<Expr>>,
    /// The slot's function-entry value occupies its argument register at EVERY
    /// point in the function. See `entry_constant_slots`.
    entry_constant: Vec<bool>,
    /// The exact value-numbered definition that reaches this body's entry for
    /// each slot, when the enclosing prefix proves one. See `advance_reaching`.
    pub(super) reaching: Vec<Option<Expr>>,
}

impl EnclosingSlots {
    pub(super) fn entry(
        arch: CallConv,
        live_ins: &[Option<Expr>],
        entry_constant: Vec<bool>,
    ) -> Self {
        let slots = arg_slots(arch).len();
        Self {
            overrides: vec![None; slots],
            blocked: vec![false; slots],
            live_ins: live_ins.to_vec(),
            entry_constant,
            reaching: vec![None; slots],
        }
    }

    /// Is `slot` provably still its function-entry value at any point at all?
    pub(super) fn is_entry_constant(&self, slot: usize) -> bool {
        self.entry_constant.get(slot).copied().unwrap_or(false)
    }

    /// The context for a body nested inside a statement whose enclosing clobber
    /// mask is `blocked` and whose proven reaching definitions are `reaching`.
    pub(super) fn with_blocked(&self, blocked: Vec<bool>, reaching: Vec<Option<Expr>>) -> Self {
        Self {
            overrides: self.overrides.clone(),
            blocked,
            live_ins: self.live_ins.clone(),
            entry_constant: self.entry_constant.clone(),
            reaching,
        }
    }

    /// Fold one statement of the enclosing prefix into a running clobber mask.
    ///
    /// The boundaries are the ones the backward scan itself refuses to cross:
    /// reaching a labelled join or crossing an explicit transfer means nothing
    /// about the value entering the following statement can be proved from
    /// what came before it.
    pub(super) fn advance(blocked: &mut [bool], statement: &Stmt, arch: CallConv) {
        if matches!(
            statement,
            Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::IndirectGoto { .. }
                | Stmt::Return { .. }
                | Stmt::Break
        ) {
            blocked.fill(true);
            return;
        }
        mark_arg_writes_in_stmt(statement, arch, blocked);
    }

    /// Fold one statement of the enclosing prefix into the per-slot reaching
    /// definition.
    ///
    /// `blocked` answers "does the FUNCTION-ENTRY value still reach"; this
    /// answers the strictly harder question "what value reaches", and it is the
    /// only thing that can name the argument of a call whose setup happens in an
    /// enclosing scope. A value-numbered `%rdi#1 = ...` before a branch is the
    /// reaching definition of the `rdi` slot inside that branch's arms.
    ///
    /// Everything about it is fail-closed:
    ///
    /// * only a TOP-LEVEL, unconditional `Stmt::Assign` records a definition, so
    ///   nothing written on one path of a nested branch is ever claimed;
    /// * only a VERSIONED destination (`rdi#1`) is recorded. An unversioned
    ///   architectural name is one storage with many definitions, and naming it
    ///   at a later call is exactly the reverted table-dispatch patch's bug —
    ///   the name no longer denotes the value it held here;
    /// * every other write of the slot, every call (all argument registers are
    ///   caller-clobbered), and every control-flow boundary the backward scan
    ///   refuses to cross clears the slot back to "unknown".
    pub(super) fn advance_reaching(
        reaching: &mut [Option<Expr>],
        statement: &Stmt,
        arch: CallConv,
    ) {
        if matches!(
            statement,
            Stmt::Label(_)
                | Stmt::Goto { .. }
                | Stmt::IndirectGoto { .. }
                | Stmt::Return { .. }
                | Stmt::Break
        ) {
            reaching.iter_mut().for_each(|slot| *slot = None);
            return;
        }
        if let Stmt::Assign {
            dst: dst @ VReg::Phys(name),
            ..
        } = statement
        {
            if let Some(slot) = slot_of(arch, name.as_str()) {
                reaching[slot] = name.contains('#').then(|| Expr::Reg(dst.clone()));
                return;
            }
        }
        let mut written = vec![false; reaching.len()];
        mark_arg_writes_in_stmt(statement, arch, &mut written);
        for (slot, written) in written.into_iter().enumerate() {
            if written {
                reaching[slot] = None;
            }
        }
    }

    /// The exact value that reaches a call in this body for `slot`, or `None`
    /// when nothing proves one.
    ///
    /// `blocked_here` is what the statements of THIS body before the call
    /// already wrote: a local write means the reaching definition is local, and
    /// recovering it is the ordinary backward scan's job, not this one.
    ///
    /// The last resort — this function's own untouched live-in register —
    /// additionally requires that the slot really carries a parameter.
    /// `param_slots` is the same guard the direct-callee fallback uses, and for
    /// the same reason: without it the recovery names an incoming register that
    /// nothing ever defines.
    pub(super) fn reaching_value(
        &self,
        slot: usize,
        blocked_here: &[bool],
        param_slots: &std::collections::HashSet<usize>,
    ) -> Option<Expr> {
        if blocked_here.get(slot).copied().unwrap_or(true) {
            return None;
        }
        if let Some(override_value) = self.overrides.get(slot).and_then(Clone::clone) {
            return Some(override_value);
        }
        if let Some(reaching) = self.reaching.get(slot).and_then(Clone::clone) {
            return Some(reaching);
        }
        (param_slots.contains(&slot) && self.entry_value_reaches(slot))
            .then(|| self.live_ins.get(slot).and_then(Clone::clone))
            .flatten()
    }

    /// Does this function's ENTRY value for `slot` still reach a call in the
    /// body being folded?
    ///
    /// A proven loop-carried override answers the question outright: it names
    /// the value that reaches, so what the path in wrote is already accounted
    /// for. Otherwise the enclosing clobber mask decides.
    pub(super) fn entry_value_reaches(&self, slot: usize) -> bool {
        self.overrides.get(slot).is_some_and(Option::is_some)
            || !self.blocked.get(slot).copied().unwrap_or(false)
    }

    pub(super) fn with_overrides(&self, overrides: Vec<Option<Expr>>) -> Self {
        Self {
            overrides,
            blocked: self.blocked.clone(),
            live_ins: self.live_ins.clone(),
            entry_constant: self.entry_constant.clone(),
            reaching: self.reaching.clone(),
        }
    }
}
