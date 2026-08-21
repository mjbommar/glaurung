//! Pointer evidence that reaches a parameter through register copies.
//!
//! The parent has two producers of pointer evidence for a parameter and both
//! are **spill-shaped**: [`super::tagging::propagate_spill_slot_pointers`] wants
//! a `Store` into a frame slot followed by a load, and the value-keyed seed in
//! [`super::valued`] is fed from `live_in_spills`, which only a frame-slot
//! `Store` populates.
//!
//! At `-O0` the compiler spills every parameter, so both fire. At `-O2` it keeps
//! the parameter in a callee-saved register — `mov rbx, rdi` — and dereferences
//! the *copy*. No spill, no evidence, and the parameter falls through to the
//! register-width fallback, which spells it `long`.
//!
//! Measured over the `-O2strip` fixture corpus against its own DWARF, 402
//! pointer parameters:
//!
//! ```text
//!                                        before    after
//!   pointer-to-1-byte -> `char *`         38.6%    58.0%
//!   ...any pointer at all                 65.9%    93.2%
//!   pointer-to-4-byte -> `int *`          67.8%    84.7%
//!   ...any pointer at all                 70.7%    89.2%
//! ```
//!
//! The evidence was always there: the renderer already printed
//! `*(char *)(var0)` inside the very function whose `arg0` it declared `long`.

use std::collections::HashMap;

use super::tagging::merge_type_hint;
use super::TypeHint;
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{LlirFunction, Op};
use crate::ir::use_def::{def_uses, InstrAddr};

/// Fold dereference evidence into whatever the rest of the chain concluded.
///
/// **Merged, not chained.** Adding this as another `.or_else` arm in
/// `recover_prototype_with_arm_vfp_args` is dead code: `live_in_parameter_view_hint`
/// answers for essentially every parameter that is read at all, returning
/// `Int { width: 8 }` for a register-resident pointer, so the fallback never
/// ran. That version was written, built and A/B'd over 402 pointer parameters
/// and moved *exactly nothing* -- every count identical to the digit.
///
/// Not `merge_type_hint`, for one reason: it resolves two pointers by taking the
/// **wider** pointee, and that is the wrong rule when the two disagree. Widening
/// invents `int *` for a buffer the callee also touches a byte at a time, and an
/// `int *` parameter makes every ordinary `char[]` call site invalid C.
/// Disagreement is evidence of the *absence* of a pointee type, so it meets to
/// `void *` — the rule
/// `arm_live_in_with_conflicting_access_widths_is_a_void_pointer` has always
/// required, and which using `merge_type_hint` here broke.
///
/// Everything else defers to `merge_type_hint`, so this can only ever promote a
/// non-pointer answer to a pointer, never demote one.
pub(super) fn combine_pointer_evidence(
    established: Option<TypeHint>,
    dereferenced: TypeHint,
) -> TypeHint {
    match (established, dereferenced) {
        (Some(TypeHint::Pointer { pointee_width: a }), TypeHint::Pointer { pointee_width: b })
            if a != b =>
        {
            TypeHint::Pointer { pointee_width: 0 }
        }
        (current, new) => merge_type_hint(current, new),
    }
}

/// Pointer evidence that reached a live-in through **identity copies only**.
///
/// Walks every memory operand's base register back through `Op::Assign` copies
/// and, when the chain ends at `value`, credits a pointer of the dereferenced
/// width. Conflicting widths meet to `void *` rather than to the wider one; see
/// [`combine_pointer_evidence`].
///
/// # Only identity copies
///
/// A conversion produces a *different* value. Projecting a pointer contract
/// through a `zext` turns an integer parameter that later derives an address
/// into `char *` — the hazard `copy_origin` in
/// `python_bindings::ir::callee_contracts` already documents. Following
/// `Op::Bin`/`Op::Un` here would reintroduce it, so the walk stops at anything
/// that is not `Op::Assign`.
///
/// # Why the ARM pointer exclusion does not apply
///
/// `super::live_in_parameter_view_hint` deliberately drops raw pointer class on
/// ARM, because its `raw` map is keyed by *physical register* and `r0`-`r3` have
/// no narrow aliases to separate two lifetimes, so a later address-bearing use
/// can retype an earlier scalar read. This walk is keyed by **SSA value**: a
/// later lifetime is a different `SsaValue` and cannot reach `value` at all. The
/// ambiguity that motivated the exclusion is not expressible here.
pub(super) fn copied_live_in_pointer_hint(
    lf: &LlirFunction,
    ssa: &SsaInfo,
    value: &SsaValue,
) -> Option<TypeHint> {
    use crate::ir::use_def::def_uses;

    let definitions: std::collections::HashMap<SsaValue, (InstrAddr, &Op)> = lf
        .blocks
        .iter()
        .enumerate()
        .flat_map(|(block_idx, block)| {
            block
                .instrs
                .iter()
                .enumerate()
                .filter_map(move |(instr_idx, instruction)| {
                    let addr = InstrAddr {
                        block_idx,
                        instr_idx,
                    };
                    ssa.def_value(lf, addr)
                        .map(|v| (v, (addr, &instruction.op)))
                })
        })
        .collect();

    // Walk back through identity copies to the live-in that ultimately supplied
    // this value, or `None` if anything but a copy intervenes. Bounded by the
    // definition count, so a malformed cycle terminates rather than hangs.
    let origin = |mut current: SsaValue| -> Option<SsaValue> {
        for _ in 0..=definitions.len() {
            if current.version == 0 {
                return Some(current);
            }
            let (at, op) = definitions.get(&current)?;
            if !matches!(op, Op::Assign { .. }) {
                return None;
            }
            current = ssa.use_value(lf, *at, 0)?;
        }
        None
    };

    let mut hint: Option<TypeHint> = None;
    for (block_idx, block) in lf.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            // The base register's index within `def_uses`, which lists the
            // predicate first for the conditional forms. See `use_def`.
            let (memop, base_use) = match &instruction.op {
                Op::Load { addr, .. } | Op::Store { addr, .. } => (addr, 0usize),
                Op::CondLoad { addr, .. } | Op::CondStore { addr, .. } => (addr, 1usize),
                _ => continue,
            };
            if memop.base.is_none() {
                continue;
            }
            let at = InstrAddr {
                block_idx,
                instr_idx,
            };
            // Guard the index rather than trusting the arm above: an op whose
            // use list is shorter than expected would otherwise read the wrong
            // operand and credit a pointer to whatever happened to be there.
            if def_uses(&instruction.op).1.len() <= base_use {
                continue;
            }
            let Some(base) = ssa.use_value(lf, at, base_use) else {
                continue;
            };
            if origin(base).as_ref() != Some(value) {
                continue;
            }
            hint = Some(match hint {
                // Conflicting access widths do not mean "the wider one". An
                // optimised byte-buffer routine writes the same caller pointer
                // through byte and word stores, and calling that `int *`
                // invents a type that makes ordinary char-array call sites
                // invalid C. The honest common contract is an untyped object
                // pointer, which is what
                // `arm_live_in_with_conflicting_access_widths_is_a_void_pointer`
                // has always required — and what `merge_type_hint`, which
                // takes the wider pointee, would have broken.
                Some(TypeHint::Pointer { pointee_width }) if pointee_width != memop.size.max(1) => {
                    TypeHint::Pointer { pointee_width: 0 }
                }
                Some(existing) => existing,
                None => TypeHint::Pointer {
                    pointee_width: memop.size.max(1),
                },
            });
        }
    }
    hint
}
