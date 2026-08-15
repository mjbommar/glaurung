//! Measure how much of a lifted function declares its effects, and how much
//! only asserts them maximally or not at all.
//!
//! Design rule 5 says unknown calls and instructions clobber conservatively and
//! that unknown never means "no effect". This module is how that rule is
//! *measured* rather than asserted: it walks an [`LlirFunction`] and sorts every
//! effect-bearing op into one of four buckets.
//!
//! | bucket | soundness | precision |
//! |---|---|---|
//! | [`Op::Unknown`] | **unsound** — declares no footprint at all | n/a |
//! | opaque [`Op::Intrinsic`] (no ins, no outs, reads+writes memory) | sound | none |
//! | modelled `Op::Intrinsic` (a narrower declared footprint) | sound | partial |
//! | [`Op::Call`] with `effects: None` | **unsound** — `def_uses` reports no def and no use | n/a |
//!
//! The last row is the one worth watching. `lift_function` already rewrites
//! every residual `Unknown` into an opaque `Intrinsic` before returning, so the
//! first row is empty by construction on that path. A call is different: its
//! ABI footprint is attached by a *separate* pass (`ir::abi::annotate_calls`),
//! and `use_def::def_uses` deliberately reports nothing for a call that pass
//! never reached — "report what is certain rather than guessing at an ABI".
//! That is a sound choice about *arguments* and an unsound one about the
//! *return register*, which every un-annotated call is then believed to
//! preserve.

use std::collections::BTreeMap;

use crate::ir::types::{LlirFunction, Op};

/// Per-bucket counts of declared and undeclared effects.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EffectCensus {
    /// Every LLIR instruction seen, effect-bearing or not.
    pub instructions: usize,
    /// `Op::Unknown` survivors, by mnemonic. Declares no footprint at all.
    pub residual_unknown: BTreeMap<String, usize>,
    /// Maximally-conservative intrinsics, by name: sound but carrying no
    /// information beyond "assume everything". This is where the lifter's
    /// coverage gaps show up, so the histogram doubles as a work queue.
    pub opaque_intrinsic: BTreeMap<String, usize>,
    /// Intrinsics with a narrower declared footprint than "assume everything".
    pub modelled_intrinsic: BTreeMap<String, usize>,
    /// Calls carrying an `abi::annotate_calls` footprint that names at least
    /// one register.
    pub calls_with_effects: usize,
    /// Calls whose `CallEffects` exist but name no argument and no result.
    /// Function lifting attaches one of these to a CFG-proven tail call before
    /// any convention is known; `abi::annotate_calls` recognises the shape and
    /// refills it. Counted apart from both other buckets because "declared
    /// empty" and "not declared" are the same footprint and different bugs.
    pub calls_with_placeholder_effects: usize,
    /// Calls with `effects: None`: no declared register footprint, which
    /// `def_uses` renders as "defines nothing, uses nothing".
    pub calls_without_effects: usize,
}

impl EffectCensus {
    /// Total ops whose footprint is undeclared rather than merely imprecise:
    /// an `Op::Unknown`, or a call declaring neither an argument nor a result.
    pub fn undeclared(&self) -> usize {
        self.residual_unknown.values().sum::<usize>()
            + self.calls_without_effects
            + self.calls_with_placeholder_effects
    }

    /// Total maximally-conservative (sound, zero-information) intrinsics.
    pub fn opaque(&self) -> usize {
        self.opaque_intrinsic.values().sum()
    }
}

/// Accumulate `function`'s effect declarations into `out`.
pub fn census_into(function: &LlirFunction, out: &mut EffectCensus) {
    for block in &function.blocks {
        for instruction in &block.instrs {
            out.instructions += 1;
            match &instruction.op {
                Op::Unknown { mnemonic } => {
                    *out.residual_unknown.entry(mnemonic.clone()).or_default() += 1;
                }
                Op::Intrinsic {
                    name,
                    ins,
                    outs,
                    reads_mem,
                    writes_mem,
                } => {
                    let is_opaque = ins.is_empty() && outs.is_empty() && *reads_mem && *writes_mem;
                    let bucket = if is_opaque {
                        &mut out.opaque_intrinsic
                    } else {
                        &mut out.modelled_intrinsic
                    };
                    *bucket.entry(name.clone()).or_default() += 1;
                }
                Op::Call { effects, .. } => match effects {
                    None => out.calls_without_effects += 1,
                    Some(declared) if declared.result.is_none() && declared.args.is_empty() => {
                        out.calls_with_placeholder_effects += 1
                    }
                    Some(_) => out.calls_with_effects += 1,
                },
                _ => {}
            }
        }
    }
}
