//! An unsound, local peephole normaliser applied to a **copy** of the lifted
//! function before CFR hashing.
//!
//! # What this is, and what it must never become
//!
//! This is a canonicaliser for *similarity*, not an optimiser. It runs on a
//! clone of the `LlirFunction` that `super::extract` has just lifted and
//! annotated, and the clone is thrown away as soon as the feature multiset has
//! been computed. **Nothing here ever reaches the decompiler.** No pass in this
//! directory is called from `crate::ir`, no result of a pass is written back
//! into the function the renderer sees, and the flag that turns it on
//! ([`super::CfrSettings::normalize`]) is off by default and is part of the
//! signature's version triple, so a normalised vector is never compared with an
//! unnormalised one.
//!
//! That separation is the point. VexIR2Vec's authors, whose VexINE is the
//! template for the pass list below, say it out loud:
//!
//! > *"soundness is not important in this context: the normalizations are
//! > designed to reduce the differences in IR generated from different
//! > architectures and compilers."*
//!
//! Glaurung already has sound, global versions of most of these
//! transformations -- `ir::copy_prop`, `ir::const_fold`, `ir::value_number`,
//! `ir::dce`, `ir::dead_stores` -- and they exist to make *rendered C* correct.
//! The passes here are allowed to be wrong in ways those may never be: to fold
//! at the wrong width, to forward a load past a store it cannot prove
//! non-aliasing, to flip a predicate that a successor block also reads. Each
//! module states its own unsoundness under a "Why unsound is fine here"
//! heading.
//!
//! # The peephole
//!
//! One basic block, straight-line, with VexINE's invariant: **values used but
//! not defined in the peephole are parameters and must survive**. No pass
//! looks outside its block, so no pass needs liveness, dominance or a call
//! graph, and the whole normaliser is `O(function size)` with small constants.
//!
//! # The passes
//!
//! | Bit | Module | Rule |
//! |---|---|---|
//! | (a) | [`opcodes`] | same-semantics opcode collapse |
//! | (b) | [`constants`] | constant folding and copy propagation |
//! | (c) | [`cse`] | local common-subexpression elimination |
//! | (d) | [`redundancy`] | dead-store and redundant-write elimination |
//! | (e) | [`polarity`] | comparison-polarity canonicalisation |
//! | (f) | [`strength`] | strength-reduction canonical forms |
//!
//! The order is fixed and is the order of the table: (a) makes operators
//! comparable so (b) can fold them, (b) exposes the operand identities (c) and
//! (d) match on, and (e) and (f) run last because they rewrite shapes that only
//! exist once copies have been propagated.
//!
//! # Determinism and the bound
//!
//! Passes run in rounds until a round changes nothing or [`MAX_ROUNDS`] is
//! reached, whichever comes first. Rounds are needed because the passes feed
//! each other -- CSE turns a duplicate into a copy that copy propagation then
//! forwards -- and a cap is needed because no pass individually proves the
//! whole system terminates. Four is measured rather than chosen: over the
//! fixture corpus no function reaches a fifth round with anything left to
//! change, and the cap costs a bounded four passes over each block regardless.
//!
//! Every container in this directory is a `BTreeMap` or a `Vec`, never a
//! `HashMap`: a canonical form whose feature set depended on hash iteration
//! order would not be an identity. `tests::normalisation_is_deterministic`
//! pins that.

pub mod common;
pub mod constants;
pub mod cse;
pub mod opcodes;
pub mod polarity;
pub mod redundancy;
pub mod strength;

use crate::ir::types::LlirFunction;

/// Rounds of the whole pass pipeline before the driver stops.
///
/// See the module doc: the passes feed each other, so one round is not a fixed
/// point, and no pass proves the system terminates on its own. The cap is the
/// proof of termination.
pub const MAX_ROUNDS: usize = 4;

/// Which passes to run. A bit field so an ablation can turn exactly one on or
/// exactly one off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Passes(u8);

impl Passes {
    /// (a) same-semantics opcode collapse.
    pub const OPCODES: Passes = Passes(1 << 0);
    /// (b) constant folding and copy propagation.
    pub const CONSTANTS: Passes = Passes(1 << 1);
    /// (c) local common-subexpression elimination.
    pub const CSE: Passes = Passes(1 << 2);
    /// (d) dead-store and redundant-write elimination.
    pub const REDUNDANCY: Passes = Passes(1 << 3);
    /// (e) comparison-polarity canonicalisation.
    pub const POLARITY: Passes = Passes(1 << 4);
    /// (f) strength-reduction canonical forms.
    pub const STRENGTH: Passes = Passes(1 << 5);

    /// Every pass, in the fixed order.
    pub const ALL: [(Passes, &'static str); 6] = [
        (Passes::OPCODES, "opcodes"),
        (Passes::CONSTANTS, "constants"),
        (Passes::CSE, "cse"),
        (Passes::REDUNDANCY, "redundancy"),
        (Passes::POLARITY, "polarity"),
        (Passes::STRENGTH, "strength"),
    ];

    /// No pass at all -- the identity normaliser, used by the ablation as the
    /// "all but the only one there is" endpoint.
    pub const NONE: Passes = Passes(0);

    /// The full set.
    pub fn everything() -> Passes {
        Passes::ALL
            .iter()
            .fold(Passes::NONE, |accumulated, (pass, _)| {
                accumulated.with(*pass)
            })
    }

    /// This set plus `other`.
    pub fn with(self, other: Passes) -> Passes {
        Passes(self.0 | other.0)
    }

    /// This set minus `other`.
    pub fn without(self, other: Passes) -> Passes {
        Passes(self.0 & !other.0)
    }

    /// Whether `other`'s bits are all set here.
    pub fn contains(self, other: Passes) -> bool {
        self.0 & other.0 == other.0
    }

    /// The raw bit field, for a report that wants to name the configuration.
    pub fn bits(self) -> u8 {
        self.0
    }
}

impl Default for Passes {
    fn default() -> Self {
        Passes::everything()
    }
}

/// Normalise a copy of `function` with every pass enabled.
///
/// The input is borrowed and never mutated: the caller's function is the one
/// the decompiler may still be holding.
pub fn normalize_function(function: &LlirFunction) -> LlirFunction {
    normalize_function_with(function, Passes::everything())
}

/// Normalise a copy of `function` with the named passes only.
///
/// This is the ablation entry point. With [`Passes::NONE`] it returns a plain
/// clone, which is what makes "no passes" a measurable row rather than a
/// special case.
pub fn normalize_function_with(function: &LlirFunction, passes: Passes) -> LlirFunction {
    let mut copy = function.clone();
    for block in &mut copy.blocks {
        for _ in 0..MAX_ROUNDS {
            let mut changed = false;
            if passes.contains(Passes::OPCODES) {
                changed |= opcodes::run(block);
            }
            if passes.contains(Passes::CONSTANTS) {
                changed |= constants::run(block);
            }
            if passes.contains(Passes::CSE) {
                changed |= cse::run(block);
            }
            if passes.contains(Passes::REDUNDANCY) {
                changed |= redundancy::run(block);
            }
            if passes.contains(Passes::POLARITY) {
                changed |= polarity::run(block);
            }
            if passes.contains(Passes::STRENGTH) {
                changed |= strength::run(block);
            }
            if !changed {
                break;
            }
        }
    }
    copy
}

#[cfg(test)]
mod tests;
