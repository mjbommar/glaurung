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
//! | Bit | Module | Rule | In [`Passes::DEFAULT`]? |
//! |---|---|---|---|
//! | (a) | [`opcodes`] | same-semantics opcode collapse | yes |
//! | (b) | [`constants`] | constant folding and copy propagation | yes |
//! | (c) | [`cse`] | local common-subexpression elimination | yes |
//! | (d) | [`redundancy`] | dead-store and redundant-write elimination | yes |
//! | (e) | [`polarity`] | comparison-polarity canonicalisation | yes |
//! | (f) | [`strength`] | strength-reduction canonical forms | **no -- measured negative** |
//!
//! The last row is the lane's one negative result and it is kept rather than
//! deleted: the pass is implemented, tested and ablated, and the ablation says
//! it costs recall in both possible directions. [`Passes::DEFAULT`] carries the
//! numbers.
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

    /// No pass at all -- the identity normaliser, and the ablation's zero row.
    pub const NONE: Passes = Passes(0);

    /// The set [`super::CfrSettings::normalize`] turns on: (a) through (e).
    ///
    /// **(f) is implemented, measured and excluded.** The rule stated in
    /// advance is that a pass whose *solo* row in the ablation is below the
    /// unnormalised baseline does not ship in the default set. On XO
    /// (gcc `-O0` -> gcc `-O2`, 341 scored queries, 1 + 100 candidates) the
    /// unnormalised baseline is 51/341 = 0.1496 and every pass alone reaches
    /// at least that -- except [`strength`], which reads 48/341 = 0.1408.
    /// With it in the set the full pipeline reads 57/341 = 0.1672; without it,
    /// 60/341 = 0.1760.
    ///
    /// The cost is entirely rule 1, the power-of-two collapse: with only rule 2
    /// enabled, `only strength` returns to exactly the baseline 51/341, which
    /// also says the magic-division recogniser never fires on this corpus. The
    /// **opposite** direction was measured too -- `Shl x, k` to `Mul x, 2^k`,
    /// which is the other way to make the two spellings one -- and is also a
    /// loss: `only strength` 49/340 = 0.1441 and the full pipeline 59/340 =
    /// 0.1735. Two spellings of a scaled index carry discrimination this corpus
    /// wants kept, in both directions, so the pass stays out of the default set
    /// rather than being tuned until it stops hurting.
    ///
    /// See `docs/reference/function-identity-cfr.md`, "Normalisation".
    pub const DEFAULT: Passes = Passes(0b01_1111);

    /// The full set, all six. The ablation's other endpoint, and not what the
    /// settings flag turns on -- see [`Passes::DEFAULT`].
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
        Passes::DEFAULT
    }
}

thread_local! {
    /// The pass set [`normalize_function`] uses on this thread.
    ///
    /// [`Passes::DEFAULT`]. [`with_passes`] is the only thing that changes it, and
    /// it exists for one reason: the ablation in `tests/identity_cfr_retrieval.rs`
    /// has to score thirteen pass configurations through the *same* pipeline
    /// `super::extract` runs, and `CfrSettings` deliberately carries one
    /// `normalize` bit rather than six, because a settings word with a bit per
    /// pass would make sixty-four incomparable quotients out of what should be
    /// one.
    ///
    /// Thread-local rather than global: `cargo test` runs each test in its own
    /// thread, so a measurement in one cannot perturb another, and the
    /// signature loop in `super::extract` is serial within a thread.
    static ACTIVE_PASSES: std::cell::Cell<Passes> =
        const { std::cell::Cell::new(Passes::DEFAULT) };
}

/// Run `body` with only `passes` enabled on this thread, restoring the previous
/// set afterwards even if `body` panics is **not** guaranteed -- a panicking
/// measurement fails the test it is in and the thread ends with it.
///
/// Measurement only. Nothing in `src/` calls this.
pub fn with_passes<T>(passes: Passes, body: impl FnOnce() -> T) -> T {
    let previous = ACTIVE_PASSES.with(|active| active.replace(passes));
    let outcome = body();
    ACTIVE_PASSES.with(|active| active.set(previous));
    outcome
}

/// Normalise a copy of `function` with the thread's active pass set, which is
/// [`Passes::DEFAULT`] unless a measurement has changed it with
/// [`with_passes`].
///
/// The input is borrowed and never mutated: the caller's function is the one
/// the decompiler may still be holding.
pub fn normalize_function(function: &LlirFunction) -> LlirFunction {
    normalize_function_with(function, ACTIVE_PASSES.with(std::cell::Cell::get))
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
