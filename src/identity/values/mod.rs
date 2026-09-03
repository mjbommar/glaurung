//! Value fingerprints (the L3 rung): what a function *computes*, not what it
//! looks like.
//!
//! This is the first slice of plan item 12 in
//! `docs/history/program-measures-2026-09-02.md`, following vSim (Wang & Lin,
//! NDSS 2026). The full rule table, every simplification, and the measured
//! numbers are in `docs/reference/function-identity-values.md`.
//!
//! # The idea in one paragraph
//!
//! Two builds of one function disagree about registers, block order,
//! addresses and instruction selection, and they agree about the numbers the
//! function produces. So: run the function under bounded execution from a few
//! fixed initial states, write down every value a register write or a memory
//! store produced, throw away the ones that are obviously addresses, normalise
//! the rest to width-free signed integers, and compare two functions by
//! weighted Jaccard over the resulting multisets. No graph, no model, no
//! training step, and the metric is the Ruzicka distance rather than an
//! approximate graph edit distance.
//!
//! # The pipeline
//!
//! | Stage | Module |
//! |---|---|
//! | Fixed initial states and the filter constants | [`seeds`] |
//! | Bounded execution over `crate::exec`, recording every write | [`harvest`] |
//! | vSim's Algorithm 1, plus two rules whole-function execution needs | [`filter`] |
//! | Branch conditions, read statically off the LLIR | [`branch`] |
//! | Width-free normal form, the stored multiset, the digest | [`fingerprint`] |
//! | Weighted Jaccard and the distance it induces | [`similarity`] |
//! | Binary on disk to one fingerprint per function | [`extract`] |
//!
//! # What this slice does NOT do
//!
//! Stated here rather than discovered later:
//!
//! * **No callee-to-caller propagation.** vSim's ablation puts it at 0.08
//!   Recall@1 -- the same order as the filter -- and it is the single largest
//!   thing left out. It needs a call graph and a bounded fixpoint, which is
//!   the next slice's work.
//! * **No symbolic expressions.** vSim harvests symbolic values and then
//!   concretizes them against a trial array; we substitute the trial values
//!   *during* execution instead, which is the same substitution done earlier.
//!   The cost is that a value's provenance is gone: two functions computing
//!   `3 * x` and `x + 2 * x` match because the numbers match, and a function
//!   whose path diverges under a seed contributes nothing for that seed rather
//!   than a partial expression.
//! * **x86-64 only.** [`extract::fingerprints_for_path`] refuses anything else
//!   rather than producing a fingerprint over a register file that does not
//!   match the code.
//!
//! # Feature gate
//!
//! Behind `exec`, because it drives `crate::exec`. `crate::identity` compiles
//! without it; `--features python-ext` includes it.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use glaurung::identity::values::{fingerprints_for_path, weighted_jaccard, ValueSettings};
//!
//! let budgets = glaurung::analysis::cfg::Budgets::default();
//! let left = fingerprints_for_path(Path::new("a.so"), ValueSettings::default(), &budgets)?;
//! let right = fingerprints_for_path(Path::new("b.so"), ValueSettings::default(), &budgets)?;
//! let score = weighted_jaccard(&left[0].fingerprint, &right[0].fingerprint, None);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod branch;
pub mod extract;
pub mod filter;
pub mod fingerprint;
pub mod harvest;
pub mod seeds;
pub mod settings;
pub mod similarity;

pub use extract::{
    fingerprint_for_function, fingerprint_of, fingerprints_for_path, FunctionValues, HarvestStats,
    ValueError,
};
pub use filter::FilterCounts;
pub use fingerprint::{normalize, BranchKind, ValueFingerprint};
pub use harvest::{bare_context, Harvest, Observation, RunOutcome, ValueContext};
pub use settings::{
    ValueSettings, ValueVersion, MAX_SEEDS, MAX_SITE_CAP, VALUE_MAJOR, VALUE_MINOR, VALUE_SCHEME,
};
pub use similarity::{
    distance, weighted_jaccard, weighted_jaccard_set, OccurrenceWeights, UniformWeights, Weights,
};

#[cfg(test)]
mod tests;
