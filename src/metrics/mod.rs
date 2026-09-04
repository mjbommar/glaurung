//! Native implementations of the decompiler-quality metrics.
//!
//! DecBench scores a decompiler on three metrics, and Glaurung reimplements
//! them so that a structural or type-recovery number can be computed in the
//! ordinary iteration loop rather than only inside an opt-in harness. The plan
//! and the component inventory are `docs/design/static-c-analysis/`.
//!
//! What lives here is only what is language- and format-agnostic about a
//! metric. The graph edit distance is in [`crate::syntax::ged`], because it is
//! a graph algorithm over degree sequences with no C in it and no metric in it
//! either.
//!
//! Two rules carry over from the substrate and matter as much here:
//!
//! * **A non-answer is a value, not an error.** A metric that cannot be
//!   measured for a function abstains, and an abstention leaves the
//!   denominator uniformly for every decompiler. Collapsing it into `0.0` or an
//!   `Err` is how a shared denominator silently rots.
//! * **Determinism is a public promise.** Every gate in this programme is a
//!   diff, so nothing that iterates a `HashMap` may reach output.

pub mod calibrate;
pub mod tree_distance;
pub mod type_match;
pub mod type_name;
