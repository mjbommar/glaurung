//! Canonical Function Representation (the L2 rung).
//!
//! A function's CFR is a Weisfeiler-Lehman feature multiset over two graphs
//! computed together and versioned together:
//!
//! * [`graph`] -- **CFR-G**, the operator-typed SSA dataflow graph. Nodes are
//!   SSA values and memory states; a node's label is a tuple and never a name.
//! * [`blocks`] -- **CFR-C**, the block-order-independent CFG labelling, seeded
//!   by degree and fused with CFR-G at each root operation.
//!
//! The design is Ghidra BSim's, restated over Glaurung's LLIR, and it is the
//! deterministic dual of HermesSim: same graph, fixed-point relabelling instead
//! of gradients, no model and no GPU. The full argument, the mask/keep table
//! and the measured numbers are in `docs/reference/function-identity-cfr.md`;
//! the literature it comes from is
//! `docs/history/program-measures-2026-09-02.md`.
//!
//! # What this buys and what it does not
//!
//! Quotient first, then metrise. Invariance is built into the representation
//! rather than paid for in the matcher: register allocation, block order,
//! addresses, NOPs, dead flag computations, stack mechanics and large constants
//! are absent by construction, so two builds of one function land on the same
//! object rather than being reconciled by an expensive comparison. What comes
//! out is a genuine pseudo-metric ([`similarity::distance`]) rather than an
//! approximate graph edit distance, which means it can index a corpus.
//!
//! Equal signatures do *not* prove two functions are the same. 1-WL is
//! one-sided: different features prove a difference, identical features prove
//! only that the canonical forms agree.
//!
//! # The optional normaliser
//!
//! [`normalize`] is an opt-in, deliberately **unsound** local peephole
//! canonicaliser that runs over a *copy* of the lifted function before the
//! graph is built. It is off by default ([`CfrSettings::normalize`]), it is a
//! bit in the version triple so a normalised vector is never compared with an
//! unnormalised one, and nothing it produces ever reaches the decompiler.
//!
//! # Order of the stages
//!
//! Canonicalisation happens **before** structuring. `crate::ir::structure_v2`
//! introduces `BinOp::LogicalAnd` and `BinOp::LogicalOr`, source-level
//! short-circuit operators sitting beside the bitwise `And` and `Or`; a machine
//! semantics graph must not contain them.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use glaurung::identity::cfr::{signatures_for_path, similarity, CfrSettings};
//!
//! let budgets = glaurung::analysis::cfg::Budgets::default();
//! let left = signatures_for_path(Path::new("a.so"), CfrSettings::default(), &budgets)?;
//! let right = signatures_for_path(Path::new("b.so"), CfrSettings::default(), &budgets)?;
//! let score = similarity::cosine(&left[0].signature, &right[0].signature, None);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod blocks;
pub mod commutativity;
pub mod dominators;
pub mod extract;
pub mod graph;
pub mod labels;
pub mod normalize;
mod operands;
mod prune;
pub mod signature;
pub mod similarity;
pub mod stack;
pub mod widths;
pub mod wl;

pub use extract::{
    signature_for_function, signature_of, signatures_for_path, CfrError, FunctionCfr,
};
pub use graph::{CfrGraph, GraphContext};
pub use labels::{ConstBucket, NodeLabel, OpKind, ValueClass, WidthClass};
pub use signature::{CfrSettings, CfrSignature, CfrVersion, CFR_MAJOR, CFR_MINOR, CFR_SCHEME};
pub use similarity::{cosine, distance, kernel, UniformWeights, Weights};
pub use stack::stack_registers_for;
pub use widths::{WidthCensus, WidthInference};

#[cfg(test)]
mod tests;
