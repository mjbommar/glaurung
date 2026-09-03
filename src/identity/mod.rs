//! Function identity: content-derived schemes for "what is this function".
//!
//! Every scheme here produces a value for the `.glaurung` project's
//! `function_identity(scheme, identity)` table, and each answers a different
//! question. Cheapest first:
//!
//! * [`warp`] -- exact identity. A WARP-compatible UUIDv5 over
//!   relocation-masked basic-block bytes. "Is this exactly a known build of a
//!   known function?"
//! * [`structural`] -- structural invariants of the CFG (MD-index, small-primes
//!   product over opcodes, block/edge/loop/SCC counts, call degree). "Which
//!   functions changed between two builds?"
//! * [`cfr`] -- the Canonical Function Representation: a Weisfeiler-Lehman
//!   feature multiset over the SSA dataflow graph and the degree-labelled CFG.
//!   "Which library function is this, across compilers and optimisation
//!   levels?"
//!
//! [`gate`] is not a scheme: it is a BinaryFuse8 membership filter over the
//! identity strings any one scheme produces for a `(scheme, architecture)`
//! pair, so "is this in any known library" can be answered before an exact or
//! masked lookup runs at all.
//!
//! The design, the mask/keep list, the metric argument and the measurement
//! protocol are in `docs/history/program-measures-2026-09-02.md`. Byte-level
//! digests (`crate::similarity`) keep one role, file-level near-duplicates;
//! they are not extended to functions.

pub mod cfr;
pub mod gate;
pub mod structural;
pub mod warp;
