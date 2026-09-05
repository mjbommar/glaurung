//! The C source front end.
//!
//! C-specific code sitting on the language-neutral substrate in
//! [`crate::syntax`]: token kinds, node tags, the grammar, control-flow event
//! emission, and the Joern-parity layer that exists only to reproduce
//! DecBench's structural metric.
//!
//! Plan: `docs/design/static-c-analysis/roadmap.md`. Contract:
//! `docs/design/static-c-analysis/requirements.md`.

pub mod cfg;
/// `S5` --- bounded equivalence checking between two `LlirFunction`s.
/// Needs the symbolic engine and its solver seam; see the module docs.
#[cfg(feature = "symbolic")]
pub mod equiv;
pub mod joern;
pub mod lex;
pub mod lower;
pub mod metrics;
pub mod normalize;
pub mod parse;
