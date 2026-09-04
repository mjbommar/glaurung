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
pub mod joern;
pub mod lex;
pub mod normalize;
pub mod parse;
