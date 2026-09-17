//! What Glaurung keeps of the C source front end.
//!
//! The reusable stack --- the language-neutral substrate (`syntax`), the C
//! lexer, parser, control flow, dataflow, metrics, graph export and the
//! DecBench parity projection --- is the `cindergraph` crate, extracted from
//! this tree at `0892552` and consumed by Git revision (`Cargo.toml`;
//! `docs/decisions/source-001-depend-on-cindergraph-by-git-rev.md`). Nothing
//! here is a copy of it: consumers import `cindergraph::{parse, dataflow,
//! metrics, export, normalize, parity, syntax, csource::{cfg, lex}}` directly.
//!
//! What stays is what needs Glaurung's own models --- its LLIR, its symbolic
//! engine and solver seam --- and was excluded from the extraction on purpose
//! (cindergraph's `EXTRACTION.md`):
//!
//! * [`lower`] --- `S4`, C to `LlirFunction`, so decompiled C can be executed
//!   against the lifted binary;
//! * [`equiv`] --- `S5`, bounded equivalence checking between two lowered
//!   functions, on the solver;
//! * [`feasibility`] --- `S6`, path feasibility and bounded property checking
//!   for a lowered function, on the solver.
//!
//! Plan: `docs/design/static-c-analysis/roadmap.md`. Contract:
//! `docs/design/static-c-analysis/requirements.md`.

/// `S5` --- bounded equivalence checking between two `LlirFunction`s.
/// Needs the symbolic engine and its solver seam; see the module docs.
#[cfg(feature = "symbolic")]
pub mod equiv;
/// `S6` --- path feasibility for a lowered function, on the solver.
/// Needs the symbolic engine and its solver seam; see the module docs.
#[cfg(feature = "symbolic")]
pub mod feasibility;
pub mod lower;
