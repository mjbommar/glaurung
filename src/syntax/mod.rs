//! The language-neutral parsing substrate.
//!
//! Every Glaurung source front end sits on this layer: source maps and spans,
//! symbol interning, a struct-of-arrays token buffer, diagnostics, the parser
//! event stream, an arena tree, error-recovery primitives, and a CFG builder
//! that consumes control-flow events rather than syntax.
//!
//! Design, requirements (`REQ-SYN-*`) and components (`SB-*`):
//! `docs/design/source-front-ends/substrate.md`. The first consumer is the C
//! front end planned in `docs/design/static-c-analysis/`.
//!
//! Four rules hold across the whole module and are checked, not merely
//! intended:
//!
//! * **Language neutrality.** Nothing here names a token kind, node tag,
//!   keyword or grammar rule of any specific language (`REQ-SYN-1`). Languages
//!   supply `u16` tags; the substrate never interprets them.
//! * **Parsing never fails.** Entry points return their product alongside a
//!   diagnostic list, never `Result`, and never panic on any input
//!   (`REQ-SYN-2`). A `Result`-returning parser cannot report a per-function
//!   failure, and per-function failure is exactly what the tool this replaces
//!   gets wrong: one bad byte voids a whole file.
//! * **Explicit-stack traversal.** No native recursion in the lexer, the parser
//!   or any tree walk (`REQ-SYN-3`). Decompiler output is adversarial in
//!   exactly this way, and a process that aborts on stack exhaustion cannot
//!   report anything at all.
//! * **Determinism is a public promise.** Identical input yields byte-identical
//!   output across runs, machines and thread counts; ids are assigned in
//!   construction order and anything iterated into output is ordered
//!   (`REQ-SYN-5`).

pub mod cfg;
pub mod diag;
pub mod event;
pub mod ged;
pub mod ids;
pub mod intern;
pub mod metrics;
pub mod recover;
pub mod scan;
pub mod source;
pub mod token;
pub mod tree;

pub use ids::{DiagId, NodeId, Span, Symbol, TokenId};
