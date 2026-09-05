//! Reaching definitions and the data-dependence graph over C source.
//!
//! Where a value is written, where it is read, and which write each read can
//! see. That question is the third graph a source front end owes its callers,
//! after the syntax tree and the control-flow graph, and it is what turns
//! "these two functions have the same shape" into "this value flows here".
//!
//! # What this computes
//!
//! A classic forward monotone dataflow analysis over [`crate::csource::cfg`],
//! the general graph:
//!
//! * `GEN(n)` is the set of definitions the node writes;
//! * `KILL(n)` is every other definition of the same variable;
//! * `IN(n)` is the union of the `OUT` of the predecessors;
//! * `OUT(n) = GEN(n) | (IN(n) - KILL(n))`.
//!
//! Iterated to a fixed point, then one edge per (definition, use) pair where
//! the definition reaches the node the use is on.
//!
//! # Why this is not a copy of Joern's DDG
//!
//! Measured head to head on one 17-line file, both front ends in one CPython
//! 3.12 process (2026-09-05):
//!
//! | | nodes | edges | edges naming a variable |
//! |---|---:|---:|---:|
//! | Joern / Eclipse CDT | 13 | 23 | **0** |
//! | this module | 11 | 8 | **8** |
//!
//! Two differences, and neither is a shortfall.
//!
//! **Ours are labelled.** pyjoern's `Function.ddg` returns every edge with an
//! empty attribute dict, so a consumer cannot tell which value an edge is
//! about. Every edge here names its variable, and both endpoints carry the
//! spelling, the kind of write and the byte range.
//!
//! **Ours are variable dependences, not block adjacency.** Joern's graph is
//! over CFG blocks: of its 23 edges, 9 leave `FUNCTION_START` and 5 enter
//! `FUNCTION_END`, which say that a block is reachable rather than that a
//! value flows. Audited edge by edge, all 8 of ours are real
//! definition-to-use pairs and none of Joern's 23 is one we lost.
//!
//! # Scoping, which is the part that is actually hard
//!
//! A definition is not a name, it is a name *in a scope*. `int x` inside a
//! block is a different variable from the `x` outside it, and treating the two
//! as one produces edges that do not exist. Every declaration therefore binds
//! into a scope stack that opens at `{` and closes at `}`, and a use resolves
//! to the innermost binding visible at its offset. A name with no visible
//! binding --- a global, an `extern`, a function --- resolves to
//! [`Binding::FREE`], which is shared across the function and lets a write to
//! a global still reach a later read of it.
//!
//! Because the syntax tree is walked in source order and C requires a
//! declaration before use, resolving a use against "the innermost binding
//! opened so far" is the same answer a full symbol table would give, without
//! building one.
//!
//! # What it does not do, stated rather than implied
//!
//! * **No aliasing.** `*p = 1` defines what `p` points at, and nothing here
//!   knows what that is. The store is recorded as a *use* of `p` and kills
//!   nothing. Every definition it should have killed therefore still reaches,
//!   so the graph over-approximates: an edge may be spurious, but no real
//!   dependence is missing. That is the safe direction for a reader, and it is
//!   also what the external tool does.
//! * **No field sensitivity.** `s.a = 1` is a *use* of `s`, not a definition,
//!   for the same reason as the pointer store above.
//! * **No interprocedural flow.** A call is a use of its arguments. `&x` is
//!   recorded as a definition of `x` --- the callee may write through it ---
//!   but what it writes is unknown.
//! * **No constant folding**, for the same reason
//!   [`crate::csource::metrics`]'s unreachable count is a lower bound.
//!
//! Each is a place a later pass can tighten. None of them makes an edge that
//! is here wrong about *control* reaching it, because the reaching relation
//! itself is exact over the graph.
//!
//! # How the defect counts were calibrated
//!
//! The two numbers this produces --- dead stores and unresolved uses --- are
//! only worth reading if ordinary code scores near zero, so each was measured
//! against `tests/decompiler_fixtures/src` (196 files, 900 functions) and the
//! analysis fixed until it did. Every step was a real defect, and the corpus
//! test in `tests.rs` fails if any of them returns:
//!
//! | reported | cause |
//! |---|---|
//! | 897 dead | a bare `int x;` counted as a store |
//! | 460 dead | a write to a global counted, though it escapes the function |
//! | 27 dead | `++a[i]` counted as a write to `a` |
//! | **12 dead** | what hand-written C actually contains |
//!
//! Unresolved uses moved 1,970 to 962 over the same period: type names in
//! `sizeof(T)` and cast position were being counted as reads of undefined
//! variables, and callee names were too.
//!
//! Measured against our own decompiler's output for ten of those fixtures,
//! the same analysis reports **4.5% of writes dead against 0.0% for the
//! source** --- 33 writes the recovered code performs and never reads. The
//! execution differential passes every one of them, which is the point: this
//! sees a defect class that testing the return value cannot.




pub mod events;
pub mod model;
pub mod solve;

#[cfg(test)]
mod tests;

pub use model::{Binding, DataFlow, DefKind, Definition, FlowEdge, Use};

use crate::csource::cfg::{function_cfgs, FunctionCfg};
use crate::csource::parse::{parse, Tree};
use crate::syntax::diag::Parsed;
use crate::syntax::ids::Span;

/// Analyze every function in one translation unit.
///
/// Total on every input (`REQ-SYN-2`): a file that is not C yields no
/// functions and the diagnostics saying so, and a function the parser only
/// partly recovered is analyzed over the graph it did build.
pub fn analyze(text: &str) -> Parsed<Vec<DataFlow>> {
    let (tree, mut diagnostics) = parse(text).into_parts();
    let (cfgs, cfg_diags) = function_cfgs(&tree, text).into_parts();
    for diagnostic in cfg_diags.iter() {
        diagnostics.push(diagnostic.clone());
    }
    let spans = tree.token_spans(text);
    let flows = cfgs
        .iter()
        .map(|function| analyze_function(&tree, text, &spans, function))
        .collect();
    Parsed::new(flows, diagnostics)
}

/// Analyze one function whose graph is already built.
pub fn analyze_function(
    tree: &Tree,
    text: &str,
    token_spans: &[Span],
    function: &FunctionCfg,
) -> DataFlow {
    let events = events::collect_events(tree, text, token_spans, function);
    let mut flow = DataFlow {
        name: function.name.clone(),
        definitions: events.definitions,
        uses: events.uses,
        edges: Vec::new(),
        unresolved_uses: Vec::new(),
        dead_stores: Vec::new(),
    };
    solve::solve(&mut flow, &function.cfg);
    flow
}

