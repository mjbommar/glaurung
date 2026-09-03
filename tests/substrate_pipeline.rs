//! The substrate's layers, exercised end to end as one pipeline.
//!
//! Every component of `src/syntax/` has its own unit tests, and each was
//! written against its own specification. That is exactly the arrangement in
//! which the pieces pass individually and do not compose: an interface agreed
//! on paper is not an interface until two layers actually meet across it.
//!
//! These tests run the whole chain a real front end will run —
//!
//! ```text
//! source text
//!   -> Tokens          (syntax::token)
//!   -> Events          (syntax::event)
//!   -> Arena           (syntax::tree)
//!   -> Flow            (syntax::cfg)
//!   -> Cfg
//!   -> GedGraph        (syntax::ged)
//!   -> a distance
//! ```
//!
//! — using a deliberately tiny made-up language, because the substrate is
//! language-neutral and testing it through C would confuse a substrate defect
//! with a C front end defect. The token kinds and node tags below are opaque
//! `u16`s, which is precisely what a real front end supplies.

use glaurung::syntax::cfg::{Cfg, CfgBuilder, Flow, LoopKind};
use glaurung::syntax::diag::Diagnostics;
use glaurung::syntax::event::{drive, Events, TagCensus};
use glaurung::syntax::ged::{ged, GedGraph, GedNode};
use glaurung::syntax::ids::{Span, TokenId};
use glaurung::syntax::intern::SymbolTable;
use glaurung::syntax::source::SourceFile;
use glaurung::syntax::token::{Tokens, TokensBuilder};
use glaurung::syntax::tree;

/// Token kinds for the toy language. Opaque to the substrate, dense from zero.
mod kind {
    pub const WORD: u16 = 0;
    pub const NUMBER: u16 = 1;
    pub const PUNCT: u16 = 2;
}

/// Node tags for the toy language. Also opaque, also dense from zero.
mod tag {
    pub const ROOT: u16 = 0;
    pub const ITEM: u16 = 1;
}

/// A word/number/punctuation splitter — the smallest thing that is honestly a
/// lexer, so the pipeline is driven by real offsets rather than hand-written
/// ones that could accidentally agree with a buggy buffer.
fn lex(text: &str) -> Tokens {
    let mut builder = TokensBuilder::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let kind = if c.is_ascii_alphabetic() || c == '_' {
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            kind::WORD
        } else if c.is_ascii_digit() {
            while i < bytes.len() && (bytes[i] as char).is_ascii_digit() {
                i += 1;
            }
            kind::NUMBER
        } else {
            i += 1;
            kind::PUNCT
        };
        builder.push(kind, start as u32);
    }
    builder.finish(text.len() as u32)
}

#[test]
fn text_reaches_a_token_buffer_whose_spans_index_the_source_file() {
    let text = "alpha 42 ; beta_2";
    let file = SourceFile::new("toy.x", text);
    let tokens = lex(text);

    assert_eq!(tokens.len(), 4, "one token per non-space run");
    let spelled: Vec<&str> = (0..tokens.len())
        .map(|i| tokens.text(TokenId::new(i as u32), file.text()).trim_end())
        .collect();
    assert_eq!(spelled, ["alpha", "42", ";", "beta_2"]);

    // The span of every token must be a valid index into the same SourceFile
    // the lexer read, which is the contract SB-1 and SB-3 meet across.
    for i in 0..tokens.len() {
        let span = tokens.span(TokenId::new(i as u32));
        assert!(span.hi as usize <= file.len() as usize);
        let line_col = file.line_col(span.lo);
        assert_eq!(line_col.line, 1, "single-line input");
        assert!(line_col.col >= 1, "columns are 1-based");
    }
}

#[test]
fn a_token_buffer_drives_an_event_stream_into_a_walkable_tree() {
    let text = "alpha 42 ; beta_2";
    let tokens = lex(text);

    // A parser's shape: one root, one ITEM node per token.
    let mut events = Events::new();
    let root = events.open(tag::ROOT);
    for i in 0..tokens.len() {
        let item = events.open(tag::ITEM);
        events.token(TokenId::new(i as u32));
        events.close(item);
    }
    events.close(root);

    let mut diagnostics = Diagnostics::new();
    let arena = tree::build(
        events.as_slice(),
        Span::new(0, text.len() as u32),
        &mut diagnostics,
    );

    assert!(
        !diagnostics.has_errors(),
        "a balanced stream must build without diagnostics"
    );
    assert_eq!(
        arena.len(),
        1 + tokens.len(),
        "root plus one node per token"
    );

    // The same event stream must drive a different sink to a consistent answer.
    // That is the whole justification for the Sink indirection.
    let mut census = TagCensus::new();
    let mut census_diagnostics = Diagnostics::new();
    drive(
        events.as_slice(),
        &mut census,
        Span::new(0, text.len() as u32),
        &mut census_diagnostics,
    );
    assert_eq!(census.count(tag::ROOT), 1, "exactly one root node");
    assert_eq!(census.count(tag::ITEM) as usize, tokens.len());
    assert!(!census_diagnostics.has_errors());
}

/// Build the CFG of `while (c) { s; }` from control-flow events alone.
///
/// No token, tag or keyword crosses into the builder — `REQ-SYN-8` — so this is
/// also a check that the boundary is usable, not merely enforced.
fn while_loop_cfg() -> Cfg {
    let mut builder = CfgBuilder::new(Span::new(0, 40));
    builder.push(Flow::LoopHeader {
        kind: LoopKind::While,
        cond: Span::new(7, 8),
    });
    builder.push(Flow::Stmt(Span::new(12, 14)));
    builder.push(Flow::EndScope);
    let parsed = builder.finish();
    assert!(
        !parsed.diagnostics().has_errors(),
        "a well-formed flow stream must not produce errors"
    );
    parsed.into_parts().0
}

#[test]
fn control_flow_events_reach_a_graph_that_satisfies_its_own_invariants() {
    let cfg = while_loop_cfg();
    assert!(cfg.node_count() >= 3, "entry, header, body at minimum");
    assert!(
        cfg.validate().is_empty(),
        "the builder's own REQ-GEN-1 invariants must hold: {:?}",
        cfg.validate()
    );
    assert!(
        !cfg.cycle_closing_edges().is_empty(),
        "a while loop must close a cycle"
    );
}

/// The join that matters: a `Cfg` becomes a `GedGraph` through degrees alone.
///
/// This is the seam the whole parity milestone rests on. `syntax::ged` reads
/// only `(in_degree, out_degree, is_entrypoint, is_exitpoint)`, and `syntax::cfg`
/// exposes exactly those four, from two components written independently.
fn to_ged(cfg: &Cfg) -> GedGraph {
    let nodes: Vec<GedNode> = (0..cfg.node_count())
        .map(|i| {
            let node_id = cfg_node_id(cfg, i);
            GedNode::new(
                cfg.in_degree(node_id),
                cfg.out_degree(node_id),
                node_id == cfg.entry(),
                node_id == cfg.exit(),
            )
        })
        .collect();
    GedGraph::new(nodes, cfg.edge_count() as u64)
}

/// The `NodeId` of the `i`th node, however the CFG chooses to number them.
fn cfg_node_id(_cfg: &Cfg, i: usize) -> glaurung::syntax::ids::NodeId {
    glaurung::syntax::ids::NodeId::new(i as u32)
}

#[test]
fn a_control_flow_graph_becomes_a_ged_graph_and_scores_zero_against_itself() {
    let cfg = while_loop_cfg();
    let graph = to_ged(&cfg);
    assert_eq!(graph.node_count(), cfg.node_count());

    let result = ged(&graph, &graph);
    assert!(result.is_exact(), "a small graph is scored exactly");
    assert_eq!(result.value, 0.0, "a graph is identical to itself");
}

#[test]
fn two_differently_shaped_functions_score_a_non_zero_distance() {
    let loop_graph = to_ged(&while_loop_cfg());

    // A straight line of three statements: no branch, no cycle.
    let mut builder = CfgBuilder::new(Span::new(0, 40));
    for start in [0u32, 10, 20] {
        builder.push(Flow::Stmt(Span::new(start, start + 4)));
    }
    let straight = to_ged(&builder.finish().into_parts().0);

    let distance = ged(&loop_graph, &straight);
    assert!(distance.is_exact());
    assert!(
        distance.value > 0.0,
        "a loop and a straight line are not the same shape (got {})",
        distance.value
    );
    // Symmetry across the seam, not just inside the distance's own tests.
    assert_eq!(ged(&straight, &loop_graph).value, distance.value);
}

#[test]
fn the_whole_chain_is_deterministic_from_text_to_distance() {
    let text = "alpha 42 ; beta_2";
    let run = || {
        let tokens = lex(text);
        let mut symbols = SymbolTable::new();
        let interned: Vec<_> = (0..tokens.len())
            .map(|i| symbols.intern(tokens.text(TokenId::new(i as u32), text).trim_end()))
            .collect();
        let graph = to_ged(&while_loop_cfg());
        (
            tokens.kinds().to_vec(),
            tokens.starts().to_vec(),
            interned,
            ged(&graph, &graph).value,
        )
    };
    let first = run();
    for _ in 0..3 {
        assert_eq!(first, run(), "the pipeline must be a function of its input");
    }
}
