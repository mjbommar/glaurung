//! F-9: Joern's expression-level node granularity for `&&`, `||` and `?:`.
//!
//! Spec: `docs/design/static-c-analysis/implementation-inventory.md` F-9, and
//! `docs/design/static-c-analysis/joern-behavior.md` section 4. Owned by stage
//! S3 of `docs/design/static-c-analysis/roadmap.md`.
//!
//! # The rule, and the published functions that establish it
//!
//! Joern's CFG is a graph over CPG nodes in evaluation order, so a short-circuit
//! operator is *itself* a node in addition to the fork it creates. Two further
//! facts are not in the inventory's description of F-9 and were read off the
//! published tree (`~/.cache/glaurung/decbench-full/tree`, `O0/bash`,
//! `O0/base-passwd`); both change the node count, so both are load-bearing.
//!
//! **A bare identifier or literal operand materializes no node.** Over 60
//! published `O0` translation units, every `IDENTIFIER` CFG node has an
//! enclosing code of `if`, `while`, `for` or `switch` --- 4,302 of them, none
//! anywhere else --- and no `LITERAL` node appears at all. So `rcatch &&
//! return_catch_flag` in bash `evalstring` is *one* block (block 5, in-degree
//! 1, out-degree 2: the `&&` node carrying the `if`), not the three
//! `REQ-CFG-6` describes, and `assigning_in_environment || executing_builtin`
//! in bash `find_variable_no_invisible` is one block of in-degree 1 and
//! out-degree 1 (block 3).
//!
//! **When the left operand materializes nothing the fork moves to the
//! predecessor, it does not disappear.** bash `load_history` holds
//! `hf && *hf && file_exists(hf)` as blocks 5 -> {1 = `*hf`, 0 = the inner
//! `&&`}, 1 -> 0, 0 -> {3 = `file_exists(hf)`, 2 = the outer `&&`}, 3 -> 2.
//! Block 5 is the *statement before* the condition; `hf` has no node of its
//! own, so the edges the left operand would have emitted come out of whatever
//! preceded it. `?:` behaves the same way with an absent condition --- bash
//! `hash_size` (`return (((table)?(table)->nentries:0));`) is 3 nodes, with
//! `FUNCTION_START` itself forking.
//!
//! **A chain nests: `a && b && c` is `(a && b) && c` and costs two operator
//! nodes, not one.** bash `rl_vi_arg_digit` shows both, with the inner one
//! (block 1, `c=='0'&&rl_numeric_arg==1`) carrying in-degree 2 and out-degree
//! 2. Our S2 lowering emits a *flat* expansion --- one join for the whole chain
//! --- because `csource::parse::tag` builds one node per precedence level, so
//! the inner operator has to be put back.
//!
//! Stated once, for `A op B` with operator node `P`, where `F` is the exit of
//! `A`'s region when `A` materializes and the region's own predecessors when it
//! does not:
//!
//! | | `B` materializes | `B` does not |
//! |---|---|---|
//! | `&&` / `\|\|` | `F -> B.entry`, `F -> P`, `B.exit -> P` | `F -> P` |
//! | `?:` | `F -> arm.entry` per arm, `arm.exit -> P` | `F -> P` for that arm |
//!
//! # How this is applied, and why it is a rewrite rather than a second builder
//!
//! S2 already emits the fork-and-join skeleton (`crate::csource::cfg::expr`).
//! What it does not do is (a) nest a flat chain and (b) know that an operand
//! may cost nothing. Both are local edits to the S2 graph, so this module is a
//! rewrite over that graph plus the AST it came from, not a second lowering:
//! duplicating the statement walk to change two rules about expressions would
//! buy a second thing to keep correct.
//!
//! Three phases, in this order, because the middle one has to see the shape the
//! first one validated:
//!
//! 1. **Collect and validate.** Every short-circuit AST node under the function
//!    body, its operands, and the CFG node each operand's evaluation ends at
//!    --- found by span, since S2 gives that node exactly the operand's span.
//!    A region whose shape does not match what S2 is documented to build is
//!    skipped whole, so an unmodelled construct costs fidelity and never a
//!    malformed graph (`REQ-CFG-11`, `REQ-SYN-2`).
//! 2. **Nest.** Insert `n - 2` operator nodes into every flat chain of `n`
//!    operands.
//! 3. **Elide.** Delete every operand node whose AST operand materializes
//!    nothing, reconnecting each predecessor to each successor --- which is
//!    exactly what makes the fork move to the predecessor in the `load_history`
//!    shape and vanish in the `evalstring` one.
//!
//! # What this deliberately does not do
//!
//! F-11 (entry/exit flags) and F-12 (singleton funcend removal) live in
//! [`super::flags`]; the graph here still carries S2's `Entry` and `Exit`
//! anchor nodes, so a node count taken from this module's output is Joern's
//! count *plus* those anchors. The tests below say so explicitly and project
//! them away to compare against published numbers.
//!
//! Joern's granularity for everything that is *not* control flow --- one node
//! per call, cast, field access and so on --- is deliberately not reproduced.
//! Those nodes are single-entry, single-successor, so F-10 chain contraction
//! merges every one of them away before the metric sees anything
//! (`joern-behavior.md` section 1.2).
//!
//! # What it costs and how far it reaches
//!
//! Swept over the 1,606 stored decompiled `.c` artifacts of the materialized
//! tree --- 188,716 functions, release build, 20.1 s for the whole sweep,
//! including the parse and the S2 build:
//!
//! ```text
//! operators 65530  rewritten 65168  skipped 362 (0.55%)
//! operator nodes inserted 0   operand nodes elided 75644
//! functions whose graph changed 22240 (11.8%)
//! coalesced blocks 2723012 -> 2628410  (-94602, -3.5%)
//! ```
//!
//! Every one of the 362 declines is the same guard: no CFG node carries the
//! operand's span, because S2 placed none --- an unevaluated context, an
//! unreachable region, or a recovered parse. None is a shape mismatch.
//!
//! `inserted 0` is real and is a property of *this* corpus, not of the rewrite:
//! Glaurung's own C printer parenthesizes, so `(a && b) && c` reaches the
//! parser already nested and never forms a flat chain. Joern sees the same
//! parentheses, so the two agree there for free; the chain nesting is for
//! everything else, and the two fixtures that check it (bash `rl_vi_arg_digit`,
//! bash `strlist_sort`) come from the source side, where the chains are flat.
//!
//! # No native recursion
//!
//! The AST walk is [`crate::syntax::tree::Arena::preorder`], an iterator with
//! its own stack; parenthesis stripping is a bounded loop; the rewrite is a
//! sequence of passes over vectors. Nothing here calls itself, so a ten
//! thousand deep `a && (b && (c && ...))` costs heap and not stack
//! (`REQ-GEN-4`, `REQ-ROB-3`).

use std::collections::{BTreeMap, BTreeSet};

use crate::csource::cfg::FunctionCfg;
use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::cfg::{Cfg, CfgEdge, CfgNode, EdgeKind, NodeKind, MAX_NODES};
use crate::syntax::ids::{NodeId, Span, TokenId};

/// What one call to [`expression_granular`] changed, for `REQ-OUT-4`.
///
/// Carried rather than recomputed because "the rewrite ran and did nothing" and
/// "the rewrite found nothing to run on" are the two failure modes a node count
/// alone cannot tell apart --- and a test that cannot tell them apart passes
/// against an empty implementation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GranularityStats {
    /// Short-circuit operators found under the function body.
    pub operators: u32,
    /// Operators whose S2 region matched the shape this rewrite expects.
    pub rewritten: u32,
    /// Operators left exactly as S2 built them, because their region did not.
    pub skipped: u32,
    /// Operator nodes inserted to nest a flat chain (phase 2).
    pub inserted: u32,
    /// Operand nodes deleted because the operand materializes nothing (phase 3).
    pub elided: u32,
}

/// Rewrite one function's S2 graph to Joern's expression granularity.
///
/// `body` is the `CompoundStmt` of the function definition `cfg` was built
/// from; `token_spans` is [`Tree::token_spans`], hoisted by the caller because
/// it costs one re-lex of the whole file and paying that per function is
/// quadratic.
///
/// Total on every input (`REQ-SYN-2`): a body the parser only partly recovered,
/// a graph whose short-circuit regions do not have the shape S2 documents, an
/// `Ok`-looking tree with missing children --- each yields a graph. The worst
/// case is that nothing is rewritten and the S2 graph comes back unchanged,
/// which is exactly the behaviour before this module existed.
///
/// The returned graph does not carry [`Cfg::continue_targets`]: they exist so
/// [`Cfg::validate`] can check `REQ-GEN-1`, and the parity layer's output is
/// deliberately not a `REQ-GEN-1` graph (`requirements.md` section 0.0).
pub fn expression_granular(
    tree: &Tree,
    token_spans: &[Span],
    body: NodeId,
    cfg: &Cfg,
) -> (Cfg, GranularityStats) {
    let mut stats = GranularityStats::default();
    let regions = collect(tree, token_spans, body, cfg, &mut stats);
    if regions.is_empty() {
        return (cfg.clone(), stats);
    }
    let mut work = Work::from_cfg(cfg);
    remember_operand_spans(&mut work, tree, token_spans, &regions);
    for region in &regions {
        nest(&mut work, region, &mut stats);
    }
    for region in &regions {
        elide(tree, &mut work, region, &mut stats);
    }
    (work.finish(cfg.entry(), cfg.exit()), stats)
}

/// [`expression_granular`] over every function graph of one translation unit.
///
/// The whole-file entry point, and the one the parity layer wires in. It pairs
/// positionally with [`crate::csource::cfg::function_cfgs`]: both walk
/// [`Tree::functions`], so `functions[i]` is the graph of the `i`th definition.
/// A definition whose body the parser never recovered, and any function the
/// caller assembled some other way, comes back untouched rather than dropped.
pub fn expression_granular_cfgs(tree: &Tree, text: &str, functions: &[FunctionCfg]) -> Vec<Cfg> {
    let token_spans = tree.token_spans(text);
    let definitions = tree.functions(text);
    // Keyed by span rather than by index so a caller that filtered its function
    // list --- as `parity_cfgs` does, by name --- still lines up.
    let bodies: BTreeMap<(u32, u32), NodeId> = definitions
        .iter()
        .filter_map(|def| def.body.map(|body| ((def.span.lo, def.span.hi), body)))
        .collect();
    functions
        .iter()
        .map(
            |function| match bodies.get(&(function.span.lo, function.span.hi)) {
                Some(&body) => expression_granular(tree, &token_spans, body, &function.cfg).0,
                None => function.cfg.clone(),
            },
        )
        .collect()
}

/// Which of the two arm shapes a short-circuit operator has.
///
/// `&&` and `||` share one shape here because the rewrite never needs to know
/// which arm carries the continuation: the operator node is found as the common
/// successor of the last operand, so "the edge to the operator" is identified
/// by its destination rather than by [`EdgeKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// `&&` or `||`: `n` operands and, after nesting, `n - 1` operators.
    Chain,
    /// `?:`: a condition and one or two arms, all joining at the operator.
    Conditional,
}

/// One short-circuit operator occurrence, resolved against the S2 graph.
#[derive(Debug, Clone)]
struct Region {
    shape: Shape,
    /// The AST operand nodes, in source order.
    operands: Vec<NodeId>,
    /// The CFG node each operand's evaluation ends at, parallel to `operands`.
    ends: Vec<NodeId>,
    /// The CFG node the whole expression ends at --- the operator node S2
    /// already materializes for the outermost operator of the region.
    terminal: NodeId,
}

/// Every short-circuit region under `body` whose S2 shape this rewrite models.
///
/// Regions are returned in AST preorder, which puts an operator before every
/// operator nested inside it. That order matters twice: phase 2 must not see a
/// region an enclosing rewrite has already reshaped, and phases are separated
/// so that phase 3's edge surgery never invalidates a validation phase 1 did.
fn collect(
    tree: &Tree,
    token_spans: &[Span],
    body: NodeId,
    cfg: &Cfg,
    stats: &mut GranularityStats,
) -> Vec<Region> {
    let index = span_index(cfg);
    let mut claimed: BTreeSet<NodeId> = BTreeSet::new();
    let mut regions = Vec::new();
    for node in tree.arena().preorder(body) {
        let Some(tag) = tag_of(tree, node) else {
            continue;
        };
        let Some(shape) = short_circuit_shape(tree, node, tag) else {
            continue;
        };
        stats.operators = stats.operators.saturating_add(1);
        match resolve(tree, token_spans, cfg, &index, node, shape) {
            Some(region) if region.ends.iter().all(|end| !claimed.contains(end)) => {
                claimed.extend(region.ends.iter().copied());
                regions.push(region);
            }
            _ => stats.skipped = stats.skipped.saturating_add(1),
        }
    }
    stats.rewritten = regions.len() as u32;
    regions
}

/// Resolve one operator's operands onto CFG nodes, or decline the region.
///
/// Every check here has the same purpose: this rewrite edits edges by position,
/// so it must refuse any region whose S2 shape is not the one
/// `crate::csource::cfg::expr` documents. Declining costs the F-9 correction
/// for one operator; guessing costs a wrong graph for the whole function.
fn resolve(
    tree: &Tree,
    token_spans: &[Span],
    cfg: &Cfg,
    index: &BTreeMap<(u32, u32), Option<NodeId>>,
    node: NodeId,
    shape: Shape,
) -> Option<Region> {
    let operands: Vec<NodeId> = tree.arena().children_iter(node).collect();
    match shape {
        // `a ?: b` gives two children, `a ? b : c` three. Anything else is a
        // recovered parse wearing a `CondExpr` tag.
        Shape::Conditional if !(2..=3).contains(&operands.len()) => return None,
        Shape::Chain if operands.len() < 2 => return None,
        _ => {}
    }

    let mut ends = Vec::with_capacity(operands.len());
    for &operand in &operands {
        let span = tree.arena().span(operand, token_spans)?;
        ends.push((*index.get(&(span.lo, span.hi))?)?);
    }
    if ends.iter().collect::<BTreeSet<_>>().len() != ends.len() {
        return None;
    }

    // The operator node is what the last operand flows into: S2 places it as
    // the join both arms reach, whatever kind the enclosing context gives it.
    let last = *ends.last()?;
    let terminal = single_successor(cfg, last)?;
    if ends.contains(&terminal) {
        return None;
    }

    match shape {
        Shape::Chain => {
            // Every operand but the last forks: one edge onward, one to the
            // join. The join is the terminal until phase 2 nests the chain.
            for &end in &ends[..ends.len() - 1] {
                let successors: Vec<NodeId> = cfg.successors(end).collect();
                if successors.len() != 2 {
                    return None;
                }
                if successors.iter().filter(|dst| **dst == terminal).count() != 1 {
                    return None;
                }
            }
        }
        Shape::Conditional => {
            if cfg.successors(ends[0]).count() != 2 {
                return None;
            }
            // Both arms join at the operator; an omitted arm is simply absent
            // from `ends`, and its fork edge already points at the terminal.
            for &arm in &ends[1..] {
                if single_successor(cfg, arm)? != terminal {
                    return None;
                }
            }
        }
    }

    Some(Region {
        shape,
        operands,
        ends,
        terminal,
    })
}

/// Phase 2: give a flat chain of `n` operands its `n - 2` inner operator nodes.
///
/// S2 emits `c0 -> {c1, T}`, `c1 -> {c2, T}`, ..., `ck -> T`: one join for the
/// whole chain. Joern nests, so each `ci` for `0 < i < k` gets an operator node
/// of its own which takes over `ci`'s fork, and the edge that used to reach the
/// join reaches the *next* operator instead. bash `rl_vi_arg_digit` is the
/// shape this produces.
fn nest(work: &mut Work, region: &Region, stats: &mut GranularityStats) {
    if region.shape != Shape::Chain || region.ends.len() < 3 {
        return;
    }
    let last = region.ends.len() - 1;
    let mut operators = Vec::with_capacity(last - 1);
    for index in 1..last {
        let span = work.cover(region.operands[0], region.operands[index]);
        let Some(operator) = work.push_node(NodeKind::Cond, span) else {
            return;
        };
        for out in work.take_out(region.ends[index]) {
            work.add_edge(operator, out.dst, out.kind, out.is_back);
        }
        work.add_edge(region.ends[index], operator, EdgeKind::Fall, false);
        operators.push(operator);
        stats.inserted = stats.inserted.saturating_add(1);
    }
    // `c0` and every operator but the last now short-circuit to the operator
    // one level out rather than to the terminal.
    work.retarget(region.ends[0], region.terminal, operators[0]);
    for pair in operators.windows(2) {
        work.retarget(pair[0], region.terminal, pair[1]);
    }
}

/// Phase 3: delete the node of every operand that materializes nothing.
///
/// A bypass, not a contraction: each predecessor inherits each successor, so an
/// elided *left* operand hands its fork to whatever preceded the region (bash
/// `load_history`) and an elided *right* operand collapses the fork to a single
/// edge, because both of its predecessor's edges then name the operator node
/// and [`Work::add_edge`] keeps one (bash `evalstring`).
fn elide(tree: &Tree, work: &mut Work, region: &Region, stats: &mut GranularityStats) {
    for (operand, end) in region.operands.iter().zip(region.ends.iter()) {
        if materializes(tree, *operand) {
            continue;
        }
        if work.bypass(*end) {
            stats.elided = stats.elided.saturating_add(1);
        }
    }
}

/// Whether `node` costs Joern at least one CFG node.
///
/// Everything does except a bare identifier and a bare literal, parentheses
/// being transparent --- `(table)` in bash `hash_size` materializes nothing,
/// and neither does the `0` of its else arm. The loop is bounded by the arena
/// size so `((((x))))` nested to any depth terminates without recursing
/// (`REQ-GEN-4`).
fn materializes(tree: &Tree, node: NodeId) -> bool {
    let mut current = node;
    for _ in 0..=tree.arena().len() {
        match tag_of(tree, current) {
            Some(NodeTag::ParenExpr) if tree.arena().child_count(current) == 1 => {
                match tree.arena().child(current, 0) {
                    Some(inner) => current = inner,
                    None => return true,
                }
            }
            Some(NodeTag::NameRef) | Some(NodeTag::Literal) => return false,
            _ => return true,
        }
    }
    true
}

/// Which short-circuit shape `node` has, if it is one.
///
/// A re-derivation of `crate::csource::cfg::expr::logical_kind`, which is
/// `pub(super)` to that module and so not reachable from here. It reads the
/// operator from the tokens *between the first two children*, because a flat
/// binary node's own main token is not guaranteed to be the operator on a
/// recovered parse.
fn short_circuit_shape(tree: &Tree, node: NodeId, tag: NodeTag) -> Option<Shape> {
    if tag == NodeTag::CondExpr {
        return Some(Shape::Conditional);
    }
    if tag != NodeTag::BinaryExpr {
        return None;
    }
    let arena = tree.arena();
    let (_, left_end) = arena.token_extent(arena.child(node, 0)?)?;
    let (right_start, _) = arena.token_extent(arena.child(node, 1)?)?;
    let tokens = tree.tokens();
    for raw in left_end..right_start {
        match TokenKind::from_u16(tokens.kind(TokenId::new(raw))) {
            Some(TokenKind::AmpAmp) | Some(TokenKind::PipePipe) => return Some(Shape::Chain),
            _ => {}
        }
    }
    None
}

/// The tag of `node`, or `None` when it carries one this front end never wrote.
fn tag_of(tree: &Tree, node: NodeId) -> Option<NodeTag> {
    tree.arena().tag(node).and_then(NodeTag::from_u16)
}

/// `node`'s only successor, or `None` when it has some other number of them.
fn single_successor(cfg: &Cfg, node: NodeId) -> Option<NodeId> {
    let mut successors = cfg.successors(node);
    let first = successors.next()?;
    successors.next().is_none().then_some(first)
}

/// Every CFG node keyed by its span, with `None` where two nodes share one.
///
/// The lookup S2's contract makes possible: an operand's evaluation ends at a
/// node carrying exactly that operand's span. A shared span is recorded as an
/// ambiguity rather than resolved arbitrarily, so a region that would depend on
/// the wrong node is declined instead.
fn span_index(cfg: &Cfg) -> BTreeMap<(u32, u32), Option<NodeId>> {
    let mut index: BTreeMap<(u32, u32), Option<NodeId>> = BTreeMap::new();
    for (position, node) in cfg.nodes().iter().enumerate() {
        let span = node.span();
        index
            .entry((span.lo, span.hi))
            .and_modify(|slot| *slot = None)
            .or_insert(Some(NodeId::new(position as u32)));
    }
    index
}

/// One out-edge of the mutable graph.
#[derive(Debug, Clone, Copy)]
struct Out {
    dst: NodeId,
    kind: EdgeKind,
    is_back: bool,
}

/// The S2 graph in a form the three phases can edit in place.
///
/// Adjacency lists rather than [`Cfg`]'s CSR arrays, because every edit here is
/// a local insertion or removal and CSR would have to be rebuilt for each one.
/// Predecessors are maintained alongside successors so a bypass does not have
/// to scan the graph.
struct Work {
    kinds: Vec<NodeKind>,
    spans: Vec<Vec<Span>>,
    alive: Vec<bool>,
    succ: Vec<Vec<Out>>,
    pred: Vec<Vec<NodeId>>,
    /// The token spans of the tree, for the covering span of an inserted node.
    /// Held as an AST-side span lookup so `nest` does not need the tree.
    operand_spans: BTreeMap<NodeId, Span>,
}

impl Work {
    fn from_cfg(cfg: &Cfg) -> Self {
        let count = cfg.node_count();
        let mut work = Self {
            kinds: cfg.nodes().iter().map(|node| node.kind()).collect(),
            spans: cfg
                .nodes()
                .iter()
                .map(|node| node.spans().to_vec())
                .collect(),
            alive: vec![true; count],
            succ: vec![Vec::new(); count],
            pred: vec![Vec::new(); count],
            operand_spans: BTreeMap::new(),
        };
        for edge in cfg.edges() {
            work.succ[edge.src.index()].push(Out {
                dst: edge.dst,
                kind: edge.kind,
                is_back: edge.is_back,
            });
            work.pred[edge.dst.index()].push(edge.src);
        }
        work
    }

    /// Record an AST node's span so [`Work::cover`] can name an inserted node.
    fn remember(&mut self, node: NodeId, span: Span) {
        self.operand_spans.insert(node, span);
    }

    /// The span an inserted operator node carries: the text of the left-nested
    /// sub-expression it stands for, which is what makes a degree-sequence
    /// mismatch localizable to a construct (`REQ-OUT-4`).
    fn cover(&self, first: NodeId, last: NodeId) -> Span {
        match (
            self.operand_spans.get(&first),
            self.operand_spans.get(&last),
        ) {
            (Some(a), Some(b)) => a.to(*b),
            (Some(a), None) => *a,
            (None, Some(b)) => *b,
            (None, None) => Span::default(),
        }
    }

    fn push_node(&mut self, kind: NodeKind, span: Span) -> Option<NodeId> {
        if self.kinds.len() >= MAX_NODES {
            return None;
        }
        let id = NodeId::new(self.kinds.len() as u32);
        self.kinds.push(kind);
        self.spans.push(vec![span]);
        self.alive.push(true);
        self.succ.push(Vec::new());
        self.pred.push(Vec::new());
        Some(id)
    }

    /// Remove and return every out-edge of `node`.
    fn take_out(&mut self, node: NodeId) -> Vec<Out> {
        let taken = std::mem::take(&mut self.succ[node.index()]);
        for out in &taken {
            self.pred[out.dst.index()].retain(|src| *src != node);
        }
        taken
    }

    /// Add `src -> dst`, keeping the existing edge when there already is one.
    ///
    /// Joern's CFG reaches DecBench as a `networkx.DiGraph`
    /// (`pyjoern.cfg.parse_dot_cfg_string`), which cannot hold a parallel edge,
    /// so a rewrite that created one would report a degree Joern can never
    /// report.
    fn add_edge(&mut self, src: NodeId, dst: NodeId, kind: EdgeKind, is_back: bool) {
        if self.succ[src.index()].iter().any(|out| out.dst == dst) {
            return;
        }
        self.succ[src.index()].push(Out { dst, kind, is_back });
        self.pred[dst.index()].push(src);
    }

    fn remove_edges(&mut self, src: NodeId, dst: NodeId) {
        self.succ[src.index()].retain(|out| out.dst != dst);
        self.pred[dst.index()].retain(|node| *node != src);
    }

    /// Point `src`'s edge to `from` at `to` instead, keeping its kind.
    fn retarget(&mut self, src: NodeId, from: NodeId, to: NodeId) {
        let Some(out) = self.succ[src.index()]
            .iter()
            .find(|out| out.dst == from)
            .copied()
        else {
            return;
        };
        self.remove_edges(src, from);
        self.add_edge(src, to, out.kind, out.is_back);
    }

    /// Delete `node`, giving every predecessor every successor.
    ///
    /// Returns whether anything was deleted, so the caller's census counts real
    /// work. A node with one successor hands its predecessors that successor
    /// under the *predecessor's* edge kind, since the deleted node contributed
    /// no branch; a node with several hands each edge its own kind, which is
    /// what preserves the true/false labelling of a fork that moves outward.
    fn bypass(&mut self, node: NodeId) -> bool {
        if !self.alive[node.index()] {
            return false;
        }
        if matches!(self.kinds[node.index()], NodeKind::Entry | NodeKind::Exit) {
            return false;
        }
        let outs: Vec<Out> = self.succ[node.index()]
            .iter()
            .copied()
            .filter(|out| out.dst != node)
            .collect();
        let single = outs.len() == 1;
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        for src in self.pred[node.index()].clone() {
            if src == node || !seen.insert(src) {
                continue;
            }
            let Some(incoming) = self.succ[src.index()]
                .iter()
                .find(|out| out.dst == node)
                .copied()
            else {
                continue;
            };
            self.remove_edges(src, node);
            for out in &outs {
                let kind = if single { incoming.kind } else { out.kind };
                self.add_edge(src, out.dst, kind, incoming.is_back || out.is_back);
            }
        }
        // Whatever is left --- a self-edge, or an edge from a predecessor the
        // loop above could not account for --- goes with the node.
        self.take_out(node);
        for src in self.pred[node.index()].clone() {
            self.remove_edges(src, node);
        }
        self.alive[node.index()] = false;
        true
    }

    /// Compact to a dense [`Cfg`], dropping the nodes phase 3 deleted.
    ///
    /// Ids are assigned in ascending old-id order and edges are emitted per
    /// source in insertion order, so the same input yields the same graph on
    /// every run and machine (`REQ-OUT-3`).
    fn finish(self, entry: NodeId, exit: NodeId) -> Cfg {
        let mut remap = vec![None; self.kinds.len()];
        let mut nodes = Vec::new();
        for (position, alive) in self.alive.iter().enumerate() {
            if !alive {
                continue;
            }
            remap[position] = Some(NodeId::new(nodes.len() as u32));
            nodes.push(CfgNode::new(
                self.kinds[position],
                self.spans[position].clone(),
            ));
        }
        let mut edges = Vec::new();
        for (position, outs) in self.succ.iter().enumerate() {
            let Some(src) = remap[position] else {
                continue;
            };
            for out in outs {
                let Some(dst) = remap[out.dst.index()] else {
                    continue;
                };
                edges.push(CfgEdge {
                    src,
                    dst,
                    kind: out.kind,
                    is_back: out.is_back,
                });
            }
        }
        let fallback = NodeId::new(0);
        Cfg::from_parts(
            nodes,
            edges,
            remap[entry.index()].unwrap_or(fallback),
            remap[exit.index()].unwrap_or(fallback),
        )
    }
}

/// Fill in the operand spans [`Work::cover`] needs, before phase 2 runs.
///
/// Separate from [`collect`] so that `Region` stays a description of the AST
/// and the graph rather than a bag of derived spans.
fn remember_operand_spans(work: &mut Work, tree: &Tree, token_spans: &[Span], regions: &[Region]) {
    for region in regions {
        for &operand in &region.operands {
            if let Some(span) = tree.arena().span(operand, token_spans) {
                work.remember(operand, span);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::cfg::function_cfgs;
    use crate::csource::parse::parse;

    /// The S2 graph, the F-9 graph and the census, for one function.
    fn rewrite(text: &str, name: &str) -> (Cfg, Cfg, GranularityStats) {
        let tree = parse(text);
        let tree = tree.value();
        let spans = tree.token_spans(text);
        let definition = tree
            .functions(text)
            .into_iter()
            .find(|def| def.name == name)
            .expect("the function is in the file");
        let functions = function_cfgs(tree, text);
        let function = functions
            .value()
            .iter()
            .find(|f| f.name == name)
            .expect("the function has a graph")
            .clone();
        let body = definition.body.expect("the body parsed");
        let (after, stats) = expression_granular(tree, &spans, body, &function.cfg);
        (function.cfg, after, stats)
    }

    /// Joern's own graph, as far as F-9 can be compared today.
    ///
    /// Two things stand between this module's output and a published node
    /// count, and both belong to `super::flags`, not here: F-11 lets the
    /// `METHOD` node take part in chain contraction, and F-12 deletes the
    /// `METHOD_RETURN` node. This adapter applies exactly those two rules to a
    /// coalesced graph so an F-9 fixture can be checked against a number that
    /// was measured, and it is a *test oracle* --- shipping it would be F-11
    /// and F-12 implemented twice. It is not [`super::flags::parity_blocks`]
    /// because that takes a chain partition in which the anchors take part, and
    /// [`Cfg::chain_partition`] deliberately excludes them
    /// ([`NodeKind::is_anchor`]); until the parity layer exports such a
    /// partition there is nothing here to call.
    ///
    /// Dropping the exit node and its in-edges covers both of Joern's regimes
    /// at once: when Joern kept a coalesced `METHOD_RETURN` it is part of a
    /// block that survives here anyway, and when Joern deleted a singleton one
    /// it deleted its in-edges with it (`joern-behavior.md` section 1.4).
    fn projected(cfg: &Cfg) -> (usize, usize, Vec<(u32, u32)>) {
        let blocks = cfg.coalesced();
        let exit = blocks.exit();
        let entry = blocks.entry();
        let mut dropped: BTreeSet<NodeId> = BTreeSet::new();
        if blocks.node_count() > 1 {
            dropped.insert(exit);
        }
        // F-11: the entry merges into its successor under the same rule every
        // other chain follows, and stays its own block when it cannot.
        if blocks.out_degree(entry) == 1 {
            if let Some(next) = blocks.successors(entry).next() {
                if next != exit && blocks.in_degree(next) == 1 && !dropped.contains(&next) {
                    dropped.insert(entry);
                }
            }
        }
        let live: Vec<NodeId> = (0..blocks.node_count() as u32)
            .map(NodeId::new)
            .filter(|id| !dropped.contains(id))
            .collect();
        let edges: Vec<(NodeId, NodeId)> = blocks
            .edges()
            .iter()
            .filter(|edge| !dropped.contains(&edge.src) && !dropped.contains(&edge.dst))
            .map(|edge| (edge.src, edge.dst))
            .collect();
        let mut degrees: Vec<(u32, u32)> = live
            .iter()
            .map(|id| {
                let incoming = edges.iter().filter(|(_, dst)| dst == id).count() as u32;
                let outgoing = edges.iter().filter(|(src, _)| src == id).count() as u32;
                (incoming, outgoing)
            })
            .collect();
        degrees.sort_unstable();
        (live.len(), edges.len(), degrees)
    }

    /// The `(in, out)` multiset of a published CFG, from its edge list.
    fn published(nodes: usize, edges: &[(u32, u32)]) -> (usize, usize, Vec<(u32, u32)>) {
        let mut degrees: Vec<(u32, u32)> = (0..nodes as u32)
            .map(|id| {
                (
                    edges.iter().filter(|(_, dst)| *dst == id).count() as u32,
                    edges.iter().filter(|(src, _)| *src == id).count() as u32,
                )
            })
            .collect();
        degrees.sort_unstable();
        (nodes, edges.len(), degrees)
    }

    /// bash `strmatch`, `O0/bash/source_cfgs/bash.json`: 5 nodes, 8 edges? no
    /// --- 5 nodes and 5 edges, entry `[4]`, exit `[]`. Both operands of the
    /// `||` are `==` comparisons, so both materialize and Joern's shape is
    /// exactly `REQ-CFG-6`'s: S2 already agrees and F-9 must not move it.
    #[test]
    fn a_condition_whose_operands_both_materialize_is_already_right() {
        let text = "int strmatch(char *pattern, char *string, int flags)\n\
                    {\n\
                      if (string == 0 || pattern == 0)\n\
                        return 1;\n\
                      return (xstrmatch (pattern, string, flags));\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "strmatch");
        assert_eq!(stats.operators, 1, "one `||`");
        assert_eq!(stats.rewritten, 1, "its region was modelled");
        assert_eq!(stats.inserted, 0, "two operands need no inner operator");
        assert_eq!(stats.elided, 0, "`x == 0` materializes");
        assert_eq!(projected(&before), projected(&after));
        assert_eq!(
            projected(&after),
            published(5, &[(0, 1), (0, 3), (2, 0), (4, 0), (4, 2)]),
            "bash strmatch, published as 5 nodes / 5 edges"
        );
    }

    /// bash `evalstring` block 5 holds `rcatch&&return_catch_flag && ` together
    /// with the statement before it, has in-degree 1 and out-degree 2, and no
    /// block anywhere in that function holds either operand. Two bare
    /// identifiers cost one node, not three.
    #[test]
    fn two_bare_identifier_operands_cost_one_node() {
        let text = "int f(void)\n\
                    {\n\
                      g ();\n\
                      if (rcatch && return_catch_flag)\n\
                        h ();\n\
                      return r;\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "f");
        assert_eq!(stats.elided, 2, "both operands materialize nothing");
        let (before_nodes, ..) = projected(&before);
        let (after_nodes, after_edges, _) = projected(&after);
        assert_eq!(
            before_nodes - after_nodes,
            2,
            "S2 spent a fork and an operand node Joern does not"
        );
        // g(); + the `&&` operator, forking to h(); and to `return r;`, which
        // carries the coalesced function end.
        assert_eq!((after_nodes, after_edges), (3, 3));
    }

    /// bash `load_history`, `hf && *hf && file_exists(hf)`: blocks
    /// `5 -> {1, 0}`, `1 -> 0`, `0 -> {3, 2}`, `3 -> 2`. `hf` has no node, so
    /// the fork it would have carried comes out of the statement before the
    /// condition --- and the chain still costs two operator nodes.
    #[test]
    fn an_elided_left_operand_hands_its_fork_to_the_predecessor() {
        let text = "void f(char *hf)\n\
                    {\n\
                      hf = get_string_value (\"HISTFILE\");\n\
                      if (hf && *hf && file_exists (hf))\n\
                        read_history (hf);\n\
                    }\n";
        let (_, after, stats) = rewrite(text, "f");
        assert_eq!(stats.inserted, 1, "a three-operand chain nests once");
        assert_eq!(stats.elided, 1, "`hf` alone materializes nothing");
        assert_eq!(
            projected(&after),
            published(6, &[(0, 2), (0, 3), (1, 0), (2, 4), (3, 2), (5, 0), (5, 1)]),
            "bash load_history, published as 6 nodes / 7 edges"
        );
    }

    /// bash `rl_vi_arg_digit`, published as 7 nodes and 8 edges with entry
    /// `[6]` and no exit: `c=='0' && rl_numeric_arg==1 && !rl_explicit_arg`
    /// materializes *two* `&&` nodes, the inner one (block 1) with in-degree 2
    /// and out-degree 2. Our flat S2 expansion produces one join for the whole
    /// chain, so this is the case F-9's chain nesting exists for.
    #[test]
    fn a_three_operand_chain_materializes_two_operator_nodes() {
        let text = "int rl_vi_arg_digit(int count, int c)\n\
                    {\n\
                      if (c == '0' && rl_numeric_arg == 1 && !rl_explicit_arg)\n\
                        return (rl_beg_of_line (1, c));\n\
                      else\n\
                        return (rl_digit_argument (count, c));\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "rl_vi_arg_digit");
        assert_eq!(stats.inserted, 1, "three operands, two operators");
        assert_eq!(stats.elided, 0, "every operand is a comparison or a `!`");
        assert_ne!(
            projected(&before),
            projected(&after),
            "the flat S2 expansion is not Joern's shape"
        );
        assert_eq!(
            projected(&after),
            published(
                7,
                &[
                    (0, 4),
                    (0, 5),
                    (1, 0),
                    (1, 2),
                    (2, 0),
                    (3, 1),
                    (6, 1),
                    (6, 3)
                ]
            ),
            "bash rl_vi_arg_digit, published as 7 nodes / 8 edges"
        );
    }

    /// bash `strlist_sort`, published as 7 nodes and 8 edges: the same nesting
    /// for `||`, with a field access on two of the three operands.
    #[test]
    fn the_chain_nesting_is_the_same_for_a_logical_or() {
        let text = "void strlist_sort(STRINGLIST *sl)\n\
                    {\n\
                      if (sl == 0 || sl->list_len == 0 || sl->list == 0)\n\
                        return;\n\
                      strvec_sort (sl->list, 0);\n\
                    }\n";
        let (_, after, stats) = rewrite(text, "strlist_sort");
        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.elided, 0);
        assert_eq!(
            projected(&after),
            published(
                7,
                &[
                    (0, 1),
                    (0, 4),
                    (2, 0),
                    (2, 5),
                    (3, 2),
                    (3, 6),
                    (5, 0),
                    (6, 2)
                ]
            ),
            "bash strlist_sort, published as 7 nodes / 8 edges"
        );
    }

    /// bash `hash_size`, published as 3 nodes and 3 edges with entry `[0]` and
    /// exit `[1]`: `(table)` is a parenthesized identifier and `0` a literal,
    /// so `FUNCTION_START` itself forks and the else arm reaches the `?:` node
    /// with no node of its own.
    #[test]
    fn a_conditional_with_a_bare_condition_forks_at_its_predecessor() {
        let text = "int hash_size(HASH_TABLE *table)\n\
                    {\n\
                      return (((table)?(table)->nentries:0));\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "hash_size");
        assert_eq!(stats.operators, 1, "one `?:`");
        assert_eq!(stats.elided, 2, "the condition and the else arm");
        assert_ne!(projected(&before), projected(&after));
        assert_eq!(
            projected(&after),
            published(3, &[(0, 1), (0, 2), (2, 1)]),
            "bash hash_size, published as 3 nodes / 3 edges"
        );
    }

    /// bash `builtin_address`, published as 4 nodes and 4 edges with entry
    /// `[2]` and exit `[1]`: a bare condition again, but both arms materialize,
    /// so the fork lands on the assignment that precedes the `return`.
    #[test]
    fn a_conditional_keeps_both_arms_when_both_materialize() {
        let text = "sh_builtin_func_t *builtin_address(char *name)\n\
                    {\n\
                      struct builtin *current_builtin;\n\
                      current_builtin = builtin_address_internal (name, 0);\n\
                      return (current_builtin ? current_builtin->function\n\
                                              : (sh_builtin_func_t *)((void *)0));\n\
                    }\n";
        let (_, after, stats) = rewrite(text, "builtin_address");
        assert_eq!(stats.elided, 1, "only the condition is a bare identifier");
        assert_eq!(
            projected(&after),
            published(4, &[(0, 1), (2, 0), (2, 3), (3, 1)]),
            "bash builtin_address, published as 4 nodes / 4 edges"
        );
    }

    /// base-passwd `xmalloc`, `O0/base-passwd/source_cfgs/update-passwd.json`,
    /// published as 6 nodes and 8 edges: the `joern-behavior.md` section 4
    /// canonical `&&`, both operands `== 0` comparisons. The rewrite must leave
    /// it alone, which is what says F-9 did not "fix" a shape that was right.
    #[test]
    fn the_documented_canonical_and_shape_survives_untouched() {
        // The published edge list is what fixes the nesting: block 0, the
        // `&&`, reaches the `return` directly on its false edge, so the second
        // `if` can only be inside the first.
        let text = "void *xmalloc(size_t n)\n\
                    {\n\
                      void *p = malloc (n);\n\
                      if (p == 0 && n == 0)\n\
                        {\n\
                          p = malloc ((size_t)1);\n\
                          if (p == 0)\n\
                            {\n\
                              fputs (\"out of memory\", stderr);\n\
                              exit (1);\n\
                            }\n\
                        }\n\
                      return p;\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "xmalloc");
        assert_eq!(stats.rewritten, 1);
        assert_eq!((stats.inserted, stats.elided), (0, 0));
        assert_eq!(projected(&before), projected(&after));
        assert_eq!(
            projected(&after),
            published(
                6,
                &[
                    (0, 2),
                    (0, 5),
                    (1, 0),
                    (3, 2),
                    (4, 0),
                    (4, 1),
                    (5, 2),
                    (5, 3)
                ]
            ),
            "base-passwd xmalloc, published as 6 nodes / 8 edges"
        );
    }

    /// bash `find_variable_no_invisible`, published as 9 nodes and 12 edges
    /// with entry `[8]` and exit `[4]`. Three things at once: the inner `||`
    /// collapses to one block (both operands bare), the outer `&&` keeps its
    /// fork (both operands materialize), and the second condition `v && ...`
    /// hands its fork to the assignment before it (block 5 -> {0, 7}).
    #[test]
    fn a_nested_operator_is_rewritten_independently_of_its_parent() {
        let text = "SHELL_VAR *find_variable_no_invisible(char *name)\n\
                    {\n\
                      SHELL_VAR *v;\n\
                      int flags;\n\
                      last_table_searched = 0;\n\
                      flags = 0x02;\n\
                      if (expanding_redir == 0 && (assigning_in_environment || executing_builtin))\n\
                        flags |= 0x01;\n\
                      v = find_variable_internal (name, flags);\n\
                      if (v && ((((v)->attributes) & (0x0000800))))\n\
                        v = find_variable_nameref (v);\n\
                      return v;\n\
                    }\n";
        let (before, after, stats) = rewrite(text, "find_variable_no_invisible");
        assert_eq!(stats.operators, 3, "two `&&` and one `||`");
        assert_eq!(stats.rewritten, 3);
        assert_eq!(stats.inserted, 0, "no chain is longer than two operands");
        assert_eq!(
            stats.elided, 3,
            "both operands of the `||`, and the `v` of the second `&&`"
        );
        assert_ne!(projected(&before), projected(&after));
        assert_eq!(
            projected(&after),
            published(
                9,
                &[
                    (0, 4),
                    (0, 6),
                    (1, 2),
                    (1, 5),
                    (2, 5),
                    (3, 1),
                    (5, 0),
                    (5, 7),
                    (6, 4),
                    (7, 0),
                    (8, 1),
                    (8, 3)
                ]
            ),
            "bash find_variable_no_invisible, published as 9 nodes / 12 edges"
        );
    }

    /// `sizeof` evaluates neither operand, so S2 emits no fork inside it and
    /// there is no region for this rewrite to find. The check that matters is
    /// that it declines rather than matching the wrong node by span.
    #[test]
    fn an_unevaluated_operand_is_left_alone() {
        let text = "unsigned f(int a, int b) { return sizeof (a && b); }";
        let (before, after, stats) = rewrite(text, "f");
        assert_eq!(stats.operators, 1, "the `&&` is in the tree");
        assert_eq!(stats.rewritten, 0, "but S2 gave it no region");
        assert_eq!(stats.skipped, 1);
        assert_eq!(projected(&before), projected(&after));
    }

    /// `REQ-OUT-3`. The rewrite reads no hash-ordered container and assigns ids
    /// in old-id order, so two runs over one input agree byte for byte.
    #[test]
    fn the_rewrite_is_deterministic() {
        let text = "int f(int a, int b, int c) { if (a() && b && c()) g(); return 0; }";
        let (_, first, stats_first) = rewrite(text, "f");
        let (_, second, stats_second) = rewrite(text, "f");
        assert_eq!(first, second);
        assert_eq!(stats_first, stats_second);
    }

    /// `REQ-GEN-4` / `REQ-ROB-3`. Ten thousand nested operators are the
    /// adversarial case for a walker that recurses; nothing here does, so this
    /// terminates with a graph rather than a stack overflow.
    #[test]
    fn deep_nesting_costs_heap_and_not_stack() {
        let depth = 10_000;
        let mut text = String::from("int f(int a) { return ");
        for _ in 0..depth {
            text.push_str("(a && ");
        }
        text.push('a');
        for _ in 0..depth {
            text.push(')');
        }
        text.push_str("; }");
        let (_, after, _) = rewrite(&text, "f");
        assert!(after.node_count() >= 2, "a graph came back");
    }

    /// A function with no short-circuit at all must come back as the very same
    /// graph, not a rebuilt one: the rewrite has to be free where it does not
    /// apply, and `Cfg`'s `PartialEq` is over nodes, edges and both anchors.
    #[test]
    fn a_function_without_a_short_circuit_is_returned_unchanged() {
        let text = "int f(int a) { while (a) { a = a - 1; } return a; }";
        let (before, after, stats) = rewrite(text, "f");
        assert_eq!(stats, GranularityStats::default());
        assert_eq!(before, after);
    }

    /// The whole-file entry point the parity layer wires in lines up with
    /// `function_cfgs` even when the caller kept only some of the functions.
    #[test]
    fn the_file_entry_point_pairs_with_the_function_list() {
        let text = "int a(void){ return p && q; }\n\
                    int b(void){ return 1; }\n\
                    int c(void){ return x ? y : z; }\n";
        let tree = parse(text);
        let tree = tree.value();
        let functions = function_cfgs(tree, text);
        let all = expression_granular_cfgs(tree, text, functions.value());
        assert_eq!(all.len(), 3);
        let kept: Vec<FunctionCfg> = functions
            .value()
            .iter()
            .filter(|f| f.name != "b")
            .cloned()
            .collect();
        let some = expression_granular_cfgs(tree, text, &kept);
        assert_eq!(some.len(), 2);
        assert_eq!(some[0], all[0], "`a` is matched by span, not by index");
        assert_eq!(some[1], all[2], "and so is `c`");
    }
}
