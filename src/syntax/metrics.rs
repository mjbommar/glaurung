//! Language-neutral control-flow metrics over a [`Cfg`].
//!
//! Everything here is a property of a graph: node and edge counts, McCabe's
//! cyclomatic number, reachability, and the back-edge census. None of it knows
//! what a statement is, so it sits beside [`crate::syntax::ged`] rather than in
//! a language module, for the reason `docs/design/static-c-analysis/`
//! `architecture.md` section 1 gives for `ged`: a metric that reads only
//! degrees and adjacency is neither C-specific nor bound to one front end, and
//! it is the piece most likely to be wanted elsewhere.
//!
//! # What "cyclomatic" means here, exactly
//!
//! [`GraphMetrics::cyclomatic`] is `E - N + 2` over the subgraph **reachable
//! from the entry**, which is McCabe's number for a connected single-entry
//! graph (`P = 1`). Restricting to the reachable subgraph is what makes that
//! `P = 1` true: a front end that recovered a fragment, or source with dead
//! code after a `return`, leaves nodes no path reaches, and counting them
//! would report a disconnected graph's number under a formula that assumes one
//! component.
//!
//! The equivalent textbook formula `decisions + 1` is **not** always the same
//! number here, and the difference is information rather than a defect. The two
//! agree when the graph has a single sink; a construct with no successor --- a
//! call to `abort()`, an infinite loop, an unresolved transfer --- adds a sink,
//! and then `E - N + 2` is lower. [`GraphMetrics::decision_points`] is
//! therefore reported raw beside it, so a caller who wants the other
//! convention computes it rather than being handed one of them silently.
//!
//! # Rules inherited from the substrate
//!
//! * **No panics** (`REQ-SYN-2`): every entry point is total on any graph,
//!   including an empty one and one whose edges name nodes that do not exist.
//! * **No native recursion** (`REQ-SYN-3`): the reachability walks this builds
//!   on use explicit stacks, and nothing here recurses either.
//! * **Determinism** (`REQ-SYN-5`): the censuses are [`BTreeMap`]s keyed by an
//!   `Ord` enum, so iteration order is the discriminant order and identical
//!   across runs.

use std::collections::BTreeMap;

use crate::syntax::cfg::{Cfg, EdgeKind, NodeKind};

/// Control-flow metrics for one function's graph.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphMetrics {
    /// Every node, reachable or not.
    pub nodes: u32,
    /// Every edge, including those leaving unreachable nodes.
    pub edges: u32,
    /// Nodes on some path from the entry.
    pub reachable_nodes: u32,
    /// `nodes - reachable_nodes`: dead code, or a fragment the parser
    /// recovered without its predecessor.
    pub unreachable_nodes: u32,
    /// Reachable nodes from which the function end cannot be reached: an
    /// infinite loop, a `noreturn` call, an unresolved transfer.
    pub dead_end_nodes: u32,
    /// McCabe's number over the reachable subgraph: `E - N + 2`, floored at 1.
    pub cyclomatic: u32,
    /// Reachable branch points, as `sum(max(0, out_degree - 1))`. See the
    /// module docs for why this is reported rather than folded into
    /// [`GraphMetrics::cyclomatic`].
    pub decision_points: u32,
    /// Edges the builder marked as returning to an enclosing loop's head.
    pub back_edges: u32,
    /// Distinct destinations of those edges --- one per natural loop.
    pub loops: u32,
    /// How many nodes carry each kind, in discriminant order.
    pub node_kinds: BTreeMap<NodeKind, u32>,
    /// How many edges carry each kind, in discriminant order.
    pub edge_kinds: BTreeMap<EdgeKind, u32>,
}

impl GraphMetrics {
    /// Measure one graph.
    ///
    /// Total on any input (`REQ-SYN-2`), including a graph with no nodes: an
    /// empty graph has no reachable subgraph, so `cyclomatic` is its floor of
    /// 1 rather than the `2` the bare formula would give for `E = N = 0`.
    pub fn of(cfg: &Cfg) -> Self {
        let reachable = cfg.reachable();
        let co_reachable = cfg.co_reachable();

        let mut node_kinds: BTreeMap<NodeKind, u32> = BTreeMap::new();
        let mut reachable_nodes = 0u32;
        let mut dead_end_nodes = 0u32;
        for (index, node) in cfg.nodes().iter().enumerate() {
            *node_kinds.entry(node.kind()).or_insert(0) += 1;
            if reachable.get(index).copied().unwrap_or(false) {
                reachable_nodes += 1;
                if !co_reachable.get(index).copied().unwrap_or(false) {
                    dead_end_nodes += 1;
                }
            }
        }

        // Only edges *inside* the reachable subgraph count toward the
        // cyclomatic number: an edge whose source no path reaches is not on any
        // path either, and including it would inflate `E` against an `N` that
        // excluded its endpoints.
        let live = |id: crate::syntax::ids::NodeId| -> bool {
            reachable.get(id.index()).copied().unwrap_or(false)
        };
        let mut edge_kinds: BTreeMap<EdgeKind, u32> = BTreeMap::new();
        let mut reachable_edges = 0u32;
        let mut back_edges = 0u32;
        let mut loop_heads = std::collections::BTreeSet::new();
        for edge in cfg.edges() {
            *edge_kinds.entry(edge.kind).or_insert(0) += 1;
            if edge.is_back {
                back_edges += 1;
                loop_heads.insert(edge.dst);
            }
            if live(edge.src) && live(edge.dst) {
                reachable_edges += 1;
            }
        }

        let mut decision_points = 0u32;
        for (index, _) in cfg.nodes().iter().enumerate() {
            if !reachable.get(index).copied().unwrap_or(false) {
                continue;
            }
            let id = crate::syntax::ids::NodeId::new(index as u32);
            decision_points += cfg.out_degree(id).saturating_sub(1);
        }

        // `E - N + 2` in signed arithmetic, then floored at 1. A reachable
        // subgraph that is a bare path has `E = N - 1` and scores 1; nothing
        // real scores less, and the floor keeps an empty or malformed graph
        // from reporting 0 or underflowing.
        let cyclomatic = (i64::from(reachable_edges) - i64::from(reachable_nodes) + 2)
            .max(1)
            .min(i64::from(u32::MAX)) as u32;

        Self {
            nodes: cfg.node_count() as u32,
            edges: cfg.edge_count() as u32,
            reachable_nodes,
            unreachable_nodes: (cfg.node_count() as u32).saturating_sub(reachable_nodes),
            dead_end_nodes,
            cyclomatic,
            decision_points,
            back_edges,
            loops: loop_heads.len() as u32,
            node_kinds,
            edge_kinds,
        }
    }
}
