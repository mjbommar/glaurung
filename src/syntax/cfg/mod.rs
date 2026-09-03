//! `SB-9` --- the language-blind control-flow graph builder.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 5 and 7.
//!
//! # Why this is its own module
//!
//! Control flow is where the C family agrees with itself. A `while`, a
//! `switch`, a labelled `break` and a `goto` mean the same thing in C, in C++
//! and (bar the `goto`) in Rust, so the machinery that resolves them --- a
//! control-context stack, a label fixup list, chain coalescing --- is written
//! once here and reused unchanged by the second front end. What varies between
//! languages is the *grammar that emits the events*, not the events, so this
//! module consumes [`Flow`] and nothing else: no token, no node tag, no keyword
//! (`REQ-SYN-8`, checked by `python/tests/test_src_dependency_boundaries.py`).
//!
//! # The graph this builds, and the one it deliberately does not
//!
//! This builder produces the graph a person would draw: real successors, real
//! join points, real loop back edges, an entry node and a function-end node
//! that are *nodes*. It does not reproduce the quirks of the external tool
//! Glaurung matches for one similarity metric --- expression-granular nodes, a
//! shared function-end node deleted only when it stayed a singleton, entry and
//! exit expressed as flags derived from degrees. Those are another program's
//! artifacts, and `docs/design/static-c-analysis/architecture.md` section 1
//! records what breaks if they leak downward: the lowering to LLIR inherits a
//! graph shaped by a JVM program's expression granularity, and the general
//! asset becomes good for one metric and nothing else.
//!
//! The parity layer is therefore built *on top* of this one, and the API is
//! shaped to make that cheap: [`Cfg::from_parts`] lets it assemble whatever
//! node set its metric wants, [`Cfg::chain_partition`] hands it the same
//! `O(V+E)` coalescing this module uses, and [`Cfg::in_degree`] /
//! [`Cfg::out_degree`] hand it exactly the degree sequence
//! [`crate::syntax::ged`] scores. Nothing in this file needs to know that layer
//! exists.
//!
//! # The four module rules, as they land here
//!
//! * **No panics** (`REQ-SYN-2`). A `break` outside a loop, an unbalanced
//!   scope, a `goto` to a label that is never defined --- each is a
//!   [`Diagnostic`], and the builder still returns a graph.
//! * **No native recursion** (`REQ-SYN-3`). Construction, reachability, the
//!   cycle scan and coalescing all use explicit stacks, and no type here is
//!   recursive, so `Debug` and `Drop` cannot recurse either.
//! * **Determinism** (`REQ-SYN-5`). Node ids are dense in construction order,
//!   edges are grouped by source with a stable sort that preserves creation
//!   order within a source, and the only map whose iteration reaches output is
//!   a [`BTreeMap`].
//! * **Spans are total** (`REQ-SYN-7`). Every node carries at least one span,
//!   which is why several [`Flow`] variants carry a span the sketch in section
//!   5 of the design doc left implicit.
//!
//! # Why this is a directory, not one file
//!
//! `docs/design/source-front-ends/substrate.md` section 7 records that this
//! component arrived as one 1,534-line file covering four separable concerns:
//! the event vocabulary, the builder's control-context stack and label
//! backpatching, maximal-chain coalescing, and the `REQ-GEN-1` structural
//! invariants. Each is now its own file, one reason to change apiece:
//!
//! * [`flow`] --- the [`Flow`] event vocabulary, [`NodeKind`], [`EdgeKind`],
//!   [`CfgNode`] and [`CfgEdge`]: the data every submodule and every future
//!   front end shares.
//! * `mod.rs` (here) --- the [`Cfg`] graph type itself: construction from
//!   parts, adjacency, and the plain accessors.
//! * [`build`] --- [`CfgBuilder`]: the control-context stack, label
//!   backpatching, and the `Flow` state machine.
//! * [`coalesce`] --- maximal-chain contraction: [`Cfg::chain_partition`],
//!   [`Cfg::coalesced`] and [`ChainPartition`].
//! * [`validate`] --- the `REQ-GEN-1` structural invariants: [`Cfg::validate`]
//!   and the reachability walks it is built from.
//!
//! Splitting the file changes no public path: everything reachable as
//! `syntax::cfg::Foo` before is reachable the same way now, via the `pub use`
//! below. Rust's privacy rules do the rest --- a private field of [`Cfg`],
//! defined in this module, stays visible to every submodule beneath it, so
//! [`build`], [`coalesce`] and [`validate`] read `self.nodes`, `self.edges`
//! and the rest exactly as the single-file version did.

mod build;
mod coalesce;
mod flow;
mod validate;

pub use build::CfgBuilder;
pub use coalesce::ChainPartition;
pub use flow::{CfgEdge, CfgNode, EdgeKind, Flow, LoopKind, NodeKind, MAX_NODES};

use crate::syntax::ids::NodeId;

/// A control-flow graph: nodes in construction order, edges grouped by source.
///
/// Adjacency is stored in compressed-sparse-row form, built once at
/// construction, so successors, predecessors and both degrees are slice
/// arithmetic rather than a search. That is what a later graph-edit-distance
/// consumer needs (it reads nothing but the degree sequence) and what a lowering
/// consumer needs (it walks successors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cfg {
    nodes: Vec<CfgNode>,
    /// Every edge, grouped by `src` ascending, creation order preserved within
    /// a group.
    edges: Vec<CfgEdge>,
    /// `succ_start[i]..succ_start[i + 1]` indexes `edges` for node `i`.
    succ_start: Vec<u32>,
    /// Predecessor node ids, grouped by destination.
    preds: Vec<NodeId>,
    /// `pred_start[i]..pred_start[i + 1]` indexes `preds` for node `i`.
    pred_start: Vec<u32>,
    entry: NodeId,
    exit: NodeId,
    continue_targets: Vec<NodeId>,
}

impl Cfg {
    /// Assemble a graph from an explicit node and edge list.
    ///
    /// This is the seam the parity layer sits on: it builds whatever node set
    /// its metric requires and still gets this module's adjacency, degrees,
    /// coalescing and validation for free. Edges naming a node outside `nodes`
    /// are dropped rather than rejected, and `entry`/`exit` are clamped into
    /// range, so no input to this constructor can panic (`REQ-SYN-2`). On an
    /// empty node list the returned ids are placeholders and [`Cfg::node`]
    /// yields `None` for them.
    pub fn from_parts(
        nodes: Vec<CfgNode>,
        edges: Vec<CfgEdge>,
        entry: NodeId,
        exit: NodeId,
    ) -> Self {
        Self::assemble(nodes, edges, entry, exit, Vec::new())
    }

    fn assemble(
        nodes: Vec<CfgNode>,
        edges: Vec<CfgEdge>,
        entry: NodeId,
        exit: NodeId,
        mut continue_targets: Vec<NodeId>,
    ) -> Self {
        let count = nodes.len();
        let clamp = |id: NodeId| {
            if id.index() < count {
                id
            } else {
                NodeId::new(0)
            }
        };
        let mut edges: Vec<CfgEdge> = edges
            .into_iter()
            .filter(|e| e.src.index() < count && e.dst.index() < count)
            .collect();
        // Stable, so creation order survives within one source: the true arm of
        // a test is emitted before its false arm and stays there (`REQ-SYN-5`).
        edges.sort_by_key(|e| e.src.raw());

        let mut succ_start = vec![0u32; count + 1];
        for e in &edges {
            succ_start[e.src.index() + 1] = succ_start[e.src.index() + 1].saturating_add(1);
        }
        let mut pred_counts = vec![0u32; count + 1];
        for e in &edges {
            pred_counts[e.dst.index() + 1] = pred_counts[e.dst.index() + 1].saturating_add(1);
        }
        for i in 0..count {
            succ_start[i + 1] = succ_start[i + 1].saturating_add(succ_start[i]);
            pred_counts[i + 1] = pred_counts[i + 1].saturating_add(pred_counts[i]);
        }
        let pred_start = pred_counts.clone();
        let mut cursor = pred_counts;
        let mut preds = vec![NodeId::new(0); edges.len()];
        for e in &edges {
            let slot = cursor[e.dst.index()] as usize;
            if let Some(entry_slot) = preds.get_mut(slot) {
                *entry_slot = e.src;
            }
            cursor[e.dst.index()] = cursor[e.dst.index()].saturating_add(1);
        }

        continue_targets.retain(|id| id.index() < count);
        continue_targets.sort_unstable();
        continue_targets.dedup();

        Self {
            nodes,
            edges,
            succ_start,
            preds,
            pred_start,
            entry: clamp(entry),
            exit: clamp(exit),
            continue_targets,
        }
    }

    /// The number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The number of edges, counting parallel edges separately.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// The function entry node.
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    /// The function end node, which `REQ-GEN-1` requires every non-diverging
    /// path to reach.
    pub fn exit(&self) -> NodeId {
        self.exit
    }

    /// The node `id` addresses, or `None` if it addresses no node.
    pub fn node(&self, id: NodeId) -> Option<&CfgNode> {
        self.nodes.get(id.index())
    }

    /// Every node, in construction order --- which is also id order.
    pub fn nodes(&self) -> &[CfgNode] {
        &self.nodes
    }

    /// Every edge, grouped by source and stable within a group.
    pub fn edges(&self) -> &[CfgEdge] {
        &self.edges
    }

    /// The edges leaving `id`, with their kinds. Empty for an unknown id.
    pub fn successor_edges(&self, id: NodeId) -> &[CfgEdge] {
        let Some(&lo) = self.succ_start.get(id.index()) else {
            return &[];
        };
        let Some(&hi) = self.succ_start.get(id.index() + 1) else {
            return &[];
        };
        self.edges.get(lo as usize..hi as usize).unwrap_or(&[])
    }

    /// The nodes control can reach in one step from `id`.
    pub fn successors(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_ {
        self.successor_edges(id).iter().map(|e| e.dst)
    }

    /// The nodes that can reach `id` in one step. Empty for an unknown id.
    pub fn predecessors(&self, id: NodeId) -> &[NodeId] {
        let Some(&lo) = self.pred_start.get(id.index()) else {
            return &[];
        };
        let Some(&hi) = self.pred_start.get(id.index() + 1) else {
            return &[];
        };
        self.preds.get(lo as usize..hi as usize).unwrap_or(&[])
    }

    /// How many edges leave `id`.
    pub fn out_degree(&self, id: NodeId) -> u32 {
        self.successor_edges(id).len() as u32
    }

    /// How many edges arrive at `id`.
    pub fn in_degree(&self, id: NodeId) -> u32 {
        self.predecessors(id).len() as u32
    }

    /// The nodes a `continue` may land on: each loop's test node, or its step
    /// region's head where it has one.
    ///
    /// Recorded because `REQ-GEN-1`'s "`break` and `continue` target the
    /// enclosing construct" is otherwise unverifiable after the fact ---
    /// [`Cfg::validate`] checks every `continue` against this list.
    pub fn continue_targets(&self) -> &[NodeId] {
        &self.continue_targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::diag::Diagnostics;
    use crate::syntax::ids::Span;

    fn s(lo: u32) -> Span {
        Span::new(lo, lo + 1)
    }

    fn build(flows: Vec<Flow>) -> (Cfg, Diagnostics) {
        let mut builder = CfgBuilder::new(Span::new(0, 1000));
        builder.extend(flows);
        builder.finish().into_parts()
    }

    #[test]
    fn from_parts_drops_an_edge_naming_a_node_that_does_not_exist() {
        let nodes = vec![CfgNode::single(NodeKind::Entry, s(0))];
        let edges = vec![CfgEdge::new(NodeId::new(0), NodeId::new(9), EdgeKind::Fall)];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(4));
        assert_eq!(cfg.edge_count(), 0);
        assert_eq!(cfg.exit(), NodeId::new(0), "an out-of-range id is clamped");
    }

    #[test]
    fn an_empty_node_list_yields_an_empty_graph_rather_than_a_panic() {
        let cfg = Cfg::from_parts(Vec::new(), Vec::new(), NodeId::new(3), NodeId::new(4));
        assert_eq!(cfg.node_count(), 0);
        assert!(cfg.node(cfg.entry()).is_none());
        assert!(cfg.reachable().is_empty());
        assert!(cfg.validate().is_empty());
        assert_eq!(cfg.chain_partition().chains().len(), 0);
        assert_eq!(cfg.coalesced().node_count(), 0);
        assert!(cfg.cycle_closing_edges().is_empty());
        assert!(cfg.co_reachable().is_empty());
    }

    #[test]
    fn successors_and_degrees_of_an_unknown_id_are_empty_rather_than_a_panic() {
        let (cfg, _) = build(vec![Flow::Stmt(s(10))]);
        let bogus = NodeId::new(999);
        assert_eq!(cfg.out_degree(bogus), 0);
        assert_eq!(cfg.in_degree(bogus), 0);
        assert!(cfg.successor_edges(bogus).is_empty());
        assert!(cfg.predecessors(bogus).is_empty());
    }

}
