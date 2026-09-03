//! Maximal-chain contraction: [`Cfg::chain_partition`], [`Cfg::coalesced`] and
//! [`ChainPartition`].
//!
//! The raw graph [`super::build::CfgBuilder`] produces is statement-granular,
//! because `REQ-SYN-7` wants every construct's span in it; this module builds
//! the basic-block view a reader wants, in one `O(V + E)` sweep over chain
//! heads rather than contracting to a fixpoint. It is kept apart from the
//! builder and from [`super::validate`] because it is the one part of this
//! component the parity layer in `docs/design/static-c-analysis/` reuses over
//! a differently-shaped graph, through [`ChainPartition`] rather than through
//! [`Cfg::coalesced`] itself.

use super::{Cfg, CfgEdge, CfgNode, NodeId, NodeKind};

impl Cfg {
    /// Partition the nodes into maximal contractible chains, in `O(V + E)`.
    ///
    /// A chain is a run of nodes joined by edges the rule contracts:
    /// `outdeg(src) == 1`, `indeg(dst) == 1`, `src != dst`, and neither end an
    /// anchor ([`NodeKind::is_anchor`]). Because `outdeg(src) == 1` gives each
    /// node at most one contractible edge out and `indeg(dst) == 1` gives it at
    /// most one in, those edges form a functional graph: disjoint simple paths
    /// and disjoint cycles, nothing else. So the chains can be read off in one
    /// sweep --- start at every node with no contractible edge *in*, follow the
    /// unique contractible edge out until there is none --- instead of
    /// contracting to a fixpoint, which re-scans every edge on every round and
    /// costs `O(V * E)`.
    ///
    /// The partition depends only on that per-edge predicate, so it is the same
    /// whatever order the graph was assembled in; only the rotation of a pure
    /// cycle depends on ids, and that is broken deterministically at the
    /// cycle's lowest id. A pure contractible cycle is unreachable from the
    /// entry by construction (every node in it already has its one predecessor
    /// inside the cycle), so it only ever arises from dead code such as
    /// `a: goto b; b: goto a;`.
    pub fn chain_partition(&self) -> ChainPartition {
        let count = self.nodes.len();
        let mut next = vec![None; count];
        let mut has_predecessor_in_chain = vec![false; count];
        for index in 0..count {
            let id = NodeId::new(index as u32);
            let out = self.successor_edges(id);
            if out.len() != 1 {
                continue;
            }
            let dst = out[0].dst;
            if dst == id || self.in_degree(dst) != 1 {
                continue;
            }
            let src_kind = self.nodes[index].kind();
            let dst_kind = self.nodes[dst.index()].kind();
            if src_kind.is_anchor() || dst_kind.is_anchor() {
                continue;
            }
            next[index] = Some(dst);
            has_predecessor_in_chain[dst.index()] = true;
        }

        let mut of_node = vec![u32::MAX; count];
        let mut chains: Vec<Vec<NodeId>> = Vec::new();
        for index in 0..count {
            if !has_predecessor_in_chain[index] && of_node[index] == u32::MAX {
                walk_chain(index, &next, &mut of_node, &mut chains);
            }
        }
        // Anything still unassigned is a pure contractible cycle; break it at
        // its lowest id so the result stays deterministic.
        for index in 0..count {
            if of_node[index] == u32::MAX {
                walk_chain(index, &next, &mut of_node, &mut chains);
            }
        }
        ChainPartition { chains, of_node }
    }

    /// The graph with every maximal chain contracted to a single node.
    ///
    /// The raw graph this module builds is statement-granular, because
    /// `REQ-SYN-7` wants every construct's span in it; this is the basic-block
    /// view a reader wants. A contracted node takes the kind of the chain's
    /// last member --- the member whose successors it inherits --- and carries
    /// every member's spans in order.
    pub fn coalesced(&self) -> Cfg {
        let partition = self.chain_partition();
        let mut nodes = Vec::with_capacity(partition.chains.len());
        for chain in &partition.chains {
            let kind = chain
                .last()
                .and_then(|id| self.nodes.get(id.index()))
                .map(|n| n.kind())
                .unwrap_or(NodeKind::Stmt);
            let mut spans = Vec::new();
            for id in chain {
                if let Some(node) = self.nodes.get(id.index()) {
                    spans.extend_from_slice(node.spans());
                }
            }
            nodes.push(CfgNode::new(kind, spans));
        }
        let mut edges = Vec::new();
        for edge in &self.edges {
            let src_chain = partition.of_node[edge.src.index()];
            let dst_chain = partition.of_node[edge.dst.index()];
            if partition.is_internal(edge.src, edge.dst) {
                continue;
            }
            edges.push(CfgEdge {
                src: NodeId::new(src_chain),
                dst: NodeId::new(dst_chain),
                kind: edge.kind,
                is_back: edge.is_back,
            });
        }
        let targets = self
            .continue_targets
            .iter()
            .map(|id| NodeId::new(partition.of_node[id.index()]))
            .collect();
        // `chain_of` rather than indexing: an empty graph has no chain for the
        // placeholder entry and exit ids, and this must not panic (`REQ-SYN-2`).
        let anchor = |id: NodeId| NodeId::new(partition.chain_of(id).unwrap_or(0));
        Cfg::assemble(nodes, edges, anchor(self.entry), anchor(self.exit), targets)
    }
}

/// Walk one chain from `start`, appending it to `chains` and recording every
/// member in `of_node`.
///
/// Stops at the first node already assigned to a chain, which is what turns a
/// contractible cycle into a single chain rather than an endless walk.
fn walk_chain(
    start: usize,
    next: &[Option<NodeId>],
    of_node: &mut [u32],
    chains: &mut Vec<Vec<NodeId>>,
) {
    let chain_index = chains.len() as u32;
    let mut members = Vec::new();
    let mut cursor = Some(NodeId::new(start as u32));
    while let Some(node) = cursor {
        match of_node.get(node.index()) {
            Some(&assigned) if assigned == u32::MAX => {}
            _ => break,
        }
        of_node[node.index()] = chain_index;
        members.push(node);
        cursor = next.get(node.index()).copied().flatten();
    }
    chains.push(members);
}

/// A partition of a [`Cfg`]'s nodes into maximal contractible chains.
///
/// Handed out separately from [`Cfg::coalesced`] because the parity layer wants
/// the same partition over a differently-shaped graph and should not have to
/// reimplement the sweep that produces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPartition {
    chains: Vec<Vec<NodeId>>,
    of_node: Vec<u32>,
}

impl ChainPartition {
    /// The chains, each in the order control passes through it. Chain `i` is
    /// node `i` of the graph [`Cfg::coalesced`] returns.
    pub fn chains(&self) -> &[Vec<NodeId>] {
        &self.chains
    }

    /// Which chain a node belongs to, or `None` for an unknown id.
    pub fn chain_of(&self, id: NodeId) -> Option<u32> {
        self.of_node.get(id.index()).copied()
    }

    /// Whether the edge `src -> dst` is one this partition contracted away,
    /// meaning both ends are in one chain and `dst` immediately follows `src`
    /// in it. A self-edge on a contracted cycle is *not* internal by this test,
    /// which is why coalescing keeps it.
    pub fn is_internal(&self, src: NodeId, dst: NodeId) -> bool {
        let Some(chain) = self.chain_of(src) else {
            return false;
        };
        if self.chain_of(dst) != Some(chain) {
            return false;
        }
        let Some(members) = self.chains.get(chain as usize) else {
            return false;
        };
        members
            .windows(2)
            .any(|pair| pair[0] == src && pair[1] == dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::cfg::{CfgBuilder, EdgeKind, Flow};
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
    fn chain_coalescing_is_independent_of_the_order_the_graph_was_built_in() {
        // The same abstract graph, assembled under two different node
        // numberings and two different edge orders. Both must partition the
        // same set of spans the same way.
        let spans: Vec<Span> = (0..6).map(|i| s(100 + i)).collect();
        let shape = [(0usize, 1usize), (1, 2), (2, 3), (3, 4), (2, 5), (5, 4)];
        let partitions: Vec<Vec<Vec<u32>>> = [
            (vec![0usize, 1, 2, 3, 4, 5], false),
            (vec![5usize, 4, 3, 2, 1, 0], true),
            (vec![3usize, 0, 5, 2, 4, 1], false),
        ]
        .iter()
        .map(|(permutation, reverse_edges)| {
            // `slot[i]` is the node id the abstract node `i` is stored at.
            let mut slot = vec![0usize; 6];
            for (position, &abstract_node) in permutation.iter().enumerate() {
                slot[abstract_node] = position;
            }
            let nodes: Vec<CfgNode> = permutation
                .iter()
                .map(|&abstract_node| {
                    let kind = match abstract_node {
                        0 => NodeKind::Entry,
                        4 => NodeKind::Exit,
                        _ => NodeKind::Stmt,
                    };
                    CfgNode::single(kind, spans[abstract_node])
                })
                .collect();
            let mut edges: Vec<CfgEdge> = shape
                .iter()
                .map(|&(from, to)| {
                    CfgEdge::new(
                        NodeId::new(slot[from] as u32),
                        NodeId::new(slot[to] as u32),
                        EdgeKind::Fall,
                    )
                })
                .collect();
            if *reverse_edges {
                edges.reverse();
            }
            let cfg = Cfg::from_parts(
                nodes,
                edges,
                NodeId::new(slot[0] as u32),
                NodeId::new(slot[4] as u32),
            );
            let mut groups: Vec<Vec<u32>> = cfg
                .chain_partition()
                .chains()
                .iter()
                .map(|chain| {
                    let mut lows: Vec<u32> = chain
                        .iter()
                        .filter_map(|id| cfg.node(*id).map(|n| n.span().lo))
                        .collect();
                    lows.sort_unstable();
                    lows
                })
                .collect();
            groups.sort();
            groups
        })
        .collect();
        assert_eq!(partitions[0], partitions[1]);
        assert_eq!(partitions[1], partitions[2]);
        // The shape is a diamond: 0 -> 1 -> 2 branches to 3 and 5, both of
        // which reach 4. So {1, 2} is one chain and nothing else merges.
        assert_eq!(
            partitions[0],
            vec![vec![100], vec![101, 102], vec![103], vec![104], vec![105],]
        );
    }

    #[test]
    fn chain_coalescing_never_contracts_a_self_edge() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Stmt, s(10)),
            CfgNode::single(NodeKind::Exit, s(20)),
        ];
        let edges = vec![
            CfgEdge::new(NodeId::new(0), NodeId::new(1), EdgeKind::Fall),
            CfgEdge::back(NodeId::new(1), NodeId::new(1), EdgeKind::Fall),
        ];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(2));
        let partition = cfg.chain_partition();
        assert_eq!(partition.chains().len(), 3);
    }

    #[test]
    fn chain_coalescing_leaves_the_entry_and_the_function_end_alone() {
        let (cfg, _) = build(vec![Flow::Stmt(s(10))]);
        let block = cfg.coalesced();
        assert_eq!(block.node_count(), 3);
        assert_eq!(
            block.node(block.entry()).map(CfgNode::kind),
            Some(NodeKind::Entry)
        );
        assert_eq!(
            block.node(block.exit()).map(CfgNode::kind),
            Some(NodeKind::Exit)
        );
    }

    #[test]
    fn chain_coalescing_contracts_a_pure_cycle_into_one_node_with_a_self_edge() {
        // Dead code only: `a: goto b; b: goto a;` unreachable from the entry.
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
            CfgNode::single(NodeKind::Goto, s(10)),
            CfgNode::single(NodeKind::Goto, s(20)),
        ];
        let edges = vec![
            CfgEdge::new(NodeId::new(0), NodeId::new(1), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(2), NodeId::new(3), EdgeKind::Jump),
            CfgEdge::new(NodeId::new(3), NodeId::new(2), EdgeKind::Jump),
        ];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        let block = cfg.coalesced();
        assert_eq!(block.node_count(), 3);
        let cycle = NodeId::new(block.node_count() as u32 - 1);
        assert_eq!(block.node(cycle).map(|n| n.spans().len()), Some(2));
        assert_eq!(block.successors(cycle).next(), Some(cycle));
    }

}
