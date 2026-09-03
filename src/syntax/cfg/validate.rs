//! The `REQ-GEN-1` structural invariants, and the reachability walks they are
//! built from.
//!
//! Kept apart from graph construction ([`super`]) and the builder
//! ([`super::build`]) because this is the module's one *checker*: a graph a
//! foreign layer assembled through [`Cfg::from_parts`] --- rather than through
//! [`super::build::CfgBuilder`] --- is validated by the same code a
//! builder-produced graph is, and [`Cfg::validate`] is what a non-empty result
//! from either one means: a builder bug, or someone else's malformed input.
//!
//! [`Cfg::reachable`], [`Cfg::co_reachable`] and [`Cfg::cycle_closing_edges`]
//! live here rather than on the graph type itself because [`Cfg::validate`] is
//! their only caller in this crate; a consumer that wants the walks alone
//! still reaches them as `cfg.reachable()`, since a method's home file is not
//! part of its public path.

use crate::syntax::diag::{Diagnostic, Diagnostics};
use crate::syntax::ids::{NodeId, Span};

use super::{Cfg, CfgNode, EdgeKind, NodeKind};

impl Cfg {
    /// Which nodes are reachable from the entry, indexed by node id.
    ///
    /// Depth-first with an explicit stack, never native recursion
    /// (`REQ-SYN-3`): a function nested thousands of constructs deep must not
    /// abort the process, because a process that aborts cannot report the
    /// per-function failure this substrate exists to report.
    pub fn reachable(&self) -> Vec<bool> {
        let mut seen = vec![false; self.nodes.len()];
        if self.nodes.is_empty() {
            return seen;
        }
        let mut stack = vec![self.entry];
        seen[self.entry.index()] = true;
        while let Some(node) = stack.pop() {
            for edge in self.successor_edges(node) {
                if !seen[edge.dst.index()] {
                    seen[edge.dst.index()] = true;
                    stack.push(edge.dst);
                }
            }
        }
        seen
    }

    /// Which nodes can reach the function end or a diverging construct.
    ///
    /// The backwards half of the previous walk, over the predecessor lists, and
    /// equally iterative.
    pub fn co_reachable(&self) -> Vec<bool> {
        let mut seen = vec![false; self.nodes.len()];
        let mut stack: Vec<NodeId> = Vec::new();
        for (index, node) in self.nodes.iter().enumerate() {
            let id = NodeId::new(index as u32);
            if node.kind() == NodeKind::Diverge || id == self.exit {
                seen[index] = true;
                stack.push(id);
            }
        }
        while let Some(node) = stack.pop() {
            for &pred in self.predecessors(node) {
                if !seen[pred.index()] {
                    seen[pred.index()] = true;
                    stack.push(pred);
                }
            }
        }
        seen
    }

    /// Which edges close a cycle, indexed the same way as [`Cfg::edges`].
    ///
    /// A depth-first walk from the entry with an explicit stack and three
    /// colours: an edge whose destination is still on the active path is a back
    /// edge in the graph-theoretic sense. Edges in code unreachable from the
    /// entry are never examined and stay `false`, because the unreachability is
    /// itself the finding to report.
    pub fn cycle_closing_edges(&self) -> Vec<bool> {
        let mut closes = vec![false; self.edges.len()];
        if self.nodes.is_empty() {
            return closes;
        }
        const WHITE: u8 = 0;
        const GREY: u8 = 1;
        const BLACK: u8 = 2;
        let mut colour = vec![WHITE; self.nodes.len()];
        // Each frame is a node plus how far through its successor slice the
        // walk has got, which is what replaces the recursive call.
        let mut stack: Vec<(NodeId, u32)> = vec![(self.entry, 0)];
        colour[self.entry.index()] = GREY;
        while let Some(&(node, cursor)) = stack.last() {
            let lo = self.succ_start.get(node.index()).copied().unwrap_or(0);
            let hi = self.succ_start.get(node.index() + 1).copied().unwrap_or(lo);
            let slot = lo.saturating_add(cursor);
            if slot >= hi {
                colour[node.index()] = BLACK;
                stack.pop();
                continue;
            }
            if let Some(frame) = stack.last_mut() {
                frame.1 = cursor.saturating_add(1);
            }
            let Some(edge) = self.edges.get(slot as usize) else {
                continue;
            };
            match colour[edge.dst.index()] {
                GREY => closes[slot as usize] = true,
                WHITE => {
                    colour[edge.dst.index()] = GREY;
                    stack.push((edge.dst, 0));
                }
                _ => {}
            }
        }
        closes
    }

    /// Check the structural invariants of `REQ-GEN-1`, reporting each failure
    /// as a diagnostic rather than as a verdict.
    ///
    /// Five invariants, in the order the requirement states them: every node is
    /// reachable from the entry; every path reaches the function end or a
    /// diverging construct; back edges correspond to loops; `break` and
    /// `continue` target the enclosing construct; a switch fall-through is an
    /// edge. A graph this module built satisfies all five, so a non-empty
    /// result is either a builder bug or --- much more usefully --- a graph
    /// some other layer assembled through [`Cfg::from_parts`].
    pub fn validate(&self) -> Diagnostics {
        let mut diagnostics = Diagnostics::new();
        let reachable = self.reachable();
        for (index, node) in self.nodes.iter().enumerate() {
            if !reachable[index] {
                diagnostics.push(Diagnostic::error(
                    node.span(),
                    format!("CFG node {index} is not reachable from the entry"),
                ));
            }
        }

        let co_reachable = self.co_reachable();
        for (index, node) in self.nodes.iter().enumerate() {
            if reachable[index] && !co_reachable[index] {
                diagnostics.push(Diagnostic::error(
                    node.span(),
                    format!(
                        "CFG node {index} reaches neither the function end nor a diverging construct"
                    ),
                ));
            }
        }

        // A node an arm falls through into must also be dispatched to, which is
        // the property that survives coalescing: a contracted chain takes its
        // tail's kind, so "the destination is a `Case` node" would stop holding
        // the moment an arm label merged with the statement after it.
        let mut dispatched_to = vec![false; self.nodes.len()];
        for edge in &self.edges {
            if matches!(edge.kind, EdgeKind::Case | EdgeKind::Default) {
                dispatched_to[edge.dst.index()] = true;
            }
        }

        let closes = self.cycle_closing_edges();
        for (index, edge) in self.edges.iter().enumerate() {
            let span = self.span_of(edge.src);
            if edge.is_back && !closes[index] {
                diagnostics.push(Diagnostic::error(
                    span,
                    format!(
                        "CFG edge {} -> {} is marked a loop back edge but closes no cycle",
                        edge.src.raw(),
                        edge.dst.raw()
                    ),
                ));
            }
            if closes[index] && !edge.is_back && edge.kind != EdgeKind::Jump {
                diagnostics.push(Diagnostic::error(
                    span,
                    format!(
                        "CFG edge {} -> {} closes a cycle that is neither a loop nor a jump",
                        edge.src.raw(),
                        edge.dst.raw()
                    ),
                ));
            }
            if edge.kind == EdgeKind::FallThrough && !dispatched_to[edge.dst.index()] {
                diagnostics.push(Diagnostic::error(
                    span,
                    format!(
                        "CFG edge {} -> {} falls through to something that is not a switch arm",
                        edge.src.raw(),
                        edge.dst.raw()
                    ),
                ));
            }
        }

        for (index, node) in self.nodes.iter().enumerate() {
            let id = NodeId::new(index as u32);
            match node.kind() {
                NodeKind::Break if self.out_degree(id) == 0 => {
                    diagnostics.push(Diagnostic::error(
                        node.span(),
                        format!("CFG node {index} is a break that leaves no enclosing construct"),
                    ));
                }
                NodeKind::Continue => {
                    let lands_on_a_loop = self
                        .successors(id)
                        .all(|dst| self.continue_targets.binary_search(&dst).is_ok());
                    if self.out_degree(id) == 0 || !lands_on_a_loop {
                        diagnostics.push(Diagnostic::error(
                            node.span(),
                            format!("CFG node {index} is a continue that lands on no loop"),
                        ));
                    }
                }
                NodeKind::Entry if self.in_degree(id) != 0 => {
                    diagnostics.push(Diagnostic::error(
                        node.span(),
                        format!("CFG node {index} is the entry but has a predecessor"),
                    ));
                }
                NodeKind::Exit if self.out_degree(id) != 0 => {
                    diagnostics.push(Diagnostic::error(
                        node.span(),
                        format!("CFG node {index} is the function end but has a successor"),
                    ));
                }
                _ => {}
            }
        }
        diagnostics
    }

    fn span_of(&self, id: NodeId) -> Span {
        self.nodes
            .get(id.index())
            .map(CfgNode::span)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::cfg::CfgEdge;

    fn s(lo: u32) -> Span {
        Span::new(lo, lo + 1)
    }

    #[test]
    fn validate_reports_a_node_unreachable_from_the_entry() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
            CfgNode::single(NodeKind::Stmt, s(10)),
        ];
        let edges = vec![
            CfgEdge::new(NodeId::new(0), NodeId::new(1), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(2), NodeId::new(1), EdgeKind::Fall),
        ];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        let report = cfg.validate();
        assert_eq!(report.error_count(), 1);
        assert!(report
            .iter()
            .any(|d| d.message.contains("not reachable from the entry")));
    }

    #[test]
    fn validate_reports_a_path_reaching_neither_the_end_nor_a_diverging_construct() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
            CfgNode::single(NodeKind::Stmt, s(10)),
        ];
        // The entry runs into a statement with no way on and never reaches the
        // function end.
        let edges = vec![CfgEdge::new(NodeId::new(0), NodeId::new(2), EdgeKind::Fall)];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        let report = cfg.validate();
        assert!(report
            .iter()
            .any(|d| d.message.contains("reaches neither the function end")));
    }

    #[test]
    fn validate_reports_a_back_edge_flag_that_closes_no_cycle() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
        ];
        let edges = vec![CfgEdge::back(
            NodeId::new(0),
            NodeId::new(1),
            EdgeKind::Fall,
        )];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        let report = cfg.validate();
        assert!(report.iter().any(|d| d.message.contains("closes no cycle")));
    }

    #[test]
    fn validate_reports_a_cycle_closed_by_an_edge_that_is_neither_loop_nor_jump() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
            CfgNode::single(NodeKind::Stmt, s(10)),
            CfgNode::single(NodeKind::Stmt, s(20)),
        ];
        let edges = vec![
            CfgEdge::new(NodeId::new(0), NodeId::new(2), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(2), NodeId::new(3), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(3), NodeId::new(2), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(3), NodeId::new(1), EdgeKind::Fall),
        ];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        let report = cfg.validate();
        assert!(report
            .iter()
            .any(|d| d.message.contains("closes a cycle that is neither")));
    }

    #[test]
    fn validate_reports_a_fall_through_edge_that_does_not_reach_a_switch_arm() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
        ];
        let edges = vec![CfgEdge::new(
            NodeId::new(0),
            NodeId::new(1),
            EdgeKind::FallThrough,
        )];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        assert!(cfg
            .validate()
            .iter()
            .any(|d| d.message.contains("not a switch arm")));
    }

    #[test]
    fn validate_reports_a_continue_that_lands_on_no_loop() {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, s(0)),
            CfgNode::single(NodeKind::Exit, s(1)),
            CfgNode::single(NodeKind::Continue, s(10)),
        ];
        let edges = vec![
            CfgEdge::new(NodeId::new(0), NodeId::new(2), EdgeKind::Fall),
            CfgEdge::new(NodeId::new(2), NodeId::new(1), EdgeKind::Jump),
        ];
        let cfg = Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(1));
        assert!(cfg
            .validate()
            .iter()
            .any(|d| d.message.contains("lands on no loop")));
    }
}
