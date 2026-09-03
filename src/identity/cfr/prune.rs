//! Shadow elimination and dead-code removal over a built CFR-G.
//!
//! Two of the mask table's rows are enforced here rather than at construction,
//! because both are properties of the finished graph:
//!
//! * A **shadow** node -- a pure copy, or a phi that merges nothing -- is
//!   register allocation and SSA bookkeeping, not computation. BSim drops the
//!   same class of varnode using the dominator tree; the rule for the trivial
//!   phi is Braun et al.'s.
//! * A **dead** node is one no root depends on. An x86 `cmp` writes six flags
//!   and a `jne` reads one; without this the other five become five features of
//!   a function that does not compute them, and every compiler that schedules
//!   flags differently looks like a different program.

use std::collections::BTreeSet;

use super::graph::{CfrNode, EdgeKind, NodeId};
use super::labels::OpKind;

/// Resolve every shadow node to its replacement, to a fixed point.
pub(crate) fn shadow_forwarding(nodes: &[CfrNode]) -> Vec<NodeId> {
    let mut forward: Vec<NodeId> = (0..nodes.len() as NodeId).collect();
    let resolve = |forward: &[NodeId], mut id: NodeId| -> NodeId {
        let mut guard = forward.len() + 1;
        while forward[id as usize] != id && guard > 0 {
            id = forward[id as usize];
            guard -= 1;
        }
        id
    };
    let mut changed = true;
    let mut rounds = 0usize;
    while changed && rounds < nodes.len() + 2 {
        changed = false;
        rounds += 1;
        for (id, node) in nodes.iter().enumerate() {
            let id = id as NodeId;
            if forward[id as usize] != id {
                continue;
            }
            let replacement = match node.label.op_kind {
                // A pure copy is register allocation, which is masked.
                OpKind::Assign => {
                    let operands: Vec<NodeId> = node
                        .inputs
                        .iter()
                        .filter(|edge| edge.kind == EdgeKind::Operand)
                        .map(|edge| resolve(&forward, edge.target))
                        .collect();
                    (operands.len() == 1 && operands[0] != id).then(|| operands[0])
                }
                // A trivial phi: once self-references are dropped, one distinct
                // incoming value remains, so the merge merges nothing.
                OpKind::Phi => {
                    let distinct: BTreeSet<NodeId> = node
                        .inputs
                        .iter()
                        .filter(|edge| edge.kind == EdgeKind::Operand)
                        .map(|edge| resolve(&forward, edge.target))
                        .filter(|target| *target != id)
                        .collect();
                    (distinct.len() == 1).then(|| *distinct.iter().next().unwrap())
                }
                _ => None,
            };
            if let Some(replacement) = replacement {
                if replacement != id {
                    forward[id as usize] = replacement;
                    changed = true;
                }
            }
        }
    }
    (0..nodes.len() as NodeId)
        .map(|id| resolve(&forward, id))
        .collect()
}

/// Nodes reachable backwards from a root along input edges.
///
/// This is the dead-code mask. Anything a root does not depend on -- the five
/// flags a `cmp` writes that no branch reads, a spilled value never reloaded --
/// contributes no feature.
pub(crate) fn live_nodes(
    nodes: &[CfrNode],
    roots: &BTreeSet<NodeId>,
    forward: &[NodeId],
) -> BTreeSet<NodeId> {
    let mut live: BTreeSet<NodeId> = BTreeSet::new();
    let mut stack: Vec<NodeId> = Vec::new();
    for root in roots {
        let root = forward[*root as usize];
        if live.insert(root) {
            stack.push(root);
        }
    }
    while let Some(id) = stack.pop() {
        for edge in &nodes[id as usize].inputs {
            if live.insert(edge.target) {
                stack.push(edge.target);
            }
        }
    }
    live
}
