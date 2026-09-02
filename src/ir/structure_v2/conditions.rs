//! Canonical reaching-condition DAG for the shadow structurer.

use std::collections::HashMap;

use super::Refusal;
use crate::ir::structure::Cfg;

/// Stable index into a [`ConditionDag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConditionId(pub usize);

/// One interned Boolean condition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConditionNode {
    False,
    True,
    Branch { block: usize },
    Not(ConditionId),
    And(Vec<ConditionId>),
    Or(Vec<ConditionId>),
}

/// Conditions under which each CFG block is reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionDag {
    pub(super) nodes: Vec<ConditionNode>,
    pub(super) reaching: Vec<ConditionId>,
}

impl ConditionDag {
    pub(super) fn from_cfg(cfg: &Cfg) -> Result<Self, Refusal> {
        let order = topological_order(&cfg.succs).ok_or(Refusal::CyclicGraph)?;
        let mut builder = Builder::new();
        let mut reaching = vec![builder.false_id; cfg.succs.len()];
        if !reaching.is_empty() {
            reaching[0] = builder.true_id;
        }

        for block in order {
            let source_condition = reaching[block];
            for &successor in &cfg.succs[block] {
                let edge_condition = match cfg.cond_taken[block] {
                    Some(taken) if cfg.succs[block].len() == 2 => {
                        let branch = builder.intern(ConditionNode::Branch { block });
                        if successor == taken {
                            branch
                        } else {
                            builder.not(branch)
                        }
                    }
                    _ => builder.true_id,
                };
                let path = builder.and([source_condition, edge_condition]);
                reaching[successor] = builder.or([reaching[successor], path]);
            }
        }

        Ok(Self {
            nodes: builder.nodes,
            reaching,
        })
    }

    /// Number of unique Boolean nodes after interning.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Per-block reaching condition in block-index order.
    pub fn reaching_conditions(&self) -> &[ConditionId] {
        &self.reaching
    }
}

struct Builder {
    nodes: Vec<ConditionNode>,
    by_node: HashMap<ConditionNode, ConditionId>,
    false_id: ConditionId,
    true_id: ConditionId,
}

impl Builder {
    fn new() -> Self {
        let nodes = vec![ConditionNode::False, ConditionNode::True];
        let by_node = nodes
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, node)| (node, ConditionId(index)))
            .collect();
        Self {
            nodes,
            by_node,
            false_id: ConditionId(0),
            true_id: ConditionId(1),
        }
    }

    fn intern(&mut self, node: ConditionNode) -> ConditionId {
        if let Some(id) = self.by_node.get(&node) {
            return *id;
        }
        let id = ConditionId(self.nodes.len());
        self.nodes.push(node.clone());
        self.by_node.insert(node, id);
        id
    }

    fn not(&mut self, id: ConditionId) -> ConditionId {
        if id == self.false_id {
            return self.true_id;
        }
        if id == self.true_id {
            return self.false_id;
        }
        if let ConditionNode::Not(inner) = self.nodes[id.0] {
            return inner;
        }
        self.intern(ConditionNode::Not(id))
    }

    fn and(&mut self, ids: impl IntoIterator<Item = ConditionId>) -> ConditionId {
        let mut terms = Vec::new();
        for id in ids {
            if id == self.false_id {
                return self.false_id;
            }
            if id == self.true_id {
                continue;
            }
            match &self.nodes[id.0] {
                ConditionNode::And(nested) => terms.extend(nested.iter().copied()),
                _ => terms.push(id),
            }
        }
        terms.sort_unstable();
        terms.dedup();
        match terms.as_slice() {
            [] => self.true_id,
            [only] => *only,
            _ => self.intern(ConditionNode::And(terms)),
        }
    }

    fn or(&mut self, ids: impl IntoIterator<Item = ConditionId>) -> ConditionId {
        let mut terms = Vec::new();
        for id in ids {
            if id == self.true_id {
                return self.true_id;
            }
            if id == self.false_id {
                continue;
            }
            match &self.nodes[id.0] {
                ConditionNode::Or(nested) => terms.extend(nested.iter().copied()),
                _ => terms.push(id),
            }
        }
        terms.sort_unstable();
        terms.dedup();
        match terms.as_slice() {
            [] => self.false_id,
            [only] => *only,
            _ => self.intern(ConditionNode::Or(terms)),
        }
    }
}

fn topological_order(successors: &[Vec<usize>]) -> Option<Vec<usize>> {
    let mut indegree = vec![0usize; successors.len()];
    for targets in successors {
        for &target in targets {
            indegree[target] += 1;
        }
    }
    let mut ready: std::collections::BTreeSet<usize> = indegree
        .iter()
        .enumerate()
        .filter_map(|(block, &degree)| (degree == 0).then_some(block))
        .collect();
    let mut order = Vec::with_capacity(successors.len());
    while let Some(block) = ready.pop_first() {
        order.push(block);
        for &target in &successors[block] {
            indegree[target] -= 1;
            if indegree[target] == 0 {
                ready.insert(target);
            }
        }
    }
    (order.len() == successors.len()).then_some(order)
}
