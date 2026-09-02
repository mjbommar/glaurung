//! A local dominator computation over an arbitrary successor relation.
//!
//! The CFR needs dominators twice -- once forward, to mark back edges, and once
//! over the reversed graph, to derive control dependence -- and it needs them
//! without depending on `structure_v2`'s dominator module. That module is owned
//! by the decompiler's structuring stage, whose representation is free to
//! change with the recovery algorithm; a stored signature that moves when the
//! *renderer* changes is not an identity. So this is a deliberate second
//! implementation, twenty lines of Cooper-Harvey-Kennedy over a plain adjacency
//! list, with no other consumer.
//!
//! Reference: Cooper, Harvey and Kennedy, "A Simple, Fast Dominance Algorithm"
//! (Rice TR-06-33870), the standard iterative formulation.

/// Immediate dominators of a rooted directed graph.
#[derive(Debug, Clone, Default)]
pub struct Dominators {
    /// Immediate dominator of each node. `None` for the entry and for any node
    /// unreachable from it.
    idom: Vec<Option<usize>>,
    /// Reverse post-order position of each node, or `usize::MAX` if unreachable.
    order: Vec<usize>,
}

impl Dominators {
    /// Compute immediate dominators of the graph rooted at `entry`.
    ///
    /// `successors[n]` lists the successors of node `n`. Successor indices out
    /// of range are ignored rather than panicking: this runs over recovered
    /// CFGs, where an edge may point at a block that was attributed elsewhere.
    pub fn compute(entry: usize, successors: &[Vec<usize>]) -> Self {
        let count = successors.len();
        if count == 0 || entry >= count {
            return Dominators::default();
        }
        let rpo = reverse_post_order(entry, successors);
        let mut order = vec![usize::MAX; count];
        for (position, node) in rpo.iter().enumerate() {
            order[*node] = position;
        }
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (node, edges) in successors.iter().enumerate() {
            for target in edges {
                if *target < count {
                    predecessors[*target].push(node);
                }
            }
        }

        let mut idom: Vec<Option<usize>> = vec![None; count];
        idom[entry] = Some(entry);
        let mut changed = true;
        while changed {
            changed = false;
            for node in rpo.iter().copied() {
                if node == entry {
                    continue;
                }
                let mut new_idom: Option<usize> = None;
                for predecessor in &predecessors[node] {
                    if idom[*predecessor].is_none() {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => *predecessor,
                        Some(current) => intersect(current, *predecessor, &idom, &order),
                    });
                }
                if new_idom.is_some() && idom[node] != new_idom {
                    idom[node] = new_idom;
                    changed = true;
                }
            }
        }
        // The entry dominates itself, but reporting that as an immediate
        // dominator makes every caller special-case it.
        idom[entry] = None;
        Dominators { idom, order }
    }

    /// Immediate dominator of `node`, if it has one.
    pub fn idom(&self, node: usize) -> Option<usize> {
        self.idom.get(node).copied().flatten()
    }

    /// Whether `node` was reached from the entry.
    pub fn is_reachable(&self, node: usize) -> bool {
        self.order
            .get(node)
            .is_some_and(|order| *order != usize::MAX)
    }

    /// Whether `dominator` dominates `node` (reflexively).
    pub fn dominates(&self, dominator: usize, node: usize) -> bool {
        if dominator == node {
            return self.is_reachable(node);
        }
        let mut walk = self.idom(node);
        while let Some(current) = walk {
            if current == dominator {
                return true;
            }
            walk = self.idom(current);
        }
        false
    }
}

fn intersect(mut a: usize, mut b: usize, idom: &[Option<usize>], order: &[usize]) -> usize {
    // Guarded rather than `while a != b`: an unreachable predecessor would walk
    // off the end of the dominator tree and spin.
    let mut guard = order.len().saturating_mul(2) + 4;
    while a != b && guard > 0 {
        guard -= 1;
        while order[a] > order[b] {
            match idom[a] {
                Some(next) if next != a => a = next,
                _ => return b,
            }
        }
        while order[b] > order[a] {
            match idom[b] {
                Some(next) if next != b => b = next,
                _ => return a,
            }
        }
    }
    a
}

/// Reverse post-order of the nodes reachable from `entry`.
fn reverse_post_order(entry: usize, successors: &[Vec<usize>]) -> Vec<usize> {
    let count = successors.len();
    let mut visited = vec![false; count];
    let mut post_order: Vec<usize> = Vec::with_capacity(count);
    // Explicit stack: recursion depth would be the block count, and a
    // 50,000-instruction function is not a hypothesis here.
    let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
    visited[entry] = true;
    while let Some((node, index)) = stack.pop() {
        if index < successors[node].len() {
            stack.push((node, index + 1));
            let target = successors[node][index];
            if target < count && !visited[target] {
                visited[target] = true;
                stack.push((target, 0));
            }
        } else {
            post_order.push(node);
        }
    }
    post_order.reverse();
    post_order
}

#[cfg(test)]
mod tests {
    use super::*;

    /// entry -> {a, b} -> c, the diamond every structuring test starts with.
    #[test]
    fn a_diamond_has_the_expected_dominator_tree() {
        let successors = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let dominators = Dominators::compute(0, &successors);
        assert_eq!(dominators.idom(0), None);
        assert_eq!(dominators.idom(1), Some(0));
        assert_eq!(dominators.idom(2), Some(0));
        assert_eq!(dominators.idom(3), Some(0));
        assert!(dominators.dominates(0, 3));
        assert!(!dominators.dominates(1, 3));
    }

    #[test]
    fn a_loop_header_dominates_its_body_and_the_latch_is_a_back_edge() {
        // 0 -> 1 -> 2 -> 1, 1 -> 3
        let successors = vec![vec![1], vec![2, 3], vec![1], vec![]];
        let dominators = Dominators::compute(0, &successors);
        assert!(dominators.dominates(1, 2));
        // The latch edge 2 -> 1 targets a block that dominates its source.
        assert!(dominators.dominates(1, 2));
    }

    #[test]
    fn an_unreachable_block_has_no_dominator_and_dominates_nothing() {
        let successors = vec![vec![1], vec![], vec![1]];
        let dominators = Dominators::compute(0, &successors);
        assert!(!dominators.is_reachable(2));
        assert_eq!(dominators.idom(2), None);
        assert!(!dominators.dominates(2, 1));
    }

    #[test]
    fn an_empty_graph_is_handled_without_panicking() {
        let dominators = Dominators::compute(0, &[]);
        assert_eq!(dominators.idom(0), None);
        assert!(!dominators.is_reachable(0));
    }
}
