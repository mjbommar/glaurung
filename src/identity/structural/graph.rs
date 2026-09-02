//! The block-and-edge shape a structural signature is computed over.
//!
//! [`CfgShape`] is a dense, index-addressed control-flow graph: block `i` is a
//! `u64` start address at position `i`, and an edge is a `(usize, usize)` pair
//! of block indices. Everything downstream -- the MD-index, the back-edge
//! count, the strongly-connected-component count -- reads only this, which is
//! what lets a unit test hand-build a shape whose invariants it computed on
//! paper.
//!
//! # Determinism
//!
//! A shape is canonicalised on construction: blocks are sorted by start
//! address, edges are deduplicated and sorted by `(from, to)`. Two runs over
//! the same function therefore produce byte-identical edge order, which the
//! MD-index needs -- it sorts its per-edge terms before summing, but the *set*
//! of terms still has to be the same set.

use std::collections::{BTreeMap, BTreeSet};

/// A canonical, index-addressed control-flow graph over one function.
///
/// Construct with [`CfgShape::new`], which sorts and deduplicates. The entry
/// block is identified by address, not by position, because discovery does not
/// promise that the entry has the lowest address -- a hot/cold split does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgShape {
    /// Block start addresses, ascending and unique.
    blocks: Vec<u64>,
    /// Edges as `(from_index, to_index)`, ascending and unique.
    edges: Vec<(usize, usize)>,
    /// Index of the entry block, or `None` when the entry address named no block.
    entry: Option<usize>,
    in_degree: Vec<u32>,
    out_degree: Vec<u32>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
}

impl CfgShape {
    /// Build a canonical shape from block start addresses and address-pair edges.
    ///
    /// Addresses that name no block are dropped from the edge list rather than
    /// silently inventing a node: discovery can emit an edge to a block whose
    /// walk was cut by a budget, and counting that target as a node would make
    /// the block count disagree with the block list.
    pub fn new(block_starts: &[u64], edges: &[(u64, u64)], entry_va: u64) -> Self {
        let mut blocks: Vec<u64> = block_starts.to_vec();
        blocks.sort_unstable();
        blocks.dedup();
        let index: BTreeMap<u64, usize> = blocks.iter().enumerate().map(|(i, a)| (*a, i)).collect();

        let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
        for (from, to) in edges {
            if let (Some(f), Some(t)) = (index.get(from), index.get(to)) {
                pairs.insert((*f, *t));
            }
        }
        let edges: Vec<(usize, usize)> = pairs.into_iter().collect();

        let n = blocks.len();
        let mut in_degree = vec![0u32; n];
        let mut out_degree = vec![0u32; n];
        let mut successors: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (f, t) in &edges {
            out_degree[*f] += 1;
            in_degree[*t] += 1;
            successors[*f].push(*t);
            predecessors[*t].push(*f);
        }
        let entry = index.get(&entry_va).copied();
        Self {
            blocks,
            edges,
            entry,
            in_degree,
            out_degree,
            successors,
            predecessors,
        }
    }

    /// Number of basic blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of distinct control-flow edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Every edge, as `(from_index, to_index)`, ascending.
    pub fn edges(&self) -> &[(usize, usize)] {
        &self.edges
    }

    /// In-degree of block `i`.
    pub fn in_degree(&self, i: usize) -> u32 {
        self.in_degree[i]
    }

    /// Out-degree of block `i`.
    pub fn out_degree(&self, i: usize) -> u32 {
        self.out_degree[i]
    }

    /// Index of the entry block, when the entry address named one.
    pub fn entry(&self) -> Option<usize> {
        self.entry
    }

    /// Start address of block `i`.
    pub fn block_address(&self, i: usize) -> u64 {
        self.blocks[i]
    }

    /// Successors of block `i`, ascending.
    pub fn successors(&self, i: usize) -> &[usize] {
        &self.successors[i]
    }

    /// Predecessors of block `i`, ascending.
    pub fn predecessors(&self, i: usize) -> &[usize] {
        &self.predecessors[i]
    }

    /// McCabe cyclomatic complexity, `E - N + 2`.
    ///
    /// Clamped to at least 1 rather than wrapped: a block set with no edges at
    /// all gives `0 - N + 2`, which is negative for `N > 2` and is not a
    /// complexity.
    pub fn cyclomatic_complexity(&self) -> u32 {
        let e = self.edges.len() as i64;
        let n = self.blocks.len() as i64;
        (e - n + 2).clamp(1, u32::MAX as i64) as u32
    }

    /// BFS levels for the MD-index, BinDiff's `bfs_top_down_`.
    ///
    /// Replicates `BreadthFirstSearch` in `google/bindiff`'s `graph_util.h`:
    /// every vertex starts at 0, every vertex with in-degree 0 is a root and
    /// keeps level 0, and a vertex first reached from level `l` gets `l + 1`. A
    /// root can never be re-labelled because a vertex of in-degree 0 is the
    /// target of no edge. Vertices in a cycle that no root reaches keep 0,
    /// exactly as BinDiff leaves them.
    ///
    /// One documented deviation: when no vertex has in-degree 0 -- a function
    /// whose entry block is also a loop header -- BinDiff's queue starts empty
    /// and every level stays 0, collapsing the top-down MD-index onto the
    /// relaxed one. We seed the entry block in that case, so "top-down" means
    /// "from the entry" as the identity ladder describes it.
    pub fn levels_top_down(&self) -> Vec<u32> {
        let mut roots: Vec<usize> = (0..self.blocks.len())
            .filter(|i| self.in_degree[*i] == 0)
            .collect();
        if roots.is_empty() {
            if let Some(e) = self.entry {
                roots.push(e);
            }
        }
        self.bfs(&roots, &self.successors)
    }

    /// BFS levels for the inverted MD-index, BinDiff's `bfs_bottom_up_`.
    ///
    /// The same walk over reversed edges, rooted at every vertex with
    /// out-degree 0. When a function has no such vertex -- an unterminated
    /// infinite loop -- there are no roots and every level stays 0, which is
    /// BinDiff's behaviour and is left alone: there is no principled "the exit"
    /// to substitute the way there is a principled entry.
    pub fn levels_bottom_up(&self) -> Vec<u32> {
        let roots: Vec<usize> = (0..self.blocks.len())
            .filter(|i| self.out_degree[*i] == 0)
            .collect();
        self.bfs(&roots, &self.predecessors)
    }

    fn bfs(&self, roots: &[usize], next: &[Vec<usize>]) -> Vec<u32> {
        let mut level = vec![0u32; self.blocks.len()];
        let mut seen = vec![false; self.blocks.len()];
        let mut queue: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
        for r in roots {
            if !seen[*r] {
                seen[*r] = true;
                queue.push_back(*r);
            }
        }
        while let Some(v) = queue.pop_front() {
            for w in &next[v] {
                if !seen[*w] {
                    seen[*w] = true;
                    level[*w] = level[v] + 1;
                    queue.push_back(*w);
                }
            }
        }
        level
    }

    /// Immediate dominators, by block index, over the entry-reachable subgraph.
    ///
    /// Cooper, Harvey and Kennedy's iterative algorithm ("A Simple, Fast
    /// Dominance Algorithm", 2001) over reverse postorder. Entry-unreachable
    /// blocks -- discovery emits them when a jump table was not resolved --
    /// have no dominator and come back as `None`.
    pub fn immediate_dominators(&self) -> Vec<Option<usize>> {
        let n = self.blocks.len();
        let mut idom: Vec<Option<usize>> = vec![None; n];
        let entry = match self.entry {
            Some(e) => e,
            None => return idom,
        };

        let order = self.reverse_postorder(entry);
        let mut rpo_number = vec![usize::MAX; n];
        for (pos, v) in order.iter().enumerate() {
            rpo_number[*v] = pos;
        }

        idom[entry] = Some(entry);
        let mut changed = true;
        while changed {
            changed = false;
            for &v in order.iter().skip(1) {
                let mut new_idom: Option<usize> = None;
                for p in &self.predecessors[v] {
                    if idom[*p].is_none() {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => *p,
                        Some(cur) => intersect(&idom, &rpo_number, *p, cur),
                    });
                }
                if new_idom.is_some() && idom[v] != new_idom {
                    idom[v] = new_idom;
                    changed = true;
                }
            }
        }
        idom
    }

    /// Reverse postorder of the entry-reachable subgraph, successors ascending.
    fn reverse_postorder(&self, entry: usize) -> Vec<usize> {
        let n = self.blocks.len();
        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut visited = vec![false; n];
        let mut stack: Vec<(usize, usize)> = vec![(entry, 0)];
        visited[entry] = true;
        while let Some((v, k)) = stack.pop() {
            let succ = &self.successors[v];
            if k < succ.len() {
                stack.push((v, k + 1));
                let w = succ[k];
                if !visited[w] {
                    visited[w] = true;
                    stack.push((w, 0));
                }
            } else {
                order.push(v);
            }
        }
        order.reverse();
        order
    }

    /// Back edges: an edge `(u, v)` where `v` dominates `u`.
    ///
    /// This is the textbook definition, and it is the one that makes the count
    /// a *loop* count rather than a *cycle* count: an irreducible cycle (two
    /// entries into one loop body) has no back edge and is not counted here. It
    /// does show up in [`Self::strongly_connected_components`], which is one
    /// reason a signature carries both.
    pub fn back_edges(&self) -> Vec<(usize, usize)> {
        let idom = self.immediate_dominators();
        self.edges
            .iter()
            .copied()
            .filter(|(u, v)| dominates(&idom, *v, *u))
            .collect()
    }

    /// Distinct natural-loop headers: the `v` of each back edge `(u, v)`.
    pub fn loop_headers(&self) -> usize {
        let mut headers: BTreeSet<usize> = BTreeSet::new();
        for (_, v) in self.back_edges() {
            headers.insert(v);
        }
        headers.len()
    }

    /// Number of strongly connected components, trivial ones included.
    ///
    /// Tarjan's algorithm, iterative so a 50,000-block function cannot blow the
    /// stack. Every block belongs to exactly one component, so an acyclic
    /// function of `n` blocks has `n` components; the discriminative quantity
    /// is `blocks - components`, which counts the blocks absorbed into cycles.
    pub fn strongly_connected_components(&self) -> usize {
        let n = self.blocks.len();
        let mut index = vec![usize::MAX; n];
        let mut lowlink = vec![0usize; n];
        let mut on_stack = vec![false; n];
        let mut stack: Vec<usize> = Vec::new();
        let mut next_index = 0usize;
        let mut components = 0usize;
        // (vertex, successor cursor)
        let mut work: Vec<(usize, usize)> = Vec::new();

        for root in 0..n {
            if index[root] != usize::MAX {
                continue;
            }
            work.push((root, 0));
            while let Some((v, k)) = work.pop() {
                if k == 0 {
                    index[v] = next_index;
                    lowlink[v] = next_index;
                    next_index += 1;
                    stack.push(v);
                    on_stack[v] = true;
                }
                let mut descended = false;
                for (ki, &w) in self.successors[v].iter().enumerate().skip(k) {
                    if index[w] == usize::MAX {
                        work.push((v, ki + 1));
                        work.push((w, 0));
                        descended = true;
                        break;
                    } else if on_stack[w] {
                        lowlink[v] = lowlink[v].min(index[w]);
                    }
                }
                if descended {
                    continue;
                }
                if lowlink[v] == index[v] {
                    components += 1;
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        if w == v {
                            break;
                        }
                    }
                }
                if let Some((parent, _)) = work.last().copied() {
                    lowlink[parent] = lowlink[parent].min(lowlink[v]);
                }
            }
        }
        components
    }
}

/// Cooper-Harvey-Kennedy's `intersect`: walk both fingers up the dominator
/// tree until they meet, ordering by reverse-postorder number.
fn intersect(idom: &[Option<usize>], rpo_number: &[usize], mut a: usize, mut b: usize) -> usize {
    while a != b {
        while rpo_number[a] > rpo_number[b] {
            match idom[a] {
                Some(next) if next != a => a = next,
                _ => return b,
            }
        }
        while rpo_number[b] > rpo_number[a] {
            match idom[b] {
                Some(next) if next != b => b = next,
                _ => return a,
            }
        }
    }
    a
}

/// Does `d` dominate `v`? Walks `v` up the dominator tree looking for `d`.
fn dominates(idom: &[Option<usize>], d: usize, v: usize) -> bool {
    let mut cur = v;
    loop {
        if cur == d {
            return true;
        }
        match idom[cur] {
            Some(next) if next != cur => cur = next,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `0x10 -> 0x20 -> 0x30`, plus `0x10 -> 0x30`.
    fn triangle() -> CfgShape {
        CfgShape::new(
            &[0x10, 0x20, 0x30],
            &[(0x10, 0x20), (0x20, 0x30), (0x10, 0x30)],
            0x10,
        )
    }

    /// `0x10 -> 0x20 -> 0x30 -> 0x20`, `0x20 -> 0x40`. One natural loop.
    fn simple_loop() -> CfgShape {
        CfgShape::new(
            &[0x10, 0x20, 0x30, 0x40],
            &[(0x10, 0x20), (0x20, 0x30), (0x30, 0x20), (0x20, 0x40)],
            0x10,
        )
    }

    #[test]
    fn canonicalises_blocks_and_edges() {
        let a = CfgShape::new(
            &[0x30, 0x10, 0x20],
            &[(0x10, 0x30), (0x10, 0x20), (0x10, 0x20)],
            0x10,
        );
        assert_eq!(a.block_count(), 3);
        assert_eq!(a.edge_count(), 2);
        assert_eq!(a.edges(), &[(0, 1), (0, 2)]);
        assert_eq!(a.entry(), Some(0));
    }

    #[test]
    fn drops_edges_to_unknown_blocks() {
        let a = CfgShape::new(&[0x10, 0x20], &[(0x10, 0x20), (0x20, 0x99)], 0x10);
        assert_eq!(a.edge_count(), 1);
        assert_eq!(a.block_count(), 2);
    }

    #[test]
    fn degrees_and_complexity() {
        let g = triangle();
        assert_eq!(g.out_degree(0), 2);
        assert_eq!(g.in_degree(2), 2);
        // E - N + 2 = 3 - 3 + 2 = 2
        assert_eq!(g.cyclomatic_complexity(), 2);
    }

    #[test]
    fn top_down_levels_are_bfs_from_the_entry() {
        // 0x10 is the only in-degree-0 vertex, so it is the only root and keeps
        // level 0; 0x20 and 0x30 are both one hop away.
        let g = triangle();
        assert_eq!(g.levels_top_down(), vec![0, 1, 1]);
    }

    #[test]
    fn bottom_up_levels_are_bfs_from_the_exits() {
        // 0x30 is the only out-degree-0 vertex. 0x20 and 0x10 are one hop back,
        // because 0x10 -> 0x30 is a direct edge.
        let g = triangle();
        assert_eq!(g.levels_bottom_up(), vec![1, 1, 0]);
    }

    #[test]
    fn entry_seeds_top_down_when_every_block_has_a_predecessor() {
        // The entry is its own loop header, so no vertex has in-degree 0.
        let g = CfgShape::new(&[0x10, 0x20], &[(0x10, 0x20), (0x20, 0x10)], 0x10);
        assert_eq!(g.levels_top_down(), vec![0, 1]);
        // Bottom-up has no root at all and stays flat, as BinDiff leaves it.
        assert_eq!(g.levels_bottom_up(), vec![0, 0]);
    }

    #[test]
    fn back_edge_is_the_edge_whose_target_dominates_it() {
        let g = simple_loop();
        // Blocks sort to [0x10=0, 0x20=1, 0x30=2, 0x40=3]; the back edge is
        // 0x30 -> 0x20, i.e. (2, 1), because 0x20 dominates 0x30.
        assert_eq!(g.back_edges(), vec![(2, 1)]);
        assert_eq!(g.loop_headers(), 1);
    }

    #[test]
    fn acyclic_graph_has_no_back_edges() {
        assert!(triangle().back_edges().is_empty());
        assert_eq!(triangle().loop_headers(), 0);
    }

    #[test]
    fn scc_count_absorbs_the_loop_body() {
        // 4 blocks, one 2-block cycle {0x20, 0x30} => 3 components.
        assert_eq!(simple_loop().strongly_connected_components(), 3);
        // Acyclic: every block is its own component.
        assert_eq!(triangle().strongly_connected_components(), 3);
    }

    #[test]
    fn nested_loops_report_two_headers() {
        // 0 -> 1 -> 2 -> 3 -> 2 (inner), 3 -> 1 (outer), 1 -> 4 (exit)
        let g = CfgShape::new(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let mut be = g.back_edges();
        be.sort_unstable();
        assert_eq!(be, vec![(3, 1), (3, 2)]);
        assert_eq!(g.loop_headers(), 2);
        // {1,2,3} collapse into one component; 0 and 4 stay singletons.
        assert_eq!(g.strongly_connected_components(), 3);
    }

    #[test]
    fn self_loop_is_a_back_edge() {
        let g = CfgShape::new(&[0, 1], &[(0, 1), (1, 1)], 0);
        assert_eq!(g.back_edges(), vec![(1, 1)]);
        assert_eq!(g.strongly_connected_components(), 2);
    }

    #[test]
    fn irreducible_cycle_has_no_back_edge_but_one_component() {
        // 0 -> 1, 0 -> 2, 1 <-> 2: neither 1 nor 2 dominates the other.
        let g = CfgShape::new(&[0, 1, 2], &[(0, 1), (0, 2), (1, 2), (2, 1)], 0);
        assert!(g.back_edges().is_empty());
        assert_eq!(g.strongly_connected_components(), 2);
    }

    #[test]
    fn unreachable_block_has_no_dominator() {
        let g = CfgShape::new(&[0, 1, 2], &[(0, 1), (2, 1)], 0);
        let idom = g.immediate_dominators();
        assert_eq!(idom[2], None);
    }
}
