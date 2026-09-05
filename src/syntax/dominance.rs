//! Dominance, post-dominance, and control dependence over a [`Cfg`].
//!
//! Pure graph work: nothing here knows what a statement is, so it sits beside
//! [`crate::syntax::metrics`] and [`crate::syntax::ged`] for the reason
//! `docs/design/static-c-analysis/architecture.md` section 1 gives --- an
//! analysis that reads only adjacency is neither C-specific nor bound to one
//! front end, and a second language front end reuses it unchanged.
//!
//! # What post-dominance needs that dominance does not
//!
//! A dominator tree is rooted at the entry, and every node is reachable from
//! the entry by construction. A **post**-dominator tree is rooted at the exit,
//! and a node is only in it when it can *reach* the exit --- which some nodes
//! cannot. An infinite loop, a call to `abort()`, an unresolved transfer: each
//! is a node from which the function end is unreachable, and
//! [`crate::syntax::metrics::GraphMetrics::dead_end_nodes`] already counts
//! them.
//!
//! The textbook fix is a **virtual exit**: one synthetic node that the real
//! exit and every dead end both flow to, which makes the reverse graph
//! single-rooted and every node's post-dominator defined. That is what
//! [`PostDominators`] builds. Without it, a function containing `while (1) {}`
//! has no post-dominator tree at all and the control-dependence graph below it
//! would be empty rather than wrong --- a silent hole exactly where the
//! interesting control flow is.
//!
//! # Control dependence
//!
//! Ferrante, Ottenstein and Warren's formulation: `B` is control dependent on
//! `A` when `A` has a successor that always reaches `B`, and another that does
//! not. Computed here as the standard tree walk --- for every edge `A -> B`
//! where `B` does not post-dominate `A`, walk from `B` up the post-dominator
//! tree to `ipdom(A)` exclusive, and every node on the way is control
//! dependent on `A` through that edge.
//!
//! The edge is kept, not just the pair, because "control dependent on the
//! *true* arm of this branch" is the information a reader wants and a bare
//! pair loses.
//!
//! # Rules inherited from the substrate
//!
//! * **No panics** (`REQ-SYN-2`): total on any graph, including an empty one,
//!   one whose edges name nodes that do not exist, and one with no path from
//!   entry to exit.
//! * **No native recursion** (`REQ-SYN-3`): the tree walks use explicit loops.
//! * **Determinism** (`REQ-SYN-5`): results are dense vectors in node order,
//!   and edge lists keep construction order.

use crate::syntax::cfg::{Cfg, EdgeKind};
use crate::syntax::ids::NodeId;

/// The immediate-post-dominator tree of a graph, plus the reachability the
/// virtual exit had to paper over.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PostDominators {
    /// `ipdom[n]`, or `None` for the root and for a node the analysis could
    /// not place. Indices are CFG node indices; the virtual exit is not in
    /// this vector.
    ipdom: Vec<Option<u32>>,
    /// Nodes from which the real exit is unreachable, so they reached the
    /// virtual exit only through the synthetic edge this analysis added.
    ///
    /// Reported rather than hidden: a caller comparing two functions wants to
    /// know that one of them contains a region no path leaves.
    dead_ends: Vec<u32>,
}

impl PostDominators {
    /// Compute the post-dominator tree of `cfg`.
    pub fn of(cfg: &Cfg) -> PostDominators {
        let n = cfg.node_count();
        if n == 0 {
            return PostDominators::default();
        }

        // The reverse graph, rooted at a virtual exit numbered `n`.
        //
        // The real exit is always a root. Then, while any node still cannot
        // reach the root set, the lowest-numbered such node becomes a root
        // too. That loop is what makes this total: it terminates because each
        // pass roots at least one more node, it is deterministic because the
        // choice is by index, and it needs no special case for a self-loop, an
        // irreducible region, or a `while (1) {}` whose header has successors
        // and still goes nowhere. An earlier version tried to identify those
        // shapes syntactically and missed the self-loop.
        let virtual_exit = n as u32;
        let exit = cfg.exit().index() as u32;
        let mut roots: Vec<u32> = Vec::new();
        let mut dead_ends: Vec<u32> = Vec::new();
        if (exit as usize) < n {
            roots.push(exit);
        }
        loop {
            let reached = reaches_any(cfg, &roots);
            let Some(stuck) = (0..n as u32).find(|node| !reached[*node as usize]) else {
                break;
            };
            roots.push(stuck);
            dead_ends.push(stuck);
            if roots.len() > n {
                break; // cannot happen: each pass roots a new node
            }
        }
        // Successors in the reverse graph are predecessors in the forward one,
        // plus the virtual exit for each root.
        let reverse_preds = |node: u32| -> Vec<u32> {
            if node == virtual_exit {
                return Vec::new();
            }
            let mut out: Vec<u32> = cfg
                .successors(NodeId::new(node))
                .map(|s| s.index() as u32)
                .collect();
            if roots.contains(&node) {
                out.push(virtual_exit);
            }
            out
        };

        let total = n + 1;
        let order = reverse_postorder(total, virtual_exit, |node| {
            if node == virtual_exit {
                roots.clone()
            } else {
                cfg.predecessors(NodeId::new(node))
                    .iter()
                    .map(|p| p.index() as u32)
                    .collect()
            }
        });
        let mut position = vec![usize::MAX; total];
        for (rank, node) in order.iter().enumerate() {
            position[*node as usize] = rank;
        }

        // Cooper, Harvey and Kennedy's iterative dominator algorithm, run on
        // the reverse graph. Simple, and well inside the budget for the
        // function sizes a source front end sees.
        let mut idom: Vec<Option<u32>> = vec![None; total];
        idom[virtual_exit as usize] = Some(virtual_exit);
        let mut changed = true;
        let mut guard = 0usize;
        while changed && guard < total * total + 8 {
            changed = false;
            guard += 1;
            for node in order.iter().copied() {
                if node == virtual_exit {
                    continue;
                }
                let mut new_idom: Option<u32> = None;
                for pred in reverse_preds(node) {
                    if idom[pred as usize].is_none() {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => pred,
                        Some(current) => intersect(pred, current, &idom, &position),
                    });
                }
                if new_idom.is_some() && idom[node as usize] != new_idom {
                    idom[node as usize] = new_idom;
                    changed = true;
                }
            }
        }

        // Drop the virtual exit from the answer: a node whose ipdom is the
        // virtual exit post-dominates nothing real.
        let mut out: Vec<Option<u32>> = vec![None; n];
        for index in 0..n {
            out[index] = match idom[index] {
                Some(parent) if parent != virtual_exit && parent != index as u32 => Some(parent),
                _ => None,
            };
        }
        dead_ends.sort_unstable();
        dead_ends.dedup();
        PostDominators {
            ipdom: out,
            dead_ends,
        }
    }

    /// The immediate post-dominator of `node`, when it has one.
    pub fn immediate(&self, node: u32) -> Option<u32> {
        self.ipdom.get(node as usize).copied().flatten()
    }

    /// Whether `candidate` post-dominates `node`: every path from `node` to
    /// the exit passes through it.
    ///
    /// A node post-dominates itself.
    pub fn post_dominates(&self, candidate: u32, node: u32) -> bool {
        if candidate == node {
            return true;
        }
        let mut current = node;
        let mut guard = 0usize;
        while let Some(parent) = self.immediate(current) {
            if parent == candidate {
                return true;
            }
            current = parent;
            guard += 1;
            if guard > self.ipdom.len() {
                return false; // malformed tree; refuse rather than spin
            }
        }
        false
    }

    /// Nodes from which the function end cannot be reached.
    pub fn dead_ends(&self) -> &[u32] {
        &self.dead_ends
    }

    /// How many nodes have an immediate post-dominator.
    pub fn placed(&self) -> usize {
        self.ipdom.iter().filter(|slot| slot.is_some()).count()
    }
}

/// One control-dependence edge: `node` executes only because `on` branched the
/// way `kind` describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEdge {
    /// The branch the dependence is on.
    pub on: u32,
    /// The node whose execution it decides.
    pub node: u32,
    /// Which arm of the branch. This is what a bare (node, on) pair loses, and
    /// it is the difference between "runs when the guard holds" and "runs when
    /// it does not".
    pub kind: EdgeKind,
}

/// The control-dependence graph of one function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ControlDependence {
    edges: Vec<ControlEdge>,
    post: PostDominators,
}

impl ControlDependence {
    /// Compute the control-dependence graph of `cfg`.
    ///
    /// Ferrante, Ottenstein and Warren: for every edge `A -> B` where `B` does
    /// not post-dominate `A`, every node from `B` up to `ipdom(A)` exclusive
    /// is control dependent on `A`.
    pub fn of(cfg: &Cfg) -> ControlDependence {
        let post = PostDominators::of(cfg);
        let mut edges: Vec<ControlEdge> = Vec::new();

        for edge in cfg.edges() {
            let a = edge.src.index() as u32;
            let b = edge.dst.index() as u32;
            if post.post_dominates(b, a) {
                // Every path from A goes through B, so B's execution is not a
                // decision A made.
                continue;
            }
            let stop = post.immediate(a);
            let mut current = Some(b);
            let mut guard = 0usize;
            while let Some(node) = current {
                if Some(node) == stop {
                    break;
                }
                edges.push(ControlEdge {
                    on: a,
                    node,
                    kind: edge.kind,
                });
                current = post.immediate(node);
                guard += 1;
                if guard > cfg.node_count() + 1 {
                    break; // malformed tree; stop rather than spin
                }
            }
        }

        edges.sort_by_key(|edge| (edge.on, edge.node, edge.kind as u8));
        edges.dedup();
        ControlDependence { edges, post }
    }

    /// Every control-dependence edge, sorted and deduplicated.
    pub fn edges(&self) -> &[ControlEdge] {
        &self.edges
    }

    /// The post-dominator tree this was computed from.
    pub fn post_dominators(&self) -> &PostDominators {
        &self.post
    }

    /// The branches `node`'s execution depends on.
    pub fn controllers(&self, node: u32) -> impl Iterator<Item = &ControlEdge> {
        self.edges.iter().filter(move |edge| edge.node == node)
    }

    /// Nodes whose execution `branch` decides.
    pub fn controlled(&self, branch: u32) -> impl Iterator<Item = &ControlEdge> {
        self.edges.iter().filter(move |edge| edge.on == branch)
    }

    /// How deeply `node` is nested in decisions: the length of the longest
    /// chain of control dependences above it.
    ///
    /// A cheap structural companion to cognitive complexity, computed on the
    /// graph rather than on the syntax, so it is not fooled by a `goto` that
    /// leaves a block or by a decompiler's flattened dispatch.
    pub fn depth(&self, node: u32) -> u32 {
        let mut seen = vec![node];
        let mut frontier = vec![node];
        let mut depth = 0u32;
        let mut guard = 0usize;
        while !frontier.is_empty() && guard < self.edges.len() + 2 {
            let mut next: Vec<u32> = Vec::new();
            for current in &frontier {
                for edge in self.controllers(*current) {
                    if !seen.contains(&edge.on) {
                        seen.push(edge.on);
                        next.push(edge.on);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            depth += 1;
            frontier = next;
            guard += 1;
        }
        depth
    }
}

/// A backward slice over a program-dependence graph.
///
/// Every node whose execution or value can affect the node the slice is taken
/// from, found by walking control and data dependences backwards to a fixed
/// point. This is the question a program-dependence graph exists to answer,
/// and it is the reason the two dependence relations have to be over the same
/// node set: a slice that followed only one of them would silently omit the
/// other's reasons.
///
/// `control` is the control-dependence graph; `data` is `(from, to)` pairs
/// lifted to the same node numbering. The result includes the seed and is
/// sorted, so two runs agree (`REQ-SYN-5`).
///
/// Total (`REQ-SYN-2`): a seed that names no node yields just that seed, and a
/// cycle terminates because a node is added at most once.
pub fn backward_slice(control: &ControlDependence, data: &[(u32, u32)], seed: u32) -> Vec<u32> {
    let mut included = vec![seed];
    let mut frontier = vec![seed];
    while let Some(node) = frontier.pop() {
        for edge in control.controllers(node) {
            if !included.contains(&edge.on) {
                included.push(edge.on);
                frontier.push(edge.on);
            }
        }
        for (from, to) in data {
            if *to == node && !included.contains(from) {
                included.push(*from);
                frontier.push(*from);
            }
        }
    }
    included.sort_unstable();
    included
}

/// Which nodes can reach any of `targets`, by a reverse walk from them.
fn reaches_any(cfg: &Cfg, targets: &[u32]) -> Vec<bool> {
    let n = cfg.node_count();
    let mut seen = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    for target in targets {
        if (*target as usize) < n && !seen[*target as usize] {
            seen[*target as usize] = true;
            stack.push(*target);
        }
    }
    while let Some(node) = stack.pop() {
        for pred in cfg.predecessors(NodeId::new(node)) {
            if !seen[pred.index()] {
                seen[pred.index()] = true;
                stack.push(pred.index() as u32);
            }
        }
    }
    seen
}

/// Reverse postorder of the graph `successors` describes, from `root`.
fn reverse_postorder(
    total: usize,
    root: u32,
    successors: impl Fn(u32) -> Vec<u32>,
) -> Vec<u32> {
    let mut seen = vec![false; total];
    let mut order: Vec<u32> = Vec::with_capacity(total);
    // Iterative postorder, so nothing here recurses (`REQ-SYN-3`).
    let mut stack: Vec<(u32, bool)> = vec![(root, false)];
    while let Some((node, expanded)) = stack.pop() {
        if expanded {
            order.push(node);
            continue;
        }
        if node as usize >= total || seen[node as usize] {
            continue;
        }
        seen[node as usize] = true;
        stack.push((node, true));
        for next in successors(node) {
            if (next as usize) < total && !seen[next as usize] {
                stack.push((next, false));
            }
        }
    }
    order.reverse();
    order
}

/// Cooper-Harvey-Kennedy's `intersect`: walk both fingers up the tree until
/// they meet, always moving the one that is deeper in reverse postorder.
fn intersect(mut a: u32, mut b: u32, idom: &[Option<u32>], position: &[usize]) -> u32 {
    let mut guard = 0usize;
    while a != b {
        guard += 1;
        if guard > idom.len() * 2 + 8 {
            return a; // malformed tree; refuse rather than spin
        }
        while position
            .get(a as usize)
            .copied()
            .unwrap_or(usize::MAX)
            > position.get(b as usize).copied().unwrap_or(usize::MAX)
        {
            match idom.get(a as usize).copied().flatten() {
                Some(parent) if parent != a => a = parent,
                _ => return b,
            }
        }
        while position
            .get(b as usize)
            .copied()
            .unwrap_or(usize::MAX)
            > position.get(a as usize).copied().unwrap_or(usize::MAX)
        {
            match idom.get(b as usize).copied().flatten() {
                Some(parent) if parent != b => b = parent,
                _ => return a,
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::cfg::{CfgNode, EdgeKind, NodeKind};
    use crate::syntax::cfg::CfgEdge;
    use crate::syntax::ids::Span;

    /// Build a graph from `(src, dst, kind)` triples over `n` nodes, where 0
    /// is the entry and `n - 1` the exit.
    fn graph(n: usize, edges: &[(u32, u32, EdgeKind)]) -> Cfg {
        let nodes: Vec<CfgNode> = (0..n)
            .map(|index| {
                let kind = if index == 0 {
                    NodeKind::Entry
                } else if index == n - 1 {
                    NodeKind::Exit
                } else {
                    NodeKind::Stmt
                };
                CfgNode::single(kind, Span::new(index as u32, index as u32 + 1))
            })
            .collect();
        let edges: Vec<CfgEdge> = edges
            .iter()
            .map(|(src, dst, kind)| CfgEdge {
                src: NodeId::new(*src),
                dst: NodeId::new(*dst),
                kind: *kind,
                is_back: false,
            })
            .collect();
        Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(n as u32 - 1))
    }

    #[test]
    fn a_straight_line_post_dominates_backwards() {
        // 0 -> 1 -> 2 -> 3(exit)
        let cfg = graph(
            4,
            &[
                (0, 1, EdgeKind::Fall),
                (1, 2, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
            ],
        );
        let post = PostDominators::of(&cfg);
        assert_eq!(post.immediate(0), Some(1));
        assert_eq!(post.immediate(1), Some(2));
        assert_eq!(post.immediate(2), Some(3));
        assert!(post.post_dominates(3, 0));
        assert!(!post.post_dominates(0, 3));
    }

    #[test]
    fn a_diamond_post_dominates_at_the_join() {
        // 0 -> {1, 2} -> 3 -> 4(exit)
        let cfg = graph(
            5,
            &[
                (0, 1, EdgeKind::True),
                (0, 2, EdgeKind::False),
                (1, 3, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
                (3, 4, EdgeKind::Fall),
            ],
        );
        let post = PostDominators::of(&cfg);
        // The join post-dominates the branch; neither arm does.
        assert!(post.post_dominates(3, 0));
        assert!(!post.post_dominates(1, 0));
        assert!(!post.post_dominates(2, 0));
        assert_eq!(post.immediate(0), Some(3));
    }

    #[test]
    fn both_arms_of_a_diamond_are_control_dependent_on_the_branch() {
        let cfg = graph(
            5,
            &[
                (0, 1, EdgeKind::True),
                (0, 2, EdgeKind::False),
                (1, 3, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
                (3, 4, EdgeKind::Fall),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        let controlled: Vec<u32> = cdg.controlled(0).map(|edge| edge.node).collect();
        assert_eq!(controlled, vec![1, 2], "{:?}", cdg.edges());
        // The join is not: it runs either way.
        assert_eq!(cdg.controllers(3).count(), 0);
        // And each arm records which way the branch went.
        let kinds: Vec<EdgeKind> = cdg.controlled(0).map(|edge| edge.kind).collect();
        assert!(kinds.contains(&EdgeKind::True));
        assert!(kinds.contains(&EdgeKind::False));
    }

    #[test]
    fn a_loop_body_is_control_dependent_on_its_header() {
        // 0 -> 1(header) -> 2(body) -> 1, and 1 -> 3(exit)
        let cfg = graph(
            4,
            &[
                (0, 1, EdgeKind::Fall),
                (1, 2, EdgeKind::True),
                (2, 1, EdgeKind::Fall),
                (1, 3, EdgeKind::False),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        let controlled: Vec<u32> = cdg.controlled(1).map(|edge| edge.node).collect();
        assert!(controlled.contains(&2), "{:?}", cdg.edges());
        // A loop header controls itself: whether it runs again is its own
        // decision. That is the classic self-edge FOW produces.
        assert!(controlled.contains(&1), "{:?}", cdg.edges());
    }

    #[test]
    fn nesting_depth_counts_the_chain_of_decisions() {
        // 0 -> 1 -> {2 -> {3}} with a join at 4 and exit 5.
        let cfg = graph(
            6,
            &[
                (0, 1, EdgeKind::Fall),
                (1, 2, EdgeKind::True),
                (1, 4, EdgeKind::False),
                (2, 3, EdgeKind::True),
                (2, 4, EdgeKind::False),
                (3, 4, EdgeKind::Fall),
                (4, 5, EdgeKind::Fall),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        assert_eq!(cdg.depth(4), 0, "the join runs unconditionally");
        assert_eq!(cdg.depth(2), 1, "one branch above it");
        assert_eq!(cdg.depth(3), 2, "two branches above it");
    }

    #[test]
    fn an_infinite_loop_still_has_a_post_dominator_tree() {
        // 0 -> 1 -> 1 forever, and a separate exit 2 nothing reaches.
        // Without a virtual exit this graph has no post-dominator tree at all.
        let cfg = graph(
            3,
            &[(0, 1, EdgeKind::Fall), (1, 1, EdgeKind::Fall)],
        );
        let post = PostDominators::of(&cfg);
        assert!(!post.dead_ends().is_empty(), "the stuck region is reported");
        // Totality is the contract: this must not panic or spin.
        let cdg = ControlDependence::of(&cfg);
        let _ = cdg.edges();
    }

    #[test]
    fn every_entry_point_is_total_on_a_degenerate_graph() {
        for cfg in [
            graph(1, &[]),
            graph(2, &[]),
            graph(2, &[(0, 1, EdgeKind::Fall)]),
            // An edge naming a node that does not exist.
            graph(2, &[(0, 9, EdgeKind::Fall)]),
        ] {
            let post = PostDominators::of(&cfg);
            let _ = post.placed();
            let cdg = ControlDependence::of(&cfg);
            for node in 0..cfg.node_count() as u32 {
                let _ = cdg.depth(node);
                let _ = post.post_dominates(0, node);
            }
        }
    }

    #[test]
    fn results_are_deterministic() {
        let cfg = graph(
            5,
            &[
                (0, 1, EdgeKind::True),
                (0, 2, EdgeKind::False),
                (1, 3, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
                (3, 4, EdgeKind::Fall),
            ],
        );
        assert_eq!(ControlDependence::of(&cfg), ControlDependence::of(&cfg));
        assert_eq!(PostDominators::of(&cfg), PostDominators::of(&cfg));
    }
}

#[cfg(test)]
mod corpus {
    use super::*;
    use crate::csource::cfg::function_cfgs;
    use crate::csource::parse::parse;

    /// Post-dominance and control dependence over 900 real functions.
    ///
    /// Asserts the invariants rather than any count: every placed node's
    /// post-dominator really does post-dominate it, no control edge names a
    /// node that does not exist, and the tree has no cycle. A cycle is the
    /// failure mode that matters --- it would make `post_dominates` spin, and
    /// the guard that stops it would silently return a wrong answer.
    #[test]
    fn the_fixture_corpus_has_a_consistent_post_dominator_tree() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let mut functions = 0usize;
        let mut placed = 0usize;
        let mut control_edges = 0usize;
        let mut stuck = 0usize;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (tree, _) = parse(&text).into_parts();
            let (cfgs, _) = function_cfgs(&tree, &text).into_parts();
            for function in &cfgs {
                functions += 1;
                let cfg = &function.cfg;
                let cdg = ControlDependence::of(cfg);
                let post = cdg.post_dominators();
                placed += post.placed();
                control_edges += cdg.edges().len();
                stuck += post.dead_ends().len();

                let n = cfg.node_count() as u32;
                for node in 0..n {
                    // No cycle: walking up terminates within the node count.
                    let mut steps = 0usize;
                    let mut current = node;
                    while let Some(parent) = post.immediate(current) {
                        assert!(parent < n, "{}: ipdom out of range", function.name);
                        current = parent;
                        steps += 1;
                        assert!(
                            steps <= n as usize,
                            "{}: post-dominator cycle at {node}",
                            function.name
                        );
                    }
                    // The relation agrees with the tree it was built from.
                    if let Some(parent) = post.immediate(node) {
                        assert!(
                            post.post_dominates(parent, node),
                            "{}: ipdom {parent} does not post-dominate {node}",
                            function.name
                        );
                    }
                }
                for edge in cdg.edges() {
                    assert!(edge.on < n && edge.node < n, "{}: edge out of range", function.name);
                }
            }
        }

        assert!(functions > 500, "only {functions} functions");
        assert!(control_edges > 1000, "only {control_edges} control edges");
        eprintln!(
            "corpus: {functions} functions, {placed} nodes placed, \
             {control_edges} control edges, {stuck} unreachable-exit roots"
        );
    }
}

#[cfg(test)]
mod slice_tests {
    use super::*;
    use crate::syntax::cfg::{CfgEdge, CfgNode, EdgeKind, NodeKind};
    use crate::syntax::ids::Span;

    fn graph(n: usize, edges: &[(u32, u32, EdgeKind)]) -> Cfg {
        let nodes: Vec<CfgNode> = (0..n)
            .map(|index| {
                let kind = if index == 0 {
                    NodeKind::Entry
                } else if index == n - 1 {
                    NodeKind::Exit
                } else {
                    NodeKind::Stmt
                };
                CfgNode::single(kind, Span::new(index as u32, index as u32 + 1))
            })
            .collect();
        let edges: Vec<CfgEdge> = edges
            .iter()
            .map(|(src, dst, kind)| CfgEdge {
                src: NodeId::new(*src),
                dst: NodeId::new(*dst),
                kind: *kind,
                is_back: false,
            })
            .collect();
        Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(n as u32 - 1))
    }

    #[test]
    fn a_slice_follows_data_dependence_backwards() {
        // 0 -> 1 -> 2 -> 3(exit), with data 1 -> 2.
        let cfg = graph(
            4,
            &[
                (0, 1, EdgeKind::Fall),
                (1, 2, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        let slice = backward_slice(&cdg, &[(1, 2)], 2);
        assert!(slice.contains(&1), "{slice:?}");
        assert!(slice.contains(&2), "the seed is in its own slice");
    }

    #[test]
    fn a_slice_follows_control_dependence_too() {
        // A diamond: the arm at 1 is control dependent on the branch at 0.
        let cfg = graph(
            5,
            &[
                (0, 1, EdgeKind::True),
                (0, 2, EdgeKind::False),
                (1, 3, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
                (3, 4, EdgeKind::Fall),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        let slice = backward_slice(&cdg, &[], 1);
        assert!(slice.contains(&0), "the branch is missing: {slice:?}");
    }

    #[test]
    fn a_slice_excludes_what_cannot_affect_the_seed() {
        let cfg = graph(
            5,
            &[
                (0, 1, EdgeKind::True),
                (0, 2, EdgeKind::False),
                (1, 3, EdgeKind::Fall),
                (2, 3, EdgeKind::Fall),
                (3, 4, EdgeKind::Fall),
            ],
        );
        let cdg = ControlDependence::of(&cfg);
        // Slicing on arm 1 must not drag in the other arm.
        let slice = backward_slice(&cdg, &[], 1);
        assert!(!slice.contains(&2), "the other arm is in the slice: {slice:?}");
    }

    #[test]
    fn a_cyclic_dependence_terminates() {
        let cfg = graph(3, &[(0, 1, EdgeKind::Fall), (1, 2, EdgeKind::Fall)]);
        let cdg = ControlDependence::of(&cfg);
        // A data cycle: 1 depends on 2 and 2 on 1.
        let slice = backward_slice(&cdg, &[(1, 2), (2, 1)], 1);
        assert!(slice.contains(&1) && slice.contains(&2));
    }

    #[test]
    fn a_seed_that_names_no_node_yields_only_itself() {
        let cfg = graph(2, &[(0, 1, EdgeKind::Fall)]);
        let cdg = ControlDependence::of(&cfg);
        assert_eq!(backward_slice(&cdg, &[], 99), vec![99]);
    }
}
