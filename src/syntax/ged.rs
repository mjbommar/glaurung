//! `G-1`, `G-2`, `G-4` --- graph edit distance over control-flow graphs.
//!
//! Spec: `docs/design/static-c-analysis/implementation-inventory.md` section 4,
//! and `docs/design/static-c-analysis/joern-behavior.md` section 2 for the
//! proof that the distance reads only degree sequences and entry/exit flags.
//!
//! # Why the input type has no edges
//!
//! This is a reimplementation of `cfgutils.similarity.vj_ged`, the
//! Vujosevic--Janicic bipartite approximation to graph edit distance that
//! DecBench scores its `ged` metric with. It is *not* exact graph edit
//! distance, and the difference is the whole reason [`GedGraph`] looks the way
//! it does.
//!
//! The reference builds an `(n + m) x (n + m)` cost matrix and solves it with
//! Munkres. Every cell of that matrix is a function of the in-degree, the
//! out-degree and the two boolean flags of the nodes it joins --- the
//! substitution cost is `|in_i - in_j| + |out_i - out_j|` plus at most one
//! entry/exit penalty, and the deletion and insertion costs are `1 + in + out`.
//! Nothing anywhere reads which node is wired to which. **Therefore the
//! distance is a function of the two degree sequences and the entry/exit flags,
//! and of nothing else**: two graphs with the same multiset of
//! `(in_degree, out_degree, is_entrypoint, is_exitpoint)` tuples score `0`
//! against each other no matter how differently they are wired, and
//! `tests::degree_multiset_is_the_only_topology_that_matters` builds a 4-cycle
//! and a pair of 2-cycles to prove it.
//!
//! Taking a degree sequence rather than an adjacency structure is a deliberate
//! consequence of that proof, and it is what makes the whole component
//! testable: every case in this file is four integers and two bits per node,
//! written inline, with no graph fixture to build, mis-build, or keep in sync.
//!
//! # Parity with the reference
//!
//! The reference matrix is `[[C, D], [I, 0]]`, **not** `[[C, D], [I, INF]]`.
//! `CFGSimED.__ED` zero-fills the whole matrix and then writes `inf` only into
//! the *off-diagonal* deletion and insertion blocks; the bottom-right `m x n`
//! dummy-to-dummy block is left at `0`, as the Riesen--Bunke formulation
//! requires. It has to be: an assignment with `k` substitutions consumes
//! exactly `k` dummy-to-dummy cells, so an infeasible bottom-right block would
//! make every assignment but the all-delete-all-insert one impossible. See the
//! note in [`cost_matrix`].
//!
//! # No native recursion, no panics
//!
//! Both hold, per `REQ-SYN-2` and `REQ-SYN-3`: the solver and the matrix
//! builder are flat loops, and every entry point returns a value for every
//! input including empty graphs, mismatched sizes and saturated degrees.

/// The integer type every cost, potential and total in this module is carried
/// in.
///
/// `i128` rather than `i64` because the infeasibility sentinel is
/// `1 + sum of all finite costs` (see [`cost_matrix`]) and the solver's dual
/// potentials are bounded by `order * sentinel`. With `u32` degrees a single
/// cell can reach `2 * u32::MAX + 100000`, so an `i64` accumulator has a
/// reachable overflow while an `i128` one does not for any matrix that fits in
/// memory. Costs are integers end to end; the only `f64` in the module is
/// [`GedResult::value`], which exists because DecBench records a float.
pub type Cost = i128;

/// The penalty the reference adds when an entry or exit flag disagrees.
///
/// `cfgutils.similarity.ged.INVALID_CHOICE_PENALTY`. Applied through an
/// `if/elif/elif/elif` chain, so **at most one** is ever added even when both
/// flags disagree --- see [`substitution_cost`].
///
/// At real CFG sizes this is a prohibition rather than a price: deleting and
/// re-inserting a node costs `2 + in_i + out_i + in_j + out_j`, which cannot
/// reach `100000` while degrees are bounded by a 200-node cap (worst case
/// `2 + 4 * 200 = 802`). The optimal
/// assignment therefore never *contains* the penalty; it is the penalty's
/// presence in the matrix that changes which assignment is optimal.
pub const INVALID_CHOICE_PENALTY: Cost = 100_000;

/// The node cap above which the metric degrades to a size delta.
///
/// `decbench.metrics.ged.GED_MAX_NODES`, overridable there by
/// `DECBENCH_GED_MAX_NODES`. The reference compares with `>`, so a graph of
/// exactly this many nodes is still scored exactly.
///
/// This was 60 from `d59b438c` until 2026-09-04, which did not mirror the
/// reference's 200 despite the sentence above saying it did. The gap is not
/// academic: 2,547 of the 91,548 published CFGs (2.78%) have between 61 and
/// 200 nodes, so on every one of them we returned a size delta where the
/// reference ran the assignment -- a disagreement by construction, on the
/// exact population the parity gate is scored over.
///
/// ```text
/// published function CFGs: 91548
///   <=60  (both exact)                      88728  (96.92%)
///   61..200 (we approximated, they did not)  2547  (2.78%)
///   >200  (both approximate)                  273  (0.30%)
/// ```
pub const DEFAULT_MAX_NODES: usize = 200;

/// One CFG node, reduced to everything the distance can read.
///
/// Four numbers is the complete input: the module docs explain why there is no
/// identity, label, address or adjacency here, and why adding any would be
/// dead weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GedNode {
    /// Number of incoming edges (the reference's `parent_count`).
    pub in_degree: u32,
    /// Number of outgoing edges (the reference's `child_count`).
    pub out_degree: u32,
    /// Whether this node is the function entry.
    pub is_entrypoint: bool,
    /// Whether this node is a function exit.
    pub is_exitpoint: bool,
}

impl GedNode {
    /// A node with the given degrees and flags.
    pub const fn new(
        in_degree: u32,
        out_degree: u32,
        is_entrypoint: bool,
        is_exitpoint: bool,
    ) -> Self {
        Self {
            in_degree,
            out_degree,
            is_entrypoint,
            is_exitpoint,
        }
    }

    /// A node with the given degrees and neither flag set.
    pub const fn plain(in_degree: u32, out_degree: u32) -> Self {
        Self::new(in_degree, out_degree, false, false)
    }

    /// `1 + in_degree + out_degree`: the reference's cost of deleting this node
    /// from `g1`, or of inserting it into `g2`.
    fn edit_cost(&self) -> Cost {
        1 + Cost::from(self.in_degree) + Cost::from(self.out_degree)
    }
}

/// A CFG as the distance sees it: a node list plus an edge count.
///
/// Node *order* is irrelevant to the result --- the solver minimises over every
/// pairing --- but it is preserved, so [`cost_matrix`] can be compared cell by
/// cell against `CFGSimED.__ED`'s matrix for a graph whose `networkx` node
/// order is known.
///
/// `edge_count` is read by exactly one thing, the large-graph fallback in
/// [`ged_with_max_nodes`]. The exact path never touches it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GedGraph {
    nodes: Vec<GedNode>,
    edge_count: u64,
}

impl GedGraph {
    /// A graph with an explicitly supplied edge count.
    ///
    /// Use this when the caller knows the edge count independently of the
    /// degree sequence; nothing checks that the two agree, because nothing in
    /// the reference does either.
    pub fn new(nodes: Vec<GedNode>, edge_count: u64) -> Self {
        Self { nodes, edge_count }
    }

    /// A graph whose edge count is the sum of the out-degrees.
    ///
    /// The right constructor for a well-formed digraph, where the two are
    /// equal by definition. The sum saturates rather than overflowing.
    pub fn from_nodes(nodes: Vec<GedNode>) -> Self {
        let edge_count = nodes
            .iter()
            .fold(0u64, |acc, n| acc.saturating_add(u64::from(n.out_degree)));
        Self { nodes, edge_count }
    }

    /// The empty graph: no nodes, no edges.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The nodes, in construction order.
    pub fn nodes(&self) -> &[GedNode] {
        &self.nodes
    }

    /// Number of nodes. Compared against the cap in [`ged_with_max_nodes`].
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges. Read only by the large-graph fallback.
    pub fn edge_count(&self) -> u64 {
        self.edge_count
    }
}

/// A distance, and whether it was computed or approximated.
///
/// The flag is the point. Above the node cap the metric returns
/// `|delta nodes| + |delta edges|`, which is a sound *lower bound* and is
/// therefore `0` whenever the two graphs merely happen to have equal node and
/// edge counts. An approximated `0` and an exact `0` mean entirely different
/// things, and a bare number cannot tell them apart.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GedResult {
    /// The distance. Lower is better; `0.0` is a perfect structural match.
    pub value: f64,
    /// `true` when the value came from the size-delta fallback rather than the
    /// assignment solver.
    pub approximated: bool,
}

impl GedResult {
    /// Whether the value came from the solver rather than the fallback.
    pub fn is_exact(&self) -> bool {
        !self.approximated
    }
}

/// The `(n + m) x (n + m)` cost matrix of `G-1`, row-major.
///
/// Exposed rather than kept private so the parity test in section 4 of the
/// inventory --- cell-by-cell equality with `CFGSimED.__ED`'s matrix --- can be
/// written at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostMatrix {
    order: usize,
    n: usize,
    m: usize,
    sentinel: Cost,
    cells: Vec<Cost>,
}

impl CostMatrix {
    /// Side length of the (square) matrix, `n + m`.
    pub fn order(&self) -> usize {
        self.order
    }

    /// Node count of the left-hand graph.
    pub fn left_len(&self) -> usize {
        self.n
    }

    /// Node count of the right-hand graph.
    pub fn right_len(&self) -> usize {
        self.m
    }

    /// The value standing in for the reference's `float('inf')`.
    pub fn sentinel(&self) -> Cost {
        self.sentinel
    }

    /// The cells, row-major, `order * order` of them.
    pub fn cells(&self) -> &[Cost] {
        &self.cells
    }

    /// The cost at `(row, col)`, or `None` if either index is out of range.
    ///
    /// Returns `None` rather than panicking, so a malformed index is a value
    /// like any other.
    pub fn get(&self, row: usize, col: usize) -> Option<Cost> {
        if row >= self.order || col >= self.order {
            return None;
        }
        self.cells.get(row * self.order + col).copied()
    }

    /// Whether `(row, col)` is one of the cells the reference marks infinite.
    pub fn is_infeasible(&self, row: usize, col: usize) -> bool {
        self.get(row, col) == Some(self.sentinel) && self.sentinel > 0
    }

    /// The minimum-cost perfect assignment over this matrix.
    pub fn solve(&self) -> Assignment {
        solve_assignment(&self.cells, self.order)
    }
}

/// The substitution cost of pairing `a` (from `g1`) with `b` (from `g2`).
///
/// `|out_a - out_b| + |in_a - in_b|`, plus at most one
/// [`INVALID_CHOICE_PENALTY`].
///
/// The reference writes the degree term as
/// `c_a + c_b - 2 * count_common(CL_a, CL_b)` over lists of `c_a` and `c_b`
/// identical `'1'` tokens. `count_common` of two such lists is `min(c_a, c_b)`,
/// so the expression is `c_a + c_b - 2 * min(c_a, c_b)`, which is exactly
/// `|c_a - c_b|`. The same holds for the parent lists. This reduction was
/// checked against the Python, not merely reasoned about: `tests` below carries
/// 124 `(degrees, degrees, expected)` triples produced by running
/// `CFGSimED.sim` on real `networkx` graphs.
///
/// The flag term is an `if/elif/elif/elif` chain in the reference, so a pair
/// that disagrees on *both* flags is charged once, not twice. That is
/// reproduced literally here; it is not a simplification.
pub fn substitution_cost(a: &GedNode, b: &GedNode) -> Cost {
    let out = (Cost::from(a.out_degree) - Cost::from(b.out_degree)).abs();
    let inn = (Cost::from(a.in_degree) - Cost::from(b.in_degree)).abs();
    let penalty = if a.is_entrypoint && !b.is_entrypoint {
        INVALID_CHOICE_PENALTY
    } else if a.is_exitpoint && !b.is_exitpoint {
        INVALID_CHOICE_PENALTY
    } else if b.is_entrypoint && !a.is_entrypoint {
        INVALID_CHOICE_PENALTY
    } else if b.is_exitpoint && !a.is_exitpoint {
        INVALID_CHOICE_PENALTY
    } else {
        0
    };
    out + inn + penalty
}

/// Build `G-1`'s cost matrix for `g1` against `g2`.
///
/// Block form, with `n = g1.node_count()` and `m = g2.node_count()`:
///
/// | block | rows | cols | contents |
/// |---|---|---|---|
/// | `C` substitution | `0..n` | `0..m` | [`substitution_cost`] |
/// | `D` deletion | `0..n` | `m..m+n` | `1 + in_i + out_i` on the diagonal, sentinel off it |
/// | `I` insertion | `n..n+m` | `0..m` | `1 + in_j + out_j` on the diagonal, sentinel off it |
/// | dummy | `n..n+m` | `m..m+n` | **zero** |
///
/// The bottom-right block being zero rather than infeasible is not a
/// simplification: `CFGSimED.__ED` zero-fills the matrix and writes `inf` only
/// into rows `n..n+m` at columns `0..m` and rows `0..n` at columns `m..m+n`,
/// leaving the dummy-to-dummy corner at `0`. It cannot be otherwise. An
/// assignment that substitutes `k` node pairs deletes `n - k` nodes and inserts
/// `m - k`, which leaves exactly `k` dummy rows and `k` dummy columns to be
/// matched to each other; make that corner infeasible and no assignment with
/// `k > 0` exists at all.
///
/// # The sentinel
///
/// The reference uses `float('inf')`. Integer arithmetic has no such value, and
/// landmine 3 of the inventory is exactly what happens when the substitute is
/// chosen carelessly: too small and the solver quietly takes a forbidden cell,
/// too large and it either swamps the `100000` entry/exit penalty into noise or
/// overflows the accumulator.
///
/// The sentinel here is `M = 1 + sum of every finite cost in the matrix`
/// (substitution block, deletion diagonal, insertion diagonal --- the zero
/// corner contributes nothing). Two properties follow, and both are tested:
///
/// * **`M` is unreachable.** Every cost is non-negative and a feasible
///   assignment picks `order` *distinct* finite cells, so its total is at most
///   the sum of all finite costs, which is `M - 1`. One forbidden cell already
///   costs `M`. So while any feasible assignment exists the solver cannot
///   prefer a forbidden one --- and one always exists, because delete-everything
///   plus insert-everything is always available.
/// * **`M` does not swamp anything.** It is a sum of the real costs, not a
///   magic constant, so it stays proportional to the problem and the `100000`
///   penalty keeps its ordering against deletion and insertion. It is carried
///   in [`Cost`] (`i128`), where a matrix large enough to overflow does not fit
///   in memory.
///
/// A degenerate matrix --- either graph empty, or `order * order` overflowing
/// `usize` --- yields an order-`0` matrix rather than a panic.
pub fn cost_matrix(g1: &GedGraph, g2: &GedGraph) -> CostMatrix {
    build_matrix(g1, g2, None)
}

/// [`cost_matrix`], but with the infeasibility sentinel forced to `sentinel`.
///
/// For tests that need to show the choice of sentinel is load-bearing: pass a
/// value below the optimal feasible total and the solver will take a forbidden
/// cell. Not useful outside that.
pub fn cost_matrix_with_sentinel(g1: &GedGraph, g2: &GedGraph, sentinel: Cost) -> CostMatrix {
    build_matrix(g1, g2, Some(sentinel))
}

fn build_matrix(g1: &GedGraph, g2: &GedGraph, forced_sentinel: Option<Cost>) -> CostMatrix {
    let n = g1.node_count();
    let m = g2.node_count();
    let order = n + m;
    let Some(area) = order.checked_mul(order) else {
        return CostMatrix {
            order: 0,
            n: 0,
            m: 0,
            sentinel: 0,
            cells: Vec::new(),
        };
    };
    if order == 0 {
        return CostMatrix {
            order: 0,
            n,
            m,
            sentinel: 0,
            cells: Vec::new(),
        };
    }

    // Pass one: every finite cost, and their sum. The sentinel cannot be
    // written until the sum is known, which is why this is two passes.
    let mut substitutions = Vec::with_capacity(n.saturating_mul(m));
    let mut finite_sum: Cost = 0;
    for a in g1.nodes() {
        for b in g2.nodes() {
            let cost = substitution_cost(a, b);
            finite_sum += cost;
            substitutions.push(cost);
        }
    }
    let deletions: Vec<Cost> = g1.nodes().iter().map(GedNode::edit_cost).collect();
    let insertions: Vec<Cost> = g2.nodes().iter().map(GedNode::edit_cost).collect();
    for cost in deletions.iter().chain(insertions.iter()) {
        finite_sum += *cost;
    }
    let sentinel = forced_sentinel.unwrap_or(finite_sum + 1);

    // Pass two: materialise.
    let mut cells = vec![0 as Cost; area];
    for row in 0..order {
        for col in 0..order {
            let value = match (row < n, col < m) {
                (true, true) => substitutions[row * m + col],
                (true, false) => {
                    if col - m == row {
                        deletions[row]
                    } else {
                        sentinel
                    }
                }
                (false, true) => {
                    if row - n == col {
                        insertions[col]
                    } else {
                        sentinel
                    }
                }
                // The dummy-to-dummy corner. Zero, per the reference.
                (false, false) => 0,
            };
            cells[row * order + col] = value;
        }
    }

    CostMatrix {
        order,
        n,
        m,
        sentinel,
        cells,
    }
}

/// A minimum-cost perfect assignment: the total, and the column chosen for
/// each row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// Sum of the chosen cells.
    pub total: Cost,
    /// `columns[row]` is the column assigned to `row`. Length `order`.
    pub columns: Vec<usize>,
}

/// `G-2`: solve the square linear sum assignment problem in `O(order^3)`.
///
/// This is the Riesen--Bunke bipartite formulation of graph edit distance, so
/// the solver is the classical Hungarian / Munkres method in its
/// column-reduction form: dual potentials `u` and `v`, a shortest augmenting
/// path per row recorded in `way`, and a `p` array mapping each column to its
/// row. `cells` is row-major and must hold at least `order * order` entries; a
/// short slice or `order == 0` yields an empty assignment rather than a panic.
/// The loops are flat --- no native recursion anywhere (`REQ-SYN-3`).
///
/// # Determinism
///
/// The returned *total* is tie-independent, being the optimum of the problem.
/// The returned *assignment* is made deterministic by the scan order: columns
/// are examined in ascending index, and both the `minv` update and the `delta`
/// selection compare with strict `<`, so among equal candidates the lowest
/// column index is kept and later equals never displace it. Rows are processed
/// in ascending index. Identical `cells` therefore give a byte-identical
/// `Assignment` on every run, machine and build (`REQ-SYN-5`).
pub fn solve_assignment(cells: &[Cost], order: usize) -> Assignment {
    let n = order;
    let empty = Assignment {
        total: 0,
        columns: Vec::new(),
    };
    if n == 0 {
        return empty;
    }
    let Some(area) = n.checked_mul(n) else {
        return empty;
    };
    if cells.len() < area {
        return empty;
    }

    // A value larger than any `cells[i][j] - u[i] - v[j]` can reach. The dual
    // potentials of an assignment problem with costs in `[-max, max]` are
    // bounded by `n * max`, so `4 * (n + 1) * (max + 1)` is comfortably above
    // every reduced cost while staying far inside `i128`.
    let mut max_abs: Cost = 0;
    for &c in &cells[..area] {
        let a = if c < 0 { -c } else { c };
        if a > max_abs {
            max_abs = a;
        }
    }
    let big = (max_abs + 1)
        .saturating_mul(4)
        .saturating_mul(n as Cost + 1)
        + 1;

    let mut u = vec![0 as Cost; n + 1];
    let mut v = vec![0 as Cost; n + 1];
    // `p[j]` is the 1-based row matched to column `j`; 0 means unmatched.
    let mut p = vec![0usize; n + 1];
    let mut way = vec![0usize; n + 1];
    let mut minv = vec![0 as Cost; n + 1];
    let mut used = vec![false; n + 1];

    for i in 1..=n {
        p[0] = i;
        let mut j0 = 0usize;
        minv.iter_mut().for_each(|x| *x = big);
        used.iter_mut().for_each(|x| *x = false);

        loop {
            used[j0] = true;
            let i0 = p[j0];
            if i0 == 0 {
                // Unreachable: `j0` is only entered while it is matched.
                break;
            }
            let base = (i0 - 1) * n;
            let mut delta = big;
            let mut j1 = 0usize;
            for j in 1..=n {
                if used[j] {
                    continue;
                }
                let cur = cells[base + (j - 1)] - u[i0] - v[j];
                if cur < minv[j] {
                    minv[j] = cur;
                    way[j] = j0;
                }
                if minv[j] < delta {
                    delta = minv[j];
                    j1 = j;
                }
            }
            if j1 == 0 {
                // Unreachable while `i <= n`: some column is always free.
                break;
            }
            for j in 0..=n {
                if used[j] {
                    let pj = p[j];
                    if pj != 0 {
                        u[pj] += delta;
                    }
                    v[j] -= delta;
                } else {
                    minv[j] -= delta;
                }
            }
            j0 = j1;
            if p[j0] == 0 {
                break;
            }
        }

        // Walk the augmenting path back to the root, flipping matches.
        while j0 != 0 {
            let j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
        }
    }

    let mut total: Cost = 0;
    let mut columns = vec![usize::MAX; n];
    for j in 1..=n {
        let row = p[j];
        if row == 0 || row > n {
            continue;
        }
        total += cells[(row - 1) * n + (j - 1)];
        columns[row - 1] = j - 1;
    }
    Assignment { total, columns }
}

/// The exact distance, with no node cap: build `G-1`'s matrix and solve it.
///
/// Callers that want DecBench's behaviour want [`ged`] instead, which applies
/// the cap. This is the parity surface --- it is what a stored expected value
/// is compared against --- and it is `O((n + m)^3)` in time and `O((n + m)^2)`
/// in memory with no guard, so do not hand it an arbitrarily large graph.
pub fn ged_exact(g1: &GedGraph, g2: &GedGraph) -> Cost {
    cost_matrix(g1, g2).solve().total
}

/// The distance as DecBench computes it, with the default node cap.
///
/// Equivalent to [`ged_with_max_nodes`] at [`DEFAULT_MAX_NODES`].
pub fn ged(g1: &GedGraph, g2: &GedGraph) -> GedResult {
    ged_with_max_nodes(g1, g2, DEFAULT_MAX_NODES)
}

/// `G-4`: the distance, degrading to a size delta above `max_nodes`.
///
/// When either graph has **more than** `max_nodes` nodes --- the reference
/// compares with `>`, so a graph of exactly `max_nodes` is still exact --- the
/// result is `|delta nodes| + |delta edges|`, flagged
/// [`approximated`](GedResult::approximated). That value is a sound lower bound
/// on the true distance and nothing more; in particular a `0` from this path
/// means only that the node and edge counts happened to match. The flag is how
/// a caller tells the two kinds of `0` apart.
pub fn ged_with_max_nodes(g1: &GedGraph, g2: &GedGraph, max_nodes: usize) -> GedResult {
    if g1.node_count() > max_nodes || g2.node_count() > max_nodes {
        let node_delta = g1.node_count().abs_diff(g2.node_count()) as u128;
        let edge_delta = u128::from(g1.edge_count().abs_diff(g2.edge_count()));
        return GedResult {
            value: (node_delta + edge_delta) as f64,
            approximated: true,
        };
    }
    GedResult {
        value: ged_exact(g1, g2) as f64,
        approximated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------- helpers

    /// A graph built from an explicit edge list, so a test can vary *topology*
    /// while holding the degree sequence fixed. The public API deliberately has
    /// no such constructor: the distance cannot read adjacency, and offering a
    /// way to pass it would suggest otherwise.
    fn graph_from_edges(
        node_count: usize,
        edges: &[(usize, usize)],
        entries: &[usize],
        exits: &[usize],
    ) -> GedGraph {
        let mut nodes = vec![GedNode::default(); node_count];
        for &(a, b) in edges {
            nodes[a].out_degree += 1;
            nodes[b].in_degree += 1;
        }
        for &i in entries {
            nodes[i].is_entrypoint = true;
        }
        for &i in exits {
            nodes[i].is_exitpoint = true;
        }
        GedGraph::new(nodes, edges.len() as u64)
    }

    fn graph(spec: &[(u32, u32, bool, bool)]) -> GedGraph {
        GedGraph::from_nodes(
            spec.iter()
                .map(|&(i, o, e, x)| GedNode::new(i, o, e, x))
                .collect(),
        )
    }

    /// Lexicographic next permutation, in place. Iterative, like everything
    /// else here.
    fn next_permutation(a: &mut [usize]) -> bool {
        if a.len() < 2 {
            return false;
        }
        let mut i = a.len() - 1;
        while i > 0 && a[i - 1] >= a[i] {
            i -= 1;
        }
        if i == 0 {
            return false;
        }
        let mut j = a.len() - 1;
        while a[j] <= a[i - 1] {
            j -= 1;
        }
        a.swap(i - 1, j);
        a[i..].reverse();
        true
    }

    /// The optimum by enumerating every one of the `k!` assignments.
    fn optimum_by_permutation(cells: &[Cost], k: usize) -> Cost {
        if k == 0 {
            return 0;
        }
        let mut perm: Vec<usize> = (0..k).collect();
        let mut best = Cost::MAX;
        loop {
            let mut total: Cost = 0;
            for (row, &col) in perm.iter().enumerate() {
                total += cells[row * k + col];
            }
            if total < best {
                best = total;
            }
            if !next_permutation(&mut perm) {
                break;
            }
        }
        best
    }

    /// The optimum by subset DP over columns. Also exhaustive --- it visits
    /// every assignment, just with the common prefixes shared --- and cheap
    /// enough to run at `k = 12` where `k!` is not.
    fn optimum_by_subset_dp(cells: &[Cost], k: usize) -> Cost {
        if k == 0 {
            return 0;
        }
        let size = 1usize << k;
        let unreachable = Cost::MAX / 4;
        let mut dp = vec![unreachable; size];
        dp[0] = 0;
        for mask in 0..size {
            if dp[mask] == unreachable {
                continue;
            }
            let row = (mask as u64).count_ones() as usize;
            if row >= k {
                continue;
            }
            for col in 0..k {
                if mask & (1 << col) != 0 {
                    continue;
                }
                let next = mask | (1 << col);
                let cand = dp[mask] + cells[row * k + col];
                if cand < dp[next] {
                    dp[next] = cand;
                }
            }
        }
        dp[size - 1]
    }

    /// A deterministic PCG-style generator, so the randomised tests are
    /// reproducible without a dependency.
    struct Lcg(u64);

    impl Lcg {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        fn below(&mut self, n: u32) -> u32 {
            if n == 0 {
                0
            } else {
                self.next_u32() % n
            }
        }

        fn flag(&mut self) -> bool {
            self.next_u32() & 1 == 1
        }
    }

    fn random_graph(rng: &mut Lcg, max_nodes: u32, max_degree: u32) -> GedGraph {
        let n = rng.below(max_nodes + 1) as usize;
        let nodes = (0..n)
            .map(|_| {
                GedNode::new(
                    rng.below(max_degree + 1),
                    rng.below(max_degree + 1),
                    rng.flag(),
                    rng.flag(),
                )
            })
            .collect();
        GedGraph::from_nodes(nodes)
    }

    // --------------------------------------------------------- 1. reflexivity

    #[test]
    fn a_graph_scores_zero_against_itself() {
        let shapes: &[&[(u32, u32, bool, bool)]] = &[
            &[],
            &[(0, 0, true, true)],
            &[(0, 1, true, false), (1, 0, false, true)],
            &[
                (0, 2, true, false),
                (1, 1, false, false),
                (1, 1, false, false),
                (2, 0, false, true),
            ],
            &[
                (1, 1, true, false),
                (1, 1, false, false),
                (1, 1, false, false),
                (1, 1, false, true),
            ],
            &[
                (3, 3, true, true),
                (0, 0, false, false),
                (7, 2, false, true),
                (2, 7, true, false),
                (1, 4, false, false),
                (4, 1, false, false),
                (5, 5, false, false),
            ],
        ];
        for spec in shapes {
            let g = graph(spec);
            assert_eq!(ged_exact(&g, &g), 0, "identity failed for {spec:?}");
            let r = ged(&g, &g);
            assert_eq!(r.value, 0.0);
            assert!(r.is_exact());
        }

        // ...and for a few hundred random shapes, including flag-heavy ones.
        let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);
        for _ in 0..300 {
            let g = random_graph(&mut rng, 9, 6);
            assert_eq!(ged_exact(&g, &g), 0, "identity failed for {:?}", g.nodes());
        }
    }

    // ------------------------------------------------- 2. brute-force parity

    #[test]
    fn subset_dp_agrees_with_full_permutation_enumeration() {
        // Validates the cheaper oracle against the literal one before the next
        // test relies on it at k = 12.
        let mut rng = Lcg(0x0DDB_A11C_0FFE_E123);
        for k in 0..=8usize {
            for _ in 0..40 {
                let cells: Vec<Cost> = (0..k * k).map(|_| Cost::from(rng.below(50)) - 10).collect();
                assert_eq!(
                    optimum_by_permutation(&cells, k),
                    optimum_by_subset_dp(&cells, k),
                    "oracles disagree at k={k}"
                );
            }
        }
    }

    #[test]
    fn hungarian_matches_exhaustive_search_on_random_matrices() {
        let mut rng = Lcg(0xF00D_CAFE_1234_5678);
        for k in 1..=8usize {
            for _ in 0..60 {
                let cells: Vec<Cost> = (0..k * k)
                    .map(|_| Cost::from(rng.below(200)) - 50)
                    .collect();
                let solved = solve_assignment(&cells, k);
                assert_eq!(
                    solved.total,
                    optimum_by_permutation(&cells, k),
                    "k={k} cells={cells:?}"
                );
                // The reported assignment must actually sum to the reported
                // total and be a permutation.
                let mut seen = vec![false; k];
                let mut check: Cost = 0;
                for (row, &col) in solved.columns.iter().enumerate() {
                    assert!(col < k);
                    assert!(!seen[col], "column {col} used twice");
                    seen[col] = true;
                    check += cells[row * k + col];
                }
                assert_eq!(check, solved.total);
            }
        }
    }

    #[test]
    fn hungarian_matches_exhaustive_search_on_ged_matrices() {
        // n, m <= 6, so k = n + m reaches 12 --- past what k! allows, which is
        // why the subset DP exists.
        let mut rng = Lcg(0xBEEF_0000_D15E_A5E5);
        let mut checked = 0usize;
        for _ in 0..600 {
            let g1 = random_graph(&mut rng, 6, 5);
            let g2 = random_graph(&mut rng, 6, 5);
            let matrix = cost_matrix(&g1, &g2);
            let k = matrix.order();
            if k == 0 {
                continue;
            }
            let expected = if k <= 8 {
                optimum_by_permutation(matrix.cells(), k)
            } else {
                optimum_by_subset_dp(matrix.cells(), k)
            };
            assert_eq!(
                matrix.solve().total,
                expected,
                "g1={:?} g2={:?}",
                g1.nodes(),
                g2.nodes()
            );
            checked += 1;
        }
        assert!(checked > 500, "only {checked} cases actually ran");
    }

    // ------------------------------------------- 3. the degree-sequence proof

    #[test]
    fn degree_multiset_is_the_only_topology_that_matters() {
        // joern-behavior.md section 2: one 4-cycle against two 2-cycles. Every
        // node has in-degree 1 and out-degree 1 in both, node 0 is the entry
        // and node 3 the exit in both, and the wiring is completely different.
        let cycle_edges = [(0, 1), (1, 2), (2, 3), (3, 0)];
        let pair_edges = [(0, 1), (1, 0), (2, 3), (3, 2)];
        assert_ne!(cycle_edges, pair_edges, "the wiring must genuinely differ");

        let one_cycle = graph_from_edges(4, &cycle_edges, &[0], &[3]);
        let two_cycles = graph_from_edges(4, &pair_edges, &[0], &[3]);
        // The reduction collapses the two wirings to the same input. That
        // equality *is* the proof --- the distance never had the chance to see
        // a difference, whatever solver sits behind it.
        assert_eq!(one_cycle, two_cycles);

        assert_eq!(ged_exact(&one_cycle, &two_cycles), 0);
        assert_eq!(ged(&one_cycle, &two_cycles).value, 0.0);

        // Same multiset, different order: still zero. A diamond against a
        // chain-with-a-back-edge.
        let diamond = graph_from_edges(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &[0], &[3]);
        let shuffled = graph(&[
            (2, 0, false, true),
            (1, 1, false, false),
            (0, 2, true, false),
            (1, 1, false, false),
        ]);
        assert_eq!(ged_exact(&diamond, &shuffled), 0);

        // And the converse: one changed degree is visible.
        let extra = graph_from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)], &[0], &[3]);
        assert!(ged_exact(&one_cycle, &extra) > 0);
    }

    // ------------------------------------------ 4. the entry/exit penalty

    #[test]
    fn both_flags_disagreeing_costs_one_penalty_not_two() {
        // g1's only node is entry-and-exit; g2's is neither. The reference's
        // if/elif chain fires once.
        let g1 = graph(&[(0, 0, true, true)]);
        let g2 = graph(&[(0, 0, false, false)]);
        let matrix = cost_matrix(&g1, &g2);
        assert_eq!(matrix.get(0, 0), Some(INVALID_CHOICE_PENALTY));
        assert_ne!(matrix.get(0, 0), Some(2 * INVALID_CHOICE_PENALTY));

        // The mirror case: g2's node carries both flags, g1's carries neither.
        // The chain reaches its third arm, still once.
        let matrix = cost_matrix(&g2, &g1);
        assert_eq!(matrix.get(0, 0), Some(INVALID_CHOICE_PENALTY));

        // Crossed flags --- each side has one the other lacks --- is also one.
        let entry_only = graph(&[(0, 0, true, false)]);
        let exit_only = graph(&[(0, 0, false, true)]);
        assert_eq!(
            cost_matrix(&entry_only, &exit_only).get(0, 0),
            Some(INVALID_CHOICE_PENALTY)
        );

        // The degree term is added to the penalty, not replaced by it, and it
        // is still charged exactly once.
        let a = graph(&[(1, 4, true, true)]);
        let b = graph(&[(3, 0, false, false)]);
        assert_eq!(
            cost_matrix(&a, &b).get(0, 0),
            Some(2 + 4 + INVALID_CHOICE_PENALTY)
        );

        // Agreement in both flags costs nothing extra.
        let c = graph(&[(1, 4, true, true)]);
        let d = graph(&[(3, 0, true, true)]);
        assert_eq!(cost_matrix(&c, &d).get(0, 0), Some(6));
    }

    #[test]
    fn the_penalty_changes_which_assignment_wins() {
        // Identical degrees. With matching flags the optimum substitutes, for
        // a distance of 0. With mismatched flags substitution costs 100000, so
        // the optimum instead deletes (1 + 0 + 1) and inserts (1 + 0 + 1): 4.
        let entry = graph(&[(0, 1, true, false)]);
        let same = graph(&[(0, 1, true, false)]);
        let not_entry = graph(&[(0, 1, false, false)]);

        assert_eq!(ged_exact(&entry, &same), 0);
        assert_eq!(ged_exact(&entry, &not_entry), 4);

        // The winning assignment really is delete-then-insert, not a
        // substitution that happens to total 4.
        let matrix = cost_matrix(&entry, &not_entry);
        let solved = matrix.solve();
        assert_eq!(solved.columns, vec![1, 0]);
        assert_eq!(matrix.get(0, 0), Some(INVALID_CHOICE_PENALTY));

        // Zero the penalty and the substitution wins again --- so the constant
        // is load-bearing rather than decorative, even though its magnitude
        // never appears in an optimal total at CFG sizes.
        let without_penalty: Vec<Cost> = matrix
            .cells()
            .iter()
            .map(|&c| {
                if c >= INVALID_CHOICE_PENALTY {
                    c - INVALID_CHOICE_PENALTY
                } else {
                    c
                }
            })
            .collect();
        assert_eq!(solve_assignment(&without_penalty, matrix.order()).total, 0);
    }

    // ----------------------------------------------- 5. the sentinel boundary

    #[test]
    fn a_too_small_sentinel_permits_a_forbidden_assignment() {
        // The crispest form of landmine 3. g2 is empty, so the whole matrix is
        // the deletion block: `1 + in + out` down the diagonal, infeasible
        // everywhere else. The honest answer is delete all three nodes.
        let g1 = graph(&[
            (9, 9, true, false),
            (0, 0, false, false),
            (4, 1, false, true),
        ]);
        let empty = GedGraph::empty();
        let honest = cost_matrix(&g1, &empty);
        let truth = honest.solve();
        assert_eq!(truth.total, 19 + 1 + 6);
        assert_eq!(truth.columns, vec![0, 1, 2]);

        // Drop the sentinel to 1 and the solver "deletes" every node at the
        // price of the cheapest one, by walking off the diagonal. The answer is
        // silently wrong --- no error, no warning, just 3 instead of 26.
        let cheap = cost_matrix_with_sentinel(&g1, &empty, 1);
        let wrong = cheap.solve();
        assert_eq!(wrong.total, 3);
        assert!(wrong.total < truth.total);
        assert!(
            wrong
                .columns
                .iter()
                .enumerate()
                .any(|(row, &col)| honest.is_infeasible(row, col)),
            "the undercut must come from a forbidden cell"
        );

        // Now the same question on a matrix with all four blocks populated:
        // walk the sentinel up from 0 and find the exact value at which the
        // solver stops cheating.
        let g1 = graph(&[
            (3, 3, true, false),
            (4, 4, false, false),
            (5, 5, false, true),
        ]);
        let g2 = graph(&[(0, 0, false, false), (9, 9, true, true)]);
        let honest = cost_matrix(&g1, &g2);
        let truth = honest.solve();

        let mut threshold = None;
        for candidate in 0..=truth.total {
            let probed = cost_matrix_with_sentinel(&g1, &g2, candidate).solve();
            assert!(
                probed.total <= truth.total,
                "a smaller sentinel can only make the total smaller"
            );
            if probed.total == truth.total {
                threshold = Some(candidate);
                break;
            }
        }
        let threshold = threshold.expect("some sentinel below the optimum must suffice");
        assert!(
            threshold > 0,
            "a sentinel of 0 must not already give the right answer"
        );
        assert_eq!(
            cost_matrix_with_sentinel(&g1, &g2, threshold - 1)
                .solve()
                .total,
            truth.total - 1,
            "one below the threshold the forbidden cell is taken"
        );

        // (a) `1 + sum of finite costs` clears that threshold with room to
        //     spare, and clears the optimum itself --- which is the property
        //     that makes a forbidden cell unaffordable in general, not just
        //     here.
        assert!(honest.sentinel() > threshold);
        assert!(
            honest.sentinel() > truth.total,
            "sentinel {} must exceed the optimum {}",
            honest.sentinel(),
            truth.total
        );

        // (b) The winning assignment touches no infeasible cell.
        for (row, &col) in truth.columns.iter().enumerate() {
            assert!(
                !honest.is_infeasible(row, col),
                "optimum used forbidden cell ({row}, {col})"
            );
        }

        // (c) Raising the sentinel far higher changes nothing, because it was
        //     already unreachable. The rule is a floor, not a tuning knob.
        let huge = cost_matrix_with_sentinel(&g1, &g2, honest.sentinel() * 1_000_000);
        assert_eq!(huge.solve().total, truth.total);

        // (d) And the floor holds across the corpus of recorded vectors: for
        //     every one of them, the sentinel is above the optimum.
        for (left, right, expected) in REFERENCE_VECTORS {
            let matrix = cost_matrix(&graph(left), &graph(right));
            if matrix.order() == 0 {
                continue;
            }
            assert!(
                matrix.sentinel() > *expected,
                "sentinel {} does not clear {expected} for {left:?} vs {right:?}",
                matrix.sentinel()
            );
        }
    }

    #[test]
    fn the_sentinel_does_not_swamp_the_entry_exit_penalty() {
        // The other half of landmine 3: a sentinel so large that 100000 stops
        // mattering. Here the two graphs are degree-identical, so every
        // substitution is free but for the flags, and the optimum must still
        // be driven by the penalty rather than by the sentinel.
        let g1 = graph(&[(1, 1, true, false), (1, 1, false, true)]);
        let g2 = graph(&[(1, 1, false, true), (1, 1, true, false)]);
        let matrix = cost_matrix(&g1, &g2);

        assert!(matrix.sentinel() > INVALID_CHOICE_PENALTY);
        // Pairing 0-with-0 is penalised; pairing 0-with-1 is free. The solver
        // must find the free pairing, which it can only do if 100000 still
        // orders correctly against the other finite costs.
        assert_eq!(matrix.get(0, 0), Some(INVALID_CHOICE_PENALTY));
        assert_eq!(matrix.get(0, 1), Some(0));
        let solved = matrix.solve();
        assert_eq!(solved.total, 0);
        assert_eq!(solved.columns[0], 1);
        assert_eq!(solved.columns[1], 0);

        // And no optimal total at CFG scale ever contains the penalty: with a
        // 60-node cap a delete plus an insert costs at most 2 + 4 * 60.
        let mut rng = Lcg(0x5EED_5EED_5EED_5EED);
        for _ in 0..300 {
            let a = random_graph(&mut rng, 7, 6);
            let b = random_graph(&mut rng, 7, 6);
            assert!(
                ged_exact(&a, &b) < INVALID_CHOICE_PENALTY,
                "penalty leaked into an optimal total"
            );
        }
    }

    #[test]
    fn the_dummy_corner_is_zero_not_infeasible() {
        // If the bottom-right block were infeasible, no assignment with any
        // substitution at all would exist and every distance would collapse to
        // delete-everything-insert-everything.
        let g1 = graph(&[(0, 1, true, false), (1, 0, false, true)]);
        let g2 = graph(&[(0, 1, true, false), (1, 0, false, true)]);
        let matrix = cost_matrix(&g1, &g2);
        for row in 2..4 {
            for col in 2..4 {
                assert_eq!(matrix.get(row, col), Some(0), "cell ({row}, {col})");
            }
        }
        assert_eq!(matrix.solve().total, 0);

        // Poison that corner and the only assignment left is the one with no
        // substitutions at all: delete both nodes of g1 (2 + 2) and insert
        // both of g2 (2 + 2). The distance between a graph and its own copy
        // would be reported as 8.
        let mut poisoned = matrix.cells().to_vec();
        for row in 2..4 {
            for col in 2..4 {
                poisoned[row * 4 + col] = matrix.sentinel();
            }
        }
        let ruined = solve_assignment(&poisoned, 4);
        assert_eq!(ruined.total, 8);
        for (row, &col) in ruined.columns.iter().enumerate() {
            assert!(
                !matrix.is_infeasible(row, col) && !(row >= 2 && col >= 2),
                "({row}, {col}) should have been unavailable"
            );
        }
    }

    // -------------------------------------------------------- 6. empty graphs

    #[test]
    fn empty_graphs_return_a_value_and_never_panic() {
        let empty = GedGraph::empty();
        assert_eq!(empty.node_count(), 0);
        assert_eq!(empty.edge_count(), 0);
        assert_eq!(ged_exact(&empty, &empty), 0);
        assert_eq!(ged(&empty, &empty).value, 0.0);
        assert!(ged(&empty, &empty).is_exact());
        assert_eq!(cost_matrix(&empty, &empty).order(), 0);
        assert_eq!(cost_matrix(&empty, &empty).get(0, 0), None);

        // Insert-everything and delete-everything are symmetric, and each node
        // costs 1 + in + out.
        let g = graph(&[
            (0, 2, true, false),
            (1, 1, false, false),
            (2, 0, false, true),
        ]);
        let expected = (1 + 0 + 2) + (1 + 1 + 1) + (1 + 2 + 0);
        assert_eq!(ged_exact(&empty, &g), expected);
        assert_eq!(ged_exact(&g, &empty), expected);

        // Degenerate solver inputs.
        assert_eq!(solve_assignment(&[], 0).total, 0);
        assert_eq!(solve_assignment(&[], 3).total, 0);
        assert_eq!(solve_assignment(&[1, 2, 3], 4).total, 0);
        assert_eq!(solve_assignment(&[7], 1).total, 7);

        // Saturated degrees must not overflow or panic.
        let big = graph(&[(u32::MAX, u32::MAX, true, true)]);
        assert_eq!(ged_exact(&big, &big), 0);
        assert!(ged_exact(&big, &empty) > 0);
        // Above ~100000 degrees the penalty stops being a prohibition: here
        // substituting costs `2 * u32::MAX + 100000` while deleting one node
        // and inserting the other costs `2 * u32::MAX + 2`, so the optimum
        // takes the delete/insert pair by a hair. No real CFG reaches this
        // regime --- a 60-node cap bounds every degree by 60 --- but the
        // arithmetic must still be exact rather than saturated there.
        let opposite = graph(&[(0, 0, false, false)]);
        let substitute = 2 * Cost::from(u32::MAX) + INVALID_CHOICE_PENALTY;
        let delete_and_insert = (1 + 2 * Cost::from(u32::MAX)) + 1;
        assert!(delete_and_insert < substitute);
        assert_eq!(ged_exact(&big, &opposite), delete_and_insert);
    }

    // ------------------------------------------------------- 7. the fallback

    #[test]
    fn the_fallback_triggers_above_the_cap_and_is_tagged() {
        let below = GedGraph::new(vec![GedNode::plain(1, 1); DEFAULT_MAX_NODES], 60);
        let at_cap = GedGraph::new(vec![GedNode::plain(1, 1); DEFAULT_MAX_NODES], 60);
        let above = GedGraph::new(vec![GedNode::plain(1, 1); DEFAULT_MAX_NODES + 1], 61);

        // The reference compares with `>`, so exactly at the cap is exact.
        let exact = ged(&below, &at_cap);
        assert!(exact.is_exact());
        assert_eq!(exact.value, 0.0);

        let approx = ged(&below, &above);
        assert!(approx.approximated);
        assert_eq!(approx.value, 2.0); // |60 - 61| + |60 - 61|

        // Either side over the cap trips it.
        assert!(ged(&above, &below).approximated);
        assert!(ged(&above, &above).approximated);

        // An approximated 0 is distinguishable from an exact 0. Both graphs
        // have the same node and edge counts but wildly different degree
        // sequences, so the true distance is not 0 --- yet the fallback reports
        // 0. Sized just past the cap: at 61 nodes this demonstrated nothing
        // once the cap moved from 60 to the reference's 200, because the pair
        // then took the exact path and scored 245.
        let over = DEFAULT_MAX_NODES + 1;
        let mut left = vec![GedNode::plain(1, 1); over];
        left[0] = GedNode::new(0, 1, true, false);
        let mut right = vec![GedNode::plain(0, 0); over];
        right[0] = GedNode::new(over as u32, over as u32, false, true);
        let a = GedGraph::new(left, over as u64);
        let b = GedGraph::new(right, over as u64);
        let r = ged(&a, &b);
        assert_eq!(r.value, 0.0);
        assert!(r.approximated, "an approximated 0 must say so");
        assert!(ged_exact(&a, &b) > 0, "the true distance is not 0");

        // The cap is a parameter, not a constant.
        let three = GedGraph::new(vec![GedNode::plain(1, 1); 3], 3);
        let four = GedGraph::new(vec![GedNode::plain(1, 1); 4], 4);
        assert!(ged_with_max_nodes(&three, &four, 3).approximated);
        assert!(!ged_with_max_nodes(&three, &four, 4).approximated);
        assert_eq!(ged_with_max_nodes(&three, &four, 3).value, 2.0);
        assert_eq!(ged_with_max_nodes(&three, &four, 4).value, 3.0);

        // Edge counts feed only the fallback --- so this must be measured above
        // the cap. Below it the two have identical degree sequences and the
        // exact path correctly returns 0.
        let same_nodes_more_edges =
            GedGraph::new(vec![GedNode::plain(1, 1); over], 100 + over as u64);
        let baseline = GedGraph::new(vec![GedNode::plain(1, 1); over], over as u64);
        assert_eq!(ged(&baseline, &same_nodes_more_edges).value, 100.0);
    }

    // ------------------------------------------------------ 8. determinism

    #[test]
    fn identical_input_gives_identical_output() {
        let mut rng = Lcg(0xD37E_2A1A_1571_C000);
        for _ in 0..200 {
            let g1 = random_graph(&mut rng, 7, 5);
            let g2 = random_graph(&mut rng, 7, 5);
            let first = cost_matrix(&g1, &g2).solve();
            let second = cost_matrix(&g1, &g2).solve();
            assert_eq!(first, second);
            assert_eq!(ged_exact(&g1, &g2), ged_exact(&g1, &g2));
        }
    }

    #[test]
    fn node_order_does_not_change_the_distance() {
        // The multiset is the input; the vector order is an artefact. Reversing
        // one side must not move the number.
        let mut rng = Lcg(0x1234_5678_9ABC_DEF0);
        for _ in 0..200 {
            let g1 = random_graph(&mut rng, 6, 5);
            let g2 = random_graph(&mut rng, 6, 5);
            let mut reversed = g2.nodes().to_vec();
            reversed.reverse();
            let g2_rev = GedGraph::from_nodes(reversed);
            assert_eq!(ged_exact(&g1, &g2), ged_exact(&g1, &g2_rev));
        }
    }

    #[test]
    fn the_distance_is_symmetric() {
        let mut rng = Lcg(0x0A0B_0C0D_0E0F_1011);
        for _ in 0..300 {
            let g1 = random_graph(&mut rng, 7, 5);
            let g2 = random_graph(&mut rng, 7, 5);
            assert_eq!(ged_exact(&g1, &g2), ged_exact(&g2, &g1));
        }
    }

    // -------------------------------------------- 9. parity with the reference

    /// `(g1 nodes, g2 nodes, expected)` triples, each produced by running
    /// `cfgutils.similarity.ged.vujosevic_janicic_ged.CFGSimED(g1, g2).sim()`
    /// in the DecBench virtualenv on a real `networkx.DiGraph` pair, at
    /// glaurung `5e882019`:
    ///
    /// ```text
    /// /nas4/data/workspace-infosec/decbench/.venv/bin/python -c '...'
    /// ```
    ///
    /// Node tuples are `(in_degree, out_degree, is_entrypoint, is_exitpoint)`.
    /// The graphs behind them are random digraphs with edge probabilities in
    /// `{0.15, 0.3, 0.5, 0.8}` over 0 to 12 nodes, self-loops included, plus
    /// eight hand-built cases covering flag disagreement in every arm of the
    /// reference's `if/elif` chain, the 4-cycle/2-cycle pair from
    /// `joern-behavior.md`, and isolated nodes.
    #[rustfmt::skip]
    const REFERENCE_VECTORS: &[(&[(u32, u32, bool, bool)], &[(u32, u32, bool, bool)], Cost)] = &[
        (&[], &[(1,1,true,false)], 3),
        (&[], &[(1,1,true,true)], 3),
        (&[], &[(0,0,true,false)], 1),
        (&[], &[(0,0,true,true)], 1),
        (&[(0,0,true,false)], &[], 1),
        (&[(1,1,true,true)], &[], 3),
        (&[(0,0,true,false)], &[], 1),
        (&[(1,1,true,false)], &[], 3),
        (&[(0,0,true,false)], &[(0,0,true,false)], 0),
        (&[(0,0,true,false)], &[(1,1,true,false)], 2),
        (&[(0,0,true,false)], &[(0,0,true,true)], 2),
        (&[(1,1,true,false)], &[(0,0,true,false)], 2),
        (&[(0,0,true,true)], &[(1,2,true,false),(2,1,false,false)], 9),
        (&[(1,1,true,false)], &[(2,2,true,false),(2,2,true,false)], 7),
        (&[(0,0,true,true)], &[(1,1,true,false),(0,0,false,true)], 5),
        (&[(0,0,true,false)], &[(0,1,true,false),(1,0,false,true)], 3),
        (&[(0,1,true,false),(1,0,false,false)], &[(0,0,true,false)], 3),
        (&[(2,1,true,false),(1,2,false,true)], &[(1,1,true,false)], 5),
        (&[(1,1,false,false),(0,0,true,true)], &[(1,1,true,false)], 7),
        (&[(1,0,true,false),(0,1,false,false)], &[(1,1,true,false)], 3),
        (&[(1,0,false,false),(1,2,true,true)], &[(1,1,true,false),(1,1,false,false)], 8),
        (&[(2,2,true,false),(2,2,false,false)], &[(2,2,true,false),(1,1,false,true)], 8),
        (&[(2,1,true,false),(0,1,false,false)], &[(1,2,false,true),(1,0,true,false)], 8),
        (&[(1,0,true,true),(0,1,false,true)], &[(1,1,false,false),(1,1,true,false)], 10),
        (&[(1,1,false,true),(0,0,true,true),(0,0,false,false)], &[(2,2,true,false),(2,2,false,true)], 9),
        (&[(0,0,true,true),(1,0,false,true),(0,1,false,true)], &[(1,1,false,false),(1,1,true,false)], 11),
        (&[(2,3,true,true),(3,2,false,false),(1,1,false,false)], &[(0,0,true,true),(0,0,false,false)], 13),
        (&[(3,2,true,false),(1,2,true,true),(3,3,false,false)], &[(0,0,true,false),(0,0,false,true)], 17),
        (&[(0,1,true,true),(2,1,false,false)], &[(0,0,false,false),(0,0,false,true),(0,0,true,false)], 7),
        (&[(0,0,false,true),(1,1,true,true)], &[(0,0,false,false),(0,0,true,false),(0,0,false,false)], 7),
        (&[(1,1,false,false),(0,0,true,false)], &[(1,2,false,true),(2,1,true,false),(2,2,false,false)], 9),
        (&[(0,1,true,false),(1,0,false,false)], &[(2,1,true,false),(0,0,true,true),(1,2,true,true)], 9),
        (&[(2,1,true,true),(2,2,false,true),(1,2,false,false)], &[(1,0,false,true),(1,0,true,false),(1,3,true,true)], 12),
        (&[(1,0,true,false),(2,2,false,false),(0,1,false,false)], &[(2,2,false,true),(3,2,false,false),(2,3,true,false)], 12),
        (&[(1,1,false,false),(2,2,false,false),(2,2,true,false)], &[(0,1,true,false),(2,1,true,true),(0,0,true,true)], 16),
        (&[(2,2,true,true),(3,2,false,false),(1,2,false,true)], &[(3,1,true,false),(0,1,true,false),(0,1,false,false)], 20),
        (&[(2,4,true,true),(2,4,false,false),(3,2,false,false),(3,0,true,true)], &[(1,1,false,false),(2,2,true,true),(1,1,false,false)], 13),
        (&[(2,2,true,false),(2,3,true,true),(2,3,false,false),(4,2,false,false)], &[(2,1,false,false),(3,3,true,true),(1,2,true,false)], 11),
        (&[(0,0,false,false),(0,1,true,true),(1,0,false,false),(1,1,false,false)], &[(3,3,true,false),(3,3,false,false),(2,2,false,true)], 21),
        (&[(1,2,true,true),(1,1,false,false),(3,3,true,true),(2,1,true,false)], &[(1,0,true,true),(0,1,true,true),(0,0,true,false)], 13),
        (&[(1,1,true,false),(3,3,false,false),(2,2,true,false)], &[(3,1,false,true),(3,3,false,false),(2,3,true,true),(1,2,true,true)], 23),
        (&[(1,1,false,true),(2,2,true,true),(2,2,false,false)], &[(2,1,true,false),(2,1,false,true),(2,4,false,false),(2,2,false,false)], 17),
        (&[(2,1,true,false),(1,1,false,false),(1,2,true,false)], &[(3,1,true,true),(3,2,false,true),(1,2,false,false),(0,2,false,false)], 23),
        (&[(2,3,false,false),(2,2,true,true),(2,1,false,true)], &[(3,2,false,true),(1,3,false,true),(3,3,false,false),(3,2,true,false)], 19),
        (&[(0,2,false,true),(3,2,false,true),(0,2,true,false),(3,0,false,false)], &[(2,2,true,true),(2,2,false,false),(3,3,true,true),(2,2,false,false)], 32),
        (&[(4,3,false,false),(3,4,false,true),(3,4,false,false),(4,3,true,false)], &[(4,3,true,true),(2,4,true,false),(4,3,false,false),(3,3,true,false)], 32),
        (&[(1,0,true,false),(0,1,false,true),(3,3,true,false),(1,1,false,false)], &[(2,4,false,false),(2,2,true,false),(1,0,true,true),(1,0,false,false)], 14),
        (&[(1,0,true,false),(0,0,false,false),(0,0,true,true),(1,2,false,true)], &[(3,3,false,false),(2,0,true,false),(2,4,false,true),(1,1,true,false)], 14),
        (&[(0,1,false,true),(2,1,false,false),(1,1,false,false),(0,0,false,true),(0,0,true,false)], &[(3,4,false,true),(4,4,true,false),(4,3,false,false),(4,4,false,true)], 29),
        (&[(2,2,true,false),(2,2,true,true),(2,3,false,false),(3,3,false,true),(2,1,false,true)], &[(1,0,true,false),(0,1,true,true),(0,0,true,false),(0,0,false,false)], 23),
        (&[(4,4,true,false),(3,5,false,true),(4,2,false,false),(4,4,false,false),(4,4,false,false)], &[(0,1,true,false),(2,1,false,true),(0,0,false,false),(1,1,true,false)], 37),
        (&[(0,0,false,false),(1,2,false,true),(2,0,false,false),(0,0,true,false),(1,2,false,true)], &[(3,4,false,true),(4,3,true,false),(3,3,false,true),(4,4,false,true)], 27),
        (&[(3,3,false,false),(3,4,true,false),(3,4,false,false),(4,2,false,false)], &[(3,2,false,false),(1,2,false,false),(3,2,true,false),(3,3,false,true),(3,4,true,false)], 25),
        (&[(3,2,true,false),(2,1,false,true),(1,4,false,false),(2,1,false,false)], &[(0,2,false,false),(1,0,false,true),(1,1,true,false),(0,0,false,true),(1,0,false,true)], 15),
        (&[(0,1,true,false),(0,0,true,true),(1,0,false,false),(2,2,false,true)], &[(0,2,false,true),(3,3,true,false),(2,0,true,true),(2,3,false,false),(4,3,false,false)], 21),
        (&[(1,3,false,false),(4,2,true,true),(1,2,true,false),(4,3,false,false)], &[(1,3,false,false),(4,1,true,false),(3,3,false,true),(1,3,false,true),(2,1,true,false)], 35),
        (&[(5,5,false,true),(2,3,false,true),(3,4,false,false),(5,4,true,true),(3,2,false,false)], &[(1,2,false,true),(1,2,true,false),(1,1,false,false),(2,0,false,false),(0,0,false,true)], 34),
        (&[(5,4,false,false),(3,4,true,false),(5,4,true,true),(5,4,false,true),(2,4,true,false)], &[(1,1,false,false),(0,1,true,false),(2,1,false,false),(1,3,true,true),(4,2,false,false)], 38),
        (&[(2,1,false,false),(0,2,false,false),(2,0,false,false),(1,2,false,false),(1,1,true,false)], &[(5,4,false,false),(5,5,false,true),(4,5,true,true),(5,5,false,true),(5,5,true,false)], 56),
        (&[(1,3,false,false),(1,1,false,true),(3,0,true,false),(1,1,false,false),(2,3,true,true)], &[(5,5,false,true),(5,5,false,false),(3,4,false,false),(4,4,true,false),(5,4,true,false)], 40),
        (&[(3,4,false,false),(4,4,true,false),(6,5,false,true),(4,4,false,false),(4,4,false,true),(5,5,false,false)], &[(4,4,true,false),(4,4,false,false),(2,2,false,false),(5,4,false,false),(2,3,false,false)], 29),
        (&[(1,1,false,false),(2,1,false,true),(1,1,false,false),(2,1,true,true),(1,3,false,false),(0,0,true,false)], &[(5,4,true,false),(4,4,false,false),(3,5,true,false),(5,5,false,true),(4,3,false,false)], 41),
        (&[(0,2,true,true),(2,0,false,true),(2,1,true,false),(1,3,true,false),(4,4,false,false),(3,2,false,true)], &[(1,1,true,false),(1,1,false,false),(2,0,false,true),(0,0,false,false),(1,3,false,false)], 23),
        (&[(0,0,false,false),(1,1,true,false),(0,2,true,true),(0,0,true,false),(2,0,false,true),(0,0,false,false)], &[(5,2,false,false),(3,4,true,false),(4,4,true,false),(2,3,false,true),(3,4,false,false)], 33),
        (&[(5,5,false,false),(4,5,false,true),(4,3,false,false),(5,5,true,true),(5,5,false,false)], &[(5,5,false,false),(4,5,false,false),(4,5,false,false),(4,4,true,true),(4,3,true,true),(5,4,false,true)], 15),
        (&[(2,3,false,false),(2,2,false,true),(3,0,false,true),(1,0,true,false),(0,3,false,true)], &[(0,0,false,true),(1,0,false,false),(1,1,false,false),(2,0,false,true),(0,1,true,false),(0,2,true,false)], 19),
        (&[(5,4,true,true),(3,3,false,true),(5,5,true,true),(4,5,true,true),(5,5,false,false)], &[(1,4,false,true),(3,2,true,false),(3,3,false,true),(4,2,false,false),(1,2,true,true),(3,2,true,true)], 37),
        (&[(2,0,true,false),(0,0,false,false),(0,2,false,false),(0,1,false,true),(1,0,false,true)], &[(4,3,false,false),(5,4,false,true),(4,4,true,false),(3,5,true,false),(4,4,false,false),(5,5,false,false)], 49),
        (&[(3,2,true,true),(4,3,false,true),(2,3,false,false),(3,2,false,true),(4,2,false,true),(1,5,false,false)], &[(1,0,false,true),(0,1,true,true),(0,0,false,true),(1,0,true,false),(0,1,false,false),(1,1,false,true)], 32),
        (&[(1,0,true,false),(0,1,true,false),(0,1,true,true),(2,0,false,true),(1,2,false,true),(0,0,false,false)], &[(0,0,true,false),(1,1,false,true),(0,0,false,false),(1,1,true,false),(0,0,false,false),(2,2,false,false)], 14),
        (&[(6,6,true,false),(5,4,false,true),(3,5,true,false),(6,4,false,false),(5,5,false,false),(5,6,false,false)], &[(5,5,true,true),(4,6,false,true),(4,4,false,true),(4,5,false,false),(5,5,false,false),(6,3,true,true)], 68),
        (&[(3,4,false,false),(2,4,false,true),(2,2,false,true),(3,3,false,true),(3,1,true,true),(3,2,false,true)], &[(0,0,true,true),(0,0,false,true),(0,0,true,false),(0,0,false,true),(1,0,true,true),(0,1,true,true)], 38),
        (&[(4,2,false,false),(2,4,false,false),(6,3,true,false),(4,5,false,false),(5,6,false,false),(2,2,false,false),(2,3,false,false)], &[(1,2,true,false),(3,3,true,true),(3,2,false,false),(1,3,true,false),(4,2,false,true),(2,2,true,true)], 69),
        (&[(2,0,false,true),(4,5,false,true),(1,1,false,false),(0,2,false,true),(1,1,true,true),(3,2,false,true),(2,2,true,true)], &[(4,6,false,true),(4,5,true,true),(6,3,false,false),(4,5,false,false),(5,5,false,false),(6,5,true,true)], 55),
        (&[(2,4,false,true),(3,3,true,true),(5,2,false,true),(4,3,false,false),(5,4,false,false),(2,5,false,false),(2,2,false,false)], &[(4,4,false,false),(2,4,true,true),(3,3,false,false),(3,1,true,false),(2,3,false,true),(3,2,false,false)], 27),
        (&[(1,2,false,false),(2,4,false,true),(1,0,false,false),(3,1,true,false),(1,1,false,false),(1,1,true,false),(3,3,false,false)], &[(1,2,false,true),(3,1,false,true),(4,2,false,false),(1,1,true,false),(3,6,true,false),(3,3,false,false)], 21),
        (&[(3,1,true,false),(1,1,false,false),(1,3,false,false),(1,2,false,false),(0,1,false,false),(3,1,false,false)], &[(3,3,false,true),(1,2,true,false),(1,1,false,true),(2,3,false,false),(1,1,false,false),(4,2,true,false),(1,1,false,false)], 25),
        (&[(1,0,true,true),(0,0,false,false),(1,3,false,true),(1,1,false,true),(0,0,false,false),(1,0,false,false)], &[(2,4,false,false),(6,4,true,false),(3,5,true,true),(5,4,false,false),(5,4,false,false),(3,2,true,true),(2,3,false,false)], 61),
        (&[(3,3,false,false),(5,3,false,false),(2,2,true,false),(3,4,true,false),(2,2,false,false),(2,3,true,true)], &[(6,3,false,true),(7,7,false,false),(5,6,false,true),(6,6,false,false),(7,7,true,true),(5,6,true,false),(5,6,false,false)], 59),
        (&[(0,2,true,true),(2,3,true,false),(1,2,false,false),(2,0,true,false),(2,0,true,false),(1,1,false,false)], &[(2,1,true,true),(1,1,false,true),(2,3,false,false),(0,0,false,true),(0,1,false,false),(1,0,false,true),(0,0,false,false)], 25),
        (&[(1,3,true,true),(3,1,false,true),(3,2,true,true),(3,4,false,true),(3,3,false,true),(2,3,true,false),(4,3,false,false)], &[(4,7,false,false),(6,4,false,false),(5,6,true,false),(3,3,true,false),(4,3,false,true),(6,3,false,true),(3,5,false,false)], 58),
        (&[(0,1,false,true),(3,0,true,false),(1,3,false,false),(0,0,false,false),(1,0,false,true),(1,2,false,true),(0,0,false,true)], &[(3,3,true,true),(2,4,true,false),(3,3,false,false),(2,4,false,false),(1,1,false,true),(3,1,false,false),(4,2,false,false)], 38),
        (&[(3,3,true,false),(3,3,true,false),(4,2,false,false),(5,4,false,true),(2,3,false,true),(2,6,true,true),(4,2,false,true)], &[(2,5,false,true),(4,4,false,true),(4,3,true,false),(4,4,true,false),(5,3,false,true),(5,4,true,false),(4,5,false,false)], 30),
        (&[(4,3,false,true),(0,5,true,false),(4,4,false,false),(6,3,true,true),(3,3,false,false),(4,5,false,false),(3,1,false,false)], &[(7,7,true,true),(7,7,true,true),(5,4,true,false),(7,7,false,false),(6,7,false,true),(6,6,false,true),(7,7,true,false)], 84),
        (&[(3,1,false,true),(1,0,false,false),(1,1,true,false),(1,0,true,false),(1,2,false,true),(0,1,false,false),(0,0,false,false),(0,2,false,false)], &[(2,3,false,false),(1,5,false,false),(4,1,false,false),(5,2,false,false),(3,5,false,true),(3,3,true,true),(3,2,false,false)], 45),
        (&[(1,1,false,false),(1,2,false,false),(1,0,false,false),(1,0,false,false),(1,1,false,false),(1,1,true,false),(0,1,true,true),(1,1,false,true)], &[(2,2,true,false),(3,1,false,true),(1,1,true,false),(2,2,true,true),(3,4,false,false),(3,1,false,false),(1,4,true,false)], 29),
        (&[(2,2,false,false),(2,3,false,false),(3,5,false,false),(6,5,true,true),(6,3,false,true),(3,3,true,true),(4,1,false,true),(1,5,false,false)], &[(3,3,true,true),(4,4,false,true),(3,4,false,true),(6,6,false,false),(2,3,true,true),(3,4,true,false),(5,2,true,false)], 51),
        (&[(0,1,true,true),(1,2,false,true),(0,0,true,false),(1,1,false,false),(1,0,true,false),(0,0,false,false),(1,0,true,true),(1,1,false,false)], &[(7,1,false,false),(4,3,true,true),(2,3,true,true),(5,5,false,false),(2,5,true,false),(1,5,true,true),(3,2,true,false)], 47),
        (&[(8,8,true,true),(8,6,false,false),(7,6,false,true),(6,8,false,false),(6,8,true,false),(7,6,false,false),(4,7,true,false),(6,3,false,true)], &[(3,7,false,false),(6,6,false,false),(7,5,false,false),(6,4,false,false),(5,6,false,false),(6,5,true,false),(4,6,false,true),(8,6,false,false)], 82),
        (&[(1,1,true,false),(1,1,false,false),(1,0,true,true),(2,0,false,false),(0,0,true,false),(1,4,false,true),(1,2,false,true),(2,1,false,true)], &[(6,5,false,true),(2,5,false,false),(3,6,false,false),(5,4,false,true),(6,3,true,false),(5,4,false,false),(4,3,false,false),(3,4,false,true)], 56),
        (&[(0,0,false,false),(3,1,false,true),(2,1,false,true),(1,4,false,true),(0,2,false,false),(1,1,true,true),(1,2,false,true),(3,0,false,true)], &[(7,8,true,false),(7,5,true,true),(6,7,false,false),(5,5,false,true),(7,6,false,true),(6,7,false,false),(7,6,true,true),(7,8,false,false)], 106),
        (&[(6,3,true,true),(4,5,false,false),(5,6,false,true),(6,6,false,false),(7,6,false,true),(5,6,true,false),(8,7,false,false),(6,8,false,false)], &[(1,3,false,false),(3,1,false,false),(1,5,true,false),(4,3,false,false),(3,1,true,false),(2,2,true,false),(4,2,true,true),(1,2,false,false)], 76),
        (&[(4,4,false,false),(6,5,true,false),(7,5,false,false),(3,6,true,true),(2,4,false,false),(3,3,false,true),(7,5,false,false),(4,5,true,true),(3,2,false,true)], &[(5,5,false,true),(5,6,true,false),(4,5,true,true),(6,5,false,false),(5,5,false,false),(3,6,false,true),(5,3,true,false),(4,4,false,false),(6,4,false,false)], 36),
        (&[(3,2,true,false),(3,1,true,true),(2,5,false,false),(3,3,true,true),(3,2,false,false),(4,3,true,false),(1,2,false,true),(1,2,true,false),(3,3,false,true)], &[(6,4,false,false),(2,5,false,true),(3,2,false,false),(4,4,true,true),(4,5,false,true),(6,5,true,false),(5,4,false,false),(5,3,false,true),(4,7,true,true)], 54),
        (&[(4,4,false,false),(5,6,true,false),(4,3,false,true),(3,5,false,true),(8,6,false,true),(3,3,true,false),(3,1,false,false),(6,6,false,false),(3,5,true,false)], &[(5,3,true,false),(8,5,true,false),(5,3,true,false),(3,7,false,true),(3,4,true,false),(5,4,false,false),(3,7,false,true),(3,2,false,false),(4,4,true,false)], 52),
        (&[(5,4,true,false),(5,5,true,false),(7,5,false,false),(4,5,false,false),(6,7,true,true),(3,3,false,true),(6,4,false,false),(4,4,false,false),(4,7,false,true)], &[(4,3,false,false),(3,4,true,false),(4,3,false,false),(6,4,false,true),(2,8,false,false),(6,5,true,true),(6,7,true,false),(7,2,false,false),(3,5,false,false)], 38),
        (&[(7,6,true,false),(8,10,false,false),(10,9,true,false),(8,9,false,false),(10,8,false,true),(9,10,false,false),(10,7,true,false),(6,10,false,false),(9,8,false,false),(9,9,false,false)], &[(2,0,true,true),(1,1,true,false),(1,1,true,true),(1,0,false,true),(0,1,false,true),(0,4,false,true),(3,1,false,false),(1,1,false,true)], 182),
        (&[(1,3,false,true),(1,0,true,true),(4,4,false,true),(2,4,false,false),(2,2,false,false),(1,0,false,false),(2,0,false,false),(3,1,false,true),(2,2,true,false),(0,2,false,false)], &[(1,1,false,false),(1,3,false,true),(0,1,false,true),(0,1,false,false),(1,1,false,false),(1,1,false,false),(2,0,true,true),(2,0,false,true)], 26),
        (&[(2,4,false,false),(5,2,true,false),(5,4,false,false),(5,3,true,false),(2,4,false,false),(3,1,false,false),(1,4,false,false),(2,3,true,true),(4,5,true,false),(2,1,false,false)], &[(0,1,false,false),(1,0,true,false),(1,4,false,false),(0,0,true,false),(1,1,true,false),(1,0,true,true),(2,0,true,false),(2,2,false,false)], 50),
        (&[(8,5,false,false),(5,8,false,false),(9,8,true,true),(9,8,true,false),(10,7,false,false),(8,10,true,false),(7,9,true,false),(5,8,false,false),(8,7,false,true),(7,6,false,false)], &[(5,3,false,false),(2,4,false,false),(5,7,false,false),(6,4,true,false),(6,4,true,false),(7,4,false,false),(4,7,false,true),(4,6,false,false)], 76),
        (&[(0,2,true,true),(1,0,true,false),(1,5,false,false),(4,2,true,false),(2,1,false,false),(3,1,true,false),(3,3,true,false),(4,1,false,false),(2,2,false,true),(0,0,true,false),(1,3,false,false),(1,2,false,false)], &[(3,5,false,true),(3,4,false,false),(2,3,true,false),(5,2,false,true),(3,4,false,false),(2,1,false,true),(3,3,false,false),(3,2,true,false),(1,4,false,false),(3,2,true,false),(3,1,true,true)], 41),
        (&[(8,6,false,true),(7,7,true,true),(8,4,false,true),(4,6,false,false),(3,6,false,false),(7,6,false,true),(5,7,false,false),(7,4,false,false),(5,5,false,false),(4,8,false,false),(5,5,false,false),(6,5,false,true)], &[(8,11,false,false),(9,8,false,false),(9,6,true,true),(8,9,false,false),(8,8,false,false),(8,9,false,true),(8,9,true,true),(9,8,true,false),(9,7,true,false),(8,8,false,true),(9,10,false,true)], 135),
        (&[(10,11,true,false),(9,9,false,false),(11,11,false,false),(10,8,false,true),(9,10,false,false),(10,8,true,false),(8,10,true,true),(10,11,false,true),(7,8,true,true),(9,7,false,false),(12,9,false,true),(8,11,true,false)], &[(9,9,true,false),(10,8,false,false),(10,11,false,false),(10,11,true,false),(8,9,false,false),(9,8,true,true),(9,8,true,false),(9,10,true,true),(11,8,false,false),(6,10,false,false),(10,9,false,false)], 113),
        (&[(1,2,false,true),(2,4,true,false),(1,1,true,false),(1,2,true,false),(1,1,true,false),(1,1,false,false),(0,1,false,false),(5,3,true,false),(3,1,true,true),(2,2,true,false),(4,1,true,true),(0,2,false,true)], &[(2,1,false,false),(2,2,false,false),(1,2,false,false),(4,0,false,false),(1,2,false,true),(1,3,false,false),(2,0,false,false),(2,2,false,false),(3,2,true,true),(0,2,true,true),(0,2,false,false)], 69),
        (&[(1,0,true,true),(1,2,false,false)], &[(2,2,false,false),(2,1,true,false),(2,2,false,true),(0,1,false,true),(2,1,false,false),(0,1,false,true)], 20),
        (&[(1,1,true,false),(1,1,false,false)], &[(1,0,false,true),(0,0,true,false),(0,1,false,false),(1,0,false,false),(0,0,false,false),(0,1,false,false)], 10),
        (&[(1,1,false,false),(1,1,true,true)], &[(3,3,false,true),(3,2,true,false),(3,3,false,false),(3,3,true,false),(4,4,false,false),(3,4,false,false)], 44),
        (&[(0,0,true,false),(0,0,false,false)], &[(2,1,false,true),(4,5,false,false),(2,1,true,false),(3,4,true,false),(5,5,false,false),(4,4,false,false)], 44),
        (&[(3,2,false,false),(4,4,false,false),(2,5,true,true),(5,4,true,false),(5,4,true,false),(3,3,false,true)], &[(0,0,false,true),(0,0,true,true)], 48),
        (&[(0,1,true,false),(2,1,false,true),(0,1,false,false),(1,1,false,false),(2,1,false,false),(0,0,false,true)], &[(1,1,true,false),(0,0,false,true)], 14),
        (&[(2,1,true,true),(0,2,false,false),(4,1,false,true),(1,3,false,false),(2,1,false,false),(1,2,false,true)], &[(2,1,true,false),(0,1,false,false)], 28),
        (&[(1,2,true,true),(2,1,false,false),(2,2,false,true),(1,1,false,true),(1,1,false,false),(1,1,false,true)], &[(2,2,false,true),(2,2,true,false)], 22),
        (&[(1,1,true,false)], &[(3,1,false,false),(0,4,true,false),(4,0,false,true),(4,3,false,true),(0,2,false,false),(3,2,false,false),(1,3,true,false)], 34),
        (&[(1,1,true,false)], &[(6,6,true,false),(6,6,true,false),(6,5,false,false),(6,5,false,false),(4,6,true,false),(6,4,false,true),(4,6,false,true)], 80),
        (&[(1,1,true,false)], &[(1,2,true,true),(2,1,true,false),(3,3,true,true),(2,2,false,false),(2,3,false,true),(3,2,true,false),(3,3,true,false)], 36),
        (&[(1,1,true,false)], &[(4,4,false,false),(4,3,false,false),(2,2,false,true),(6,6,true,false),(3,3,false,false),(2,5,false,false),(5,3,false,true)], 56),
        (&[(0,1,true,false),(1,0,false,true)], &[(0,1,false,false),(1,0,false,false)], 8),
        (&[(0,1,true,false),(1,0,false,true)], &[(0,1,false,true),(1,0,true,false)], 4),
        (&[(0,1,true,true),(1,0,false,false)], &[(0,1,false,false),(1,0,true,true)], 4),
        (&[(1,1,true,false),(1,1,false,false),(1,1,false,true)], &[(1,1,false,false),(1,1,true,false),(1,1,false,true)], 0),
        (&[(0,0,true,true)], &[(0,0,false,false)], 2),
        (&[(0,0,true,false)], &[(0,0,false,true)], 2),
        (&[(1,1,true,false),(1,1,false,false),(1,1,false,false),(1,1,false,true)], &[(1,1,true,false),(1,1,false,false),(1,1,false,false),(1,1,false,true)], 0),
        (&[(1,2,true,false),(1,0,false,true)], &[(0,1,true,false),(2,1,false,true)], 4),
    ];

    #[test]
    fn matches_the_reference_implementation_on_every_recorded_vector() {
        assert!(
            REFERENCE_VECTORS.len() >= 120,
            "the vector table shrank: {} left",
            REFERENCE_VECTORS.len()
        );
        let mut mismatches = Vec::new();
        for (left, right, expected) in REFERENCE_VECTORS {
            let g1 = graph(left);
            let g2 = graph(right);
            let got = ged_exact(&g1, &g2);
            if got != *expected {
                mismatches.push(format!("{left:?} vs {right:?}: got {got}, want {expected}"));
            }
            // The reference is symmetric in its inputs; so are we.
            let flipped = ged_exact(&g2, &g1);
            if flipped != *expected {
                mismatches.push(format!(
                    "{right:?} vs {left:?} (flipped): got {flipped}, want {expected}"
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} reference mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    #[test]
    fn every_recorded_vector_is_also_the_exhaustive_optimum() {
        // Belt and braces: the stored values are not merely what our solver
        // says, they are the true optima of the matrices we build. This is the
        // test that would catch a shared bug between the matrix builder and
        // the solver only if the reference disagreed --- so it is paired with
        // the test above, not a substitute for it.
        for (left, right, expected) in REFERENCE_VECTORS {
            let matrix = cost_matrix(&graph(left), &graph(right));
            let k = matrix.order();
            if k == 0 || k > 12 {
                continue;
            }
            assert_eq!(
                optimum_by_subset_dp(matrix.cells(), k),
                *expected,
                "{left:?} vs {right:?}"
            );
        }
    }
}
