//! The derived-facts view of one function's CFG, built once per [`recover`].
//!
//! [`Cfg`] is the only thing in this module that *reads* an [`LlirFunction`]:
//! successors, predecessors, typed edges, dominators, post-dominators, branch
//! polarity and return/dispatch flags are all computed here, and every
//! recogniser, predicate and builder above is a pure question asked of the
//! result. Its reason to change is a new derived fact, or a cheaper way to
//! compute an existing one — the caching layer (the reachability closure and
//! the two natural-loop memos) exists for exactly that second reason and has
//! no other caller.
//!
//! [`natural_loop_body`] lives here rather than with the loop recognisers
//! because it is a graph walk that returns a block set, not a region: it is
//! the read side of the `(header, tail)` memo two fields below it.
//!
//! [`recover`]: super::recover

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::ir::ssa::SsaInfo;
use crate::ir::types::{CmpOp, LlirFunction, Op, Value, Width};
use crate::ir::use_def::InstrAddr;

/// A shared, immutable set of block indices — what the natural-loop memos hand
/// out. Shared rather than cloned because every consumer only reads it.
pub(super) type BlockSet = Rc<HashSet<usize>>;

/// Exact predicate facts recoverable from a conditional branch's SSA producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BranchPredicate {
    pub(crate) op: Option<CmpOp>,
    pub(crate) operand_width: Option<Width>,
    pub(crate) inverted: bool,
}

/// Lookup helpers built once per call to [`super::recover`].
pub(crate) struct Cfg {
    /// Block index → list of successor block indices.
    pub(crate) succs: Vec<Vec<usize>>,
    /// Block index → distinct successor position → jump-table labels.
    ///
    /// Graph algorithms need unique successor nodes, but switch recovery also
    /// needs every raw table slot. Keeping both views prevents equal targets
    /// from renumbering all later cases.
    pub(crate) case_labels: Vec<Vec<Vec<i64>>>,
    /// Block index → list of predecessor block indices.
    pub(crate) preds: Vec<Vec<usize>>,
    /// Cached: true iff block `a` dominates block `b`.
    /// We precompute a dense bitset because functions are small.
    dom: Vec<Vec<bool>>,
    /// Immediate post-dominator of each block (the nearest block through which
    /// every path from it to a function exit must pass), or `None` when the
    /// block has no post-dominator (e.g. it can diverge without reaching an
    /// exit). Used to recover conditional regions whose arms reconverge only at
    /// a distant join — the `-O0` switch/comparison-ladder shape.
    pub(super) ipostdom: Vec<Option<usize>>,
    /// For a block ending in a conditional branch, the successor index that is
    /// the branch's *taken* target (the `if (cond)` arm). `None` for blocks
    /// that don't end in a conditional branch. Lets conditional structuring put
    /// the taken arm in the `then` slot so the rendered condition polarity is
    /// correct regardless of block address ordering.
    pub(crate) cond_taken: Vec<Option<usize>>,
    /// Whether a block ends in an explicit machine return.
    ///
    /// A successor-free block can instead end in a non-returning call, trap, or
    /// tail transfer. Keeping that distinction prevents the structurer from
    /// treating two ordinary return arms like a cold non-returning guard merely
    /// because both have zero CFG successors.
    pub(crate) ends_in_return: Vec<bool>,
    /// Number of lifted instructions owned by each source block.
    ///
    /// Shadow cleanup uses this exact source measure to keep tail duplication
    /// bounded; rendered statement counts are a later, less stable view.
    pub(crate) block_instruction_counts: Vec<usize>,
    /// Whether the block ends in a resolved, index-bearing indirect transfer.
    /// Raw-loop lowering needs this stronger fact than the structural
    /// multi-successor switch fallback used for imported/synthetic CFGs.
    explicit_dispatch: Vec<bool>,
    /// Typed edges parallel to `succs`, OWNED here.
    ///
    /// The CFG is the thing that knows how control transfers, so it records it once
    /// rather than letting each consumer re-derive edge meaning from block order.
    /// Re-deriving is what inverted rotated-loop conditions: "successor 0 is the
    /// fallthrough" is a guess, and the branch's own target is a fact.
    pub(crate) edges: Vec<Vec<crate::ir::cfg_edges::Edge>>,
    /// Lazily-built reflexive-transitive reachability closure, one dense bitset
    /// row of `⌈n/64⌉` words per block: bit `t` of row `s` is set iff `t` is
    /// reachable from `s` (with `s` reachable from itself).
    ///
    /// [`super::path_predicates::can_reach`] used to run a fresh depth-first search, with a fresh
    /// `HashSet` allocation, on every call. It is asked the same question
    /// thousands of times per function: the shape predicates call it once per
    /// (loop header, body conditional, successor) triple, and reachability does
    /// not change while a `Cfg` is alive. Building the closure once turns each
    /// of those O(V+E) walks into one bit test.
    ///
    /// Lazy rather than eager because the majority of functions never ask: the
    /// predicates that call [`super::path_predicates::can_reach`] all sit behind a loop-detection guard,
    /// so a loop-free function must not pay for a closure nobody reads.
    reaches: std::cell::OnceCell<Vec<u64>>,
    /// Memo for [`natural_loop_body`], keyed by `(header, tail)`.
    ///
    /// The same pair is requested many times per function — the shape
    /// predicates iterate headers, and several of them then call a helper that
    /// rebuilds the *same* header's body once per block inside it. The set is a
    /// pure function of `preds`, so caching it changes nothing but the count.
    loop_bodies: std::cell::RefCell<HashMap<(usize, usize), BlockSet>>,
    /// Memo for [`Cfg::natural_loop_body_of`] — the union of every natural loop
    /// body headed at a block, keyed by that header.
    ///
    /// Four shape predicates and [`super::loop_shape::loop_break_shape`] open with
    /// the identical five lines: collect the dominating predecessors of `header`,
    /// then union
    /// their natural loop bodies. `loop_break_shape` runs them once per
    /// candidate conditional *within* the loop it is describing, so the union
    /// was rebuilt O(body) times per header even after the per-`(header, tail)`
    /// walk itself became a memo hit.
    header_loop_bodies: std::cell::RefCell<HashMap<usize, BlockSet>>,
}

impl Cfg {
    pub(crate) fn from(lf: &LlirFunction, ssa: &SsaInfo) -> Self {
        let n = lf.blocks.len();
        let va_to_idx: HashMap<u64, usize> = lf
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start_va, i))
            .collect();
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut case_labels: Vec<Vec<Vec<i64>>> = vec![Vec::new(); n];
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, b) in lf.blocks.iter().enumerate() {
            for s_va in &b.succs {
                if let Some(&j) = va_to_idx.get(s_va) {
                    succs[i].push(j);
                    preds[j].push(i);
                }
            }
        }
        // Successor order is semantic for a jump table: raw entry N is source
        // `case N`. Graph algorithms still need distinct successor nodes, so
        // group the labels for repeated targets while retaining first-target
        // order. This is the same two-view split used by Ghidra's address-table
        // plus block-to-index map and angr's case-value-to-entry map.
        for (block_index, successors) in succs.iter_mut().enumerate() {
            let raw = std::mem::take(successors);
            let mut target_positions: HashMap<usize, usize> = HashMap::new();
            for (label, successor) in raw.into_iter().enumerate() {
                if let Some(position) = target_positions.get(&successor).copied() {
                    case_labels[block_index][position].push(label as i64);
                } else {
                    let position = successors.len();
                    target_positions.insert(successor, position);
                    successors.push(successor);
                    case_labels[block_index].push(vec![label as i64]);
                }
            }
        }
        for predecessors in &mut preds {
            predecessors.sort_unstable();
            predecessors.dedup();
        }

        // Materialise the dominance relation from idom chains.
        let mut dom: Vec<Vec<bool>> = vec![vec![false; n]; n];
        for i in 0..n {
            // Every reachable block is dominated by itself (entry included).
            // Unreachable blocks (idom == None && i != 0) are handled by
            // leaving their row all-false, which causes structural analysis
            // to treat them as isolated and bucket them into Unstructured.
            if i == 0 || ssa.idom.get(i).and_then(|x| *x).is_some() {
                let mut cur = Some(i);
                while let Some(c) = cur {
                    dom[c][i] = true;
                    if c == 0 {
                        break;
                    }
                    cur = ssa.idom.get(c).and_then(|x| *x);
                }
            }
        }
        let ipostdom = compute_ipostdom(n, &succs);
        let ends_in_return = lf
            .blocks
            .iter()
            .map(|block| {
                block
                    .instrs
                    .last()
                    .is_some_and(|instr| instr.op.is_unconditional_return())
            })
            .collect();
        let block_instruction_counts = lf.blocks.iter().map(|block| block.instrs.len()).collect();
        let explicit_dispatch = lf
            .blocks
            .iter()
            .map(|block| {
                block.instrs.last().is_some_and(|instruction| {
                    matches!(
                        instruction.op,
                        crate::ir::types::Op::IndirectJump { index: Some(_), .. }
                    )
                })
            })
            .collect();
        // Record each conditional block's taken-branch successor index.
        let mut cond_taken: Vec<Option<usize>> = vec![None; n];
        for (i, b) in lf.blocks.iter().enumerate() {
            if let Some(crate::ir::types::LlirInstr {
                op: crate::ir::types::Op::CondJump { target, .. },
                ..
            }) = b.instrs.last()
            {
                cond_taken[i] = va_to_idx.get(target).copied();
            }
        }
        // Typed edges, computed once from the graph this Cfg describes.
        let edges = {
            let d =
                |a: usize, b: usize| dom.get(a).and_then(|r| r.get(b)).copied().unwrap_or(false);
            crate::ir::cfg_edges::classify(lf, &succs, d)
        };
        Cfg {
            succs,
            case_labels,
            preds,
            dom,
            ipostdom,
            cond_taken,
            ends_in_return,
            block_instruction_counts,
            explicit_dispatch,
            edges,
            reaches: std::cell::OnceCell::new(),
            loop_bodies: std::cell::RefCell::new(HashMap::new()),
            header_loop_bodies: std::cell::RefCell::new(HashMap::new()),
        }
    }

    /// Derive exact predicate facts only when the shadow structurer asks.
    pub(crate) fn branch_predicates(
        &self,
        lf: &LlirFunction,
        ssa: &SsaInfo,
    ) -> Vec<Option<BranchPredicate>> {
        let mut comparisons = HashMap::new();
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            for (instr_idx, instruction) in block.instrs.iter().enumerate() {
                let Op::Cmp { op, lhs, rhs, .. } = &instruction.op else {
                    continue;
                };
                let addr = InstrAddr {
                    block_idx,
                    instr_idx,
                };
                if let Some(value) = ssa.def_value_ref(lf, addr) {
                    comparisons.insert(value.clone(), (*op, comparison_operand_width(lhs, rhs)));
                }
            }
        }

        let mut predicates = vec![None; self.succs.len()];
        for (block_idx, block) in lf.blocks.iter().enumerate() {
            let Some((
                instr_idx,
                crate::ir::types::LlirInstr {
                    op: Op::CondJump { inverted, .. },
                    ..
                },
            )) = block.instrs.iter().enumerate().next_back()
            else {
                continue;
            };
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let comparison = ssa
                .use_value_ref(lf, addr, 0)
                .and_then(|value| comparisons.get(value));
            predicates[block_idx] = Some(BranchPredicate {
                op: comparison.map(|(op, _)| *op),
                operand_width: comparison.and_then(|(_, width)| *width),
                inverted: *inverted,
            });
        }
        predicates
    }

    /// The predecessors of `header` that `header` dominates — the back-edge
    /// tails, i.e. the latches of the natural loops headed there.
    pub(crate) fn dominating_tails(&self, header: usize) -> Vec<usize> {
        self.preds[header]
            .iter()
            .copied()
            .filter(|&tail| self.dominates(header, tail))
            .collect()
    }

    /// `header` plus every block of every natural loop headed at it, memoised.
    ///
    /// Empty (not even `header`) when there is no back edge, which is the same
    /// thing the open-coded `if tails.is_empty() { continue; }` guard tested
    /// for; callers that need to distinguish "no loop" still consult
    /// [`Cfg::dominating_tails`] themselves.
    pub(crate) fn natural_loop_body_of(&self, header: usize) -> BlockSet {
        // The borrow is scoped to this statement on purpose: the miss path
        // below calls `natural_loop_body`, which borrows the sibling memo, and
        // `borrow_mut()`s this one at the end. Holding a read guard across
        // either would be a runtime panic rather than a compile error.
        let cached = self.header_loop_bodies.borrow().get(&header).cloned();
        if let Some(cached) = cached {
            return cached;
        }
        let mut body = HashSet::new();
        for tail in self.dominating_tails(header) {
            body.extend(natural_loop_body(header, tail, self).iter().copied());
        }
        let body = Rc::new(body);
        self.header_loop_bodies
            .borrow_mut()
            .insert(header, Rc::clone(&body));
        body
    }

    /// The memoised natural loop body for `(header, tail)`, if already built.
    fn cached_natural_loop_body(&self, header: usize, tail: usize) -> Option<BlockSet> {
        self.loop_bodies.borrow().get(&(header, tail)).cloned()
    }

    /// Record a freshly walked natural loop body and hand back the shared copy.
    fn store_natural_loop_body(
        &self,
        header: usize,
        tail: usize,
        body: HashSet<usize>,
    ) -> BlockSet {
        let body = Rc::new(body);
        self.loop_bodies
            .borrow_mut()
            .insert((header, tail), Rc::clone(&body));
        body
    }

    pub(crate) fn dominates(&self, a: usize, b: usize) -> bool {
        self.dom[a][b]
    }

    /// Number of `u64` words in one row of the reachability closure.
    fn reach_words(&self) -> usize {
        self.succs.len().div_ceil(64).max(1)
    }

    /// The reachability closure, built on first use.
    ///
    /// `reaches[s] = {s} ∪ ⋃ reaches[t] for t ∈ succs[s]`, iterated to a true
    /// fixpoint (no sweep cap — this is a cache of an exact depth-first search
    /// and a truncated one would answer differently). Sweeping in descending
    /// block index makes it converge in a couple of passes on the
    /// forward-biased graphs a lifter produces, while remaining correct for
    /// back edges and irreducible entries because the loop runs until nothing
    /// changes.
    fn reachability(&self) -> &[u64] {
        self.reaches.get_or_init(|| {
            let n = self.succs.len();
            let words = self.reach_words();
            let mut reaches = vec![0u64; n * words];
            for s in 0..n {
                reaches[s * words + s / 64] |= 1u64 << (s % 64);
            }
            let mut scratch = vec![0u64; words];
            let mut changed = true;
            while changed {
                changed = false;
                for s in (0..n).rev() {
                    scratch.copy_from_slice(&reaches[s * words..(s + 1) * words]);
                    for &t in &self.succs[s] {
                        let row = &reaches[t * words..(t + 1) * words];
                        for (accumulated, &incoming) in scratch.iter_mut().zip(row) {
                            *accumulated |= incoming;
                        }
                    }
                    let current = &mut reaches[s * words..(s + 1) * words];
                    if current != scratch.as_slice() {
                        current.copy_from_slice(&scratch);
                        changed = true;
                    }
                }
            }
            reaches
        })
    }

    /// Whether `target` is reachable from `start` (reflexively).
    pub(super) fn can_reach(&self, start: usize, target: usize) -> bool {
        let words = self.reach_words();
        self.reachability()[start * words + target / 64] & (1u64 << (target % 64)) != 0
    }

    pub(super) fn is_switch_dispatch(&self, block: usize) -> bool {
        !self.edges[block].is_empty()
            && self.edges[block]
                .iter()
                .all(|edge| edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchCase)
    }

    pub(super) fn is_explicit_switch_dispatch(&self, block: usize) -> bool {
        self.explicit_dispatch[block] && self.is_switch_dispatch(block)
    }
}

fn comparison_operand_width(lhs: &Value, rhs: &Value) -> Option<Width> {
    let lhs = match lhs {
        Value::Reg(register) => register.width(),
        Value::Const(_) | Value::Addr(_) => None,
    };
    let rhs = match rhs {
        Value::Reg(register) => register.width(),
        Value::Const(_) | Value::Addr(_) => None,
    };
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) if lhs == rhs => Some(lhs),
        (Some(width), None) | (None, Some(width)) => Some(width),
        _ => None,
    }
}

/// The blocks of the natural loop with the given `header` and back-edge `tail`:
/// `header` itself plus every block that can reach `tail` by walking
/// predecessors without going through `header`.
///
/// Memoised on the `Cfg`, which is why this hands back a shared `Rc` rather than
/// a fresh set. The body of one `(header, tail)` pair is a pure function of the
/// graph, and the shape predicates ask for the *same* pair over and over: the
/// worst offender was [`super::loop_shape::loop_break_shape`], which rebuilt the
/// entire natural loop of `header` once per candidate conditional *inside* that
/// same loop, so recognising one loop cost O(body²) predecessor walks. Every
/// caller
/// only reads the set (`contains`, `extend`, `iter`), so sharing is invisible
/// to them.
pub(super) fn natural_loop_body(header: usize, tail: usize, cfg: &Cfg) -> BlockSet {
    // `cached_natural_loop_body` returns an owned `Option<Rc<_>>` so no read
    // guard survives into the walk below, which ends in a `borrow_mut()`.
    if let Some(cached) = cfg.cached_natural_loop_body(header, tail) {
        return cached;
    }
    let mut body = HashSet::new();
    body.insert(header);
    let mut stack = vec![tail];
    while let Some(n) = stack.pop() {
        if body.insert(n) {
            for &p in &cfg.preds[n] {
                if p != header {
                    stack.push(p);
                }
            }
        }
    }
    cfg.store_natural_loop_body(header, tail, body)
}

/// Immediate post-dominators via an iterative set fixpoint on the reversed CFG.
/// `pdom[n] = {n} ∪ (⋂ over succs s of pdom[s])`, seeded so exit blocks
/// post-dominate only themselves; a node whose successors never converge (can
/// diverge without exiting) keeps no post-dominator (`None`).
///
/// The sets are dense bitsets — one row of `⌈n/64⌉` words per block, stored in a
/// single flat allocation — rather than one `BTreeSet` per block. The fixpoint
/// is unchanged: same seeding, same Gauss-Seidel sweep in index order, same
/// `n + 4` sweep guard, same "last of the equal maxima" tie-break when picking
/// the immediate post-dominator. Only the representation moved.
///
/// **Why this is not a micro-optimisation.** A `BTreeSet` round of `clone()` +
/// `intersection().collect()` allocates a fresh node per element, so one sweep
/// over one block costs O(|pdom|) allocations and the whole fixpoint costs
/// O(sweeps · n · n) of them. That is the entire superlinear curve in region
/// recovery: measured at `047ccfe4`, this function was 16.5 ms of the 21.5 ms
/// `structure::recover` spent on the 601-block `wide154_sparse_switch`
/// (~2.9 M allocations over 4 sweeps).
///
/// It is also the *shape* anomaly, not just the size one. The sweep count is
/// driven by loop-nesting depth, because a Gauss-Seidel pass in index order
/// propagates post-dominance one nesting level at a time: 50-block
/// `deep152_nested_loops` (twelve nested loops) needs **26** sweeps where
/// 34-block `deep152_conditional_tower` needs **4**. With `BTreeSet` rows those
/// 26 sweeps cost 726 µs — 73% of that lane's `recover` — which is why a
/// 50-block function was costing 41x a 34-block one. Word-at-a-time rows make a
/// sweep ~O(n²/64) branch-free word ops with no allocation at all, so the depth
/// factor stops being expensive instead of the sweep count having to shrink.
fn compute_ipostdom(n: usize, succs: &[Vec<usize>]) -> Vec<Option<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let words = n.div_ceil(64);

    // Row-major dense bitset: block `i` owns `pdom[i * words .. (i + 1) * words]`.
    // Bits at index >= n are never set, so `count_ones` is an exact cardinality
    // and row equality is exact set equality.
    let mut pdom = vec![0u64; n * words];
    let mut universe = vec![u64::MAX; words];
    if !n.is_multiple_of(64) {
        // Mask the tail word so no bit above `n - 1` is ever set.
        universe[words - 1] = (1u64 << (n % 64)) - 1;
    }
    for i in 0..n {
        let row = &mut pdom[i * words..(i + 1) * words];
        if succs[i].is_empty() {
            // An exit post-dominates only itself.
            row[i / 64] = 1u64 << (i % 64);
        } else {
            row.copy_from_slice(&universe);
        }
    }

    let mut next = vec![0u64; words];
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < n + 4 {
        changed = false;
        guard += 1;
        for i in 0..n {
            if succs[i].is_empty() {
                continue;
            }
            // next = ⋂ pdom[s] over successors, then ∪ {i}.
            let mut first = true;
            for &s in &succs[i] {
                let row = &pdom[s * words..(s + 1) * words];
                if first {
                    next.copy_from_slice(row);
                    first = false;
                } else {
                    for (accumulated, &incoming) in next.iter_mut().zip(row) {
                        *accumulated &= incoming;
                    }
                }
            }
            next[i / 64] |= 1u64 << (i % 64);
            let current = &mut pdom[i * words..(i + 1) * words];
            if current != next.as_slice() {
                current.copy_from_slice(&next);
                changed = true;
            }
        }
    }

    // ipostdom[n] = the closest strict post-dominator: the member of
    // pdom[n]\{n} with the largest pdom set (deepest in the post-dom tree).
    let cardinality: Vec<u32> = (0..n)
        .map(|i| {
            pdom[i * words..(i + 1) * words]
                .iter()
                .map(|word| word.count_ones())
                .sum()
        })
        .collect();
    (0..n)
        .map(|i| {
            let mut best: Option<usize> = None;
            let mut best_cardinality = 0u32;
            for (word_index, &word) in pdom[i * words..(i + 1) * words].iter().enumerate() {
                let mut remaining = word;
                while remaining != 0 {
                    let p = word_index * 64 + remaining.trailing_zeros() as usize;
                    remaining &= remaining - 1;
                    // `>=`, not `>`: members are visited in ascending index
                    // order and `Iterator::max_by_key` keeps the *last* of
                    // several equal maxima. Using `>` would pick a different
                    // post-dominator on ties and silently reshape conditionals.
                    if p != i && (best.is_none() || cardinality[p] >= best_cardinality) {
                        best = Some(p);
                        best_cardinality = cardinality[p];
                    }
                }
            }
            best
        })
        .collect()
}
