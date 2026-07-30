//! Structural analysis — recover high-level control-flow structures from an
//! [`LlirFunction`]'s CFG.
//!
//! The output is a [`Region`] tree: a compact description of the function's
//! control flow in terms of sequences, conditionals, and natural loops. This
//! is the substrate a future decompiler AST pass will consume.
//!
//! Scope (v1):
//!
//! * Straight-line sequences (`Seq`).
//! * Single-entry diamond `if-then` and `if-then-else` with a common join.
//! * Natural loops with a single back-edge and a single header (`While` and
//!   `DoWhile`).
//! * Anything else is preserved as [`Region::Unstructured`] carrying the raw
//!   block indices so no control flow is ever silently dropped.
//!
//! The algorithm walks the CFG from the entry block, pattern-matching on
//! successor counts and dominator info. It is intentionally simple and
//! conservative; irreducible or heavily goto-laden code degrades gracefully
//! to `Unstructured`.

use std::collections::{HashMap, HashSet};

use crate::ir::ssa::SsaInfo;
use crate::ir::types::LlirFunction;

/// One structured region in the recovered tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Region {
    /// A single basic block, referenced by its index in `LlirFunction::blocks`.
    Block(usize),
    /// Straight-line sequence — the regions execute in order.
    Seq(Vec<Region>),
    /// `if (cond) then { then_r }` — no else arm. `join` is the merge block
    /// that control rejoins after the conditional, or `None` if the `then`
    /// arm exits the function without returning to a join.
    IfThen {
        cond: usize,
        then_r: Box<Region>,
        join: Option<usize>,
        /// When true the lowered condition must be negated: `then_r`'s entry is
        /// the branch's *fall-through* arm, not its *taken* arm, so the raw
        /// condition (which is true when the branch is taken) points the wrong
        /// way. Set from `cond_taken` so polarity survives block-index ordering.
        invert: bool,
    },
    /// `if (cond) then { then_r } else { else_r }` joining at `join`.
    IfThenElse {
        cond: usize,
        then_r: Box<Region>,
        else_r: Box<Region>,
        join: Option<usize>,
        /// See [`Region::IfThen::invert`].
        invert: bool,
    },
    /// `while (...) { body }` — header branches to body or exit; body's
    /// back-edge returns to header.
    While {
        header: usize,
        body: Box<Region>,
        exit: Option<usize>,
    },
    /// `do { body } while (cond)` — the conditional block is the loop latch,
    /// so the body executes before the condition on every iteration.
    DoWhile {
        body: Box<Region>,
        cond: usize,
        exit: Option<usize>,
    },
    /// `switch (discriminant) { case 0: <arm>; case 1: <arm>; ... }`
    /// (#193). The dispatch block has N>=3 successors (typical jump-
    /// table dispatch); each arm is a sub-region; the join is the
    /// shared post-dominator if one exists.
    Switch {
        dispatch: usize,
        /// Normalized case labels attached to each distinct arm, parallel to
        /// `arms`. Multiple table slots may target one block after compiler
        /// case folding, so one arm can own several labels.
        case_labels: Vec<Vec<i64>>,
        arms: Vec<Region>,
        join: Option<usize>,
    },
    /// `goto <block>;` — an explicit jump to a block that is emitted (with a
    /// label) elsewhere. Used when a conditional arm targets a *shared* join
    /// block already consumed by a sibling arm: rather than drop the edge into an
    /// empty arm (the short-circuit `&&`/`||` bug), we reference the shared block
    /// so control still reaches it. The block's statements render exactly once at
    /// their natural position; every other incoming edge is a `Goto` to its label.
    Goto(usize),
    /// Fallback — a set of blocks that didn't fit any recognised pattern.
    Unstructured(Vec<usize>),
}

impl Region {
    /// Yield every block index referenced by this region (DFS order). Used to
    /// verify that structural analysis doesn't silently lose blocks.
    pub fn blocks(&self) -> Vec<usize> {
        fn walk(r: &Region, out: &mut Vec<usize>) {
            match r {
                Region::Block(b) => out.push(*b),
                Region::Seq(parts) => {
                    for p in parts {
                        walk(p, out);
                    }
                }
                Region::IfThen {
                    cond, then_r, join, ..
                } => {
                    out.push(*cond);
                    walk(then_r, out);
                    if let Some(j) = join {
                        out.push(*j);
                    }
                }
                Region::IfThenElse {
                    cond,
                    then_r,
                    else_r,
                    join,
                    ..
                } => {
                    out.push(*cond);
                    walk(then_r, out);
                    walk(else_r, out);
                    if let Some(j) = join {
                        out.push(*j);
                    }
                }
                Region::While { header, body, exit } => {
                    out.push(*header);
                    walk(body, out);
                    if let Some(e) = exit {
                        out.push(*e);
                    }
                }
                Region::DoWhile { body, cond, exit } => {
                    walk(body, out);
                    out.push(*cond);
                    if let Some(e) = exit {
                        out.push(*e);
                    }
                }
                Region::Switch {
                    dispatch,
                    arms,
                    join,
                    ..
                } => {
                    out.push(*dispatch);
                    for a in arms {
                        walk(a, out);
                    }
                    if let Some(j) = join {
                        out.push(*j);
                    }
                }
                Region::Goto(b) => out.push(*b),
                Region::Unstructured(bs) => out.extend(bs.iter().copied()),
            }
        }
        let mut v = Vec::new();
        walk(self, &mut v);
        v
    }
}

/// Lookup helpers built once per call to [`recover`].
struct Cfg {
    /// Block index → list of successor block indices.
    succs: Vec<Vec<usize>>,
    /// Block index → distinct successor position → jump-table labels.
    ///
    /// Graph algorithms need unique successor nodes, but switch recovery also
    /// needs every raw table slot. Keeping both views prevents equal targets
    /// from renumbering all later cases.
    case_labels: Vec<Vec<Vec<i64>>>,
    /// Block index → list of predecessor block indices.
    preds: Vec<Vec<usize>>,
    /// Cached: true iff block `a` dominates block `b`.
    /// We precompute a dense bitset because functions are small.
    dom: Vec<Vec<bool>>,
    /// Immediate post-dominator of each block (the nearest block through which
    /// every path from it to a function exit must pass), or `None` when the
    /// block has no post-dominator (e.g. it can diverge without reaching an
    /// exit). Used to recover conditional regions whose arms reconverge only at
    /// a distant join — the `-O0` switch/comparison-ladder shape.
    ipostdom: Vec<Option<usize>>,
    /// For a block ending in a conditional branch, the successor index that is
    /// the branch's *taken* target (the `if (cond)` arm). `None` for blocks
    /// that don't end in a conditional branch. Lets conditional structuring put
    /// the taken arm in the `then` slot so the rendered condition polarity is
    /// correct regardless of block address ordering.
    cond_taken: Vec<Option<usize>>,
    /// Whether a block ends in an explicit machine return.
    ///
    /// A successor-free block can instead end in a non-returning call, trap, or
    /// tail transfer. Keeping that distinction prevents the structurer from
    /// treating two ordinary return arms like a cold non-returning guard merely
    /// because both have zero CFG successors.
    ends_in_return: Vec<bool>,
    /// Typed edges parallel to `succs`, OWNED here.
    ///
    /// The CFG is the thing that knows how control transfers, so it records it once
    /// rather than letting each consumer re-derive edge meaning from block order.
    /// Re-deriving is what inverted rotated-loop conditions: "successor 0 is the
    /// fallthrough" is a guess, and the branch's own target is a fact.
    edges: Vec<Vec<crate::ir::cfg_edges::Edge>>,
}

impl Cfg {
    fn from(lf: &LlirFunction, ssa: &SsaInfo) -> Self {
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
                    .is_some_and(|instr| matches!(instr.op, crate::ir::types::Op::Return))
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
            edges,
        }
    }

    fn dominates(&self, a: usize, b: usize) -> bool {
        self.dom[a][b]
    }
}

/// Immediate post-dominators via an iterative set fixpoint on the reversed CFG.
/// Blocks are few, so a dense set-per-node fixpoint is simplest and fast enough.
/// `pdom[n] = {n} ∪ (⋂ over succs s of pdom[s])`, seeded so exit blocks
/// post-dominate only themselves; a node whose successors never converge (can
/// diverge without exiting) keeps no post-dominator (`None`).
fn compute_ipostdom(n: usize, succs: &[Vec<usize>]) -> Vec<Option<usize>> {
    use std::collections::BTreeSet;
    let universe: BTreeSet<usize> = (0..n).collect();
    let mut pdom: Vec<BTreeSet<usize>> = (0..n)
        .map(|i| {
            if succs[i].is_empty() {
                let mut s = BTreeSet::new();
                s.insert(i);
                s
            } else {
                universe.clone()
            }
        })
        .collect();
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < n + 4 {
        changed = false;
        guard += 1;
        for i in 0..n {
            if succs[i].is_empty() {
                continue;
            }
            let mut inter: Option<BTreeSet<usize>> = None;
            for &s in &succs[i] {
                inter = Some(match inter {
                    None => pdom[s].clone(),
                    Some(acc) => acc.intersection(&pdom[s]).copied().collect(),
                });
            }
            let mut new = inter.unwrap_or_default();
            new.insert(i);
            if new != pdom[i] {
                pdom[i] = new;
                changed = true;
            }
        }
    }
    // ipostdom[n] = the closest strict post-dominator: the member of
    // pdom[n]\{n} with the largest pdom set (deepest in the post-dom tree).
    (0..n)
        .map(|i| {
            pdom[i]
                .iter()
                .filter(|&&p| p != i)
                .max_by_key(|&&p| pdom[p].len())
                .copied()
        })
        .collect()
}

/// Single public entry point — build a region tree for the function.
pub fn recover(lf: &LlirFunction, ssa: &SsaInfo) -> Region {
    if lf.blocks.is_empty() {
        return Region::Unstructured(Vec::new());
    }
    let cfg = Cfg::from(lf, ssa);
    build_full(lf, &cfg)
}

fn flatten_seq(r: Region) -> Vec<Region> {
    match r {
        Region::Seq(parts) => parts,
        other => vec![other],
    }
}

// ---------------------------------------------------------------------------
// Structure verifier (semantics-preserving-structuring §5)
// ---------------------------------------------------------------------------

/// A structural-analysis invariant violation. A non-empty result means the
/// region tree does not faithfully represent the CFG — control flow was dropped
/// or mis-attached, which renders as missing/empty branches (e.g. the
/// short-circuit `&&`/`||` empty-arm bug). This is the check the design doc asks
/// to run before/around the structurer so silent corruption becomes loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructError {
    /// A block reachable in the CFG never appears in the region tree.
    BlockDropped { block: usize },
    /// A conditional block's CFG successor edge is represented by neither an arm
    /// nor the join — the branch to it is silently dropped (empty arm).
    CondEdgeUncovered { cond: usize, missing_succ: usize },
}

/// The first block a region begins executing at, or `None` if the region is
/// empty (renders nothing). Public so the AST lowerer can place a `goto` label
/// on whichever region (Block or a structured `if`/`while`) *begins* at a target.
pub fn entry_block(r: &Region) -> Option<usize> {
    match r {
        Region::Block(b) => Some(*b),
        Region::Seq(parts) => parts.iter().find_map(entry_block),
        Region::IfThen { cond, .. } | Region::IfThenElse { cond, .. } => Some(*cond),
        Region::While { header, .. } => Some(*header),
        Region::DoWhile { body, cond, .. } => entry_block(body).or(Some(*cond)),
        Region::Switch { dispatch, .. } => Some(*dispatch),
        Region::Goto(b) => Some(*b),
        Region::Unstructured(bs) => bs.first().copied(),
    }
}

/// Verify a region tree against the CFG successor relation. Pure over `succs`
/// so it is unit-testable without SSA/dominators.
///
/// Invariants:
///  * **block coverage** — every block reachable from `entry` appears at least
///    once in the region tree;
///  * **conditional edge coverage** — for every `IfThen`/`IfThenElse`, each of
///    the condition block's two CFG successors is represented (as an arm entry
///    or, for `IfThen`, the join). A successor represented by neither is an
///    uncovered edge — the branch is dropped and that arm renders empty.
pub fn verify_region(succs: &[Vec<usize>], entry: usize, region: &Region) -> Vec<StructError> {
    let mut errors = Vec::new();

    // Block coverage.
    let reachable = {
        let mut seen = HashSet::new();
        let mut stack = vec![entry];
        while let Some(b) = stack.pop() {
            if b < succs.len() && seen.insert(b) {
                stack.extend(succs[b].iter().copied());
            }
        }
        seen
    };
    let present: HashSet<usize> = region.blocks().into_iter().collect();
    let mut dropped: Vec<usize> = reachable.difference(&present).copied().collect();
    dropped.sort_unstable();
    for b in dropped {
        errors.push(StructError::BlockDropped { block: b });
    }

    // Conditional edge coverage.
    fn walk(r: &Region, succs: &[Vec<usize>], out: &mut Vec<StructError>) {
        match r {
            Region::Seq(parts) => parts.iter().for_each(|p| walk(p, succs, out)),
            Region::IfThenElse {
                cond,
                then_r,
                else_r,
                ..
            } => {
                let covered: HashSet<usize> = [entry_block(then_r), entry_block(else_r)]
                    .into_iter()
                    .flatten()
                    .collect();
                report_uncovered(*cond, succs, &covered, out);
                walk(then_r, succs, out);
                walk(else_r, succs, out);
            }
            Region::IfThen {
                cond, then_r, join, ..
            } => {
                let mut covered: HashSet<usize> = HashSet::new();
                covered.extend(entry_block(then_r));
                covered.extend(*join);
                // With no join the second edge is the (non-local) continuation;
                // only require the then-arm edge to be represented.
                if join.is_some() {
                    report_uncovered(*cond, succs, &covered, out);
                } else if let Some(e) = entry_block(then_r) {
                    if e < succs.len() && !succs[*cond].contains(&e) {
                        out.push(StructError::CondEdgeUncovered {
                            cond: *cond,
                            missing_succ: e,
                        });
                    }
                }
                walk(then_r, succs, out);
            }
            Region::While { body, .. } => walk(body, succs, out),
            Region::DoWhile { body, cond, exit } => {
                let mut covered: HashSet<usize> = HashSet::new();
                covered.extend(entry_block(body).or(Some(*cond)));
                covered.extend(*exit);
                report_uncovered(*cond, succs, &covered, out);
                walk(body, succs, out);
            }
            Region::Switch { arms, .. } => arms.iter().for_each(|a| walk(a, succs, out)),
            Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => {}
        }
    }
    fn report_uncovered(
        cond: usize,
        succs: &[Vec<usize>],
        covered: &HashSet<usize>,
        out: &mut Vec<StructError>,
    ) {
        if cond >= succs.len() {
            return;
        }
        for &s in &succs[cond] {
            if !covered.contains(&s) {
                out.push(StructError::CondEdgeUncovered {
                    cond,
                    missing_succ: s,
                });
            }
        }
    }
    walk(region, succs, &mut errors);
    errors
}

/// Verify the region tree [`recover`] produces for `lf`. Empty == the structure
/// faithfully covers every reachable block and conditional edge.
pub fn verify_structure(lf: &LlirFunction, ssa: &SsaInfo) -> Vec<StructError> {
    if lf.blocks.is_empty() {
        return Vec::new();
    }
    let cfg = Cfg::from(lf, ssa);
    let region = recover(lf, ssa);
    verify_region(&cfg.succs, 0, &region)
}

/// [`recover`] plus a non-fatal structural self-check: any invariant violation
/// (dropped block / uncovered conditional edge — e.g. the short-circuit empty-arm
/// bug) is emitted as a `tracing` diagnostic rather than reaching the rendered
/// output silently. Non-fatal by design while the known structurer defects are
/// burned down (see docs/design/semantics-preserving-structuring.md); the total
/// structurer will make these hard failures. This is the single production entry
/// the decompile paths should call.
pub fn recover_verified(lf: &LlirFunction, ssa: &SsaInfo) -> Region {
    let cfg = Cfg::from(lf, ssa);
    let region = build_full(lf, &cfg);
    let errors = verify_region(&cfg.succs, 0, &region);
    if !errors.is_empty() {
        tracing::debug!(
            entry_va = format_args!("{:#x}", lf.entry_va),
            count = errors.len(),
            "structure verifier: {} unfaithful region(s): {:?}",
            errors.len(),
            errors
        );
    }
    // Full structural accounting, SHADOW ONLY: every block and every typed edge, in
    // both directions (a CFG edge the tree does not express, and an edge the tree
    // claims that does not exist). It reports strictly more than the check above —
    // on the clang -O0 `statemachine` shape that one is silent — so it runs behind
    // an env var until a region analysis can act on it. Nothing here changes
    // `region`.
    if std::env::var_os("GLAURUNG_ACCOUNT_STRUCTURE").is_some() {
        let acct = crate::ir::structure_accounting::account(&cfg.edges, &cfg.preds, 0, &region);
        if !acct.is_empty() {
            // stderr, not `tracing`: no subscriber is installed on the CLI or PyO3
            // paths, so a `tracing::warn!` here reached nobody — a diagnostic that
            // cannot be read is not a diagnostic. Matches `GLAURUNG_DUMP_PASSES`.
            eprintln!(
                "[account] {:#x}: {} finding(s): {:?}",
                lf.entry_va,
                acct.len(),
                acct
            );
        }
    }
    region
}

/// The block-losing-leftover-aware region build shared by [`recover`] and
/// [`recover_verified`], so both see the identical tree.
fn build_full(lf: &LlirFunction, cfg: &Cfg) -> Region {
    if lf.blocks.is_empty() {
        return Region::Unstructured(Vec::new());
    }
    // `While` can represent one distinguished exit reached from its header.
    // A rotated multi-latch loop may instead have an early-return edge from
    // the header *and* a different normal-exhaustion edge from its latches.
    // Forcing that graph into `While` silently moves one set of blocks below
    // the other return (clang -O2 binary search was the real canary).  Preserve
    // the complete labelled CFG until the region algebra grows owned multi-
    // exits; `Unstructured` is explicitly the lossless fallback contract.
    if has_multi_latch_loop_with_distinct_exits(cfg)
        || has_loop_conditional_with_join_beyond_loop(cfg)
        || has_inner_loop_exit_that_reenters_via_outer_cycle(cfg)
    {
        return Region::Unstructured((0..lf.blocks.len()).collect());
    }
    let mut visited: HashSet<usize> = HashSet::new();
    let region = build(0, cfg, &mut visited, None);
    let leftover: Vec<usize> = (0..lf.blocks.len())
        .filter(|b| !visited.contains(b))
        .collect();
    if leftover.is_empty() {
        region
    } else {
        let mut parts = flatten_seq(region);
        parts.push(Region::Unstructured(leftover));
        Region::Seq(parts)
    }
}

/// An inner natural loop can return through its header while its latch takes an
/// exhaustion edge, executes an outer-loop reload/reset, and later re-enters the
/// inner header. `Region::While` has only the header's distinguished exit, so
/// absorbing that latch exit into the body drops the intervening outer-loop
/// blocks. Preserve the labelled CFG until the region algebra can express an
/// owned `break` followed by outer-loop work.
///
/// The terminal-header-exit restriction is load-bearing. Ordinary nested loops
/// also leave an inner cycle and later re-enter it through an outer latch, but
/// their header exit is the non-terminal continuation after the inner loop. They
/// remain representable by the existing nested-loop path and must not force a
/// whole-function fallback.
fn has_inner_loop_exit_that_reenters_via_outer_cycle(cfg: &Cfg) -> bool {
    for header in 0..cfg.succs.len() {
        let tails: Vec<usize> = cfg.preds[header]
            .iter()
            .copied()
            .filter(|&tail| cfg.dominates(header, tail))
            .collect();
        if tails.is_empty() {
            continue;
        }

        let mut body = HashSet::new();
        for tail in tails {
            body.extend(natural_loop_body(header, tail, cfg));
        }
        let header_exits: HashSet<usize> = cfg.succs[header]
            .iter()
            .copied()
            .filter(|succ| !body.contains(succ))
            .collect();
        if header_exits.len() != 1 || !header_exits.iter().all(|&exit| cfg.succs[exit].is_empty()) {
            continue;
        }

        for block in body.iter().copied().filter(|&block| block != header) {
            for exit in cfg.succs[block]
                .iter()
                .copied()
                .filter(|succ| !body.contains(succ))
            {
                if !header_exits.contains(&exit) && can_reach(exit, header, cfg) {
                    return true;
                }
            }
        }
    }
    false
}

fn has_multi_latch_loop_with_distinct_exits(cfg: &Cfg) -> bool {
    for header in 0..cfg.succs.len() {
        let tails: Vec<usize> = cfg.preds[header]
            .iter()
            .copied()
            .filter(|&tail| cfg.dominates(header, tail))
            .collect();
        if tails.len() < 2 {
            continue;
        }

        let mut body = HashSet::new();
        for tail in tails {
            body.extend(natural_loop_body(header, tail, cfg));
        }
        let header_exits: HashSet<usize> = cfg.succs[header]
            .iter()
            .copied()
            .filter(|succ| !body.contains(succ))
            .collect();
        if header_exits.is_empty() {
            continue;
        }
        let non_header_exits: HashSet<usize> = body
            .iter()
            .copied()
            .filter(|&block| block != header)
            .flat_map(|block| cfg.succs[block].iter().copied())
            .filter(|succ| !body.contains(succ))
            .collect();
        if non_header_exits
            .iter()
            .any(|exit| !header_exits.contains(exit))
        {
            return true;
        }
    }
    false
}

/// A conditional inside a natural loop may return through the same epilogue as
/// the loop's ordinary exit while its sibling continues to a latch.  The shared
/// epilogue post-dominates the conditional globally, but it is not a join owned
/// by that conditional *inside this iteration*.  `detect_if_shape` cannot encode
/// the split ownership yet, so recognise the unsafe case before it can invent an
/// edge from the continuing arm to the epilogue.
fn has_loop_conditional_with_join_beyond_loop(cfg: &Cfg) -> bool {
    // A recovered multi-way dispatch already has a more precise Switch region.
    // Falling the *whole function* back would discard that information and can
    // expose raw indirect jumps, so leave those functions on the switch path.
    if cfg.succs.iter().any(|succs| succs.len() >= 3) {
        return false;
    }
    for header in 0..cfg.succs.len() {
        let tails: Vec<usize> = cfg.preds[header]
            .iter()
            .copied()
            .filter(|&tail| cfg.dominates(header, tail))
            .collect();
        if tails.is_empty() {
            continue;
        }
        let mut body = HashSet::new();
        for tail in tails {
            body.extend(natural_loop_body(header, tail, cfg));
        }

        for cond in body.iter().copied().filter(|&block| block != header) {
            if cfg.succs[cond].len() != 2 {
                continue;
            }
            let Some(join) = cfg.ipostdom[cond] else {
                continue;
            };
            if body.contains(&join) || join == header {
                continue;
            }
            let reaches_next_iteration = cfg.succs[cond]
                .iter()
                // A direct edge to the header is the ordinary loop latch.  Its
                // sibling may set final carried values on the way to the exit
                // (`while_prefix`); raw fallback before phi lowering loses those
                // values.  The ownership bug is an *internal* early-return
                // conditional whose continuing arm still has body work before
                // reaching a latch.
                .filter(|&&succ| succ != header && can_reach(succ, header, cfg))
                .count();
            let reaches_nonlocal_join = cfg.succs[cond]
                .iter()
                .filter(|&&succ| {
                    succ != join
                        && !can_reach(succ, header, cfg)
                        && linear_chain_reaches(succ, join, cfg)
                })
                .count();
            if reaches_next_iteration > 0 && reaches_nonlocal_join > 0 {
                return true;
            }
        }
    }
    false
}

fn linear_chain_reaches(start: usize, target: usize, cfg: &Cfg) -> bool {
    let mut current = start;
    let mut seen = HashSet::new();
    while current != target && seen.insert(current) {
        let [next] = cfg.succs[current].as_slice() else {
            return false;
        };
        current = *next;
    }
    current == target
}

/// Recursively build a Region starting at `start`, stopping at `stop_at`
/// (exclusive). `visited` tracks blocks consumed into the output.
fn build(start: usize, cfg: &Cfg, visited: &mut HashSet<usize>, stop_at: Option<usize>) -> Region {
    let mut parts: Vec<Region> = Vec::new();
    let mut cur = start;

    loop {
        if Some(cur) == stop_at {
            break;
        }
        if visited.contains(&cur) {
            // Already consumed — avoid infinite loops on back-edges or shared
            // successors we don't currently model structurally.
            break;
        }

        // --- Bottom-tested natural loop ------------------------------------
        // Detect this before inserting `cur` into `visited`: the recovered body
        // begins at `cur` and must be structured recursively up to (but not
        // including) the conditional latch.
        if let Some(loop_r) = detect_bottom_tested_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // `detect_bottom_tested_loop` needs an unconsumed body entry. All other
        // shapes retain the original consume-before-detect behaviour.
        if !visited.insert(cur) {
            break;
        }

        // --- Natural loop detection: any successor that dominates `cur`  ----
        // means there's a back edge from `cur` to that dominator, forming a
        // natural loop with that block as header. We only structure this when
        // `cur` itself is the loop header (single-block loop) or when we are
        // already sitting at the header.
        if let Some(loop_r) = detect_natural_loop(cur, cfg, visited) {
            parts.push(loop_r.region);
            match loop_r.exit {
                Some(next) => {
                    cur = next;
                    continue;
                }
                None => break,
            }
        }

        // --- Conditional shapes ---------------------------------------------
        if cfg.succs[cur].len() == 2 {
            if let Some((ite, after)) = detect_if_shape(cur, cfg, visited, stop_at) {
                parts.push(ite);
                match after {
                    Some(next) => {
                        cur = next;
                        continue;
                    }
                    None => break,
                }
            }
        }

        // --- Switch shape (#193) -------------------------------------------
        // A block with N>=3 successors is almost always a jump-table-driven
        // switch dispatch. Each successor that's reached only from this
        // block is an arm; the shared post-dominator (if any) is the join.
        if cfg.succs[cur].len() >= 3 {
            if let Some((sw, after)) = detect_switch_shape(cur, cfg, visited, stop_at) {
                parts.push(sw);
                match after {
                    Some(next) => {
                        cur = next;
                        continue;
                    }
                    None => break,
                }
            }
        }

        // --- Default: straight-line block -----------------------------------
        parts.push(Region::Block(cur));

        // Advance through a single-successor chain. We used to require the
        // successor have exactly one predecessor, but that broke loop-header
        // recognition: a header has multiple preds (entry + back-edge), yet
        // we still want the outer DFS to reach it so the natural-loop
        // detector can fire. We rely on `visited` to prevent re-entry and on
        // `stop_at` to bound recursion inside sub-regions.
        let succs = &cfg.succs[cur];
        if succs.len() != 1 {
            break;
        }
        let next = succs[0];
        if Some(next) == stop_at {
            break;
        }
        if visited.contains(&next) {
            // An explicit machine jump is already present in `Block(cur)` and
            // lowers to a C goto.  A LINEAR edge has no instruction to carry
            // it: once structuring relocates `cur` away from the block that
            // previously followed it in memory, silently stopping here drops
            // control flow. Materialise only that adjacency edge as a region
            // goto to the already-owned block.
            if cfg.edges[cur]
                .iter()
                .any(|edge| edge.to == next && edge.kind == crate::ir::cfg_edges::EdgeKind::Linear)
            {
                parts.push(Region::Goto(next));
            }
            break;
        }
        cur = next;
    }

    if parts.len() == 1 {
        parts.pop().unwrap()
    } else {
        Region::Seq(parts)
    }
}

/// Build a conditional *arm* starting at `entry`. Identical to [`build`] except
/// that when `entry` has already been consumed by a sibling (a *shared* join
/// block, e.g. the common false block of `a && b`) we emit an explicit
/// [`Region::Goto`] to it rather than letting [`build`] hit its visited-guard and
/// return an empty region — which silently drops the edge (the short-circuit
/// empty-arm bug). `stop_at` (the join) is never gotoed; it is emitted after the
/// conditional.
fn build_arm(
    entry: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    stop_at: Option<usize>,
) -> Region {
    if Some(entry) != stop_at && visited.contains(&entry) {
        return Region::Goto(entry);
    }
    build(entry, cfg, visited, stop_at)
}

struct LoopRegion {
    region: Region,
    exit: Option<usize>,
}

/// Recognise a natural while-loop headed at `header`.
///
/// The pattern:
///   * `header` has exactly two successors: `body_head` and `exit_block`.
///   * `body_head` eventually reaches back to `header` via a block `back` whose
///     only successor is `header` (single back-edge).
///   * `header` dominates `body_head` and `back`.
fn detect_natural_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    if cfg.succs[header].len() != 2 {
        return None;
    }
    // A natural loop requires a back-edge: a predecessor `tail` of `header`
    // that `header` dominates.
    let tail = cfg.preds[header]
        .iter()
        .copied()
        .find(|&p| cfg.dominates(header, p))?;
    // The loop body is `header` plus every block that can reach `tail` without
    // passing back through `header` (the standard natural-loop body set).
    let body_set = natural_loop_body(header, tail, cfg);
    // Of the header's two successors, exactly one should be inside the body
    // (the loop entry); the other leaves the loop.
    let a = cfg.succs[header][0];
    let b = cfg.succs[header][1];
    let (body_head, exit) = match (body_set.contains(&a), body_set.contains(&b)) {
        (true, false) => (a, b),
        (false, true) => (b, a),
        // Both or neither inside → shape we don't model; fall back gracefully.
        _ => return None,
    };

    // Commit. Consume the header, then structure the body *recursively* via
    // `build` so nested loops and conditionals inside the body are recovered
    // too — the old linear walk bailed on any branch, leaving multi-level loops
    // (matrix multiply, nested sorts) as goto soup. Temporarily mark the exit
    // visited so body structuring can't escape the loop through it.
    visited.insert(header);
    let exit_was_visited = visited.contains(&exit);
    visited.insert(exit);
    let body = build(body_head, cfg, visited, Some(header));
    if !exit_was_visited {
        visited.remove(&exit);
    }
    Some(LoopRegion {
        region: Region::While {
            header,
            body: Box::new(body),
            exit: Some(exit),
        },
        exit: Some(exit),
    })
}

/// Recognise a natural loop whose conditional branch is in the latch.
///
/// The shape is `header ... -> cond`, with `cond -> header` as the back-edge and
/// `cond -> exit` leaving the loop. Unlike [`detect_natural_loop`], the loop
/// header need not branch: it is ordinary body code and therefore executes once
/// before the first condition test.
fn detect_bottom_tested_loop(
    header: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
) -> Option<LoopRegion> {
    // A genuine single-latch do-while has exactly one dominated predecessor of
    // its header. A pre-tested loop with `continue` or an early-exit arm may
    // also have a conditional predecessor that points to the header, but it has
    // at least one additional back-edge; accepting one predecessor out of that
    // set moves the first condition test after the body and changes behaviour.
    let mut back_preds = cfg.preds[header]
        .iter()
        .copied()
        .filter(|&candidate| cfg.dominates(header, candidate));
    let cond = back_preds.next()?;
    if back_preds.next().is_some()
        || cfg.succs[cond].len() != 2
        || !cfg.succs[cond].contains(&header)
        || cfg.cond_taken[cond].is_none()
        || visited.contains(&cond)
    {
        return None;
    }
    let body_set = natural_loop_body(header, cond, cfg);
    // Loop rotation puts an initial top-test in a predecessor outside the
    // natural loop, then uses a bottom latch for subsequent iterations. That
    // CFG is not a source-level do-while: the predecessor can bypass the body
    // entirely. Only promote when every outside entry falls unconditionally
    // into the header, which proves the body executes at least once.
    if cfg.preds[header].iter().copied().any(|pred| {
        !body_set.contains(&pred) && (cfg.succs[pred].len() != 1 || cfg.succs[pred][0] != header)
    }) {
        return None;
    }
    // A second exit from the body (break/early return) needs nested region
    // ownership that this bounded A1 detector does not yet model. Promoting
    // such a loop pulled its exit block into the `do` body and changed both
    // return values and termination in the O2 loop canaries. The conditional
    // latch is the only block allowed to leave this natural loop.
    if body_set
        .iter()
        .copied()
        .any(|block| block != cond && cfg.succs[block].iter().any(|succ| !body_set.contains(succ)))
    {
        return None;
    }
    let exit = cfg.succs[cond]
        .iter()
        .copied()
        .find(|succ| *succ != header && !body_set.contains(succ))?;

    // The latch's condition belongs to the DoWhile node, not its body. Mark it
    // consumed while recursively structuring everything from the header up to
    // the latch. Temporarily consume the exit as well so an inner detector
    // cannot absorb control outside the loop.
    visited.insert(cond);
    let exit_was_visited = !visited.insert(exit);
    let body = build(header, cfg, visited, Some(cond));
    if !exit_was_visited {
        visited.remove(&exit);
    }

    Some(LoopRegion {
        region: Region::DoWhile {
            body: Box::new(body),
            cond,
            exit: Some(exit),
        },
        exit: Some(exit),
    })
}

/// The blocks of the natural loop with the given `header` and back-edge `tail`:
/// `header` itself plus every block that can reach `tail` by walking
/// predecessors without going through `header`.
fn natural_loop_body(header: usize, tail: usize, cfg: &Cfg) -> HashSet<usize> {
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
    body
}

/// Recognise an if-then / if-then-else diamond rooted at `cond`.
///
/// Returns `Some((region, after))` when we can structurally absorb the whole
/// conditional and continue at `after` (the join block, or None if one of
/// the arms exits outright).
/// Whether the lowered condition at block `cond` must be negated when
/// `then_entry` is used as the `then` arm. The raw condition is true when the
/// branch is *taken* (jumps to `cond_taken`); if `then_entry` is instead the
/// fall-through arm, `if (cond) { then_entry }` would run it on the wrong edge,
/// so the condition is inverted. This is THE fix for the polarity bug where arms
/// were chosen by sorted block index rather than the taken edge.
fn invert_for(cfg: &Cfg, cond: usize, then_entry: usize) -> bool {
    cfg.cond_taken[cond] != Some(then_entry)
}

fn detect_if_shape(
    cond: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    stop_at: Option<usize>,
) -> Option<(Region, Option<usize>)> {
    let t = cfg.succs[cond][0];
    let e = cfg.succs[cond][1];

    // --- if-then-else ------------------------------------------------------
    // Both arms have `cond` as their only predecessor and share a common
    // successor `join` that has exactly {arm_then_last, arm_else_last} as
    // predecessors.
    let then_single = cfg.preds[t] == vec![cond] && cfg.succs[t].len() == 1;
    let else_single = cfg.preds[e] == vec![cond] && cfg.succs[e].len() == 1;
    if then_single && else_single && cfg.succs[t][0] == cfg.succs[e][0] {
        let join = cfg.succs[t][0];
        let invert = invert_for(cfg, cond, t);
        // Mark cond consumed, recurse on arms.
        visited.insert(cond);
        let then_r = build_arm(t, cfg, visited, Some(join));
        let else_r = build_arm(e, cfg, visited, Some(join));
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: Some(join),
                invert,
            },
            Some(join),
        ));
    }

    // --- if-then (no else) -------------------------------------------------
    // `t` is the "body" arm: cond → t → join; and `e` is the join directly.
    for &(body, join) in &[(t, e), (e, t)] {
        let body_single = cfg.preds[body] == vec![cond] && cfg.succs[body] == vec![join];
        if body_single && cfg.preds[join].contains(&cond) {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // --- terminal guard with a terminal continuation -----------------------
    // Both direct arms can be CFG terminals even though one is semantically a
    // non-returning guard and the other is an ordinary function tail. Prefer
    // the unique arm without an explicit machine return as the one-arm body.
    // If both have the same terminal kind, use the semantic taken edge as the
    // deterministic tie-breaker. Successor-vector order is never branch truth.
    let t_terminates = cfg.preds[t] == vec![cond] && cfg.succs[t].is_empty();
    let e_terminates = cfg.preds[e] == vec![cond] && cfg.succs[e].is_empty();
    if t_terminates && e_terminates {
        let body_and_cont = match (cfg.ends_in_return[t], cfg.ends_in_return[e]) {
            (false, true) => Some((t, e)),
            (true, false) => Some((e, t)),
            _ => match cfg.cond_taken[cond] {
                Some(taken) if taken == t => Some((t, e)),
                Some(taken) if taken == e => Some((e, t)),
                _ => None,
            },
        };
        if let Some((body, cont)) = body_and_cont {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, None);
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                    invert,
                },
                Some(cont),
            ));
        }
    }

    // --- if-then with early-exit body (#192) -------------------------------
    // The shape: one arm terminates the function (return / unreachable), the
    // other continues. The terminating arm becomes the `then` body of an
    // IfThen with `join: None`, and the surviving arm is the continuation.
    //
    // This catches the canonical `if (cond) return;` pattern that the
    // earlier structurer left as Unstructured. The terminating arm must be
    // single-pred-from-cond so we don't speculatively pull in shared
    // exit blocks reached by multiple gotos.
    for &(body, cont) in &[(t, e), (e, t)] {
        let body_terminates = cfg.preds[body] == vec![cond] && cfg.succs[body].is_empty();
        if body_terminates {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, None);
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: None,
                    invert,
                },
                Some(cont),
            ));
        }
    }

    // --- if-then with shared-exit goto (#192) ------------------------------
    // The richer shape: one arm is a terminating block that is reached from
    // multiple sites (e.g. `L_end: return;` shared by every `if (cond) goto
    // L_end;` in the function). We clone-inline the terminating block into
    // this if-then's body but DO NOT mark it visited, so other branches in
    // the same function can also fold their gotos away — and so the outer
    // build will still emit the block as the function's tail.
    //
    // The block-index reference inside `IfThen { then_r: Region::Block(b) }`
    // causes the AST lowerer to render the terminating statements twice
    // (once per if-goto site, once at the tail), which is the right
    // semantics: each if statement is conceptually `if (cond) { return; }`.
    for &(body, cont) in &[(t, e), (e, t)] {
        let body_is_shared_exit = cfg.succs[body].is_empty() && cfg.preds[body].len() > 1;
        if body_is_shared_exit {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            // Don't mark `body` as visited — let outer recursion emit it
            // when we eventually fall through (or when another branch also
            // references it).
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(Region::Block(body)),
                    join: None,
                    invert,
                },
                Some(cont),
            ));
        }
    }

    // --- optional preheader feeding a shared natural loop -----------------
    // Optimisers commonly peel one iteration or initialise an odd/even lane in
    // only one arm, after which both arms enter the same loop header.  A side
    // exit from that optional preheader (for example `if (n == 1) return`) makes
    // the function epilogue the condition's global post-dominator, even though
    // the loop header is the local join for every continuing path.  Choosing the
    // epilogue nests the loop inside only the direct arm and makes the setup arm
    // skip all remaining iterations.
    for &(body, join) in &[(t, e), (e, t)] {
        let join_is_loop_header = cfg.preds[join]
            .iter()
            .copied()
            .any(|tail| cfg.dominates(join, tail));
        if join_is_loop_header
            && cfg.preds[body] == vec![cond]
            && can_reach(body, join, cfg)
            && every_path_reaches_join_or_terminates(body, join, cfg)
        {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // --- guarded multi-way body with a partial continuation ---------------
    // A compiler guards a jump table with an out-of-range edge directly to
    // the common latch/epilogue. Most cases reach that same block, but a case
    // may return early. The continuation therefore does not post-dominate the
    // dispatch, even though every non-terminating path reaches it. This is a
    // one-armed `if (in_range) switch (...)` followed by the continuation, not
    // an if/else whose sibling arm owns the continuation.
    for &(body, join) in &[(t, e), (e, t)] {
        if cfg.succs[body].len() >= 3
            && cfg.preds[body] == vec![cond]
            && cfg.preds[join].contains(&cond)
            && can_reach(body, join, cfg)
            && every_path_reaches_join_or_terminates(body, join, cfg)
        {
            let invert = invert_for(cfg, cond, body);
            visited.insert(cond);
            let then_r = build(body, cfg, visited, Some(join));
            return Some((
                Region::IfThen {
                    cond,
                    then_r: Box::new(then_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    // (switch detection lives in detect_switch_shape — invoked by build()
    // before falling through to the default block path, since this fn is
    // only called for 2-successor blocks.)

    // --- if-then-else where both arms terminate (#192) ---------------------
    // Both arms exit the function; there is no continuation. We emit an
    // IfThenElse with join=None and signal the outer build to stop.
    if t_terminates && e_terminates {
        let invert = invert_for(cfg, cond, t);
        visited.insert(cond);
        let then_r = build(t, cfg, visited, None);
        let else_r = build(e, cfg, visited, None);
        return Some((
            Region::IfThenElse {
                cond,
                then_r: Box::new(then_r),
                else_r: Box::new(else_r),
                join: None,
                invert,
            },
            None,
        ));
    }

    // --- General conditional via immediate post-dominator ------------------
    // The arms reconverge only at a *distant* join (not an immediate diamond):
    // the classic gcc -O0 comparison-ladder / switch shape, where each case
    // body jumps to a shared end block. Structuring it against the post-dominator
    // collapses the whole ladder into nested if/else with a single exit instead
    // of goto soup. Runs only after every tighter pattern above has declined.
    let mut distant_join = cfg.ipostdom[cond];
    let mut bounded_by_enclosing_region = false;
    if let (Some(boundary), Some(join)) = (stop_at, distant_join) {
        // An immediate post-dominator may lie beyond the region currently being
        // built (most importantly, a function epilogue beyond a loop latch).
        // In that case it is not this conditional's local join: use the region
        // boundary when at least one arm continues there. The other arm may
        // legitimately terminate early.
        if join != boundary
            && !can_reach(join, boundary, cfg)
            && (can_reach(t, boundary, cfg) || can_reach(e, boundary, cfg))
            && (!cfg.dominates(boundary, cond)
                || contains_multiway_before(t, boundary, cfg)
                || contains_multiway_before(e, boundary, cfg))
        {
            distant_join = Some(boundary);
            bounded_by_enclosing_region = true;
        }
    }
    if let Some(join) = distant_join {
        if join != cond && t != join && e != join {
            // Order the arms by the branch's taken target so the rendered
            // condition polarity is correct: `if (cond)` must guard the arm the
            // branch jumps to when taken. Without this the ladder inverts (block
            // address order is not taken/fallthrough order).
            let (then_a, else_a) = match cfg.cond_taken[cond] {
                Some(tk) if tk == e => (e, t),
                _ => (t, e),
            };
            let invert = invert_for(cfg, cond, then_a);
            visited.insert(cond);
            let (then_r, else_r) = if bounded_by_enclosing_region {
                // Paths that leave a bounded region (a return from inside a
                // loop is the common case) may include a shared function
                // epilogue. Render that terminating path here, but only commit
                // ownership of blocks which can rejoin the region boundary;
                // otherwise outer paths lose their one real epilogue.
                let mut scoped_visited = visited.clone();
                let then_r = build_arm(then_a, cfg, &mut scoped_visited, Some(join));
                let else_r = build_arm(else_a, cfg, &mut scoped_visited, Some(join));
                visited.extend(
                    scoped_visited
                        .into_iter()
                        .filter(|&block| can_reach(block, join, cfg)),
                );
                (then_r, else_r)
            } else {
                (
                    build_arm(then_a, cfg, visited, Some(join)),
                    build_arm(else_a, cfg, visited, Some(join)),
                )
            };
            return Some((
                Region::IfThenElse {
                    cond,
                    then_r: Box::new(then_r),
                    else_r: Box::new(else_r),
                    join: Some(join),
                    invert,
                },
                Some(join),
            ));
        }
    }

    None
}

/// True when every path starting at `start` either reaches `join` or ends at a
/// terminal block. Cycles encountered before the join are rejected
/// conservatively: the optional-preheader rule is for acyclic one-time setup,
/// not for guessing ownership of another loop.
fn every_path_reaches_join_or_terminates(start: usize, join: usize, cfg: &Cfg) -> bool {
    fn visit(
        node: usize,
        join: usize,
        cfg: &Cfg,
        active: &mut HashSet<usize>,
        memo: &mut HashMap<usize, bool>,
    ) -> bool {
        if node == join || cfg.succs[node].is_empty() {
            return true;
        }
        if let Some(&known) = memo.get(&node) {
            return known;
        }
        if !active.insert(node) {
            return false;
        }
        let valid = cfg.succs[node]
            .iter()
            .copied()
            .all(|succ| visit(succ, join, cfg, active, memo));
        active.remove(&node);
        memo.insert(node, valid);
        valid
    }

    visit(start, join, cfg, &mut HashSet::new(), &mut HashMap::new())
}

fn can_reach(start: usize, target: usize, cfg: &Cfg) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(block) = stack.pop() {
        if block == target {
            return true;
        }
        if seen.insert(block) {
            stack.extend(cfg.succs[block].iter().copied());
        }
    }
    false
}

fn contains_multiway_before(start: usize, boundary: usize, cfg: &Cfg) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![start];
    while let Some(block) = stack.pop() {
        if block == boundary || !seen.insert(block) {
            continue;
        }
        if cfg.succs[block].len() >= 3 {
            return true;
        }
        stack.extend(cfg.succs[block].iter().copied());
    }
    false
}

/// Recognise a switch dispatch (#193).
///
/// Pattern: `cur` has N>=3 successors. Each arm should have `cur` as
/// either its only predecessor (clean dispatch) or as one of a small
/// number of preds when other arms fall through. We identify a join
/// block as the multi-predecessor block reached from the greatest number of
/// distinct arms. Counting distinct arms matters: a merge wholly inside one case
/// or a shared exceptional exit used by only two cases is not the normal switch
/// continuation when more cases converge elsewhere.
///
/// Each arm is then recursively built with `stop_at = join`. Arms
/// that terminate without reaching the join become Region sub-trees
/// with their own returns.
fn detect_switch_shape(
    dispatch: usize,
    cfg: &Cfg,
    visited: &mut HashSet<usize>,
    enclosing_stop: Option<usize>,
) -> Option<(Region, Option<usize>)> {
    let arms = cfg.succs[dispatch].clone();
    let case_labels = cfg.case_labels[dispatch].clone();
    if arms.len() < 3 {
        return None;
    }
    // Every arm must be reached only from this dispatch — a stricter
    // check than the if-shape ones, but jump tables typically produce
    // dedicated case blocks. Arms that share predecessors (e.g.
    // fall-through cases) can land in v1.
    for &a in &arms {
        if !cfg.preds[a].iter().all(|&p| p == dispatch) {
            return None;
        }
    }

    let join = find_switch_join(dispatch, &arms, cfg, enclosing_stop);
    // When the dispatch is one arm of an enclosing conditional, its local
    // post-dominator may be absent solely because the sibling/default arm also
    // reaches that continuation.  The enclosing boundary is still a proven
    // join and is the correct ownership limit for every case.
    let effective_join = join.or(enclosing_stop);
    let enclosing_loop = innermost_natural_loop_containing(dispatch, cfg);

    visited.insert(dispatch);
    let mut sub_arms: Vec<Region> = Vec::new();
    // A switch may have no join dominated by its dispatch while still being
    // nested inside a region with a shared continuation.  The canonical shape
    // is an out-of-range guard whose direct/default arm and every switch case
    // meet at the same epilogue.  In that case `join` is None (the default path
    // prevents dispatch dominance), but `enclosing_stop` is authoritative: no
    // case owns or may consume that outer continuation.
    let arm_stop = effective_join;
    for &a in &arms {
        if let Some((_, loop_body)) = &enclosing_loop {
            // Case-local returns may pass through a function epilogue outside
            // the loop. Render that path in the case, but do not globally claim
            // the shared epilogue: the loop-exit and pre-loop paths still need
            // it at function scope. Only loop-body ownership is committed.
            let mut arm_visited = visited.clone();
            sub_arms.push(build(a, cfg, &mut arm_visited, arm_stop));
            visited.extend(
                arm_visited
                    .into_iter()
                    .filter(|block| loop_body.contains(block)),
            );
        } else {
            sub_arms.push(build(a, cfg, visited, arm_stop));
        }
    }
    Some((
        Region::Switch {
            dispatch,
            case_labels,
            arms: sub_arms,
            join: effective_join,
        },
        effective_join,
    ))
}

/// Walk reachable blocks from each arm and return the block reached from the
/// greatest number of DISTINCT arms that also has >1 predecessors and is
/// dominated by `dispatch`. Address order breaks ties only after arm coverage;
/// otherwise an earlier shared error exit can steal the normal continuation.
/// None if no candidate is shared by at least two arms.
fn find_switch_join(
    dispatch: usize,
    arms: &[usize],
    cfg: &Cfg,
    enclosing_stop: Option<usize>,
) -> Option<usize> {
    use std::collections::VecDeque;
    let enclosing_loop = innermost_natural_loop_containing(dispatch, cfg);
    let mut arm_reach_counts: HashMap<usize, usize> = HashMap::new();
    for &a in arms {
        let mut q: VecDeque<usize> = VecDeque::new();
        q.push_back(a);
        let mut seen: HashSet<usize> = HashSet::new();
        while let Some(b) = q.pop_front() {
            // A switch nested in a loop must not walk through the loop header
            // into a later iteration. Doing so makes every case-internal merge
            // appear reachable from every arm and selects it as the join.
            if Some(b) == enclosing_stop {
                continue;
            }
            // A local if/else join can replace the loop header as `stop_at`
            // while recursively building a switch nested inside that arm. Find
            // the natural loop independently: paths leaving its body are case
            // exits, and the header starts the *next* iteration, neither of
            // which may participate in this iteration's switch join.
            if let Some((header, body)) = &enclosing_loop {
                if b == *header || !body.contains(&b) {
                    continue;
                }
            }
            if !seen.insert(b) {
                continue;
            }
            for &s in &cfg.succs[b] {
                if !seen.contains(&s) {
                    q.push_back(s);
                }
            }
        }
        for b in seen {
            *arm_reach_counts.entry(b).or_default() += 1;
        }
    }
    let mut candidates: Vec<(usize, usize)> = arm_reach_counts
        .into_iter()
        .filter_map(|(b, arm_count)| {
            (arm_count > 1
                && !arms.contains(&b)
                && cfg.preds[b].len() > 1
                && cfg.dominates(dispatch, b))
            .then_some((arm_count, b))
        })
        .collect();
    candidates.sort_unstable_by(|(count_a, block_a), (count_b, block_b)| {
        count_b.cmp(count_a).then_with(|| block_a.cmp(block_b))
    });
    candidates.into_iter().next().map(|(_, block)| block)
}

/// The smallest natural-loop body containing `node`, paired with its header.
/// Smallest is the innermost loop when loops are nested. A header may have more
/// than one back-edge, so its body is the union of the standard predecessor
/// walks from every dominated tail.
fn innermost_natural_loop_containing(node: usize, cfg: &Cfg) -> Option<(usize, HashSet<usize>)> {
    let mut loops = Vec::new();
    for header in 0..cfg.succs.len() {
        if !cfg.dominates(header, node) {
            continue;
        }
        let tails: Vec<usize> = cfg.preds[header]
            .iter()
            .copied()
            .filter(|&tail| cfg.dominates(header, tail))
            .collect();
        if tails.is_empty() {
            continue;
        }
        let mut body = HashSet::new();
        for tail in tails {
            body.extend(natural_loop_body(header, tail, cfg));
        }
        if body.contains(&node) {
            loops.push((header, body));
        }
    }
    loops.into_iter().min_by_key(|(_, body)| body.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirInstr, Op, VReg, Value};

    fn mk_cfg(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        let entry_va = spec.first().map(|(s, _, _)| *s).unwrap_or(0);
        let blocks = spec
            .into_iter()
            .map(|(start_va, ops, succs)| LlirBlock {
                start_va,
                end_va: start_va + 0x100,
                instrs: ops
                    .into_iter()
                    .enumerate()
                    .map(|(j, op)| LlirInstr {
                        va: start_va + (j as u64) * 4,
                        op,
                    })
                    .collect(),
                succs,
            })
            .collect();
        LlirFunction { entry_va, blocks }
    }

    fn recover_for(lf: &LlirFunction) -> Region {
        let ssa = compute_ssa(lf);
        recover(lf, &ssa)
    }

    #[test]
    fn duplicate_jump_table_targets_keep_every_case_label() {
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![
                    0x1100, 0x1200, 0x1300, 0x1400, 0x1500, 0x1300, 0x1600, 0x1700,
                ],
            ),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
            (0x1500, vec![Op::Return], vec![]),
            (0x1600, vec![Op::Return], vec![]),
            (0x1700, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Switch {
            arms, case_labels, ..
        } = region
        else {
            panic!("expected a switch, got {region:#?}");
        };

        assert_eq!(arms.len(), 7, "one body per distinct destination");
        assert_eq!(
            case_labels,
            vec![
                vec![0],
                vec![1],
                vec![2, 5],
                vec![3],
                vec![4],
                vec![6],
                vec![7],
            ],
            "the shared body must retain both table indices"
        );
    }

    #[test]
    fn switch_join_prefers_a_shared_continuation_over_an_internal_arm_merge() {
        // Block 5 is an internal merge in case 0; block 8 is the normal switch
        // continuation reached by all three cases. The extra conditional at
        // block 1 gives recursive if lowering a function-level `stop_at` (9),
        // not the surrounding loop header (0). Following the back-edge through
        // block 0 makes every arm appear to reach block 5 and lets its lower
        // address steal ownership from block 8. This is the shape of
        // `05_cleanup_and_state_machine:fsm`.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1b00,
                    inverted: false,
                }],
                vec![0x1100, 0x1b00],
            ),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::C),
                    target: 0x1a00,
                    inverted: false,
                }],
                vec![0x1200, 0x1a00],
            ),
            (0x1200, vec![Op::Nop], vec![0x1300, 0x1600, 0x1700]),
            (
                0x1300,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1c00,
                    inverted: false,
                }],
                vec![0x1400, 0x1c00],
            ),
            (0x1400, vec![Op::Nop], vec![0x1500]),
            (0x1500, vec![Op::Nop], vec![0x1800]),
            (0x1600, vec![Op::Nop], vec![0x1800]),
            (0x1700, vec![Op::Nop], vec![0x1800]),
            (0x1800, vec![Op::Jump { target: 0x1000 }], vec![0x1000]),
            (0x1900, vec![Op::Return], vec![]),
            (0x1a00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
            (0x1b00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
            (0x1c00, vec![Op::Jump { target: 0x1900 }], vec![0x1900]),
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);
        assert_eq!(
            find_switch_join(2, &[3, 6, 7], &cfg, Some(9)),
            Some(8),
            "the shared loop continuation is the join"
        );
        fn find_switch(region: &Region) -> Option<&Region> {
            match region {
                Region::Switch { .. } => Some(region),
                Region::Seq(parts) => parts.iter().find_map(find_switch),
                Region::IfThen { then_r, .. } => find_switch(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    find_switch(then_r).or_else(|| find_switch(else_r))
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => find_switch(body),
                Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => None,
            }
        }
        let region = recover_for(&lf);
        let Some(Region::Switch { arms, .. }) = find_switch(&region) else {
            panic!("expected recovered switch: {region:?}");
        };
        assert!(
            arms.iter().all(|arm| !arm.blocks().contains(&9)),
            "the shared function epilogue must stay outside the switch: {arms:?}"
        );
        assert!(
            region.blocks().into_iter().any(|block| block == 9),
            "the shared epilogue must remain represented at function scope"
        );
    }

    #[test]
    fn comparison_ladder_recovers_as_nested_if_else() {
        use crate::ir::types::{Flag, VReg};
        let cj = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target,
            inverted: false,
        };
        // A -O0 switch comparison ladder: two conditional blocks whose case
        // bodies reconverge at a distant join (b5), not an immediate diamond.
        // The post-dominator fallback must fold this into nested if/else instead
        // of leaving it Unstructured (goto soup).
        //   b0 -> b1(fall) / b3(taken)     b1 -> b2(fall) / b4(taken)
        //   b2,b3,b4 -> b5(join); b5 returns.
        let lf = mk_cfg(vec![
            (0x1000, vec![cj(0x1030)], vec![0x1010, 0x1030]), // 0
            (0x1010, vec![cj(0x1040)], vec![0x1020, 0x1040]), // 1
            (0x1020, vec![Op::Nop], vec![0x1050]),            // 2 default
            (0x1030, vec![Op::Nop], vec![0x1050]),            // 3 case
            (0x1040, vec![Op::Nop], vec![0x1050]),            // 4 case
            (0x1050, vec![Op::Return], vec![]),               // 5 join
        ]);
        let r = recover_for(&lf);
        let dbg = format!("{:?}", r);
        assert!(
            dbg.matches("IfThenElse").count() >= 2,
            "ladder should nest into >=2 if-else, got: {}",
            dbg
        );
        assert!(
            !dbg.contains("Unstructured"),
            "ladder must be fully structured, got: {}",
            dbg
        );
    }

    #[test]
    fn rotated_for_loop_is_recovered_as_while() {
        // gcc -O0 for-loop shape (from `sum_to`): entry jumps forward to the
        // condition block, which conditionally branches *back* to the body.
        //   B0(entry) -> COND
        //   COND -> BODY (taken, back-edge target) / AFTER (fallthrough)
        //   BODY -> COND
        // Block order in memory is B0, BODY, COND, AFTER.
        let lf = mk_cfg(vec![
            (0x10f9, vec![Op::Nop], vec![0x1122]),         // 0: B0  -> COND
            (0x1115, vec![Op::Nop], vec![0x1122]),         // 1: BODY-> COND
            (0x1122, vec![Op::Nop], vec![0x1115, 0x112a]), // 2: COND-> BODY/AFTER
            (0x112a, vec![Op::Return], vec![]),            // 3: AFTER
        ]);
        let r = recover_for(&lf);
        let has_while = format!("{:?}", r).contains("While");
        assert!(
            has_while,
            "rotated for-loop not structured as While: {:?}",
            r
        );
    }

    #[test]
    fn optional_preheader_with_early_return_joins_before_the_shared_loop() {
        use crate::ir::types::{Flag, VReg};

        let branch = |target: u64| {
            vec![Op::CondJump {
                cond: VReg::Flag(Flag::Z),
                target,
                inverted: false,
            }]
        };
        // GCC -O2 `sum_to` / `factorial` peel one iteration according to parity:
        //
        //          b0
        //       /      \
        //      b1       |       b1 is an optional one-time preheader
        //    /   \      |       whose side exit returns from the function
        //   b2   exit   |
        //     \         /
        //       loop_header -> loop_body -> loop_header
        //              \
        //               exit
        //
        // The function exit is b0's global post-dominator, but it is not the
        // conditional's local join. Nesting the loop in only b0's direct arm
        // makes the preheader path skip every remaining iteration.
        let lf = mk_cfg(vec![
            (0x1000, branch(0x1030), vec![0x1010, 0x1030]), // b0
            (0x1010, branch(0x1050), vec![0x1020, 0x1050]), // b1
            (0x1020, vec![Op::Nop], vec![0x1030]),          // b2
            (0x1030, branch(0x1050), vec![0x1040, 0x1050]), // loop header
            (0x1040, vec![Op::Jump { target: 0x1030 }], vec![0x1030]),
            (0x1050, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("expected preheader, shared loop, and exit sequence: {region:#?}");
        };
        assert!(
            matches!(
                parts.first(),
                Some(Region::IfThen {
                    cond: 0,
                    join: Some(3),
                    ..
                })
            ),
            "the optional setup must join at the loop header: {region:#?}"
        );
        assert!(
            matches!(parts.get(1), Some(Region::While { header: 3, .. })),
            "the loop must be shared after the optional setup: {region:#?}"
        );
    }

    #[test]
    fn straight_line_collapses_to_seq() {
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 3);
                for (i, p) in parts.iter().enumerate() {
                    assert_eq!(p, &Region::Block(i));
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn diamond_recovers_as_if_then_else() {
        //     B0 cond
        //    /       \
        //   B1        B2
        //    \       /
        //     B3 join
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        // Expect Seq([IfThenElse{cond=0, then=Block(1), else=Block(2), join=3}, Block(3)]).
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThenElse {
                        cond,
                        then_r,
                        else_r,
                        join,
                        ..
                    } => {
                        assert_eq!(*cond, 0);
                        assert_eq!(**then_r, Region::Block(1));
                        assert_eq!(**else_r, Region::Block(2));
                        assert_eq!(*join, Some(3));
                    }
                    other => panic!("expected IfThenElse; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(3));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn if_then_without_else_recognised() {
        //   B0 cond
        //   / \
        //  B1 |
        //   \ |
        //    B2 join
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThen {
                        cond, then_r, join, ..
                    } => {
                        assert_eq!(*cond, 0);
                        assert_eq!(**then_r, Region::Block(1));
                        assert_eq!(*join, Some(2));
                    }
                    other => panic!("expected IfThen; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(2));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn while_loop_recovered_with_body_and_exit() {
        //   B0: entry (straight into header)
        //   B1: header, two succs (body=B2, exit=B3)
        //   B2: body → B1
        //   B3: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1100]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert!(parts.len() >= 2, "expected entry block + loop + exit");
                // First part must be Block(0) (the entry).
                assert_eq!(parts[0], Region::Block(0));
                // Second part must be While with header=1 and body=Block(2).
                match &parts[1] {
                    Region::While { header, body, exit } => {
                        assert_eq!(*header, 1);
                        assert_eq!(**body, Region::Block(2));
                        assert_eq!(*exit, Some(3));
                    }
                    other => panic!("expected While; got {:?}", other),
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn bottom_tested_loop_recovers_as_do_while() {
        //   B0: entry
        //   B1: body
        //   B2: conditional latch -> B1 (continue), B3 (exit)
        //   B3: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts[0], Region::Block(0));
                match &parts[1] {
                    Region::DoWhile { body, cond, exit } => {
                        assert_eq!(**body, Region::Block(1));
                        assert_eq!(*cond, 2);
                        assert_eq!(*exit, Some(3));
                    }
                    other => panic!("expected DoWhile; got {other:?}"),
                }
                assert_eq!(parts[2], Region::Block(3));
            }
            other => panic!("expected Seq; got {other:?}"),
        }
    }

    #[test]
    fn single_block_bottom_tested_loop_recovers_as_do_while() {
        // The body and latch share one block, as emitted for compact do-while
        // loops after CFG block splitting.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![
                    Op::Nop,
                    Op::CondJump {
                        cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                        target: 0x1100,
                        inverted: false,
                    },
                ],
                vec![0x1100, 0x1200],
            ),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Seq(parts) => match &parts[1] {
                Region::DoWhile { body, cond, exit } => {
                    assert_eq!(**body, Region::Seq(Vec::new()));
                    assert_eq!(*cond, 1);
                    assert_eq!(*exit, Some(2));
                }
                other => panic!("expected DoWhile; got {other:?}"),
            },
            other => panic!("expected Seq; got {other:?}"),
        }
        let succs = vec![vec![1], vec![1, 2], vec![]];
        assert!(verify_region(&succs, 0, &r).is_empty());
    }

    #[test]
    fn multiple_back_edges_do_not_turn_a_pretested_loop_into_do_while() {
        // B1 is the pre-test. B2 can continue directly to it, while B3 is the
        // ordinary latch. Treating B2 as a bottom-test would skip B1 before the
        // first iteration and was enough to break five -O2 fixture canaries.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1400,
                    inverted: false,
                }],
                vec![0x1200, 0x1400],
            ),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        fn contains_do_while(region: &Region) -> bool {
            match region {
                Region::DoWhile { .. } => true,
                Region::Seq(parts) => parts.iter().any(contains_do_while),
                Region::IfThen { then_r, .. } => contains_do_while(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    contains_do_while(then_r) || contains_do_while(else_r)
                }
                Region::While { body, .. } => contains_do_while(body),
                Region::Switch { arms, .. } => arms.iter().any(contains_do_while),
                Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => false,
            }
        }
        assert!(
            !contains_do_while(&r),
            "pre-tested loop became DoWhile: {r:#?}"
        );
    }

    #[test]
    fn multi_latch_loop_with_distinct_early_and_normal_exits_falls_back_totally() {
        // Optimised binary-search shape (clang -O2): B3 is the rotated loop
        // header, B2 and B5 are distinct latches, B7 is the successful early
        // return, and B6 is the ordinary exhausted-range return.
        //
        // Region::While has one header exit.  Choosing B7 strands both latch
        // arms after the successful return; choosing B6 invents a header edge
        // which does not exist.  Until the region algebra represents multiple
        // owned exits, the semantics-preserving representation is the complete
        // labelled CFG, not a lossy While plus leftovers.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, cond(0x1600), vec![0x1100, 0x1600]), // initial empty test
            (0x1100, vec![Op::Nop], vec![0x1300]),        // initialise bounds
            (0x1200, cond(0x1600), vec![0x1300, 0x1600]), // high-side latch
            (0x1300, cond(0x1700), vec![0x1400, 0x1700]), // compare / found
            (0x1400, cond(0x1200), vec![0x1200, 0x1500]), // choose update arm
            (0x1500, cond(0x1300), vec![0x1300, 0x1600]), // low-side latch
            (0x1600, vec![Op::Return], vec![]),           // not found
            (0x1700, vec![Op::Return], vec![]),           // found
        ]);

        let r = recover_for(&lf);
        assert_eq!(r, Region::Unstructured((0..8).collect()), "{r:#?}");
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn nested_loop_with_distinct_match_and_exhaustion_exits_falls_back_totally() {
        // Reduced GCC -O2 `has_pair`. B4/B3 is the inner search loop: B4's
        // match edge returns through B5, while B3's exhausted edge reaches the
        // outer latch B6 and eventually re-enters through B2. A Region::While
        // has only one distinguished exit. Treating B5 as that exit absorbed
        // B6 into the loop body but dropped B2's reload/reset, causing an
        // out-of-bounds search and false positive return on a real 16-element
        // differential vector.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, cond(0x1700), vec![0x1100, 0x1700]), // empty input guard
            (0x1100, cond(0x1700), vec![0x1200, 0x1700]), // one-element guard
            (0x1200, vec![Op::Nop], vec![0x1400]),        // load a[i], reset j
            (0x1300, cond(0x1600), vec![0x1400, 0x1600]), // inner latch/exhausted
            (0x1400, cond(0x1500), vec![0x1300, 0x1500]), // compare/match
            (0x1500, vec![Op::Return], vec![]),           // found
            (0x1600, cond(0x1200), vec![0x1200, 0x1700]), // outer latch/back-edge
            (0x1700, vec![Op::Return], vec![]),           // not found
        ]);

        let r = recover_for(&lf);
        assert_eq!(r, Region::Unstructured((0..8).collect()), "{r:#?}");
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn nonterminal_inner_exit_does_not_force_a_whole_function_fallback() {
        // Both exits from the inner cycle continue into outer-loop work. This
        // is the ordinary nested-loop class used by matrix/sort code, not the
        // `has_pair` class where the header exit returns from the function.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (0x1200, cond(0x1400), vec![0x1300, 0x1400]), // inner header / normal exit
            (0x1300, cond(0x1600), vec![0x1200, 0x1600]), // back-edge / secondary exit
            (0x1400, vec![Op::Nop], vec![0x1600]),        // post-inner continuation
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, cond(0x1200), vec![0x1200, 0x1700]), // outer latch / re-entry
            (0x1700, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        let cfg = Cfg::from(&lf, &ssa);

        assert!(!has_inner_loop_exit_that_reenters_via_outer_cycle(&cfg));
    }

    #[test]
    fn loop_early_return_through_shared_epilogue_falls_back_totally() {
        // GCC -O0 `fsm`: the loop header B1 normally exits through epilogue B6,
        // while B2 may return early through B5 -> B6 and its sibling continues
        // through the state-update ladder and latch.  B6 post-dominates B2 but
        // lies outside the loop.  Treating it as B2's local if/else join moves
        // the epilogue into the loop and strands the update ladder afterward.
        let cond = |target| {
            vec![Op::CondJump {
                cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                target,
                inverted: false,
            }]
        };
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (0x1100, cond(0x1600), vec![0x1200, 0x1600]), // loop header / normal exit
            (0x1200, cond(0x1500), vec![0x1300, 0x1500]), // continue / early return
            (0x1300, vec![Op::Nop], vec![0x1400]),        // state update
            (0x1400, vec![Op::Jump { target: 0x1100 }], vec![0x1100]),
            (0x1500, vec![Op::Jump { target: 0x1600 }], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let r = recover_for(&lf);
        assert_eq!(r, Region::Unstructured((0..7).collect()), "{r:#?}");
        assert!(verify_structure(&lf, &compute_ssa(&lf)).is_empty());
    }

    #[test]
    fn rotated_top_test_does_not_turn_the_latch_into_do_while() {
        // B0 can bypass the body before its first iteration. B2 is a bottom
        // latch only for subsequent iterations, so emitting `do` for B1..B2
        // would execute the body once when B0's condition is false.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1300,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200]),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1300],
            ),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        fn contains_do_while(region: &Region) -> bool {
            match region {
                Region::DoWhile { .. } => true,
                Region::Seq(parts) => parts.iter().any(contains_do_while),
                Region::IfThen { then_r, .. } => contains_do_while(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    contains_do_while(then_r) || contains_do_while(else_r)
                }
                Region::While { body, .. } => contains_do_while(body),
                Region::Switch { arms, .. } => arms.iter().any(contains_do_while),
                Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => false,
            }
        }
        assert!(
            !contains_do_while(&r),
            "rotated while became DoWhile: {r:#?}"
        );
    }

    #[test]
    fn early_exit_loop_is_not_promoted_to_plain_do_while() {
        // Entry into B1 is unconditional, but B1 can return through B3 before
        // reaching the latch B2. A DoWhile with only `{body, cond, exit}` cannot
        // own that second exit without moving it to the wrong nesting level.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100]),
            (
                0x1100,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1300,
                    inverted: false,
                }],
                vec![0x1200, 0x1300],
            ),
            (
                0x1200,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::S),
                    target: 0x1100,
                    inverted: false,
                }],
                vec![0x1100, 0x1400],
            ),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        fn contains_do_while(region: &Region) -> bool {
            match region {
                Region::DoWhile { .. } => true,
                Region::Seq(parts) => parts.iter().any(contains_do_while),
                Region::IfThen { then_r, .. } => contains_do_while(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    contains_do_while(then_r) || contains_do_while(else_r)
                }
                Region::While { body, .. } => contains_do_while(body),
                Region::Switch { arms, .. } => arms.iter().any(contains_do_while),
                Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => false,
            }
        }
        assert!(
            !contains_do_while(&r),
            "early-exit loop became DoWhile: {r:#?}"
        );
    }

    #[test]
    fn region_blocks_cover_every_llir_block() {
        // Structural analysis must never silently drop blocks — the Region
        // tree's coverage should match the function's block count modulo
        // ordering. (Duplicates are allowed because join blocks appear both
        // inside the conditional and as the subsequent Seq step.)
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        let seen: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        for i in 0..lf.blocks.len() {
            assert!(seen.contains(&i), "region tree missed block {i}: {:#?}", r);
        }
    }

    #[test]
    fn if_then_with_early_return_no_goto() {
        // The canonical `if (cond) return;` shape:
        //   B0 cond → B1 (terminating arm, returns), B2 (continuation)
        //   B1: return  (no successors)
        //   B2: return  (the function tail)
        // Expected: Seq[ IfThen{cond=0, then=Block(1), join=None}, Block(2) ]
        // Before #192 this fell through to Unstructured because B1 had zero
        // successors and the structurer required the body arm to reach a
        // shared join.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match r {
            Region::Seq(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Region::IfThen {
                        cond, then_r, join, ..
                    } => {
                        assert_eq!(*cond, 0);
                        assert!(matches!(**then_r, Region::Block(1)));
                        assert_eq!(*join, None);
                    }
                    other => panic!("expected IfThen with join=None; got {:?}", other),
                }
                assert_eq!(parts[1], Region::Block(2));
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn nonreturning_terminal_guard_is_body_independent_of_successor_order() {
        use crate::ir::types::{CallTarget, Flag, VReg};

        // The branch target is the successful continuation and the lexical
        // fallthrough is a non-returning guard body. Deliberately list the
        // taken target first: successor-vector order is not branch semantics.
        //
        //   b0: if (ok) goto b2
        //   b1: exit / unreachable       (fallthrough)
        //   b2: normal work; return      (taken target)
        //
        // Both arms terminate at CFG level, but presentation must remain
        // Seq[if (!ok) b1, b2], matching the machine fallthrough topology.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1200,
                    inverted: false,
                }],
                vec![0x1200, 0x1100],
            ),
            (
                0x1100,
                vec![Op::Call {
                    target: CallTarget::Direct(0x9000),
                    effects: None,
                }],
                vec![],
            ),
            (0x1200, vec![Op::Return], vec![]),
        ]);

        let r = recover_for(&lf);
        let Region::Seq(parts) = r else {
            panic!("expected terminal guard followed by continuation; got {r:?}");
        };
        assert_eq!(parts.len(), 2, "unexpected region sequence: {parts:?}");
        match &parts[0] {
            Region::IfThen {
                cond,
                then_r,
                join,
                invert,
            } => {
                assert_eq!(*cond, 0);
                assert_eq!(**then_r, Region::Block(1));
                assert_eq!(*join, None);
                assert!(*invert, "the raw taken condition must be negated");
            }
            other => panic!("expected one-arm terminal guard; got {other:?}"),
        }
        assert_eq!(parts[1], Region::Block(2));
    }

    #[test]
    fn two_returning_terminals_prefer_the_taken_edge_as_the_if_body() {
        use crate::ir::types::{Flag, VReg};

        // With two ordinary return arms there is no unique non-returning guard.
        // Resolve the tie from the conditional's semantic taken edge, never
        // from whichever successor happens to occupy a vector slot.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: VReg::Flag(Flag::Z),
                    target: 0x1200,
                    inverted: false,
                }],
                vec![0x1200, 0x1100],
            ),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);

        let r = recover_for(&lf);
        let Region::Seq(parts) = r else {
            panic!("expected terminal branch followed by sibling; got {r:?}");
        };
        assert_eq!(parts.len(), 2, "unexpected region sequence: {parts:?}");
        match &parts[0] {
            Region::IfThen { then_r, invert, .. } => {
                assert_eq!(**then_r, Region::Block(2));
                assert!(!*invert, "the taken arm uses the raw condition");
            }
            other => panic!("expected one-arm terminal branch; got {other:?}"),
        }
        assert_eq!(parts[1], Region::Block(1));
    }

    #[test]
    fn if_then_else_both_arms_terminate() {
        //   B0 cond → B1 (return), B2 (return)
        //   No continuation. Both arms exit the function.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
        ]);
        // Force "both terminate" by NOT using the early-return single-arm
        // pattern. The single-arm pattern fires first because it iterates
        // (t,e) and (e,t); to test the both-terminate branch in isolation
        // we use a CFG where neither arm is the structural continuation.
        // Since both early-return patterns produce equivalent output for a
        // 2-arm leaf, this test mirrors `if_then_with_early_return_no_goto`
        // to keep the contract covered. The both-terminate branch is the
        // safety net for irreducible cases.
        let r = recover_for(&lf);
        // Either Seq[IfThen, Block] or Seq[IfThenElse{join=None}] depending
        // on which detector fires first; both are correct shapes that
        // structure the goto away.
        let blocks: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        assert!(blocks.contains(&0));
        assert!(blocks.contains(&1));
        assert!(blocks.contains(&2));
        // Most importantly, the recovered region is NOT Unstructured.
        assert!(
            !matches!(&r, Region::Unstructured(_)),
            "expected structured shape; got {:?}",
            r,
        );
    }

    #[test]
    fn shared_exit_goto_folds_into_if_thens() {
        // The canonical real-binary shape:
        //   B0: cond → B1, L (goto L on true)
        //   B1: cond → B2, L (goto L on true)
        //   B2: → L  (fall-through)
        //   L:  return
        // Expected: the structurer wraps each `if cond` around `Block(L)`
        // and emits L itself as the function tail. Crucially, no
        // Unstructured nodes — every block participates in a structured
        // shape.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1300]), // B0: cond → B1, L
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]), // B1: cond → B2, L
            (0x1200, vec![Op::Nop], vec![0x1300]),         // B2: → L
            (0x1300, vec![Op::Return], vec![]),            // L:  return
        ]);
        let r = recover_for(&lf);
        // Walk the tree and confirm no Unstructured leaves and that the
        // shared exit (block 3) is referenced more than once (the
        // clone-inline behaviour).
        fn count_block(r: &Region, target: usize) -> (usize, bool) {
            match r {
                Region::Block(b) => ((*b == target) as usize, false),
                Region::Seq(parts) => {
                    let mut count = 0;
                    let mut bad = false;
                    for p in parts {
                        let (c, b) = count_block(p, target);
                        count += c;
                        bad |= b;
                    }
                    (count, bad)
                }
                Region::IfThen { then_r, .. } => count_block(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    let (c1, b1) = count_block(then_r, target);
                    let (c2, b2) = count_block(else_r, target);
                    (c1 + c2, b1 || b2)
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => {
                    count_block(body, target)
                }
                Region::Switch { arms, .. } => {
                    let mut count = 0;
                    let mut bad = false;
                    for a in arms {
                        let (c, b) = count_block(a, target);
                        count += c;
                        bad |= b;
                    }
                    (count, bad)
                }
                Region::Goto(_) => (0, false),
                Region::Unstructured(_) => (0, true),
            }
        }
        let (count, has_unstructured) = count_block(&r, 3);
        assert!(!has_unstructured, "expected no Unstructured; got {:?}", r);
        assert!(
            count >= 2,
            "expected shared-exit block referenced >=2 times; got {} in {:?}",
            count,
            r
        );
    }

    #[test]
    fn nested_early_returns_chain_into_seq() {
        //   B0 cond → B1 (return), B2 (next test)
        //   B2 cond → B3 (return), B4 (return)
        // Expected: two IfThens fused into a Seq, no Unstructured leaves.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Nop], vec![0x1300, 0x1400]),
            (0x1300, vec![Op::Return], vec![]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        // No Unstructured anywhere in the tree.
        fn assert_no_unstructured(r: &Region) {
            match r {
                Region::Block(_) => {}
                Region::Seq(parts) => parts.iter().for_each(assert_no_unstructured),
                Region::IfThen { then_r, .. } => assert_no_unstructured(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    assert_no_unstructured(then_r);
                    assert_no_unstructured(else_r);
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => {
                    assert_no_unstructured(body)
                }
                Region::Switch { arms, .. } => {
                    arms.iter().for_each(assert_no_unstructured);
                }
                Region::Goto(_) => {}
                Region::Unstructured(bs) => panic!("found Unstructured: {:?}", bs),
            }
        }
        assert_no_unstructured(&r);
        // All five blocks must still be covered.
        let blocks: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
        for i in 0..5 {
            assert!(blocks.contains(&i), "block {} missing", i);
        }
    }

    #[test]
    fn switch_shape_with_three_arms_recognized() {
        //   B0 dispatch → B1, B2, B3 (3 arms)
        //   B1, B2, B3 each → B4 (join)
        //   B4: return
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200, 0x1300]),
            (0x1100, vec![Op::Nop], vec![0x1400]),
            (0x1200, vec![Op::Nop], vec![0x1400]),
            (0x1300, vec![Op::Nop], vec![0x1400]),
            (0x1400, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Seq(parts) => {
                assert!(parts.len() >= 2);
                match &parts[0] {
                    Region::Switch {
                        dispatch,
                        arms,
                        join,
                        ..
                    } => {
                        assert_eq!(*dispatch, 0);
                        assert_eq!(arms.len(), 3);
                        assert_eq!(*join, Some(4));
                    }
                    other => panic!("expected Switch; got {:?}", other),
                }
            }
            other => panic!("expected Seq; got {:?}", other),
        }
    }

    #[test]
    fn nested_switch_arms_stop_at_the_enclosing_conditional_join() {
        // Clang -O0 jump-table dispatch is guarded by an out-of-range branch:
        //
        //        b0
        //       /  \
        //   default b5   dispatch b1 -> b2,b3,b4
        //       \          /   |   /
        //                 join b6 -> return
        //
        // The switch has no join dominated by its dispatch because b5 also
        // reaches b6.  Nevertheless b6 is the enclosing if/else join and no
        // switch arm owns it.  Letting the first case consume b6 nests the one
        // shared return in that case and makes every default path fall off the
        // emitted C function.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1500,
                    inverted: false,
                }],
                vec![0x1100, 0x1500],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300, 0x1400]),
            (0x1200, vec![Op::Nop], vec![0x1600]),
            (0x1300, vec![Op::Nop], vec![0x1600]),
            (0x1400, vec![Op::Nop], vec![0x1600]),
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("the shared join must be emitted after the conditional: {region:#?}")
        };
        assert!(
            matches!(parts.last(), Some(Region::Block(6))),
            "{region:#?}"
        );

        fn find_switch(region: &Region) -> Option<&Region> {
            match region {
                Region::Switch { .. } => Some(region),
                Region::Seq(parts) => parts.iter().find_map(find_switch),
                Region::IfThen { then_r, .. } => find_switch(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    find_switch(then_r).or_else(|| find_switch(else_r))
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => find_switch(body),
                Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => None,
            }
        }
        let Some(Region::Switch { arms, join, .. }) = find_switch(&region) else {
            panic!("expected nested switch: {region:#?}")
        };
        assert_eq!(
            *join,
            Some(6),
            "the switch must expose its enclosing shared continuation"
        );
        assert!(
            arms.iter().all(|arm| !arm.blocks().contains(&6)),
            "the enclosing join must not be consumed by a switch case: {region:#?}"
        );
    }

    #[test]
    fn guarded_switch_with_terminating_case_keeps_its_partial_join_outside() {
        // The range guard can bypass the dispatch directly to b5. Most cases
        // also reach b5, while one case returns through b6.  Since b5 does not
        // post-dominate the returning case, a global post-dominator search
        // misses the source shape:
        //
        //     if (in_range) { switch (...) { ...; case 3: return; } }
        //     b5: latch/update;
        //
        // Treating it as if/else places b5 in the bypass arm and forces every
        // continuing case to goto into that sibling arm.
        let lf = mk_cfg(vec![
            (
                0x1000,
                vec![Op::CondJump {
                    cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                    target: 0x1500,
                    inverted: false,
                }],
                vec![0x1100, 0x1500],
            ),
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300, 0x1400]),
            (0x1200, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1300, vec![Op::Jump { target: 0x1500 }], vec![0x1500]),
            (0x1400, vec![Op::Return], vec![]),
            (0x1500, vec![Op::Nop], vec![0x1600]),
            (0x1600, vec![Op::Return], vec![]),
        ]);

        let region = recover_for(&lf);
        let Region::Seq(parts) = &region else {
            panic!("expected guarded switch followed by its join: {region:#?}")
        };
        let Some(Region::IfThen {
            then_r,
            join: Some(5),
            ..
        }) = parts.first()
        else {
            panic!("expected one-armed guarded switch: {region:#?}")
        };
        assert!(
            matches!(then_r.as_ref(), Region::Switch { join: Some(5), .. }),
            "the switch and guard must share b5 as their continuation: {region:#?}"
        );
        assert!(
            matches!(parts.get(1), Some(Region::Block(5))),
            "{region:#?}"
        );
    }

    #[test]
    fn switch_shape_arms_with_terminating_returns() {
        //   B0 dispatch → B1, B2, B3
        //   each Bi: return  (no shared join)
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200, 0x1300]),
            (0x1100, vec![Op::Return], vec![]),
            (0x1200, vec![Op::Return], vec![]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let r = recover_for(&lf);
        match &r {
            Region::Switch {
                dispatch,
                arms,
                join,
                ..
            } => {
                assert_eq!(*dispatch, 0);
                assert_eq!(arms.len(), 3);
                assert_eq!(*join, None);
            }
            other => panic!("expected Switch with join=None; got {:?}", other),
        }
    }

    #[test]
    fn runs_on_real_binary_without_losing_blocks() {
        use crate::analysis::cfg::{analyze_functions_bytes, Budgets};
        use crate::core::binary::Arch;
        use crate::ir::lift_function::lift_function_from_bytes;
        let path = std::path::Path::new(
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
        );
        if !path.exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let (funcs, _cg) = analyze_functions_bytes(
            &data,
            &Budgets {
                max_functions: 4,
                max_blocks: 128,
                max_instructions: 2000,
                timeout_ms: 500,
            },
        );
        for f in &funcs {
            if let Some(lf) = lift_function_from_bytes(&data, f, Arch::X86_64) {
                let ssa = compute_ssa(&lf);
                let r = recover(&lf, &ssa);
                // Every block must be covered at least once.
                let covered: std::collections::HashSet<usize> = r.blocks().into_iter().collect();
                for i in 0..lf.blocks.len() {
                    assert!(
                        covered.contains(&i),
                        "block {} missing from region tree of {}",
                        i,
                        f.name,
                    );
                }
            }
        }
    }

    // --- structure verifier (§5) -------------------------------------------

    #[test]
    fn verify_region_flags_an_empty_arm_edge() {
        // succs: 0 -> {1,3}, 1 -> {2,3}, 2 -> {4}, 3 -> {4}, 4 -> {}.
        // A region that structures block 1 as an if whose then-arm is EMPTY
        // drops the edge 1->3: verify_region must report it.
        let succs = vec![vec![1, 3], vec![2, 3], vec![4], vec![4], vec![]];
        let bad = Region::Seq(vec![
            Region::IfThenElse {
                cond: 0,
                then_r: Box::new(Region::Block(3)),
                else_r: Box::new(Region::IfThenElse {
                    cond: 1,
                    then_r: Box::new(Region::Seq(vec![])), // <-- empty arm, drops 1->3
                    else_r: Box::new(Region::Block(2)),
                    join: Some(4),
                    invert: false,
                }),
                join: Some(4),
                invert: false,
            },
            Region::Block(4),
        ]);
        let errs = verify_region(&succs, 0, &bad);
        assert!(
            errs.contains(&StructError::CondEdgeUncovered {
                cond: 1,
                missing_succ: 3
            }),
            "expected the dropped 1->3 edge to be flagged; got {:?}",
            errs
        );
    }

    #[test]
    fn verify_region_flags_a_dropped_block() {
        // Block 2 is reachable (0->2) but absent from the region tree.
        let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let region = Region::Seq(vec![
            Region::IfThen {
                cond: 0,
                then_r: Box::new(Region::Block(1)),
                join: Some(3),
                invert: false,
            },
            Region::Block(3),
        ]);
        let errs = verify_region(&succs, 0, &region);
        assert!(errs.contains(&StructError::BlockDropped { block: 2 }));
    }

    #[test]
    fn verify_region_clean_on_well_formed_diamond() {
        let succs = vec![vec![1, 2], vec![3], vec![3], vec![]];
        let region = Region::Seq(vec![
            Region::IfThenElse {
                cond: 0,
                then_r: Box::new(Region::Block(1)),
                else_r: Box::new(Region::Block(2)),
                join: Some(3),
                invert: false,
            },
            Region::Block(3),
        ]);
        assert!(verify_region(&succs, 0, &region).is_empty());
    }

    #[test]
    fn verify_structure_clean_on_recovered_diamond() {
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1200]),
            (0x1100, vec![Op::Nop], vec![0x1300]),
            (0x1200, vec![Op::Nop], vec![0x1300]),
            (0x1300, vec![Op::Return], vec![]),
        ]);
        let ssa = compute_ssa(&lf);
        assert!(verify_structure(&lf, &ssa).is_empty());
    }

    #[test]
    fn short_circuit_shared_join_is_faithful_via_goto() {
        // The `x>0 && y>0` shape: two conditionals share a common false block.
        //   B0 -> {B1, Bfalse}   B1 -> {Btrue, Bfalse}
        //   Btrue -> Bend  Bfalse -> Bend  Bend: return
        // The shared Bfalse must not be dropped into an empty arm: build_arm
        // references it via Region::Goto, so the region is faithful (verifier
        // clean) and the edge to Bfalse is preserved.
        let lf = mk_cfg(vec![
            (0x1000, vec![Op::Nop], vec![0x1100, 0x1300]), // B0 cond
            (0x1100, vec![Op::Nop], vec![0x1200, 0x1300]), // B1 cond
            (0x1200, vec![Op::Nop], vec![0x1400]),         // Btrue
            (0x1300, vec![Op::Nop], vec![0x1400]),         // Bfalse (shared)
            (0x1400, vec![Op::Return], vec![]),            // Bend
        ]);
        let ssa = compute_ssa(&lf);
        let region = recover(&lf, &ssa);
        assert!(
            verify_structure(&lf, &ssa).is_empty(),
            "short-circuit region must be faithful after the goto fix; got {:?}",
            verify_structure(&lf, &ssa)
        );
        // The shared false block (index 3) is referenced via a Goto somewhere.
        fn has_goto(r: &Region, target: usize) -> bool {
            match r {
                Region::Goto(b) => *b == target,
                Region::Seq(v) => v.iter().any(|p| has_goto(p, target)),
                Region::IfThen { then_r, .. } => has_goto(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    has_goto(then_r, target) || has_goto(else_r, target)
                }
                Region::While { body, .. } => has_goto(body, target),
                Region::Switch { arms, .. } => arms.iter().any(|a| has_goto(a, target)),
                _ => false,
            }
        }
        assert!(
            has_goto(&region, 3),
            "expected a Goto to the shared false block; region={:?}",
            region
        );
    }

    #[test]
    fn relocated_linear_fallthrough_to_an_owned_join_becomes_a_goto() {
        use crate::ir::types::{Flag, VReg};

        let cj = |target: u64| Op::CondJump {
            cond: VReg::Flag(Flag::S),
            target,
            inverted: false,
        };
        // The first arm owns B3 before the second arm is structured.  Inside
        // that second arm B5 reaches B3 by machine-code adjacency, not an
        // explicit jump.  Once B5 is nested in C, B3 is no longer lexically
        // next, so the linear edge must be materialised as Goto(3).
        //
        // This is the reduced shape of Clang O2 loop_return_on_neg: its i=6
        // negative arm fell through to a shared result block in the binary but
        // fell out of a nested C `if`, returning an uninitialised value.
        let lf = mk_cfg(vec![
            (0x1000, vec![cj(0x1100)], vec![0x1100, 0x1200]), // B0
            (0x1100, vec![Op::Nop], vec![0x1300]),            // B1 -> shared
            (0x1200, vec![cj(0x1500)], vec![0x1500, 0x1600]), // B2
            (0x1300, vec![Op::Nop], vec![0x1400]),            // B3 shared
            (0x1400, vec![Op::Return], vec![]),               // B4 epilogue
            (0x1500, vec![Op::Nop], vec![0x1300]),            // B5 linear -> B3
            (0x1600, vec![Op::Jump { target: 0x1400 }], vec![0x1400]), // B6 bypass
        ]);

        fn has_goto(r: &Region, target: usize) -> bool {
            match r {
                Region::Goto(block) => *block == target,
                Region::Seq(parts) => parts.iter().any(|part| has_goto(part, target)),
                Region::IfThen { then_r, .. } => has_goto(then_r, target),
                Region::IfThenElse { then_r, else_r, .. } => {
                    has_goto(then_r, target) || has_goto(else_r, target)
                }
                Region::While { body, .. } | Region::DoWhile { body, .. } => has_goto(body, target),
                Region::Switch { arms, .. } => arms.iter().any(|arm| has_goto(arm, target)),
                Region::Block(_) | Region::Unstructured(_) => false,
            }
        }

        let region = recover_for(&lf);
        assert!(
            has_goto(&region, 3),
            "relocated linear edge to B3 was dropped: {region:#?}"
        );
    }
}
