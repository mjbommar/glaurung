//! The recovered region tree — the value structuring produces, and the two
//! pure queries over it.
//!
//! [`Region`] is the whole vocabulary the rest of the decompiler speaks: the
//! AST lowerer, the accounting pass and the verifier all consume this tree and
//! nothing else from structuring. It changes when the region algebra grows a
//! shape it can express, which is a different event from any recogniser
//! learning to spot one.
//!
//! [`Region::blocks`] and [`entry_block`] are the only questions answerable
//! from the tree alone, with no CFG in hand; every predicate that needs a
//! [`super::cfg::Cfg`] lives with the pass that asks it.

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
    /// A natural loop with multiple internal conditional latches and no
    /// distinguished header test. Blocks are owned once and lowered in labelled
    /// CFG form inside `while (1)`, preserving the loop boundary without
    /// pretending one latch condition governs every back-edge.
    RawLoop {
        header: usize,
        blocks: Vec<usize>,
        /// Every CFG successor leaving the owned natural-loop body. Raw
        /// dispatch loops can terminate through more than one case, so a
        /// single distinguished exit would lose executable control flow.
        exits: Vec<usize>,
    },
    /// `switch (discriminant) { case 0: <arm>; case 1: <arm>; ... }`
    /// (#193). The dispatch block has N>=3 successors (typical jump-
    /// table dispatch); each arm is a sub-region; the join is the
    /// shared post-dominator if one exists.
    Switch {
        /// Optional range-check block folded into this switch. Ghidra, angr,
        /// and Kuna all recover the resolved multi-way component before its
        /// surrounding guard; retaining the guard here lets the AST discard
        /// the compiler branch while preserving its normalization prefix.
        guard: Option<usize>,
        dispatch: usize,
        /// Normalized case labels attached to each distinct arm, parallel to
        /// `arms`. Multiple table slots may target one block after compiler
        /// case folding, so one arm can own several labels.
        case_labels: Vec<Vec<i64>>,
        arms: Vec<Region>,
        /// Default region proven by a guarding conditional and also targeted
        /// by in-range table holes. When `guard` is present this region owns
        /// the default-only blocks up to `join`; otherwise it is a borrowed
        /// view because the enclosing conditional owns them.
        formal_default: Option<Box<Region>>,
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
                Region::RawLoop { blocks, .. } => out.extend(blocks.iter().copied()),
                Region::Switch {
                    guard,
                    dispatch,
                    arms,
                    formal_default,
                    join,
                    ..
                } => {
                    if let Some(guard) = guard {
                        out.push(*guard);
                    }
                    out.push(*dispatch);
                    for a in arms {
                        walk(a, out);
                    }
                    if guard.is_some() {
                        if let Some(default) = formal_default {
                            walk(default, out);
                        }
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
        Region::RawLoop { header, .. } => Some(*header),
        Region::Switch {
            guard, dispatch, ..
        } => guard.or(Some(*dispatch)),
        Region::Goto(b) => Some(*b),
        Region::Unstructured(bs) => bs.first().copied(),
    }
}
