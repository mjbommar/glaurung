//! F-11 entry/exit flag derivation and F-12 singleton-funcend removal.
//!
//! Owned by stage S3. `mod.rs` currently derives both inline and
//! approximately; this module is where the rules Joern actually applies go,
//! and `mod.rs` will call into it once they are here.
//!
//! # Why these two rules are worth their own file
//!
//! `cfgutils.similarity.vj_ged` reads three things about a node: its in-degree,
//! its out-degree, and its `is_entrypoint` / `is_exitpoint` flags
//! ([`docs/design/static-c-analysis/joern-behavior.md`] section 2). This module
//! produces two of the three, and F-12 moves the third: deleting the
//! function-end block drops its in-edges with it, which takes every `return`
//! block from out-degree 1 to out-degree 0. Getting either rule wrong changes
//! the score of every function, not the bookkeeping.
//!
//! # What the published corpus says (measured, not assumed)
//!
//! Over the 91,548 functions of `~/.cache/glaurung/decbench-full/tree`
//! (`O0`, `O2`, `O2-noinline`), re-measured 2026-09-04:
//!
//! | fact | count |
//! |---|---|
//! | functions with no entry-flagged block | 0 |
//! | functions with **more than one** entry-flagged block | 1,334 |
//! | functions with more than one exit-flagged block | 0 |
//! | functions with no exit-flagged block | 44,832 |
//! | `exit` set equals "blocks holding `FUNCTION_END`" | 91,548 / 91,548 |
//! | exit-flagged blocks that have a successor | 0 |
//! | functions with a duplicated edge in the published edge list | 0 |
//! | functions with at least one self-loop | 3,914 |
//! | exit-flagged functions whose exit block is the graph's only sink | 46,711 / 46,716 |
//! | functions with **no** exit flag and yet exactly one sink | 4,773 |
//! | functions with no exit flag and no sink at all | 3,729 |
//!
//! Four of those shape the code below.
//!
//! *Multi-entry is legal output.* 1,334 functions carry more than one entry
//! flag, so [`derive_flags`] ORs across a block's members and never collapses
//! the result to a single block. Normalizing them away is the natural bug.
//! We do not yet *produce* multi-entry output --- S2 emits one
//! [`NodeKind::Entry`] node per function --- and the corpus shows that costing
//! us directly: of the 8 mismatched cells whose degree multiset already
//! matches the published one, 4 differ only in that the published side carries
//! two entry flags where we emit one, and 2 of those are stored `0.0`, which
//! means Joern's CFG of the *decompiled* text carried two as well. Closing
//! that is upstream of this file, not in it.
//!
//! *The exit flag and the funcend block are the same fact.* "No exit flag"
//! (44,832) and "no block holding `FUNCTION_END`" (44,832) are the same
//! functions, so F-12's guard is what decides 49.0% of all exit flags.
//!
//! *"Kept iff `in_degree(METHOD_RETURN) == 1`" is not the rule.* 4,773
//! published functions have no exit flag and yet exactly one sink, so "the
//! funcend was deleted" is not the same claim as "the funcend had several
//! predecessors". `to_supergraph` contracts `src -> dst` only when
//! `outdeg(src) == 1` **and** `indeg(dst) == 1`, so a `METHOD_RETURN` whose
//! single predecessor forks still stays a singleton and is still deleted. The
//! condition this file tests is the one that survives that: the funcend block
//! is a singleton, which is a property of the partition it is handed.
//!
//! *Block edges are a set.* No published function has a duplicated edge, but
//! 3,914 have a self-loop, so [`parity_blocks`] deduplicates and keeps
//! self-loops. `pyjoern` parses DOT into an `nx.DiGraph`, which is exactly
//! those two behaviours.
//!
//! # What the reference actually does when it merges two blocks
//!
//! Not an OR of the two blocks' flags, which is what an earlier revision of
//! this file asserted. `cfgutils.data.generic_block` is:
//!
//! ```text
//! def copy(self):
//!     return self.__class__(self.addr, statements=..., idx=self.idx)
//!
//! def merge_blocks(cls, block1, block2):
//!     new_node = block1.copy()             # <-- drops block1's stored flags
//!     new_node.statements += block2.statements
//!     new_node.is_entrypoint |= block2.is_entrypoint
//!     new_node.is_exitpoint |= block2.is_exitpoint
//! ```
//!
//! `copy()` forwards neither flag, so `block1` contributes nothing it had
//! previously been *told* --- only what `pyjoern`'s `Block` recomputes from the
//! statement list, and both of those properties are positional:
//!
//! * `is_entrypoint` is `statements[0]` being `Nop(FUNC_START)`, and after the
//!   concatenation `statements[0]` is still `block1`'s first statement. So
//!   `entry(a then b) = (a's first statement is FUNC_START) OR entry(b)`.
//! * `is_exitpoint` is `statements[-1]` being `Nop(FUNC_END)`, and after the
//!   concatenation that is `block2`'s last statement. So
//!   `exit(a then b) = exit(b)`: the last member decides, alone.
//!
//! The entry half is therefore **merge-order dependent** --- fold a chain from
//! the right and every member is asked, fold it from the left and only the
//! first and the last are --- and `to_supergraph` folds in `nx` edge order,
//! which is an insertion order and not a property of the graph. That is
//! exactly the gap the corpus measures: taking the block's first statement
//! matches 91,192 / 91,548 functions and taking membership over statements
//! matches 89,978 / 91,548, with the truth strictly between them
//! (`first ⊆ published ⊆ membership` holds for all 91,548).
//!
//! [`derive_flags`] takes membership, the upper bound. For the graphs this
//! layer is handed the three rules coincide, and `syntax::cfg`'s validator is
//! what makes that true rather than luck: it rejects an `Entry` with a
//! predecessor and an `Exit` with a successor, so
//!
//! * the function-start node can have nothing contracted into it and is
//!   always its chain's **first** member, and
//! * the function-end node can contract nothing after it and is always its
//!   chain's **last** member.
//!
//! Two published functions pin the two halves, both in
//! `O0/bash/source_cfgs/bash.json`:
//!
//! * `pop_var_context` --- published `entry [4, 5]`, but only block 5 has
//!   `FUNCTION_START` as its first statement. Block 4 holds it in a later
//!   position and is still flagged, because a fold reached it as `block2` and
//!   asked it for its own flag. Membership across a merged block is required.
//! * `strvec_sort` --- published `entry [0]`, yet blocks 1 and 2 also *contain*
//!   a `FUNCTION_START` line. Those lines sit mid-label inside a single
//!   pre-coalescing node, so the corresponding `Block` was never an entry point
//!   and the fold had nothing to ask. Membership over raw statements is not
//!   enough.
//!
//! # Why the off-by-one mismatch bucket is not this file's
//!
//! At 79,790 / 85,645 cells exact (93.1636%,
//! `tools/source_cfg_parity.py --provider glaurung`, 2026-09-04), the 1,527
//! cells that miss by one split as
//!
//! | cause | cells |
//! |---|---|
//! | our CFG is role-isomorphic to the *published source* CFG, so we score 0 where the metric's `max(1.0, ...)` floor stores 1 | 42 |
//! | the >200-node size lower bound, off by one node or one edge | 8 |
//! | a genuine shape difference: 936 over-counting, 549 under-counting | 1,477 |
//!
//! The first class cannot be won without making the front end worse: on those
//! 42 functions we recover a graph structurally identical to the original
//! source, and Joern did not. None of the three is a flag defect, and
//! replacing the rules in this file with each plausible alternative loses far
//! more corpus-wide than it wins:
//!
//! | alternative | gained | lost | net | metric |
//! |---|---|---|---|---|
//! | never flag an exit (delete the funcend unconditionally) | 55 | 42,844 | -42,789 | bare |
//! | flag every sink as an exit | 68 | 20,618 | -20,550 | bare |
//! | delete the exit-flagged sink as well | 131 | 53,989 | -53,858 | bare |
//! | never delete the funcend | 176 | 25,151 | -24,975 | bare |
//! | drop self-loops | 12 | 3,100 | -3,088 | bare |
//! | flag the unique sink as an exit | 1 | 70 | -69 | **authoritative** |
//! | keep only the lowest-id entry flag | 0 | 0 | 0 | **authoritative** |
//!
//! "bare" rows were scored with bare `vj_ged` against a base of 79,535 rather
//! than the `GEDMetric` decision procedure against 79,790; the two differ only
//! by an isomorphism fast path and a `max(1.0, ...)` floor, worth 255 cells in
//! total, so they cannot move a five-figure margin. The two rows whose margin
//! was small enough to flip were re-scored under the authoritative metric and
//! did not.
//!
//! Only 8 of the 5,855 mismatched cells corpus-wide have a matching degree
//! multiset and a differing role multiset, which is the only shape a flag
//! defect can take at all --- and 4 of those are the multi-entry gap named
//! above. Before changing a rule here, re-run that table; a rule that wins the
//! bucket and loses the corpus is not a rule.

use crate::syntax::cfg::{Cfg, NodeKind};
use crate::syntax::ids::NodeId;

/// Joern's `is_entrypoint` / `is_exitpoint`, one pair per coalesced block.
///
/// Indexed by block number, which is the index into the chain slice the flags
/// were derived from --- the same numbering [`crate::syntax::cfg::Cfg::coalesced`]
/// gives its nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockFlags {
    entry: Vec<bool>,
    exit: Vec<bool>,
}

impl BlockFlags {
    /// How many blocks are flagged.
    pub fn len(&self) -> usize {
        self.entry.len()
    }

    /// Whether there are no blocks at all.
    pub fn is_empty(&self) -> bool {
        self.entry.is_empty()
    }

    /// Whether `block` carries `is_entrypoint`. `false` for an unknown block,
    /// because a flag lookup must not panic (`REQ-SYN-2`).
    pub fn is_entry(&self, block: u32) -> bool {
        self.entry.get(block as usize).copied().unwrap_or(false)
    }

    /// Whether `block` carries `is_exitpoint`. `false` for an unknown block.
    pub fn is_exit(&self, block: u32) -> bool {
        self.exit.get(block as usize).copied().unwrap_or(false)
    }

    /// Every entry-flagged block, ascending. Usually one, legally more (1,334
    /// published functions carry several).
    pub fn entry_blocks(&self) -> Vec<u32> {
        flagged(&self.entry)
    }

    /// Every exit-flagged block, ascending. Empty for 44,832 of the 91,548
    /// published functions --- see F-12.
    pub fn exit_blocks(&self) -> Vec<u32> {
        flagged(&self.exit)
    }
}

/// The indices of the `true` entries of `bits`, ascending.
fn flagged(bits: &[bool]) -> Vec<u32> {
    bits.iter()
        .enumerate()
        .filter(|(_, set)| **set)
        .map(|(index, _)| index as u32)
        .collect()
}

/// F-11: derive `is_entrypoint` / `is_exitpoint` for each block of a chain
/// partition of `source`.
///
/// `chains` is a partition of `source`'s nodes into coalesced blocks, in the
/// order control passes through each --- [`crate::syntax::cfg::ChainPartition::chains`]
/// is one, and the parity layer may supply another that merges the anchors
/// Joern merges. Block `i` is `chains[i]`.
///
/// A block is an entry point iff any member is the function-start marker
/// ([`NodeKind::Entry`]) and an exit point iff any member is the function-end
/// marker ([`NodeKind::Exit`]) --- the OR that `GenericBlock.merge_blocks`
/// performs. See the module docs for why membership is the right test here and
/// what would have to change if a node ever held more than one statement.
///
/// Nodes named by `chains` that `source` does not have are ignored rather than
/// rejected: this is a projection, not a validator.
pub fn derive_flags(source: &Cfg, chains: &[Vec<NodeId>]) -> BlockFlags {
    let mut entry = Vec::with_capacity(chains.len());
    let mut exit = Vec::with_capacity(chains.len());
    for chain in chains {
        entry.push(
            chain
                .iter()
                .any(|id| kind_of(source, *id) == Some(NodeKind::Entry)),
        );
        exit.push(
            chain
                .iter()
                .any(|id| kind_of(source, *id) == Some(NodeKind::Exit)),
        );
    }
    BlockFlags { entry, exit }
}

/// The kind of `id` in `source`, or `None` when `source` has no such node.
fn kind_of(source: &Cfg, id: NodeId) -> Option<NodeKind> {
    source.node(id).map(|node| node.kind())
}

/// The block-level projection F-12 and [`parity_blocks`] both need.
///
/// Kept private: it is an implementation detail of the two public rules, and
/// exposing a second block-graph type next to [`Cfg`] would invite a caller to
/// pick the wrong one.
struct BlockView {
    /// Which block each source node landed in, `u32::MAX` when no chain claims
    /// it.
    of_node: Vec<u32>,
    /// Block-to-block edges, deduplicated and ascending. Self-loops survive.
    edges: Vec<(u32, u32)>,
    /// `out_degree[b]` counts the deduplicated edges leaving block `b`.
    out_degree: Vec<u32>,
}

impl BlockView {
    /// Project `source`'s edges onto `chains`.
    ///
    /// An edge is contracted away exactly when both ends are in one chain and
    /// the destination immediately follows the source in it --- the same test
    /// [`crate::syntax::cfg::ChainPartition::is_internal`] applies, restated
    /// here because this module takes a chain slice rather than the partition
    /// type, so that a parity-specific partition can be substituted.
    ///
    /// A back edge closing a contracted cycle has both ends in one chain but is
    /// not consecutive, so it survives as a self-loop --- which is what
    /// `nx.DiGraph` does with it and what 3,914 published functions contain.
    fn new(source: &Cfg, chains: &[Vec<NodeId>]) -> Self {
        let count = source.node_count();
        let mut of_node = vec![u32::MAX; count];
        let mut position = vec![u32::MAX; count];
        for (block, chain) in chains.iter().enumerate() {
            for (offset, id) in chain.iter().enumerate() {
                if let Some(slot) = of_node.get_mut(id.index()) {
                    *slot = block as u32;
                }
                if let Some(slot) = position.get_mut(id.index()) {
                    *slot = offset as u32;
                }
            }
        }

        let mut edges: Vec<(u32, u32)> = Vec::with_capacity(source.edge_count());
        for edge in source.edges() {
            let (Some(&src), Some(&dst)) =
                (of_node.get(edge.src.index()), of_node.get(edge.dst.index()))
            else {
                continue;
            };
            if src == u32::MAX || dst == u32::MAX {
                continue;
            }
            let (Some(&src_pos), Some(&dst_pos)) = (
                position.get(edge.src.index()),
                position.get(edge.dst.index()),
            ) else {
                continue;
            };
            if src == dst && dst_pos == src_pos.saturating_add(1) {
                continue;
            }
            edges.push((src, dst));
        }
        // `nx.DiGraph` holds at most one edge per ordered pair, and no
        // published function has a duplicated edge; parallel edges here would
        // inflate both degrees and therefore the distance.
        edges.sort_unstable();
        edges.dedup();

        let mut out_degree = vec![0u32; chains.len()];
        for (src, _) in &edges {
            if let Some(slot) = out_degree.get_mut(*src as usize) {
                *slot = slot.saturating_add(1);
            }
        }

        // `position` is construction-only: it decides which edges the chains
        // contract away, and nothing downstream re-reads it.
        Self {
            of_node,
            edges,
            out_degree,
        }
    }

    /// How many deduplicated edges leave `block`. `0` for an unknown block.
    fn out_degree(&self, block: u32) -> u32 {
        self.out_degree.get(block as usize).copied().unwrap_or(0)
    }
}

/// F-12: the one block the funcend rule deletes, if its guard holds.
///
/// The guard is a conjunction of four conditions, and every one of them is
/// load-bearing (`REQ-CFG-10`). A block is a candidate when
///
/// 1. its out-degree is `0`,
/// 2. it holds **exactly one** statement, and
/// 3. that statement is the function-end marker ([`NodeKind::Exit`]);
///
/// and the deletion happens only when
///
/// 4. the graph holds **exactly one** such candidate.
///
/// Anything else keeps the block. That is not a formality: a funcend block that
/// coalesced into a larger block fails (2) and survives *flagged*
/// `is_exitpoint`, and 46,716 of the 91,548 published functions are in that
/// regime while the other 44,832 are in the deletion regime. Deleting
/// unconditionally would erase every exit flag in the corpus and take each
/// `return` block's out-degree with it.
///
/// Evidence for each condition, and its absence:
///
/// * (1) and (2) are what the corpus discriminates on: all 46,716 surviving
///   funcend blocks have out-degree 0 **and** more than one statement, so (2)
///   is the condition that actually fires. `O0/base-passwd/update-passwd.json`
///   holds both regimes --- `xstrdup` (two `return`s, funcend stayed a
///   singleton, deleted, `exit []`) and `xasprintf` (one `return`, funcend
///   merged into it, kept, `exit [0]`).
/// * (2) counts **statements**, not chain members --- see [`statement_count`].
///   The two agree on every graph S2 produces today, because the function-end
///   node is built by `CfgNode::single`; they stop agreeing the moment a node
///   carries more than one span, and then counting members would delete a
///   block the reference keeps.
/// * (1) alone and (4) are **not exercised by the corpus**: Joern gives a
///   method one shared `METHOD_RETURN` with no successor, so no published
///   function has a funcend block with a successor (0 of 46,716 exit-flagged
///   blocks have one) or two funcend candidates. They are implemented from
///   `REQ-CFG-10` and tested against it, not against an observation.
///
/// Returns the block index into `chains`, or `None` when nothing is deleted.
pub fn singleton_funcend(source: &Cfg, chains: &[Vec<NodeId>]) -> Option<u32> {
    let view = BlockView::new(source, chains);
    funcend_candidate(source, chains, &view)
}

/// [`singleton_funcend`] over an already-built projection.
///
/// Written in the reference's order --- out-degree, then statement count, then
/// the marker --- so the two can be diffed line by line.
fn funcend_candidate(source: &Cfg, chains: &[Vec<NodeId>], view: &BlockView) -> Option<u32> {
    let mut found = None;
    let mut candidates = 0u32;
    for (block, chain) in chains.iter().enumerate() {
        if view.out_degree(block as u32) != 0 {
            continue;
        }
        // Condition (2). A chain of two nodes holds at least two statements,
        // so this subsumes "the chain is a singleton" rather than adding to
        // it, and the `any` below is then a test of that one member.
        if statement_count(source, chain) != 1 {
            continue;
        }
        if !chain
            .iter()
            .any(|id| kind_of(source, *id) == Some(NodeKind::Exit))
        {
            continue;
        }
        candidates = candidates.saturating_add(1);
        found = Some(block as u32);
    }
    // Condition (4): the reference deletes only when the candidate is unique.
    if candidates == 1 {
        found
    } else {
        None
    }
}

/// How many statements a block holds, in the reference's sense.
///
/// F-12's guard is `len(node.statements) == 1`, and a `pyjoern` `Block`'s
/// statements are the label lines of one Joern DOT node, concatenated across
/// everything `to_supergraph` merged into it. The analogue here is the
/// coalesced span list: [`crate::syntax::cfg::CfgNode::spans`] carries one
/// entry per source construct a node covers, and a chain concatenates them the
/// same way. Counting chain *members* instead is the same number only while
/// every node holds exactly one span --- true of what S2 emits today, and not
/// something F-9's node layer promises to keep, which is why the count is
/// taken over spans and not over the chain.
///
/// A node with no spans still counts as one statement. A block the reference
/// can see always has at least one, so treating an empty span list as zero
/// would let a funcend block fail condition (2) for a reason the reference has
/// no counterpart to, and silently stop deleting it.
fn statement_count(source: &Cfg, chain: &[NodeId]) -> usize {
    chain
        .iter()
        .filter_map(|id| source.node(*id))
        .map(|node| node.spans().len().max(1))
        .sum()
}

/// The coalesced blocks of one function after F-11 and F-12, in block ids.
///
/// Ids are the pre-removal block numbering --- the index into the chain slice
/// [`parity_blocks`] was given --- so a caller can map a surviving block back to
/// the chain and the source spans it came from. [`ParityBlocks::renumbered`]
/// compacts them to `0..n-1` when a dense numbering is what is wanted (F-14
/// owns the choice of order; the compaction here preserves ascending block id).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParityBlocks {
    /// The surviving blocks, ascending.
    pub kept: Vec<u32>,
    /// Edges between surviving blocks, deduplicated and ascending. Self-loops
    /// are kept; the deleted funcend block's in-edges are not.
    pub edges: Vec<(u32, u32)>,
    /// Surviving blocks carrying `is_entrypoint`, ascending.
    pub entry: Vec<u32>,
    /// Surviving blocks carrying `is_exitpoint`, ascending. Empty whenever
    /// F-12 fired, which is 49.0% of the published corpus.
    pub exit: Vec<u32>,
    /// The block F-12 deleted, in the pre-removal numbering. It has no dense
    /// id, so [`ParityBlocks::renumbered`] leaves this field alone.
    pub removed_funcend: Option<u32>,
}

impl ParityBlocks {
    /// Where `block` sits in [`ParityBlocks::kept`], or `None` if it did not
    /// survive. `kept` is ascending, so this is a binary search.
    pub fn index_of(&self, block: u32) -> Option<u32> {
        self.kept.binary_search(&block).ok().map(|at| at as u32)
    }

    /// The same blocks renumbered `0..n-1` in ascending block order.
    ///
    /// F-12 is the only step that can leave a hole in the numbering, so this is
    /// where the hole is closed. Every id in `edges`, `entry` and `exit` is
    /// remapped; an id with no surviving block is dropped, which cannot happen
    /// for a well-formed input and is handled rather than asserted
    /// (`REQ-SYN-2`).
    pub fn renumbered(&self) -> ParityBlocks {
        let map = |block: &u32| self.index_of(*block);
        ParityBlocks {
            kept: (0..self.kept.len() as u32).collect(),
            edges: self
                .edges
                .iter()
                .filter_map(|(src, dst)| Some((map(src)?, map(dst)?)))
                .collect(),
            entry: self.entry.iter().filter_map(map).collect(),
            exit: self.exit.iter().filter_map(map).collect(),
            removed_funcend: self.removed_funcend,
        }
    }
}

/// Apply F-11 and F-12 to one chain partition of `source`.
///
/// The one call the parity layer needs: it projects `source`'s edges onto the
/// blocks, derives the flags, applies the guarded funcend deletion, and drops
/// the deleted block's in-edges with it. The projection is computed once, so
/// the flags and the guard cannot disagree about what the block graph is.
///
/// Ordering is total and derived from block ids alone, so the result is
/// byte-identical across runs (`REQ-OUT-3`): no hash container's iteration
/// order reaches it.
pub fn parity_blocks(source: &Cfg, chains: &[Vec<NodeId>]) -> ParityBlocks {
    let view = BlockView::new(source, chains);
    let flags = derive_flags(source, chains);
    let removed_funcend = funcend_candidate(source, chains, &view);

    let survives = |block: u32| Some(block) != removed_funcend;
    let kept: Vec<u32> = (0..chains.len() as u32).filter(|b| survives(*b)).collect();
    // "Deleting it drops its in-edges with it" (`REQ-CFG-10`). The out-edge
    // filter is vacuous under the guard's out-degree-0 condition and is written
    // anyway, so that a future partition that reaches here with a different
    // shape cannot leave a dangling edge behind.
    let edges: Vec<(u32, u32)> = view
        .edges
        .iter()
        .copied()
        .filter(|(src, dst)| survives(*src) && survives(*dst))
        .collect();

    ParityBlocks {
        kept,
        edges,
        entry: flags
            .entry_blocks()
            .into_iter()
            .filter(|b| survives(*b))
            .collect(),
        exit: flags
            .exit_blocks()
            .into_iter()
            .filter(|b| survives(*b))
            .collect(),
        removed_funcend,
    }
}

/// Which block each source node landed in, for a caller that wants to map a
/// surviving block back to source spans (`REQ-OUT-4`).
///
/// `u32::MAX` marks a node no chain claimed.
pub fn block_of_node(source: &Cfg, chains: &[Vec<NodeId>]) -> Vec<u32> {
    BlockView::new(source, chains).of_node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::cfg::{CfgEdge, CfgNode, EdgeKind};
    use crate::syntax::ids::Span;

    /// The S2 graph of one function of `text`.
    fn s2(text: &str, name: &str) -> Cfg {
        let tree = crate::csource::parse::parse(text);
        let functions = crate::csource::cfg::function_cfgs(tree.value(), text);
        functions
            .value()
            .iter()
            .find(|function| function.name == name)
            .map(|function| function.cfg.clone())
            .unwrap_or_else(|| panic!("{name} is recovered from the fixture"))
    }

    /// A hand-built graph, for the block shapes our own chain partition cannot
    /// produce today: [`crate::syntax::cfg::Cfg::chain_partition`] refuses to
    /// absorb [`NodeKind::Entry`] and [`NodeKind::Exit`] into a chain, while
    /// Joern's `to_supergraph` has no anchor concept and merges both. Passing
    /// the chain list explicitly is what lets F-11 and F-12 be tested against
    /// the partition Joern actually produces.
    fn graph(kinds: &[NodeKind], edges: &[(u32, u32)]) -> Cfg {
        let nodes = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| CfgNode::single(*kind, Span::new(index as u32, index as u32 + 1)))
            .collect();
        let edges = edges
            .iter()
            .map(|(src, dst)| CfgEdge::new(NodeId::new(*src), NodeId::new(*dst), EdgeKind::Fall))
            .collect();
        Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(0))
    }

    /// [`graph`], with an explicit statement count per node.
    ///
    /// F-12's condition (2) counts statements, and a [`CfgNode`] carries them
    /// as its span list, so a test of that condition needs a node with more
    /// than one span --- which [`CfgNode::single`], and therefore [`graph`],
    /// cannot make.
    fn graph_with_statements(spec: &[(NodeKind, usize)], edges: &[(u32, u32)]) -> Cfg {
        let nodes = spec
            .iter()
            .enumerate()
            .map(|(index, (kind, statements))| {
                let base = index as u32 * 16;
                let spans = (0..*statements as u32)
                    .map(|offset| Span::new(base + offset, base + offset + 1))
                    .collect();
                CfgNode::new(*kind, spans)
            })
            .collect();
        let edges = edges
            .iter()
            .map(|(src, dst)| CfgEdge::new(NodeId::new(*src), NodeId::new(*dst), EdgeKind::Fall))
            .collect();
        Cfg::from_parts(nodes, edges, NodeId::new(0), NodeId::new(0))
    }

    /// A chain list from a slice of slices of node indices.
    fn chains(spec: &[&[u32]]) -> Vec<Vec<NodeId>> {
        spec.iter()
            .map(|chain| chain.iter().map(|id| NodeId::new(*id)).collect())
            .collect()
    }

    #[test]
    fn the_entry_flag_lands_on_the_block_holding_the_function_start_marker() {
        let cfg = s2("int f(int a){ if (a) { return 1; } return 0; }", "f");
        let partition = cfg.chain_partition();
        let flags = derive_flags(&cfg, partition.chains());

        let entry = flags.entry_blocks();
        assert_eq!(entry.len(), 1, "one Entry node gives one entry block");
        // The corpus invariant this is the local form of: 0 of 91,548 published
        // functions carry no entry flag.
        assert!(
            !entry.is_empty(),
            "no published function has zero entry flags"
        );
        let block = entry[0];
        assert!(
            partition.chains()[block as usize]
                .iter()
                .any(|id| cfg.node(*id).map(|n| n.kind()) == Some(NodeKind::Entry)),
            "the flagged block is the one holding the marker, not block 0 by convention"
        );
        // A derivation that flagged everything would pass the checks above.
        assert!(
            flags.entry_blocks().len() < flags.len(),
            "not every block is an entry block"
        );
    }

    #[test]
    fn merging_ors_the_flags_it_does_not_take_the_blocks_first_statement() {
        // O0/bash/source_cfgs/bash.json `pop_var_context`: published
        // `entry [4, 5]`, yet only block 5 has FUNCTION_START as its first
        // statement. Block 4 absorbed a node that had it first, so the OR in
        // `GenericBlock.merge_blocks` flags it too. Same for the exit half:
        // O0/base-passwd/update-passwd.json `xasprintf` block 0 is
        // `return result; FUNCTION_END` and is published `exit [0]`.
        let cfg = graph(
            &[
                NodeKind::Stmt,
                NodeKind::Entry,
                NodeKind::Return,
                NodeKind::Exit,
            ],
            &[(0, 1), (1, 2), (2, 3)],
        );
        let chains = chains(&[&[0, 1, 2, 3]]);
        let flags = derive_flags(&cfg, &chains);

        assert_eq!(
            flags.entry_blocks(),
            vec![0],
            "FUNC_START in a later position still flags the merged block"
        );
        assert_eq!(flags.exit_blocks(), vec![0], "FUNC_END likewise");
    }

    #[test]
    fn a_block_with_no_marker_carries_no_flag() {
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Stmt, NodeKind::Exit],
            &[(0, 1), (1, 2)],
        );
        let flags = derive_flags(&cfg, &chains(&[&[0], &[1], &[2]]));
        assert_eq!(flags.entry_blocks(), vec![0]);
        assert_eq!(flags.exit_blocks(), vec![2]);
        assert!(
            !flags.is_entry(1) && !flags.is_exit(1),
            "the body is neither"
        );
        assert!(
            !flags.is_entry(9),
            "an unknown block is not flagged, and does not panic"
        );
    }

    #[test]
    fn several_entry_blocks_are_reported_rather_than_normalized_away() {
        // 1,334 of the 91,548 published functions carry more than one entry
        // flag (measured over ~/.cache/glaurung/decbench-full/tree). Collapsing
        // them to one is the natural bug, so the derivation must report both.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Stmt, NodeKind::Entry],
            &[(0, 1), (2, 1)],
        );
        let flags = derive_flags(&cfg, &chains(&[&[0], &[1], &[2]]));
        assert_eq!(flags.entry_blocks(), vec![0, 2]);
    }

    #[test]
    fn two_returns_lose_the_funcend_block_and_its_in_edges_with_it() {
        // O0/base-passwd/source_cfgs/update-passwd.json `xstrdup`: two return
        // paths, so METHOD_RETURN kept in-degree 2, stayed a singleton, and was
        // deleted --- published `exit []`, and both return blocks end at
        // out-degree 0.
        let cfg = s2(
            "char *xstrdup(char *s){ if (!s) { return 0; } return g(s); }",
            "xstrdup",
        );
        let partition = cfg.chain_partition();
        let blocks = parity_blocks(&cfg, partition.chains());

        let funcend = blocks
            .removed_funcend
            .expect("a singleton funcend is deleted");
        assert!(
            !blocks.kept.contains(&funcend),
            "the deleted block does not survive"
        );
        assert_eq!(blocks.kept.len(), partition.chains().len() - 1);
        assert!(
            blocks.exit.is_empty(),
            "deleting the funcend leaves no exit flag"
        );
        assert!(
            blocks.edges.iter().all(|(_, dst)| *dst != funcend),
            "its in-edges went with it"
        );
        // The point of the rule, in the terms `vj_ged` reads: each `return`
        // block ends at out-degree 0.
        let returns: Vec<u32> = partition
            .chains()
            .iter()
            .enumerate()
            .filter(|(_, chain)| {
                chain
                    .iter()
                    .any(|id| cfg.node(*id).map(|n| n.kind()) == Some(NodeKind::Return))
            })
            .map(|(block, _)| block as u32)
            .collect();
        assert_eq!(returns.len(), 2, "the fixture has two returns");
        for block in returns {
            assert!(
                blocks.edges.iter().all(|(src, _)| *src != block),
                "return block {block} is a sink once the funcend is gone"
            );
        }
    }

    #[test]
    fn a_funcend_that_coalesced_into_a_larger_block_survives_and_is_flagged() {
        // O0/base-passwd/source_cfgs/update-passwd.json `xasprintf`: one
        // return, so METHOD_RETURN merged into it. Published block 0 is
        // `return result; FUNCTION_END`, `exit [0]`, and the block is kept.
        // All 46,716 surviving funcend blocks in the corpus have more than one
        // statement, which is the condition that discriminates the two regimes.
        let cfg = graph(
            &[
                NodeKind::Entry,
                NodeKind::Cond,
                NodeKind::Return,
                NodeKind::Exit,
                NodeKind::Diverge,
            ],
            &[(0, 1), (1, 2), (1, 4), (2, 3)],
        );
        let chains = chains(&[&[0, 1], &[2, 3], &[4]]);
        let blocks = parity_blocks(&cfg, &chains);

        assert_eq!(
            blocks.removed_funcend, None,
            "a merged funcend is not a singleton"
        );
        assert_eq!(blocks.exit, vec![1], "and it keeps its exit flag");
        assert_eq!(blocks.kept, vec![0, 1, 2]);
    }

    #[test]
    fn a_wholly_linear_function_is_one_block_that_is_both_entry_and_exit() {
        // O0/zlib/source_cfgs/example.json `adler32`: 1 node, 0 edges,
        // `entry [0]`, `exit [0]`, not degenerate. The whole function ---
        // METHOD, the body, and METHOD_RETURN --- is one chain.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Return, NodeKind::Exit],
            &[(0, 1), (1, 2)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0, 1, 2]]));

        assert_eq!(blocks.kept, vec![0]);
        assert!(blocks.edges.is_empty(), "every edge was contracted away");
        assert_eq!(blocks.entry, vec![0]);
        assert_eq!(blocks.exit, vec![0]);
        assert_eq!(blocks.removed_funcend, None);
    }

    #[test]
    fn the_guard_keeps_a_funcend_block_that_still_has_a_successor() {
        // Condition (1) of `REQ-CFG-10`, which the corpus cannot exercise: all
        // 46,716 surviving funcend blocks have out-degree 0, and Joern's shared
        // METHOD_RETURN never has a successor. Tested against the requirement.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Exit, NodeKind::Stmt],
            &[(0, 1), (1, 2)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0], &[1], &[2]]));
        assert_eq!(
            blocks.removed_funcend, None,
            "out-degree 0 is part of the guard, not a formality"
        );
        assert_eq!(blocks.exit, vec![1]);
    }

    #[test]
    fn the_guard_keeps_both_when_there_are_two_singleton_funcend_candidates() {
        // Condition (4). Also unexercised by the corpus --- Joern gives a
        // method exactly one METHOD_RETURN, and our own S2 builder emits one
        // Exit node --- so this is a `REQ-CFG-10` test, not an observation.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Exit, NodeKind::Exit],
            &[(0, 1), (0, 2)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0], &[1], &[2]]));
        assert_eq!(
            blocks.removed_funcend, None,
            "the rule needs a unique candidate"
        );
        assert_eq!(blocks.exit, vec![1, 2]);
        assert_eq!(blocks.kept, vec![0, 1, 2]);
    }

    #[test]
    fn a_lone_singleton_candidate_is_what_the_guard_admits() {
        // The positive control for the two guard tests above: same shape, one
        // candidate, and the deletion fires.
        let cfg = graph(
            &[NodeKind::Entry, NodeKind::Exit, NodeKind::Return],
            &[(0, 1), (0, 2), (2, 1)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0], &[1], &[2]]));
        assert_eq!(blocks.removed_funcend, Some(1));
        assert_eq!(blocks.kept, vec![0, 2]);
        assert!(blocks.exit.is_empty());
    }

    #[test]
    fn block_edges_are_a_set_and_a_self_loop_survives() {
        // No published function has a duplicated edge (0 of 91,548), because
        // pyjoern parses DOT into an `nx.DiGraph`; 3,914 do have a self-loop
        // --- O0/bash/source_cfgs/bash.json `xrealloc` has `(3, 3)`. Parallel
        // edges here would inflate both degrees and so the distance.
        // The duplicated pair is `(1, 2)`, between two *surviving* blocks: put
        // it on an edge the funcend deletion removes and the assertion below
        // passes with the deduplication taken out.
        let cfg = graph(
            &[
                NodeKind::Entry,
                NodeKind::LoopHeader,
                NodeKind::Return,
                NodeKind::Exit,
            ],
            &[(0, 1), (1, 1), (1, 2), (1, 2), (2, 3)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0], &[1], &[2], &[3]]));
        assert_eq!(
            blocks.edges,
            vec![(0, 1), (1, 1), (1, 2)],
            "the duplicate is collapsed, the self-loop is kept, and the funcend edge went with the deleted block"
        );
        assert_eq!(blocks.removed_funcend, Some(3));
    }

    #[test]
    fn an_edge_inside_a_chain_is_contracted_but_a_chain_back_edge_is_not() {
        // `ChainPartition::is_internal`'s rule, restated: consecutive members
        // are contracted, a non-consecutive pair in the same chain becomes a
        // self-loop.
        let cfg = graph(
            &[NodeKind::Stmt, NodeKind::Stmt, NodeKind::Stmt],
            &[(0, 1), (1, 2), (2, 0)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0, 1, 2]]));
        assert_eq!(blocks.edges, vec![(0, 0)]);
    }

    #[test]
    fn renumbering_closes_the_hole_the_deletion_left() {
        let cfg = graph(
            &[
                NodeKind::Entry,
                NodeKind::Exit,
                NodeKind::Return,
                NodeKind::Return,
            ],
            &[(0, 2), (0, 3), (2, 1), (3, 1)],
        );
        let blocks = parity_blocks(&cfg, &chains(&[&[0], &[1], &[2], &[3]]));
        assert_eq!(blocks.removed_funcend, Some(1));
        assert_eq!(blocks.kept, vec![0, 2, 3]);
        assert_eq!(blocks.edges, vec![(0, 2), (0, 3)]);

        let dense = blocks.renumbered();
        assert_eq!(dense.kept, vec![0, 1, 2]);
        assert_eq!(dense.edges, vec![(0, 1), (0, 2)]);
        assert_eq!(dense.entry, vec![0]);
        assert!(dense.exit.is_empty());
        assert_eq!(blocks.index_of(3), Some(2));
        assert_eq!(
            blocks.index_of(1),
            None,
            "the deleted block has no dense id"
        );
    }

    #[test]
    fn our_own_s2_graphs_satisfy_the_two_corpus_invariants() {
        // 0 of 91,548 published functions have no entry flag and 0 have more
        // than one exit flag. Both must hold of what we emit.
        for source in [
            "int f(void){ return 1; }",
            "int g(int a){ if (a) { return 1; } return 0; }",
            "int h(int a){ while (a) { a = a - 1; } return a; }",
            "void e(void){ }",
            "int s(int a){ switch (a) { case 1: return 1; default: return 0; } }",
        ] {
            let tree = crate::csource::parse::parse(source);
            let functions = crate::csource::cfg::function_cfgs(tree.value(), source);
            assert!(!functions.value().is_empty(), "{source} yields a function");
            for function in functions.value() {
                let partition = function.cfg.chain_partition();
                let blocks = parity_blocks(&function.cfg, partition.chains());
                assert!(
                    !blocks.entry.is_empty(),
                    "{source}: every function has an entry flag"
                );
                assert!(
                    blocks.exit.len() <= 1,
                    "{source}: no function has two exit flags"
                );
            }
        }
    }

    #[test]
    fn the_projection_is_deterministic_and_an_empty_graph_does_not_panic() {
        let cfg = s2("int f(int a){ while (a) { a = a - 1; } return a; }", "f");
        let partition = cfg.chain_partition();
        assert_eq!(
            parity_blocks(&cfg, partition.chains()),
            parity_blocks(&cfg, partition.chains())
        );

        let empty = Cfg::from_parts(Vec::new(), Vec::new(), NodeId::new(0), NodeId::new(0));
        let blocks = parity_blocks(&empty, &[]);
        assert_eq!(blocks, ParityBlocks::default());
        assert!(derive_flags(&empty, &[]).is_empty());
        assert_eq!(singleton_funcend(&empty, &[]), None);
        assert!(block_of_node(&empty, &[]).is_empty());
    }

    #[test]
    fn a_chain_naming_a_node_the_graph_does_not_have_is_ignored_not_a_panic() {
        let cfg = graph(&[NodeKind::Entry], &[]);
        let flags = derive_flags(&cfg, &chains(&[&[0, 77]]));
        assert_eq!(flags.entry_blocks(), vec![0]);
        assert!(flags.exit_blocks().is_empty());
    }

    #[test]
    fn the_funcend_guard_counts_statements_not_chain_members() {
        // `pyjoern.cfg.normalize_cfg` deletes a funcend block when
        // `cfg.out_degree(node) == 0 and len(node.statements) == 1`. A chain of
        // one node whose node carries two statements satisfies the first and
        // fails the second, so the reference keeps it. Counting chain members
        // instead --- which is what this file used to do --- deletes it, and
        // takes the exit flag and the predecessor's out-degree with it.
        let layout = &[
            (NodeKind::Entry, 1),
            (NodeKind::Return, 1),
            (NodeKind::Exit, 2),
        ];
        let partition = chains(&[&[0], &[1], &[2]]);
        let blocks = parity_blocks(
            &graph_with_statements(layout, &[(0, 1), (1, 2)]),
            &partition,
        );
        assert_eq!(
            blocks.removed_funcend, None,
            "two statements fail `len(node.statements) == 1`, so the block stays"
        );
        assert_eq!(blocks.exit, vec![2], "and it keeps its exit flag");
        assert_eq!(blocks.kept, vec![0, 1, 2]);
        assert_eq!(blocks.edges, vec![(0, 1), (1, 2)]);

        // The mutation control. Identical in every way but the statement
        // count, and the deletion fires --- so the assertions above are about
        // the count and not about the shape they were built on.
        let one = &[
            (NodeKind::Entry, 1),
            (NodeKind::Return, 1),
            (NodeKind::Exit, 1),
        ];
        let blocks = parity_blocks(&graph_with_statements(one, &[(0, 1), (1, 2)]), &partition);
        assert_eq!(blocks.removed_funcend, Some(2));
        assert_eq!(blocks.kept, vec![0, 1]);
        assert!(blocks.exit.is_empty());
    }

    #[test]
    fn the_anchors_sit_at_the_ends_of_their_chains_so_membership_is_enough() {
        // `derive_flags` tests membership; the reference tests position --- the
        // block's *first* statement for entry, its *last* for exit (see the
        // module docs). They agree only because `syntax::cfg`'s validator
        // rejects an `Entry` with a predecessor and an `Exit` with a successor,
        // so neither anchor can be contracted into the middle of a chain. This
        // is the invariant that makes `first` and `membership` the same answer
        // on our graphs; if it ever breaks, the flag test has to move inside
        // the node and the module docs say what it becomes.
        for source in [
            "int f(void){ return 1; }",
            "int g(int a){ if (a) { return 1; } return 0; }",
            "int h(int a){ while (a) { a = a - 1; } return a; }",
            "void e(void){ }",
            "int s(int a){ switch (a) { case 1: return 1; default: return 0; } }",
            "int l(int a){ for (;;) { a = a + 1; } }",
        ] {
            let tree = crate::csource::parse::parse(source);
            let functions = crate::csource::cfg::function_cfgs(tree.value(), source);
            assert!(!functions.value().is_empty(), "{source} yields a function");
            for function in functions.value() {
                let cfg = &function.cfg;
                let partition = crate::csource::joern::chains::parity_chains(cfg);
                for chain in &partition {
                    for (offset, id) in chain.iter().enumerate() {
                        match cfg.node(*id).map(|node| node.kind()) {
                            Some(NodeKind::Entry) => assert_eq!(
                                offset, 0,
                                "{source}: the function start is not its chain's first member"
                            ),
                            Some(NodeKind::Exit) => assert_eq!(
                                offset,
                                chain.len() - 1,
                                "{source}: the function end is not its chain's last member"
                            ),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}
