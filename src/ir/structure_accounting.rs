//! Structural accounting: does the region tree account for the whole graph?
//!
//! [`crate::ir::structure::verify_region`] checks two things — that no reachable
//! block is dropped, and that a conditional's two arms are represented. Both are
//! real, and both were silent on the shape that costs us the most.
//!
//! Run against the minimized clang `-O0` `statemachine` CFG (a rotated loop whose
//! body holds an indirect dispatch, one arm of which leaves the loop), the existing
//! verifier reports NOTHING while the region tree:
//!
//! * emits block 9 twice and block 8 twice — the epilogue is pulled into a switch
//!   arm AND used as a conditional's join, and the loop exit is both the `While`'s
//!   exit and the block after it;
//! * leaves the edges `4 -> 7`, `6 -> 7` and `8 -> 9` accounted for by nothing;
//! * claims an edge `7 -> 9` that the CFG does not contain, because block 7 is used
//!   as a conditional arm whose join is 9 while its real successor is the loop
//!   header.
//!
//! A verifier that is quiet about that cannot be used to judge a new structurer, so
//! this module accounts for every block and every edge instead of a chosen subset.
//! Production recovery uses the hard findings to reject an unfaithful region and
//! render the complete labelled CFG instead. Quality-only findings such as an
//! explicit goto remain diagnostic.
//!
//! The accounting is by IMPLICATION. Each region node declares the edges it means:
//! a `Seq` means its parts run in order, an `IfThenElse` means the condition reaches
//! both arms and both arms reach the join, a `While` means the header reaches the
//! body and the exit and that the body's escaping edges return to the header. Two
//! questions follow, and both matter:
//!
//! * which CFG edges does the tree NOT imply (control the reader cannot see)?
//! * which implied edges are NOT in the CFG (control the reader is told about that
//!   does not exist)?
//!
//! # What this CANNOT see
//!
//! The accounting is relative to the CFG it is given. A block that never entered the
//! CFG is not "dropped by the structurer" — it does not exist as far as this module
//! is concerned, and the region covering what remains is reported as faithful.
//!
//! That boundary is not hypothetical. `statemachine` at clang `-O0` scores a graph
//! edit distance of 32, and it is tempting to read that as the same structuring
//! failure the gcc `-O0` build has. It is not. clang emits a jump table there, the
//! `jmp *%rax` was never resolved into successors, and the case arms — thirty
//! instructions of state machine — are absent from the function altogether; the
//! dispatch renders as an indirect CALL through a table entry. The region over the
//! seven blocks that DID make it is genuinely faithful, and this module correctly
//! says so.
//!
//! So a clean accounting means "the tree expresses this graph", never "the graph is
//! the program". Detecting the second needs discovery-side coverage — bytes in the
//! function's range that no block claims — which is a different measurement.

use std::collections::{HashMap, HashSet};

use crate::ir::cfg_edges::{Edge, EdgeKind};
use crate::ir::structure::{entry_block, Region};

/// What the region tree fails to account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// A block reachable in the CFG that the region tree never emits. Duplicated
    /// from `structure::verify_region` deliberately: `account` is the total check, and
    /// a total check that relies on a caller having run a different one is not total.
    BlockDropped { block: usize },
    /// A block appears more than once in the tree. Sometimes deliberate (a shared
    /// terminating block is clone-inlined), so it is reported rather than assumed
    /// wrong — but it means "emitted twice", and a reader seeing two copies of one
    /// basic block is seeing a claim about the program that is not true.
    BlockDuplicated { block: usize, count: usize },
    /// A CFG edge no region node implies: real control flow the rendered code does
    /// not express. Carries the kind so a dropped `SwitchCase` is distinguishable
    /// from a dropped `Fallthrough`.
    EdgeUnaccounted {
        from: usize,
        to: usize,
        kind: EdgeKind,
    },
    /// An edge no region node implies, but which an explicit `Goto` does express.
    ///
    /// Weaker than [`AccountError::EdgeUnaccounted`] and deliberately distinct: the
    /// rendered C is CORRECT — the jump is there and the label exists — but the
    /// structure did not explain the edge, so a reader gets a `goto` instead of a
    /// loop, a case, or an arm. Counting a goto as full accounting is what made this
    /// module silent on the real `statemachine`: every stranded edge in goto soup
    /// has a goto, so treating that as "accounted" passes the worst output we
    /// produce. The count of these IS the goto-soup measurement.
    EdgeViaGoto {
        from: usize,
        to: usize,
        kind: EdgeKind,
    },
    /// A latch edge whose target is not a `While` header — a loop the tree does not
    /// present as a loop.
    BackEdgeUnowned { from: usize, to: usize },
    /// The tree implies an edge the CFG does not have: the reader is shown control
    /// flow that cannot happen.
    ImpliedEdgeAbsent { from: usize, to: usize },
    /// A `Goto` whose target block is emitted nowhere, so the label does not exist.
    GotoTargetMissing { target: usize },
    /// A dispatch inside a loop whose `Switch` node is not nested within that
    /// loop's `While`. This is the `statemachine` signature: the case analysis ends
    /// up after the loop instead of inside it.
    SwitchArmOutsideLoop { dispatch: usize, header: usize },
}

/// Blocks a region owns, with multiplicity.
fn owned(r: &Region, out: &mut Vec<usize>) {
    match r {
        Region::Block(b) => out.push(*b),
        Region::Seq(parts) => parts.iter().for_each(|p| owned(p, out)),
        Region::IfThen { cond, then_r, .. } => {
            out.push(*cond);
            owned(then_r, out);
        }
        Region::IfThenElse {
            cond,
            then_r,
            else_r,
            ..
        } => {
            out.push(*cond);
            owned(then_r, out);
            owned(else_r, out);
        }
        Region::While { header, body, .. } => {
            out.push(*header);
            owned(body, out);
        }
        Region::DoWhile { body, cond, .. } => {
            owned(body, out);
            out.push(*cond);
        }
        Region::RawLoop { blocks, .. } => out.extend(blocks.iter().copied()),
        Region::Switch {
            guard,
            dispatch,
            arms,
            formal_default,
            ..
        } => {
            if let Some(guard) = guard {
                out.push(*guard);
            }
            out.push(*dispatch);
            arms.iter().for_each(|a| owned(a, out));
            if guard.is_some() {
                if let Some(default) = formal_default {
                    owned(default, out);
                }
            }
        }
        // A `Goto` REFERENCES a block; it does not emit it.
        Region::Goto(_) => {}
        Region::Unstructured(bs) => out.extend(bs.iter().copied()),
    }
}

fn block_set(r: &Region) -> HashSet<usize> {
    let mut v = Vec::new();
    owned(r, &mut v);
    v.into_iter().collect()
}

/// Edges leaving `r`: a block inside it whose successor is outside.
fn escaping(r: &Region, edges: &[Vec<Edge>]) -> Vec<(usize, usize)> {
    let inside = block_set(r);
    let mut out = Vec::new();
    for &b in &inside {
        for e in edges.get(b).into_iter().flatten() {
            if !inside.contains(&e.to) {
                out.push((b, e.to));
            }
        }
    }
    out.sort_unstable();
    out
}

/// The block a region structurally begins at, or `None` for a `Goto`.
///
/// `entry_block` reports a `Goto`'s TARGET, which is right for placing a label and
/// wrong for accounting: using it makes `if (c) goto L;` look like an ordinary arm
/// and every jump look like structure. Nothing here treats a jump as structure; the
/// edge is reported as [`AccountError::EdgeViaGoto`] instead.
fn structural_entry(r: &Region) -> Option<usize> {
    match r {
        Region::Goto(_) => None,
        other => entry_block(other),
    }
}

/// Which (from, to) edges an explicit `Goto` expresses.
///
/// Target alone is not enough: "some goto lands on block 7" said nothing about WHICH
/// edge into 7 was expressed, so one goto excused every edge into its target. The
/// source is the set of blocks whose control reaches the goto's position — the
/// escaping blocks of the preceding sibling in a `Seq`, or the condition of an arm.
fn goto_edges(r: &Region, edges: &[Vec<Edge>], out: &mut HashSet<(usize, usize)>) {
    match r {
        Region::Seq(parts) => {
            for (i, part) in parts.iter().enumerate() {
                if let Region::Goto(t) = part {
                    // Reached by whatever precedes it.
                    if let Some(prev) = parts[..i].iter().next_back() {
                        for (from, _) in escaping(prev, edges) {
                            out.insert((from, *t));
                        }
                        for b in block_set(prev) {
                            if edges.get(b).into_iter().flatten().any(|e| e.to == *t) {
                                out.insert((b, *t));
                            }
                        }
                    }
                }
                goto_edges(part, edges, out);
            }
        }
        Region::IfThen { cond, then_r, .. } => {
            if let Region::Goto(t) = then_r.as_ref() {
                out.insert((*cond, *t));
            }
            goto_edges(then_r, edges, out);
        }
        Region::IfThenElse {
            cond,
            then_r,
            else_r,
            ..
        } => {
            for arm in [then_r.as_ref(), else_r.as_ref()] {
                if let Region::Goto(t) = arm {
                    out.insert((*cond, *t));
                }
                goto_edges(arm, edges, out);
            }
        }
        Region::While { header, body, .. } => {
            if let Region::Goto(t) = body.as_ref() {
                out.insert((*header, *t));
            }
            goto_edges(body, edges, out);
        }
        Region::DoWhile { body, .. } => goto_edges(body, edges, out),
        Region::Switch {
            dispatch,
            arms,
            formal_default,
            ..
        } => {
            for a in arms {
                if let Region::Goto(t) = a {
                    out.insert((*dispatch, *t));
                }
                goto_edges(a, edges, out);
            }
            if let Some(default) = formal_default {
                goto_edges(default, edges, out);
            }
        }
        Region::Block(block) => {
            // An explicit machine jump lowers to a C goto. If structure did not
            // consume it as a loop/arm/sequence edge, retain it as the weaker
            // goto-quality finding rather than reporting missing control flow.
            for edge in edges.get(*block).into_iter().flatten() {
                if edge.kind == EdgeKind::Jump {
                    out.insert((*block, edge.to));
                }
            }
        }
        Region::Goto(_) | Region::RawLoop { .. } | Region::Unstructured(_) => {}
    }
}

/// Whether the exact `from -> target` edge is an explicit region or machine
/// goto. Destination-only matching is unsound: one goto to a shared target must
/// not excuse a different block's edge to that target.
fn has_explicit_goto(r: &Region, from: usize, target: usize, edges: &[Vec<Edge>]) -> bool {
    let mut gotos = HashSet::new();
    goto_edges(r, edges, &mut gotos);
    gotos.contains(&(from, target))
}

/// Every edge the tree declares.
fn implied(r: &Region, edges: &[Vec<Edge>], out: &mut HashSet<(usize, usize)>) {
    match r {
        Region::Block(_) => {}
        Region::Goto(_) => {}
        Region::RawLoop { blocks, .. } | Region::Unstructured(blocks) => {
            // Lossless labelled-CFG regions emit every machine transfer
            // explicitly when source-order fallthrough is displaced, so their
            // declared graph is exactly the CFG induced by their owned blocks
            // (including exits).
            for block in blocks {
                for edge in edges.get(*block).into_iter().flatten() {
                    out.insert((*block, edge.to));
                }
            }
        }
        Region::Seq(parts) => {
            // A `Goto` is NOT a region control flows into: it is an explicit jump.
            // Using it as a sequential successor launders the edge into looking
            // structural — `entry_block(Goto(t))` is `t`, so `Seq[.., Goto(2), ..]`
            // would declare every escaping edge to 2 as ordinary flow. That is how
            // goto soup came out fully accounted. Skip them, and let the edges be
            // reported as `EdgeViaGoto` instead.
            for (i, part) in parts.iter().enumerate() {
                // Labelled-CFG regions already declare their exact outgoing
                // transfers. Their lexical successor is only an emission
                // order, not an additional control-flow claim.
                if matches!(part, Region::RawLoop { .. } | Region::Unstructured(_)) {
                    continue;
                }
                let next = parts[i + 1..].iter().find_map(structural_entry);
                if let Some(next) = next {
                    for (from, target) in escaping(part, edges) {
                        // A preceding arm may end in an explicit jump out of
                        // the sequence (for example, a loop `break`).  That
                        // edge does not also fall through into the next
                        // sibling merely because the sibling follows it in
                        // the region tree.
                        if target == next || !has_explicit_goto(part, from, target, edges) {
                            out.insert((from, next));
                        }
                    }
                }
            }
            parts.iter().for_each(|p| implied(p, edges, out));
        }
        Region::IfThen {
            cond, then_r, join, ..
        } => {
            if let Some(t) = structural_entry(then_r) {
                out.insert((*cond, t));
            }
            if let Some(j) = *join {
                out.insert((*cond, j));
                for (from, target) in escaping(then_r, edges) {
                    if !has_explicit_goto(then_r, from, target, edges) {
                        out.insert((from, j));
                    }
                }
            }
            implied(then_r, edges, out);
        }
        Region::IfThenElse {
            cond,
            then_r,
            else_r,
            join,
            ..
        } => {
            if let Some(t) = structural_entry(then_r) {
                out.insert((*cond, t));
            }
            if let Some(e) = structural_entry(else_r) {
                out.insert((*cond, e));
            }
            if let Some(j) = *join {
                for arm in [then_r.as_ref(), else_r.as_ref()] {
                    for (from, target) in escaping(arm, edges) {
                        if !has_explicit_goto(arm, from, target, edges) {
                            out.insert((from, j));
                        }
                    }
                }
            }
            implied(then_r, edges, out);
            implied(else_r, edges, out);
        }
        Region::While { header, body, exit } => {
            if let Some(b) = structural_entry(body) {
                out.insert((*header, b));
            }
            if let Some(x) = *exit {
                out.insert((*header, x));
            }
            // The body's ordinary escaping edges are the latch: they return to
            // the header. An explicit goto to the distinguished exit is a
            // source-level break and must not also invent a latch edge.
            for (from, target) in escaping(body, edges) {
                let is_explicit_exit =
                    *exit == Some(target) && has_explicit_goto(body, from, target, edges);
                if !is_explicit_exit {
                    out.insert((from, *header));
                }
            }
            implied(body, edges, out);
        }
        Region::DoWhile { body, cond, exit } => {
            let header = structural_entry(body).unwrap_or(*cond);
            out.insert((*cond, header));
            if let Some(x) = *exit {
                out.insert((*cond, x));
            }
            for (from, target) in escaping(body, edges) {
                let is_explicit_exit =
                    *exit == Some(target) && has_explicit_goto(body, from, target, edges);
                if !is_explicit_exit {
                    out.insert((from, *cond));
                }
            }
            implied(body, edges, out);
        }
        Region::Switch {
            guard,
            dispatch,
            arms,
            formal_default,
            join,
            ..
        } => {
            if let Some(guard) = guard {
                out.insert((*guard, *dispatch));
                if let Some(default) = formal_default {
                    if let Some(entry) = structural_entry(default) {
                        out.insert((*guard, entry));
                    }
                }
            }
            for a in arms {
                if let Some(e) = structural_entry(a) {
                    out.insert((*dispatch, e));
                } else if let Some(join) = *join {
                    out.insert((*dispatch, join));
                }
            }
            if let Some(default) = formal_default {
                if let Some(entry) = structural_entry(default) {
                    out.insert((*dispatch, entry));
                }
            }
            if let Some(j) = *join {
                let arm_entries: HashSet<usize> =
                    arms.iter().filter_map(structural_entry).collect();
                for a in arms {
                    for (from, target) in escaping(a, edges) {
                        // A source-level fallthrough case exits its own arm by
                        // entering the next case arm, not by jumping directly
                        // to the switch join. Preserve that actual edge; only
                        // an escape outside every case implies the join.
                        if arm_entries.contains(&target) {
                            out.insert((from, target));
                        } else if !has_explicit_goto(a, from, target, edges) {
                            out.insert((from, j));
                        }
                    }
                }
                if guard.is_some() {
                    if let Some(default) = formal_default {
                        for (from, _) in escaping(default, edges) {
                            out.insert((from, j));
                        }
                    }
                }
            }
            arms.iter().for_each(|a| implied(a, edges, out));
            if guard.is_some() {
                if let Some(default) = formal_default {
                    implied(default, edges, out);
                }
            }
        }
    }
}

/// `While` headers in the tree, and the `Switch` dispatches nested under each.
fn loops_and_switches(
    r: &Region,
    enclosing: &mut Vec<usize>,
    headers: &mut HashSet<usize>,
    switch_owner: &mut HashMap<usize, Vec<usize>>,
) {
    match r {
        Region::While { header, body, .. } => {
            headers.insert(*header);
            enclosing.push(*header);
            loops_and_switches(body, enclosing, headers, switch_owner);
            enclosing.pop();
        }
        Region::DoWhile { body, cond, .. } => {
            let header = structural_entry(body).unwrap_or(*cond);
            headers.insert(header);
            enclosing.push(header);
            loops_and_switches(body, enclosing, headers, switch_owner);
            enclosing.pop();
        }
        Region::RawLoop { header, .. } => {
            headers.insert(*header);
        }
        Region::Switch {
            dispatch,
            arms,
            formal_default,
            ..
        } => {
            switch_owner.insert(*dispatch, enclosing.clone());
            arms.iter()
                .for_each(|a| loops_and_switches(a, enclosing, headers, switch_owner));
            if let Some(default) = formal_default {
                loops_and_switches(default, enclosing, headers, switch_owner);
            }
        }
        Region::Seq(parts) => parts
            .iter()
            .for_each(|p| loops_and_switches(p, enclosing, headers, switch_owner)),
        Region::IfThen { then_r, .. } => {
            loops_and_switches(then_r, enclosing, headers, switch_owner)
        }
        Region::IfThenElse { then_r, else_r, .. } => {
            loops_and_switches(then_r, enclosing, headers, switch_owner);
            loops_and_switches(else_r, enclosing, headers, switch_owner);
        }
        Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => {}
    }
}

/// Blocks of the natural loop with `header`, from the latch edges that reach it.
fn natural_loop(header: usize, edges: &[Vec<Edge>], preds: &[Vec<usize>]) -> HashSet<usize> {
    let latches: Vec<usize> = (0..edges.len())
        .filter(|&b| edges[b].iter().any(|e| e.to == header && e.back))
        .collect();
    let mut body: HashSet<usize> = HashSet::new();
    body.insert(header);
    let mut stack = latches;
    while let Some(n) = stack.pop() {
        if body.insert(n) {
            stack.extend(preds.get(n).into_iter().flatten().copied());
        }
    }
    body
}

/// Account for every reachable block and every edge.
///
/// Diagnostic only. An empty result means the tree expresses exactly the graph:
/// nothing dropped, nothing emitted twice, no edge without a home, and no edge
/// claimed that does not exist.
pub fn account(
    edges: &[Vec<Edge>],
    preds: &[Vec<usize>],
    entry: usize,
    region: &Region,
) -> Vec<AccountError> {
    let mut errors = Vec::new();

    let reachable = {
        let mut seen = HashSet::new();
        let mut stack = vec![entry];
        while let Some(b) = stack.pop() {
            if b < edges.len() && seen.insert(b) {
                stack.extend(edges[b].iter().map(|e| e.to));
            }
        }
        seen
    };

    // Blocks the tree never emits.
    let mut emitted_once = Vec::new();
    owned(region, &mut emitted_once);
    let present: HashSet<usize> = emitted_once.iter().copied().collect();
    let mut dropped: Vec<usize> = reachable.difference(&present).copied().collect();
    dropped.sort_unstable();
    for block in dropped {
        errors.push(AccountError::BlockDropped { block });
    }

    // Multiplicity. `owned` counts emissions; a `Goto` reference is not one.
    let mut counts: HashMap<usize, usize> = HashMap::new();
    let mut flat = Vec::new();
    owned(region, &mut flat);
    for b in flat {
        *counts.entry(b).or_default() += 1;
    }
    let mut dup: Vec<(usize, usize)> = counts
        .iter()
        .filter(|(_, &c)| c > 1)
        .map(|(&b, &c)| (b, c))
        .collect();
    dup.sort_unstable();
    for (block, count) in dup {
        errors.push(AccountError::BlockDuplicated { block, count });
    }

    // Goto targets must be emitted somewhere or the label does not exist.
    let emitted: HashSet<usize> = counts.keys().copied().collect();
    let mut goto_targets = Vec::new();
    fn gotos(r: &Region, out: &mut Vec<usize>) {
        match r {
            Region::Goto(t) => out.push(*t),
            Region::Seq(parts) => parts.iter().for_each(|p| gotos(p, out)),
            Region::IfThen { then_r, .. } => gotos(then_r, out),
            Region::IfThenElse { then_r, else_r, .. } => {
                gotos(then_r, out);
                gotos(else_r, out);
            }
            Region::While { body, .. } | Region::DoWhile { body, .. } => gotos(body, out),
            Region::Switch {
                arms,
                formal_default,
                ..
            } => {
                arms.iter().for_each(|a| gotos(a, out));
                if let Some(default) = formal_default {
                    gotos(default, out);
                }
            }
            Region::Block(_) | Region::RawLoop { .. } | Region::Unstructured(_) => {}
        }
    }
    gotos(region, &mut goto_targets);
    goto_targets.sort_unstable();
    goto_targets.dedup();
    for t in &goto_targets {
        if !emitted.contains(t) {
            errors.push(AccountError::GotoTargetMissing { target: *t });
        }
    }

    // Edge accounting, both directions.
    let mut declared = HashSet::new();
    implied(region, edges, &mut declared);
    let mut goto_pairs = HashSet::new();
    goto_edges(region, edges, &mut goto_pairs);
    let mut headers = HashSet::new();
    let mut switch_owner = HashMap::new();
    loops_and_switches(region, &mut Vec::new(), &mut headers, &mut switch_owner);

    let mut actual = HashSet::new();
    for &from in &reachable {
        for e in edges.get(from).into_iter().flatten() {
            actual.insert((from, e.to));
            if e.back && !headers.contains(&e.to) {
                errors.push(AccountError::BackEdgeUnowned { from, to: e.to });
                continue;
            }
            if declared.contains(&(from, e.to)) {
                continue;
            }
            // Not structurally explained. An explicit `Goto` for THIS edge still
            // renders correct control flow, so it is a WEAKER finding rather than
            // no finding — see `EdgeViaGoto`. Attribution is per edge: a goto to
            // block 7 excuses the edge that reaches it, not every edge into 7.
            if goto_pairs.contains(&(from, e.to)) {
                errors.push(AccountError::EdgeViaGoto {
                    from,
                    to: e.to,
                    kind: e.kind,
                });
                continue;
            }
            errors.push(AccountError::EdgeUnaccounted {
                from,
                to: e.to,
                kind: e.kind,
            });
        }
    }

    let mut absent: Vec<(usize, usize)> = declared
        .difference(&actual)
        .copied()
        .filter(|(f, _)| reachable.contains(f))
        .collect();
    absent.sort_unstable();
    for (from, to) in absent {
        errors.push(AccountError::ImpliedEdgeAbsent { from, to });
    }

    // A dispatch inside a loop must be structured inside that loop's `While`.
    for (&dispatch, enclosing) in &switch_owner {
        for &header in &headers {
            if natural_loop(header, edges, preds).contains(&dispatch)
                && dispatch != header
                && !enclosing.contains(&header)
            {
                errors.push(AccountError::SwitchArmOutsideLoop { dispatch, header });
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::cfg_edges::classify;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure::recover;
    use crate::ir::types::{Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg};

    fn mk(spec: Vec<(u64, Vec<Op>, Vec<u64>)>) -> LlirFunction {
        LlirFunction {
            entry_va: spec.first().map(|(v, _, _)| *v).unwrap_or(0),
            blocks: spec
                .into_iter()
                .map(|(start_va, ops, succs)| LlirBlock {
                    start_va,
                    end_va: start_va + 0x10,
                    instrs: ops
                        .into_iter()
                        .enumerate()
                        .map(|(j, op)| LlirInstr {
                            va: start_va + j as u64,
                            op,
                        })
                        .collect(),
                    succs,
                })
                .collect(),
        }
    }

    fn cj(t: u64) -> Op {
        Op::CondJump {
            cond: VReg::Flag(Flag::Z),
            target: t,
            inverted: false,
        }
    }

    fn jmp(t: u64) -> Op {
        Op::Jump { target: t }
    }

    /// Build succs/preds/dominance and run the accounting on whatever `recover`
    /// produces. Deliberately uses the REAL structurer: the point of Phase A is to
    /// judge the structurer we have, not a hand-written tree.
    fn account_recovered(lf: &LlirFunction) -> Vec<AccountError> {
        let ssa = compute_ssa(lf);
        let region = recover(lf, &ssa);
        let n = lf.blocks.len();
        let va_to_idx: HashMap<u64, usize> = lf
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.start_va, i))
            .collect();
        let mut succs = vec![Vec::new(); n];
        let mut preds = vec![Vec::new(); n];
        for (i, b) in lf.blocks.iter().enumerate() {
            for s in &b.succs {
                if let Some(&j) = va_to_idx.get(s) {
                    succs[i].push(j);
                    preds[j].push(i);
                }
            }
        }
        // Dominance from the SSA idom chain, the same source the structurer uses.
        let dominates = |a: usize, b: usize| {
            let mut cur = Some(b);
            while let Some(c) = cur {
                if c == a {
                    return true;
                }
                cur = ssa.idom.get(c).and_then(|x| *x);
            }
            a == 0
        };
        let edges = classify(lf, &succs, dominates);
        account(&edges, &preds, 0, &region)
    }

    /// The minimized clang -O0 `statemachine` failure: a rotated loop whose body
    /// holds an indirect dispatch guarded by a bounds check, with case arms
    /// converging on the latch and ONE arm leaving the loop (`S_DONE: return`).
    ///
    ///   0 entry      -> 1
    ///   1 header     -> 2 (body, fallthrough) | 8 (exit, taken)
    ///   2 bounds     -> 3 (dispatch) | 7 (default -> latch)
    ///   3 dispatch   -> 4 | 5 | 6            (indirect)
    ///   4 case A     -> 7
    ///   5 case B     -> 9                    (leaves the loop)
    ///   6 case C     -> 7
    ///   7 latch      -> 1                    (back edge)
    ///   8 loop exit  -> 9
    ///   9 epilogue   -> {}
    fn statemachine_shape() -> LlirFunction {
        mk(vec![
            (0x1000, vec![jmp(0x1010)], vec![0x1010]),
            (0x1010, vec![cj(0x1080)], vec![0x1020, 0x1080]),
            (0x1020, vec![cj(0x1070)], vec![0x1030, 0x1070]),
            (0x1030, vec![jmp(0x1040)], vec![0x1040, 0x1050, 0x1060]),
            (0x1040, vec![jmp(0x1070)], vec![0x1070]),
            (0x1050, vec![jmp(0x1090)], vec![0x1090]),
            (0x1060, vec![jmp(0x1070)], vec![0x1070]),
            (0x1070, vec![jmp(0x1010)], vec![0x1010]),
            (0x1080, vec![jmp(0x1090)], vec![0x1090]),
            (0x1090, vec![Op::Return], vec![]),
        ])
    }

    /// RED #1. The existing verifier reports NOTHING for this shape. The accounting
    /// must report SOMETHING, or it cannot be used to judge a new structurer.
    #[test]
    fn the_statemachine_shape_is_not_accounted_for() {
        let errs = account_recovered(&statemachine_shape());
        assert!(
            !errs.is_empty(),
            "the accounting is as blind as the verifier it replaces"
        );
    }

    /// Regression for the sharpest original defect. The tree used to say the
    /// case arms flowed to the EPILOGUE when they really flow to the LATCH: it
    /// claimed `4 -> 9` and `6 -> 9`, which do not exist. The switch join repair
    /// must never reintroduce that false ownership even while the shadow
    /// accounting still reports other incomplete edge attribution.
    ///
    /// Note what is NOT wrong: the epilogue is emitted once. `Region::blocks()`
    /// counts it twice because it treats a `join`/`exit` REFERENCE as ownership, and
    /// the lowerer only strips a trailing goto to a join rather than emitting it —
    /// so a duplication check built on `blocks()` would have reported a defect that
    /// does not exist. `owned()` here counts emissions only.
    #[test]
    fn switch_arm_edges_are_not_misattributed_to_the_epilogue() {
        let errs = account_recovered(&statemachine_shape());
        for (from, to) in [(4usize, 9usize), (6, 9)] {
            assert!(
                !errs.contains(&AccountError::ImpliedEdgeAbsent { from, to }),
                "the tree must not claim the absent epilogue edge {from} -> {to}: {errs:?}"
            );
        }
    }

    /// `4 -> 7` and `6 -> 7` are case arms returning to the latch. The guarded
    /// switch now exposes block 7 as its partial join, so those real edges must
    /// have a structural home rather than surviving only as gotos.
    #[test]
    fn case_arm_edges_to_the_latch_are_accounted() {
        let errs = account_recovered(&statemachine_shape());
        for (from, to) in [(4usize, 7usize), (6, 7)] {
            assert!(
                !errs.iter().any(|error| matches!(
                    error,
                    AccountError::EdgeUnaccounted { from: f, to: t, .. }
                        | AccountError::EdgeViaGoto { from: f, to: t, .. }
                        if *f == from && *t == to
                )),
                "case-to-latch edge {from} -> {to} must be structured: {errs:?}"
            );
        }
    }

    /// The repaired guarded-switch tree must not invent any edge absent from the
    /// CFG. Residual duplicate-block diagnostics are independent of edge fidelity.
    #[test]
    fn the_tree_claims_no_edge_that_does_not_exist() {
        let errs = account_recovered(&statemachine_shape());
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, AccountError::ImpliedEdgeAbsent { .. })),
            "the tree must not invent an edge: {errs:?}"
        );
    }

    #[test]
    fn the_statemachine_terminating_case_is_owned_once() {
        let errs = account_recovered(&statemachine_shape());
        assert!(
            !errs
                .iter()
                .any(|error| matches!(error, AccountError::BlockDuplicated { block: 5, .. })),
            "the terminating switch case must not be appended again as leftover: {errs:?}"
        );
    }

    // --- controls: shapes we DO structure correctly must stay silent -----------

    /// Control: a plain diamond. Both arms reconverge at a real join.
    #[test]
    fn a_diamond_is_fully_accounted() {
        let lf = mk(vec![
            (0x00, vec![cj(0x20)], vec![0x10, 0x20]),
            (0x10, vec![jmp(0x30)], vec![0x30]),
            (0x20, vec![jmp(0x30)], vec![0x30]),
            (0x30, vec![Op::Return], vec![]),
        ]);
        assert_eq!(account_recovered(&lf), vec![], "a diamond must be clean");
    }

    /// Control: a rotated loop — test at the top with the exit as the taken edge,
    /// unconditional jump back at the bottom. This is the shape whose CONDITION we
    /// used to invert; the accounting must find its structure sound.
    #[test]
    fn a_rotated_loop_is_fully_accounted() {
        let lf = mk(vec![
            (0x00, vec![jmp(0x10)], vec![0x10]),
            (0x10, vec![cj(0x30)], vec![0x20, 0x30]),
            (0x20, vec![jmp(0x10)], vec![0x10]),
            (0x30, vec![Op::Return], vec![]),
        ]);
        assert_eq!(
            account_recovered(&lf),
            vec![],
            "a rotated loop must be clean"
        );
    }

    /// A sparse switch with a bounds-check default and three arms converging on one
    /// join is now a clean control: the enclosing conditional owns the join and the
    /// nested switch cases stop there rather than letting the first case absorb it.
    #[test]
    fn a_sparse_switchs_shared_join_is_fully_accounted() {
        let lf = mk(vec![
            (0x00, vec![cj(0x50)], vec![0x10, 0x50]),
            (0x10, vec![jmp(0x20)], vec![0x20, 0x30, 0x40]),
            (0x20, vec![jmp(0x60)], vec![0x60]),
            (0x30, vec![jmp(0x60)], vec![0x60]),
            (0x40, vec![jmp(0x60)], vec![0x60]),
            (0x50, vec![jmp(0x60)], vec![0x60]),
            (0x60, vec![Op::Return], vec![]),
        ]);
        let errs = account_recovered(&lf);
        assert_eq!(errs, vec![], "a sparse guarded switch must be clean");
    }

    #[test]
    fn switch_case_fallthrough_does_not_invent_direct_join_edges() {
        // Clang -O0 lowers `case 0: ...; fallthrough; case 1: ...` as a
        // dispatch into successive suffixes of one linear chain. The earlier
        // accountant claimed every case jumped directly to the final join,
        // even though B1/B2/B3 really fall through to the next case entry.
        let switch_case = |to| Edge {
            to,
            kind: EdgeKind::SwitchCase,
            back: false,
        };
        let linear = |to| Edge {
            to,
            kind: EdgeKind::Linear,
            back: false,
        };
        let edges = vec![
            vec![
                switch_case(1),
                switch_case(2),
                switch_case(3),
                switch_case(4),
            ],
            vec![linear(2)],
            vec![linear(3)],
            vec![linear(4)],
            vec![linear(5)],
            vec![],
        ];
        let preds = vec![vec![], vec![0], vec![0, 1], vec![0, 2], vec![0, 3], vec![4]];
        let region = Region::Seq(vec![
            Region::Switch {
                guard: None,
                dispatch: 0,
                case_labels: vec![vec![0], vec![1], vec![2], vec![3]],
                arms: vec![
                    Region::Block(1),
                    Region::Block(2),
                    Region::Block(3),
                    Region::Block(4),
                ],
                formal_default: None,
                join: Some(5),
            },
            Region::Block(5),
        ]);

        let errs = account(&edges, &preds, 0, &region);
        assert!(
            !errs
                .iter()
                .any(|error| matches!(error, AccountError::ImpliedEdgeAbsent { .. })),
            "case fallthrough must not be misreported as an invented join edge: {errs:?}"
        );
    }

    #[test]
    fn an_explicit_arm_goto_does_not_also_imply_the_enclosing_join() {
        let edges = vec![
            vec![],
            vec![Edge {
                to: 3,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
            vec![],
            vec![],
        ];
        let arm = Region::Seq(vec![Region::Block(1), Region::Goto(3)]);
        let region = Region::IfThen {
            cond: 0,
            then_r: Box::new(arm),
            join: Some(4),
            invert: false,
        };
        let mut declared = HashSet::new();
        implied(&region, &edges, &mut declared);
        assert!(
            !declared.contains(&(1, 4)),
            "the goto to B3 must not be restated as an absent B1->B4 join edge: {declared:?}"
        );
    }

    #[test]
    fn a_machine_jump_inside_a_block_is_recorded_as_an_explicit_goto() {
        let edges = vec![
            vec![Edge {
                to: 2,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
            vec![],
        ];
        let mut gotos = HashSet::new();
        goto_edges(&Region::Block(0), &edges, &mut gotos);
        assert_eq!(gotos, HashSet::from([(0, 2)]));
    }

    #[test]
    fn a_machine_jump_arm_does_not_also_imply_the_enclosing_join() {
        let edges = vec![
            vec![],
            vec![Edge {
                to: 3,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
            vec![],
            vec![],
        ];
        let region = Region::IfThen {
            cond: 0,
            then_r: Box::new(Region::Block(1)),
            join: Some(4),
            invert: false,
        };
        let mut declared = HashSet::new();
        implied(&region, &edges, &mut declared);
        assert!(
            !declared.contains(&(1, 4)),
            "the machine goto to B3 must not become an absent B1->B4 join edge: {declared:?}"
        );
    }

    #[test]
    fn a_goto_from_one_arm_exit_does_not_excuse_another_exit() {
        let edges = vec![
            vec![],
            vec![
                Edge {
                    to: 3,
                    kind: EdgeKind::Taken,
                    back: false,
                },
                Edge {
                    to: 2,
                    kind: EdgeKind::Fallthrough,
                    back: false,
                },
            ],
            vec![Edge {
                to: 3,
                kind: EdgeKind::Linear,
                back: false,
            }],
            vec![],
            vec![],
        ];
        let arm = Region::IfThenElse {
            cond: 1,
            then_r: Box::new(Region::Goto(3)),
            else_r: Box::new(Region::Block(2)),
            join: None,
            invert: false,
        };
        let region = Region::IfThen {
            cond: 0,
            then_r: Box::new(arm),
            join: Some(4),
            invert: false,
        };

        let mut declared = HashSet::new();
        implied(&region, &edges, &mut declared);
        assert!(
            !declared.contains(&(1, 4)),
            "the explicit B1->B3 goto must not be restated as B1->B4: {declared:?}"
        );
        assert!(
            declared.contains(&(2, 4)),
            "the unrelated B2->B3 escape must still imply its enclosing join: {declared:?}"
        );
    }

    /// An edge a `Goto` expresses is a WEAKER finding, not no finding. Treating a
    /// goto as full accounting made this module silent on the real `statemachine`,
    /// whose every stranded edge has a goto — so the worst output we produce looked
    /// perfectly accounted for.
    #[test]
    fn an_edge_expressed_only_by_a_goto_is_still_reported() {
        // 0 -> {1 fallthrough, 3 taken}; 1 -> 2 -> 3. The taken edge SKIPS block 2,
        // so it is not sequential flow: only `if (c) goto L3;` expresses it.
        let edges = vec![
            vec![
                Edge {
                    to: 1,
                    kind: EdgeKind::Fallthrough,
                    back: false,
                },
                Edge {
                    to: 3,
                    kind: EdgeKind::Taken,
                    back: false,
                },
            ],
            vec![Edge {
                to: 2,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![Edge {
                to: 3,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
        ];
        let preds = vec![vec![], vec![0], vec![1], vec![0, 2]];
        let region = Region::Seq(vec![
            Region::IfThen {
                cond: 0,
                then_r: Box::new(Region::Goto(3)),
                join: None,
                invert: false,
            },
            Region::Block(1),
            Region::Block(2),
            Region::Block(3),
        ]);
        let errs = account(&edges, &preds, 0, &region);
        assert!(
            errs.iter()
                .any(|e| matches!(e, AccountError::EdgeViaGoto { .. })),
            "expected a goto-expressed edge to be reported: {errs:?}"
        );
        assert!(
            !errs
                .iter()
                .any(|e| matches!(e, AccountError::EdgeUnaccounted { from: 0, to: 3, .. })),
            "a goto-expressed edge is not fully unaccounted: {errs:?}"
        );
    }

    /// The boundary, pinned: accounting is relative to the CFG it is handed. A graph
    /// that is MISSING blocks is reported clean, because the missing blocks are not
    /// in it to be missed.
    ///
    /// This is how `statemachine` at clang -O0 passes: its jump table was never
    /// resolved, so the case arms are not in the CFG, and the region over what
    /// remains is faithful. Reading a clean result as "the output is complete" is the
    /// mistake this test exists to prevent.
    #[test]
    fn a_cfg_missing_blocks_is_reported_clean() {
        // The real function branches to a third block; this CFG does not know it.
        let edges = vec![
            vec![Edge {
                to: 1,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
        ];
        let preds = vec![vec![], vec![0]];
        let region = Region::Seq(vec![Region::Block(0), Region::Block(1)]);
        assert_eq!(
            account(&edges, &preds, 0, &region),
            vec![],
            "accounting cannot see a block that never entered the CFG"
        );
    }

    /// 4a: a reachable block the tree never emits is reported by `account` itself,
    /// not only by the older `verify_region`. A total check that depends on a caller
    /// having run a different one is not total.
    #[test]
    fn a_reachable_block_the_tree_never_emits_is_reported() {
        let edges = vec![
            vec![Edge {
                to: 1,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![Edge {
                to: 2,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
        ];
        let preds = vec![vec![], vec![0], vec![1]];
        // Block 1 is simply missing from the tree.
        let region = Region::Seq(vec![Region::Block(0), Region::Block(2)]);
        let errs = account(&edges, &preds, 0, &region);
        assert!(
            errs.contains(&AccountError::BlockDropped { block: 1 }),
            "expected block 1 dropped: {errs:?}"
        );
    }

    /// 4b: a goto excuses the edge that REACHES it, not every edge into its target.
    /// Attributing by target alone let one goto launder an arbitrary number of
    /// unexpressed edges into the same block.
    #[test]
    fn a_goto_excuses_only_its_own_edge_not_every_edge_into_the_target() {
        // Both 0 and 1 branch to 3. The tree gives block 1 a `goto 3`; block 0's
        // edge to 3 is expressed by nothing and must still be reported.
        let edges = vec![
            vec![
                Edge {
                    to: 1,
                    kind: EdgeKind::Fallthrough,
                    back: false,
                },
                Edge {
                    to: 3,
                    kind: EdgeKind::Taken,
                    back: false,
                },
            ],
            vec![
                Edge {
                    to: 2,
                    kind: EdgeKind::Fallthrough,
                    back: false,
                },
                Edge {
                    to: 3,
                    kind: EdgeKind::Taken,
                    back: false,
                },
            ],
            vec![Edge {
                to: 3,
                kind: EdgeKind::Jump,
                back: false,
            }],
            vec![],
        ];
        let preds = vec![vec![], vec![0], vec![1], vec![0, 1, 2]];
        let region = Region::Seq(vec![
            Region::Block(0),
            Region::IfThen {
                cond: 1,
                then_r: Box::new(Region::Goto(3)),
                join: None,
                invert: false,
            },
            Region::Block(2),
            Region::Block(3),
        ]);
        let errs = account(&edges, &preds, 0, &region);
        assert!(
            errs.iter()
                .any(|e| matches!(e, AccountError::EdgeViaGoto { from: 1, to: 3, .. })),
            "block 1's goto expresses ITS edge: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| matches!(e, AccountError::EdgeUnaccounted { from: 0, to: 3, .. })),
            "block 0's edge to the same target is expressed by nothing: {errs:?}"
        );
    }
}
