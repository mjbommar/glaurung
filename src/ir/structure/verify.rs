//! The structure verifier (semantics-preserving-structuring §5).
//!
//! One question, asked of a finished [`Region`] tree and a raw successor
//! relation: does the tree still represent every block and every conditional
//! edge the graph has? It is deliberately pure over `succs` — it knows nothing
//! about how the tree was built, which is what lets it be a check rather than
//! a restatement of the builder. Its reason to change is a change to the
//! well-formedness contract itself.
//!
//! [`super::structure_accounting`] is the stronger, typed-edge form of the same
//! idea; this one stays because it is unit-testable without SSA or dominators.
//!
//! [`super::structure_accounting`]: crate::ir::structure_accounting

use std::collections::HashSet;

use super::region::{entry_block, Region};

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
    /// A raw-switch presentation prefix is not a bounded, disjoint,
    /// predecessor-closed path owned by its typed case/default entry.
    RawLoopPrefixInvalid { entry: Option<usize> },
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
            Region::MultiExitLoop { body, exits, .. } => {
                walk(body, succs, out);
                exits.iter().for_each(|(_, exit)| walk(exit, succs, out));
            }
            Region::RawLoop {
                blocks,
                switch,
                switch_inline_prefixes,
                ..
            } => {
                if switch_inline_prefixes.is_empty() {
                    return;
                }
                let Some(evidence) = switch.as_ref().filter(|evidence| evidence.complete) else {
                    out.push(StructError::RawLoopPrefixInvalid { entry: None });
                    return;
                };
                let case_targets = evidence
                    .cases
                    .iter()
                    .map(|case| case.target)
                    .collect::<HashSet<_>>();
                let default = evidence.default.as_ref();
                let mut claimed = HashSet::new();
                for prefix in switch_inline_prefixes {
                    let entry = prefix.first().copied();
                    let valid_entry = entry.is_some_and(|entry| {
                        let is_case = case_targets.contains(&entry);
                        let is_default = default.is_some_and(|default| default.target == entry);
                        if is_case == is_default || !blocks.contains(&entry) {
                            return false;
                        }
                        let predecessors = (0..succs.len())
                            .filter(|predecessor| succs[*predecessor].contains(&entry))
                            .collect::<Vec<_>>();
                        !predecessors.is_empty()
                            && predecessors.iter().all(|predecessor| {
                                *predecessor == evidence.dispatch
                                    || (is_default
                                        && default
                                            .is_some_and(|default| *predecessor == default.guard))
                            })
                    });
                    let valid_chain = !prefix.is_empty()
                        && prefix.len() <= 8
                        && prefix
                            .iter()
                            .all(|block| blocks.contains(block) && claimed.insert(*block))
                        && prefix.windows(2).all(|pair| {
                            let [from, to] = pair else { return false };
                            succs
                                .get(*from)
                                .is_some_and(|next| next.as_slice() == [*to])
                                && (0..succs.len())
                                    .filter(|predecessor| succs[*predecessor].contains(to))
                                    .eq(std::iter::once(*from))
                        });
                    if !valid_entry || !valid_chain {
                        out.push(StructError::RawLoopPrefixInvalid { entry });
                    }
                }
            }
            Region::Switch {
                guard,
                dispatch,
                arms,
                formal_default,
                ..
            } => {
                if let Some(guard) = guard {
                    let covered: HashSet<usize> = [
                        Some(*dispatch),
                        formal_default.as_deref().and_then(entry_block),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();
                    report_uncovered(*guard, succs, &covered, out);
                }
                arms.iter().for_each(|a| walk(a, succs, out));
                if let Some(default) = formal_default {
                    walk(default, succs, out);
                }
            }
            Region::Borrowed(inner) => walk(inner, succs, out),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::structure::{
        SwitchCaseEvidence, SwitchDefaultEvidence, SwitchEvidence, SwitchEvidenceProvenance,
    };

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
    fn verify_region_rejects_a_prefix_that_crosses_a_shared_join() {
        let succs = vec![vec![1, 3], vec![2], vec![4], vec![4], vec![]];
        let region = Region::RawLoop {
            header: 0,
            blocks: vec![0, 1, 2, 3, 4],
            exits: Vec::new(),
            switch: Some(SwitchEvidence {
                dispatch: 1,
                cases: vec![SwitchCaseEvidence {
                    target: 2,
                    values: vec![0],
                }],
                default: Some(SwitchDefaultEvidence {
                    guard: 0,
                    target: 3,
                    dispatch: Some(1),
                    taken: false,
                }),
                complete: true,
                provenance: SwitchEvidenceProvenance::TypedCfgEdges,
            }),
            switch_guard: Some(0),
            // Block 4 is reached by both the case and default. It is a shared
            // join, not part of either private prefix.
            switch_inline_prefixes: vec![vec![2, 4]],
        };

        assert!(verify_region(&succs, 0, &region)
            .contains(&StructError::RawLoopPrefixInvalid { entry: Some(2) }));
    }
}
