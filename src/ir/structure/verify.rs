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
            Region::RawLoop { .. } => {}
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
}
