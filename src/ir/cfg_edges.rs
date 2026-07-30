//! Typed control-flow edges: what a transfer IS, recorded once.
//!
//! The structurer has been deriving edge meaning from position — "successor 0 is
//! the fallthrough", "the taken arm is the lower block index" — and that has been
//! wrong in a specific, expensive way more than once. Loop rotation is the clearest
//! case: a header's conditional branch is the loop's CONTINUE test when its taken
//! edge re-enters the body and its EXIT test when the taken edge leaves, and those
//! two layouts are indistinguishable from block order alone. Emitting the condition
//! verbatim turned `while (n > 1)` into `while (n <= 1)`.
//!
//! So an edge carries what the instruction stream actually said:
//!
//! * [`EdgeKind::Taken`] / [`EdgeKind::Fallthrough`] — the two sides of a
//!   conditional branch, decided by the branch's own target rather than by index.
//! * [`EdgeKind::SwitchCase`] — an arm of an indirect dispatch (a jump table).
//! * [`EdgeKind::SwitchDefault`] — the out-of-range arm of the bounds check that
//!   guards such a dispatch. This one is DERIVED, not read: there is no `Op::Switch`
//!   in the IR, so it is recognised as "the conditional edge that bypasses an
//!   indirect dispatch". The derivation is stated here so a reader knows it is an
//!   inference and not a fact from the encoding.
//! * [`EdgeKind::Jump`] — an explicit unconditional transfer.
//! * [`EdgeKind::Linear`] — control running off the end of a block into the next,
//!   with no transfer instruction. Kept apart from `Jump` because one is an
//!   instruction and the other is only where the block happens to sit.
//!
//! [`Edge::back`] is orthogonal to all of them, and deliberately a separate flag
//! rather than another kind: a latch edge is still *taken* or *jumped*, and
//! collapsing the two loses which. It is computed from dominance — `to` dominates
//! `from` — so it does not depend on the terminator at all.

use crate::ir::types::{LlirFunction, Op};

/// How control reaches a successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// The conditional branch was taken.
    Taken,
    /// The conditional branch was not taken.
    Fallthrough,
    /// An arm of an indirect dispatch (jump table).
    SwitchCase,
    /// The bounds-check arm that bypasses an indirect dispatch. Derived — see the
    /// module docs.
    SwitchDefault,
    /// An explicit unconditional transfer (`Op::Jump`).
    Jump,
    /// Control runs off the end of a block into the next one, with no transfer
    /// instruction at all. Distinct from [`EdgeKind::Jump`] because a structurer may
    /// reorder blocks joined by a jump and may NOT reorder blocks joined only by
    /// adjacency — the second is a layout fact, the first is an instruction.
    Linear,
}

/// One CFG edge, with what it is and whether it closes a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub to: usize,
    pub kind: EdgeKind,
    /// `to` dominates `from`: this edge is a loop latch. Independent of `kind`.
    pub back: bool,
}

/// A block whose terminator hands control to more targets than a conditional
/// branch can name is an indirect dispatch — the jump-table shape.
fn is_dispatch(succ_count: usize, terminator: Option<&Op>) -> bool {
    match terminator {
        // A resolved indirect transfer is a dispatch even when compiler case
        // folding leaves only two distinct destinations. The LLIR block still
        // carries the full table-slot sequence.
        Some(Op::IndirectJump { .. }) => succ_count >= 2,
        // Retain the structural fallback for synthetic/imported CFGs that do
        // not carry an explicit indirect-jump terminator.
        Some(Op::CondJump { .. }) => false,
        _ => succ_count > 2,
    }
}

/// Classify every edge of `lf`.
///
/// `succs` is passed in rather than recomputed so this describes exactly the graph
/// the caller is structuring — a second traversal could disagree about
/// unresolvable targets. `dominates(a, b)` answers "does a dominate b".
pub fn classify(
    lf: &LlirFunction,
    succs: &[Vec<usize>],
    dominates: impl Fn(usize, usize) -> bool,
) -> Vec<Vec<Edge>> {
    let va_to_idx: std::collections::HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();

    // Which blocks are indirect dispatches, so the bounds check in front of one can
    // recognise its own default edge.
    let dispatch: Vec<bool> = (0..succs.len())
        .map(|i| {
            let term = lf
                .blocks
                .get(i)
                .and_then(|b| b.instrs.last())
                .map(|i| &i.op);
            is_dispatch(succs[i].len(), term)
        })
        .collect();

    let mut out: Vec<Vec<Edge>> = Vec::with_capacity(succs.len());
    for (i, targets) in succs.iter().enumerate() {
        let term = lf
            .blocks
            .get(i)
            .and_then(|b| b.instrs.last())
            .map(|x| &x.op);
        let taken = match term {
            Some(Op::CondJump { target, .. }) => va_to_idx.get(target).copied(),
            _ => None,
        };
        let mut edges = Vec::with_capacity(targets.len());
        for &t in targets {
            let kind = if dispatch[i] {
                EdgeKind::SwitchCase
            } else if let Some(tk) = taken {
                if t == tk {
                    // A conditional edge that skips PAST an indirect dispatch is the
                    // switch's out-of-range arm.
                    if targets.iter().any(|&o| o != t && dispatch[o]) {
                        EdgeKind::SwitchDefault
                    } else {
                        EdgeKind::Taken
                    }
                } else {
                    EdgeKind::Fallthrough
                }
            } else if matches!(term, Some(Op::Jump { .. })) {
                EdgeKind::Jump
            } else {
                EdgeKind::Linear
            };
            edges.push(Edge {
                to: t,
                kind,
                back: dominates(t, i),
            });
        }
        out.push(edges);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{Flag, LlirBlock, LlirInstr, VReg, Value};

    fn blocks(spec: &[(u64, Vec<Op>, Vec<u64>)]) -> LlirFunction {
        LlirFunction {
            entry_va: spec.first().map(|(v, _, _)| *v).unwrap_or(0),
            blocks: spec
                .iter()
                .map(|(va, ops, s)| LlirBlock {
                    start_va: *va,
                    end_va: va + 0x10,
                    instrs: ops
                        .iter()
                        .cloned()
                        .enumerate()
                        .map(|(j, op)| LlirInstr {
                            va: va + j as u64,
                            op,
                        })
                        .collect(),
                    succs: s.clone(),
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

    /// A conditional's two edges are told apart by the branch's own TARGET, not by
    /// successor order. Deriving it from order is what turned a rotated loop's exit
    /// test into its continue condition.
    #[test]
    fn a_conditional_names_its_taken_edge_from_the_branch_target() {
        // 0 -> {1 fallthrough, 2 taken}; the branch targets block 2.
        let lf = blocks(&[
            (0x00, vec![cj(0x20)], vec![0x10, 0x20]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![]];
        let e = classify(&lf, &succs, |_, _| false);
        assert_eq!(e[0][0].kind, EdgeKind::Fallthrough, "{:?}", e[0]);
        assert_eq!(e[0][1].kind, EdgeKind::Taken, "{:?}", e[0]);
    }

    /// The same graph with the branch targeting the OTHER successor must swap the
    /// labels. Order is identical; only the target moved.
    #[test]
    fn swapping_the_branch_target_swaps_the_edge_kinds() {
        let lf = blocks(&[
            (0x00, vec![cj(0x10)], vec![0x10, 0x20]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![]];
        let e = classify(&lf, &succs, |_, _| false);
        assert_eq!(e[0][0].kind, EdgeKind::Taken);
        assert_eq!(e[0][1].kind, EdgeKind::Fallthrough);
    }

    /// An unconditional jump is a transfer, not a taken branch.
    #[test]
    fn an_unconditional_jump_is_a_transfer() {
        let lf = blocks(&[
            (0x00, vec![Op::Jump { target: 0x10 }], vec![0x10]),
            (0x10, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1], vec![]];
        let e = classify(&lf, &succs, |_, _| false);
        assert_eq!(e[0][0].kind, EdgeKind::Jump);
    }

    /// An indirect dispatch's arms are switch cases, and the bounds check in front
    /// of it names its own out-of-range edge.
    #[test]
    fn a_jump_table_has_case_arms_and_a_derived_default() {
        // 0 = bounds check: taken -> 4 (default), fallthrough -> 1 (dispatch)
        // 1 = indirect dispatch -> {2, 3, 5}
        let lf = blocks(&[
            (0x00, vec![cj(0x40)], vec![0x10, 0x40]),
            (
                0x10,
                vec![Op::Jump { target: 0x20 }],
                vec![0x20, 0x30, 0x50],
            ),
            (0x20, vec![Op::Return], vec![]),
            (0x30, vec![Op::Return], vec![]),
            (0x40, vec![Op::Return], vec![]),
            (0x50, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 4], vec![2, 3, 5], vec![], vec![], vec![], vec![]];
        let e = classify(&lf, &succs, |_, _| false);
        assert_eq!(e[0][0].kind, EdgeKind::Fallthrough, "into the dispatch");
        assert_eq!(
            e[0][1].kind,
            EdgeKind::SwitchDefault,
            "the edge that bypasses the dispatch is the default arm"
        );
        for edge in &e[1] {
            assert_eq!(edge.kind, EdgeKind::SwitchCase, "{edge:?}");
        }
    }

    #[test]
    fn an_indirect_table_with_two_unique_targets_is_still_a_switch() {
        let lf = blocks(&[
            (
                0x00,
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("target")),
                    index: Some(Value::Reg(VReg::phys("index"))),
                }],
                vec![0x10, 0x20, 0x10, 0x20],
            ),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        // Graph algorithms receive distinct destinations; the LLIR block above
        // still carries all four resolved table slots.
        let succs = vec![vec![1, 2], vec![], vec![]];

        let edges = classify(&lf, &succs, |_, _| false);

        assert!(
            edges[0]
                .iter()
                .all(|edge| edge.kind == EdgeKind::SwitchCase),
            "an indirect table does not stop being a switch when labels share bodies: {:?}",
            edges[0]
        );
    }

    /// A latch is flagged from DOMINANCE, so it is independent of the terminator —
    /// and it keeps its transfer kind rather than being relabelled.
    #[test]
    fn a_latch_is_marked_back_without_losing_its_kind() {
        // 1 -> 0 where 0 dominates 1.
        let lf = blocks(&[
            (0x00, vec![cj(0x20)], vec![0x10, 0x20]),
            (0x10, vec![Op::Jump { target: 0x00 }], vec![0x00]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![0], vec![]];
        let e = classify(&lf, &succs, |a, b| a == 0 && b == 1);
        assert!(e[1][0].back, "1 -> 0 is a latch");
        assert_eq!(e[1][0].kind, EdgeKind::Jump, "and still an explicit jump");
        assert!(
            !e[0][0].back && !e[0][1].back,
            "forward edges are not latches"
        );
    }

    /// A block with no transfer instruction runs into the next one: LINEAR, not a
    /// jump. Conflating them hides that one is an instruction and the other is only
    /// where the block happens to sit.
    #[test]
    fn adjacency_without_a_jump_is_linear_not_a_jump() {
        let lf = blocks(&[(0x00, vec![], vec![0x10]), (0x10, vec![Op::Return], vec![])]);
        let succs = vec![vec![1], vec![]];
        let e = classify(&lf, &succs, |_, _| false);
        assert_eq!(e[0][0].kind, EdgeKind::Linear);
    }

    /// Every edge kind is reachable from some real shape — a kind nothing produces
    /// is a kind nobody can rely on.
    #[test]
    fn every_edge_kind_is_produced_by_some_shape() {
        use std::collections::HashSet;
        let mut seen: HashSet<EdgeKind> = HashSet::new();
        // conditional + linear + jump
        let lf = blocks(&[
            (0x00, vec![cj(0x20)], vec![0x10, 0x20]),
            (0x10, vec![], vec![0x20]),
            (0x20, vec![Op::Jump { target: 0x00 }], vec![0x00]),
        ]);
        let succs = vec![vec![1, 2], vec![2], vec![0]];
        for row in classify(&lf, &succs, |a, b| a == 0 && b == 2) {
            seen.extend(row.iter().map(|e| e.kind));
        }
        // dispatch + derived default
        let lf2 = blocks(&[
            (0x00, vec![cj(0x30)], vec![0x10, 0x30]),
            (
                0x10,
                vec![Op::Jump { target: 0x20 }],
                vec![0x20, 0x40, 0x50],
            ),
            (0x20, vec![Op::Return], vec![]),
            (0x30, vec![Op::Return], vec![]),
            (0x40, vec![Op::Return], vec![]),
            (0x50, vec![Op::Return], vec![]),
        ]);
        let succs2 = vec![vec![1, 3], vec![2, 4, 5], vec![], vec![], vec![], vec![]];
        for row in classify(&lf2, &succs2, |_, _| false) {
            seen.extend(row.iter().map(|e| e.kind));
        }
        for k in [
            EdgeKind::Taken,
            EdgeKind::Fallthrough,
            EdgeKind::SwitchCase,
            EdgeKind::SwitchDefault,
            EdgeKind::Jump,
            EdgeKind::Linear,
        ] {
            assert!(seen.contains(&k), "no shape produced {k:?}: {seen:?}");
        }
    }
}
