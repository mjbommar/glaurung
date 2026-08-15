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
//! * [`EdgeKind::Exceptional`] — a transfer to a landing pad proven by the LSDA,
//!   not by any branch instruction. Only produced when the caller supplies the
//!   recovered call sites (see [`classify_with_exceptions`]).
//! * [`EdgeKind::Unknown`] — an edge the block's terminator does NOT explain.
//!
//! [`Edge::back`] is orthogonal to all of them, and deliberately a separate flag
//! rather than another kind: a latch edge is still *taken* or *jumped*, and
//! collapsing the two loses which. It is computed from dominance — `to` dominates
//! `from` — so it does not depend on the terminator at all.
//!
//! # Why `Unknown` is a kind and not an absence
//!
//! A terminator can explain a bounded number of successors: a `CondJump` explains
//! two, a `Jump` explains one, a block with no transfer instruction explains one
//! (the block it physically abuts). This module used to hand the *same* order-derived
//! label to every unexplained extra: two `Fallthrough` edges out of one conditional,
//! two `Linear` edges out of one call. Both are impossible, and both read downstream
//! as ordinary facts. The exceptional edge is the everyday case —
//! [`crate::analysis::exception::with_exceptional_successors`] appends a landing pad
//! to a protected call block, and without the LSDA in hand that extra successor was
//! labelled `Linear`, i.e. "the block runs off its end into the handler".
//!
//! So exactly one successor may carry an order-derived label, and any further one is
//! [`EdgeKind::Unknown`] — design rule 8, a failed proof becomes an explicit unknown
//! rather than a silent falsehood.
//!
//! # Leaving the function
//!
//! [`EdgeKind`] describes transfers to another block of the SAME function. A block
//! with no successors at all used to produce no edge of any kind, so a return, a
//! `noreturn` call, a tail call and an unresolved `jmp *%rax` were indistinguishable
//! from each other and from a block whose successors were simply lost. [`TerminalKind`]
//! names them, and [`classify_terminals`] guarantees the total: every block has at
//! least one way out, listed or terminal.

use std::collections::{BTreeMap, BTreeSet};

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
    /// A transfer to a landing pad, proven by the language-specific data area
    /// rather than by any branch instruction. No instruction in the source block
    /// names this target: control reaches it only by unwinding.
    Exceptional,
    /// The block's terminator does not explain this edge.
    ///
    /// Not a failure of this module — it is what the module knows. A `CondJump`
    /// with three successors, a `Jump` with two, a call block with two
    /// fallthroughs: in each case one edge is real and the rest came from
    /// somewhere the terminator cannot account for. Labelling them by position
    /// would state a fact nothing proved.
    Unknown,
}

/// One CFG edge, with what it is and whether it closes a loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub to: usize,
    pub kind: EdgeKind,
    /// `to` dominates `from`: this edge is a loop latch. Independent of `kind`.
    pub back: bool,
}

/// How control leaves a block by a transfer with no successor in this function.
///
/// A CFG successor list answers "where next, inside this function". It cannot
/// answer "and what happens at the blocks that have no next", which is every
/// return, every `noreturn` call, every tail call and every computed transfer we
/// failed to resolve. Those all presented identically — as an empty successor
/// list — so a function whose dispatch was never resolved looked exactly like a
/// function that ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalKind {
    /// A machine return: `Op::Return` / `Op::ReturnValue`.
    Return,
    /// A return taken on one polarity only (`Op::CondReturn` / `Op::CondReturnValue`).
    ///
    /// Emitted **in addition to** the block's ordinary successor edges, because the
    /// block does both: it leaves the function on one path and continues on the other.
    ConditionalReturn,
    /// A frame-replacing call — `CallEffects::is_tail_call`. Control leaves and
    /// does not come back to this frame.
    TailCall,
    /// A call the block ends on with no successor: the callee does not return
    /// here (`exit`, `abort`, `__stack_chk_fail`, `__cxa_throw`, any `noreturn`).
    ///
    /// Distinct from [`TerminalKind::TailCall`]: a tail call is proven to replace
    /// the frame, while this is only proven not to come back to the next block.
    Call,
    /// An explicit direct transfer to an address this function does not own.
    ///
    /// Two different situations wear this shape and neither is proven: an
    /// unrecovered tail call (`jmp strlen`), and a target that the owned-range
    /// clip removed from the function. Both are honest as "leaves directly, to
    /// somewhere outside", and neither may be reported as a return.
    Direct,
    /// A computed transfer whose destination a relocation proves: it reads a
    /// place the loader binds to a named symbol, so control goes there. A PLT
    /// stub's `jmp *GOT[f]` is the everyday case, and `deregister_tm_clones`'
    /// `jmp *%rax` one load later is the same fact with a register hop.
    ///
    /// Frame-replacing, like [`TerminalKind::TailCall`], but proven by a
    /// different thing: `TailCall` reads `CallEffects::is_tail_call` off a
    /// direct call, and this reads a relocation off the place the transfer
    /// dereferences. Kept apart so a reader can tell which proof was available.
    IndirectToSymbol,
    /// A computed transfer that reads a fixed, statically known place which no
    /// relocation names.
    ///
    /// The place is recovered and the contents are not, and the difference is
    /// worth a kind of its own: `.plt`'s header stub reads `.got.plt[2]`, which
    /// the loader fills with `_dl_runtime_resolve`. Nothing static can name it
    /// and nothing is wrong — that is not the same situation as a dispatch whose
    /// table was never found, and lumping the two together is what made the
    /// unresolved count unreadable.
    IndirectThroughSlot,
    /// A computed transfer whose destinations were never recovered — `jmp *%rax`
    /// with an empty successor list.
    ///
    /// The precise shape that made `statemachine:clang:O0` look faithful while
    /// thirty instructions of case arms were missing from the function entirely.
    ///
    /// After [`classify_terminals_with_destinations`] this is the residue: the
    /// transfers no relocation and no table recovery accounted for. A declined
    /// jump table stays here, by design — see [`crate::ir::indirect_targets`].
    Indirect,
    /// Control leaves and nothing in the block says how.
    ///
    /// An explicit unknown, never an absence: a block with no successors and no
    /// recognised terminator has lost its outgoing flow somewhere, and reporting
    /// zero edges is what makes that undetectable.
    Unknown,
}

/// One way out of the function, attributed to the block it leaves from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalEdge {
    /// Block index this transfer leaves from.
    pub from: usize,
    pub kind: TerminalKind,
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
    classify_with_exceptions(lf, succs, dominates, &BTreeSet::new())
}

/// [`classify`] with LSDA-proven exceptional edges named as such.
///
/// `exceptional` holds `(source block start VA, landing pad VA)` pairs, as produced
/// by [`crate::analysis::exception::exceptional_edges`]. It is a parameter rather
/// than something read off the LLIR because the proof lives in `.eh_frame` and the
/// LSDA, not in any instruction: a protected call block's transfer to its handler
/// has no branch to recover it from.
///
/// Exceptional successors are also excluded from the dispatch heuristic. A protected
/// call block with one fallthrough plus one landing pad has two successors and no
/// branch, which the `succ_count > 2` fallback would otherwise start reading as a
/// jump table as soon as a second handler appeared.
pub fn classify_with_exceptions(
    lf: &LlirFunction,
    succs: &[Vec<usize>],
    dominates: impl Fn(usize, usize) -> bool,
    exceptional: &BTreeSet<(u64, u64)>,
) -> Vec<Vec<Edge>> {
    let va_to_idx: std::collections::HashMap<u64, usize> = lf
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start_va, i))
        .collect();

    let is_exceptional = |from: usize, to: usize| -> bool {
        if exceptional.is_empty() {
            return false;
        }
        match (lf.blocks.get(from), lf.blocks.get(to)) {
            (Some(f), Some(t)) => exceptional.contains(&(f.start_va, t.start_va)),
            _ => false,
        }
    };

    let terminator = |i: usize| -> Option<&Op> {
        lf.blocks
            .get(i)
            .and_then(|b| b.instrs.last())
            .map(|x| &x.op)
    };

    // Which blocks are indirect dispatches, so the bounds check in front of one can
    // recognise its own default edge. Counted over branch-reachable successors only.
    let dispatch: Vec<bool> = (0..succs.len())
        .map(|i| {
            let branch_reachable = succs[i].iter().filter(|&&t| !is_exceptional(i, t)).count();
            is_dispatch(branch_reachable, terminator(i))
        })
        .collect();

    let mut out: Vec<Vec<Edge>> = Vec::with_capacity(succs.len());
    for (i, targets) in succs.iter().enumerate() {
        let term = terminator(i);
        let taken = match term {
            Some(Op::CondJump { target, .. }) => va_to_idx.get(target).copied(),
            _ => None,
        };
        let jumped = match term {
            Some(Op::Jump { target }) => va_to_idx.get(target).copied(),
            _ => None,
        };
        let is_jump = matches!(term, Some(Op::Jump { .. }));
        // The block physically abutting this one: the single successor a
        // fallthrough or a linear run is allowed to name.
        let end_va = lf.blocks.get(i).map(|b| b.end_va);
        let abutting = targets.iter().copied().find(|&t| {
            !is_exceptional(i, t)
                && end_va.is_some()
                && lf.blocks.get(t).map(|b| b.start_va) == end_va
        });
        let branch_reachable: Vec<usize> = targets
            .iter()
            .copied()
            .filter(|&t| !is_exceptional(i, t))
            .collect();
        // How many successors are left for the non-taken side of a conditional to
        // claim. One is the fallthrough; a second has no branch behind it.
        let untaken = branch_reachable
            .iter()
            .filter(|&&t| Some(t) != taken)
            .count();

        let mut edges = Vec::with_capacity(targets.len());
        for &t in targets {
            let kind = if is_exceptional(i, t) {
                EdgeKind::Exceptional
            } else if dispatch[i] {
                EdgeKind::SwitchCase
            } else if let Some(tk) = taken {
                if t == tk {
                    // A conditional edge that skips PAST an indirect dispatch is the
                    // switch's out-of-range arm.
                    if branch_reachable.iter().any(|&o| o != t && dispatch[o]) {
                        EdgeKind::SwitchDefault
                    } else {
                        EdgeKind::Taken
                    }
                } else if untaken <= 1 || abutting == Some(t) {
                    EdgeKind::Fallthrough
                } else {
                    EdgeKind::Unknown
                }
            } else if is_jump {
                if branch_reachable.len() <= 1 || jumped == Some(t) {
                    EdgeKind::Jump
                } else {
                    EdgeKind::Unknown
                }
            } else if branch_reachable.len() <= 1 || abutting == Some(t) {
                EdgeKind::Linear
            } else {
                EdgeKind::Unknown
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

/// Name every way control leaves the function, block by block.
///
/// Returns one row per block, parallel to `succs`. A row is normally empty — the
/// block's outgoing flow is fully described by its successor edges — and carries a
/// [`TerminalEdge`] exactly when control also, or only, leaves the function there.
///
/// The invariant this exists to make checkable: **no block has zero ways out.**
/// Every block either names a successor or names how it leaves, and a block that
/// can prove neither reports [`TerminalKind::Unknown`] rather than nothing.
pub fn classify_terminals(lf: &LlirFunction, succs: &[Vec<usize>]) -> Vec<Vec<TerminalEdge>> {
    classify_terminals_with_destinations(lf, succs, &BTreeMap::new())
}

/// [`classify_terminals`] with relocation-proven computed destinations named as
/// such.
///
/// `destinations` maps the virtual address of an `Op::IndirectJump` to what a
/// relocation proves about where it goes, as produced by
/// [`crate::ir::indirect_targets::resolve_indirect_jumps`]. It is a parameter
/// for the same reason `exceptional` is one on
/// [`classify_with_exceptions`]: the proof lives in the relocation table, and no
/// instruction in the block carries it. A transfer with no entry keeps
/// [`TerminalKind::Indirect`], so the default is always the weaker claim.
pub fn classify_terminals_with_destinations(
    lf: &LlirFunction,
    succs: &[Vec<usize>],
    destinations: &BTreeMap<u64, crate::ir::indirect_targets::IndirectDestination>,
) -> Vec<Vec<TerminalEdge>> {
    use crate::ir::indirect_targets::IndirectDestination;

    let indirect_kind = |va: u64| match destinations.get(&va) {
        Some(IndirectDestination::Symbol(_)) => TerminalKind::IndirectToSymbol,
        Some(IndirectDestination::UnnamedSlot(_)) => TerminalKind::IndirectThroughSlot,
        None => TerminalKind::Indirect,
    };

    (0..succs.len())
        .map(|i| {
            let instrs = lf.blocks.get(i).map(|b| b.instrs.as_slice()).unwrap_or(&[]);
            let term = instrs.last().map(|x| &x.op);
            let term_va = instrs.last().map(|x| x.va);
            let mut edges = Vec::new();
            if term.is_some_and(|op| op.is_conditional_return()) {
                edges.push(TerminalEdge {
                    from: i,
                    kind: TerminalKind::ConditionalReturn,
                });
            }
            if !succs[i].is_empty() {
                return edges;
            }
            // No successor inside this function, so control leaves here. Say how.
            //
            // A recovered tail call is `Call { is_tail_call } ; Return` — the
            // synthetic `Return` is the terminator, so the frame-replacing fact is
            // one instruction back. Reading only the terminator reports every tail
            // call as an ordinary return.
            let tail_before_return = matches!(
                instrs.len().checked_sub(2).and_then(|j| instrs.get(j)).map(|x| &x.op),
                Some(Op::Call {
                    effects: Some(effects),
                    ..
                }) if effects.is_tail_call
            );
            let kind = match term {
                None => TerminalKind::Unknown,
                Some(op) if op.is_unconditional_return() => {
                    if tail_before_return {
                        TerminalKind::TailCall
                    } else {
                        TerminalKind::Return
                    }
                }
                Some(Op::Call { effects, .. }) => {
                    if effects.as_ref().is_some_and(|e| e.is_tail_call) {
                        TerminalKind::TailCall
                    } else {
                        TerminalKind::Call
                    }
                }
                Some(Op::IndirectJump { .. }) => {
                    term_va.map_or(TerminalKind::Indirect, &indirect_kind)
                }
                Some(Op::Jump { .. }) => TerminalKind::Direct,
                // A conditional return with no successor already reported the
                // returning side; the OTHER side went somewhere unrecorded.
                Some(_) => TerminalKind::Unknown,
            };
            edges.push(TerminalEdge { from: i, kind });
            edges
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{CallTarget, Flag, LlirBlock, LlirInstr, VReg, Value};
    use std::collections::HashSet;

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
        use std::collections::BTreeSet;
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
        // the two kinds that state a failed proof
        let lf3 = blocks(&[
            (
                0x00,
                vec![Op::Call {
                    target: CallTarget::Direct(0x900),
                    effects: None,
                }],
                vec![0x10, 0x20],
            ),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs3 = vec![vec![1, 2], vec![], vec![]];
        let mut eh = BTreeSet::new();
        eh.insert((0x00u64, 0x20u64));
        for row in classify_with_exceptions(&lf3, &succs3, |_, _| false, &eh) {
            seen.extend(row.iter().map(|e| e.kind));
        }
        for row in classify(&lf3, &succs3, |_, _| false) {
            seen.extend(row.iter().map(|e| e.kind));
        }
        for k in [
            EdgeKind::Taken,
            EdgeKind::Fallthrough,
            EdgeKind::SwitchCase,
            EdgeKind::SwitchDefault,
            EdgeKind::Jump,
            EdgeKind::Linear,
            EdgeKind::Exceptional,
            EdgeKind::Unknown,
        ] {
            assert!(seen.contains(&k), "no shape produced {k:?}: {seen:?}");
        }
    }

    // ---- edges the terminator cannot explain -------------------------------

    fn call(target: u64) -> Op {
        Op::Call {
            target: CallTarget::Direct(target),
            effects: None,
        }
    }

    /// A call block with two successors has one fallthrough and one edge from
    /// somewhere else. Both used to be `Linear` — "this block runs off its end"
    /// said twice about one block, which cannot be true of either.
    #[test]
    fn a_second_linear_successor_is_unknown_rather_than_a_second_fallthrough() {
        // 0 abuts 1 (0x00..0x10, 1 starts at 0x10). 2 is reachable from nothing
        // in the instruction stream.
        let lf = blocks(&[
            (0x00, vec![call(0x900)], vec![0x10, 0x20]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![]];

        let e = classify(&lf, &succs, |_, _| false);

        assert_eq!(e[0][0].kind, EdgeKind::Linear, "the abutting block");
        assert_eq!(
            e[0][1].kind,
            EdgeKind::Unknown,
            "nothing in the block names block 2: {:?}",
            e[0]
        );
    }

    /// One successor and no transfer instruction is still `Linear`. The rule is
    /// "at most one order-derived label", not "no order-derived labels".
    #[test]
    fn a_single_successor_keeps_its_order_derived_label() {
        let lf = blocks(&[
            (0x00, vec![call(0x900)], vec![0x10]),
            (0x10, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1], vec![]];
        assert_eq!(
            classify(&lf, &succs, |_, _| false)[0][0].kind,
            EdgeKind::Linear
        );
    }

    /// A conditional explains exactly two edges. A third is not a second
    /// fallthrough, however plausible it looks from successor order.
    #[test]
    fn a_conditional_with_three_successors_names_only_one_fallthrough() {
        let lf = blocks(&[
            (0x00, vec![cj(0x20)], vec![0x10, 0x20, 0x30]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
            (0x30, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2, 3], vec![], vec![], vec![]];

        let e = classify(&lf, &succs, |_, _| false);

        assert_eq!(e[0][0].kind, EdgeKind::Fallthrough, "the abutting block");
        assert_eq!(e[0][1].kind, EdgeKind::Taken, "the branch target");
        assert_eq!(
            e[0][2].kind,
            EdgeKind::Unknown,
            "a conditional has two arms, not three: {:?}",
            e[0]
        );
    }

    /// An unconditional jump explains its own target and nothing else.
    #[test]
    fn a_jump_with_a_second_successor_names_only_its_target() {
        let lf = blocks(&[
            (0x00, vec![Op::Jump { target: 0x20 }], vec![0x10, 0x20]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![]];

        let e = classify(&lf, &succs, |_, _| false);

        assert_eq!(e[0][0].kind, EdgeKind::Unknown, "{:?}", e[0]);
        assert_eq!(e[0][1].kind, EdgeKind::Jump, "the instruction's own target");
    }

    /// An LSDA-proven landing pad is an exceptional edge, and the SAME graph
    /// without that proof reports the edge as unknown rather than inventing a
    /// fallthrough into a handler.
    #[test]
    fn a_landing_pad_edge_is_exceptional_and_unknown_without_the_proof() {
        let lf = blocks(&[
            (0x00, vec![call(0x900)], vec![0x10, 0x20]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![]];
        let mut sites = BTreeSet::new();
        sites.insert((0x00u64, 0x20u64));

        let with = classify_with_exceptions(&lf, &succs, |_, _| false, &sites);
        assert_eq!(with[0][0].kind, EdgeKind::Linear, "the normal return path");
        assert_eq!(with[0][1].kind, EdgeKind::Exceptional, "{:?}", with[0]);

        let without = classify(&lf, &succs, |_, _| false);
        assert_eq!(
            without[0][1].kind,
            EdgeKind::Unknown,
            "an unproven handler edge is unknown, never a fallthrough: {:?}",
            without[0]
        );
    }

    /// An exceptional successor must not push a protected call block over the
    /// structural jump-table threshold. Two handlers plus a fallthrough is three
    /// successors, and `succ_count > 2` would start reading it as a dispatch.
    #[test]
    fn exceptional_successors_do_not_make_a_call_block_a_dispatch() {
        let lf = blocks(&[
            (0x00, vec![call(0x900)], vec![0x10, 0x20, 0x30]),
            (0x10, vec![Op::Return], vec![]),
            (0x20, vec![Op::Return], vec![]),
            (0x30, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1, 2, 3], vec![], vec![], vec![]];
        let sites: BTreeSet<(u64, u64)> = [(0x00u64, 0x20u64), (0x00u64, 0x30u64)].into();

        let e = classify_with_exceptions(&lf, &succs, |_, _| false, &sites);

        assert_eq!(e[0][0].kind, EdgeKind::Linear);
        assert_eq!(e[0][1].kind, EdgeKind::Exceptional);
        assert_eq!(e[0][2].kind, EdgeKind::Exceptional);
        assert!(
            classify(&lf, &succs, |_, _| false)[0]
                .iter()
                .all(|edge| edge.kind == EdgeKind::SwitchCase),
            "without the proof the same shape is still read as a jump table — \
             which is exactly what the proof is for"
        );
    }

    // ---- leaving the function ---------------------------------------------

    fn terminals_of(lf: &LlirFunction, succs: &[Vec<usize>]) -> Vec<Vec<TerminalKind>> {
        classify_terminals(lf, succs)
            .into_iter()
            .map(|row| row.into_iter().map(|edge| edge.kind).collect())
            .collect()
    }

    #[test]
    fn a_machine_return_is_named_as_one() {
        let lf = blocks(&[(0x00, vec![Op::Return], vec![])]);
        assert_eq!(
            terminals_of(&lf, &[vec![]]),
            vec![vec![TerminalKind::Return]]
        );
    }

    /// A conditional return leaves the function AND continues. Reporting only one
    /// of those is how an A32 `bxeq lr` loses either its exit or its body.
    #[test]
    fn a_conditional_return_both_leaves_and_continues() {
        let lf = blocks(&[
            (
                0x00,
                vec![Op::CondReturn {
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                }],
                vec![0x10],
            ),
            (0x10, vec![Op::Return], vec![]),
        ]);
        let succs = vec![vec![1], vec![]];

        assert_eq!(
            terminals_of(&lf, &succs),
            vec![
                vec![TerminalKind::ConditionalReturn],
                vec![TerminalKind::Return]
            ]
        );
        assert_eq!(
            classify(&lf, &succs, |_, _| false)[0][0].kind,
            EdgeKind::Linear,
            "the continuing side is still an ordinary successor edge"
        );
    }

    /// The lifter rewrites a proven tail call as `Call { is_tail_call } ; Return`.
    /// Reading only the terminator reports every one of them as a plain return —
    /// a frame that comes back where the machine never does.
    #[test]
    fn a_recovered_tail_call_is_not_reported_as_a_return() {
        let lf = blocks(&[(
            0x00,
            vec![
                Op::Call {
                    target: CallTarget::Direct(0x900),
                    effects: Some(crate::ir::types::CallEffects {
                        is_tail_call: true,
                        ..Default::default()
                    }),
                },
                Op::Return,
            ],
            vec![],
        )]);
        assert_eq!(
            terminals_of(&lf, &[vec![]]),
            vec![vec![TerminalKind::TailCall]]
        );
    }

    /// A block ending at a call with no successor is a callee that does not come
    /// back — `abort`, `exit`, `__stack_chk_fail`, `__cxa_throw`.
    #[test]
    fn a_call_with_no_successor_is_a_call_that_never_returns_here() {
        let lf = blocks(&[(0x00, vec![call(0x900)], vec![])]);
        assert_eq!(terminals_of(&lf, &[vec![]]), vec![vec![TerminalKind::Call]]);
    }

    /// A direct branch to an address this function does not own leaves directly.
    /// It is NOT a return, and it is not proven to be a tail call either: the
    /// same shape appears when the owned-range clip removed the target.
    #[test]
    fn a_direct_branch_out_of_the_function_is_a_direct_transfer() {
        let lf = blocks(&[(0x00, vec![Op::Jump { target: 0x9000 }], vec![])]);
        assert_eq!(
            terminals_of(&lf, &[vec![]]),
            vec![vec![TerminalKind::Direct]]
        );
    }

    /// An unresolved computed transfer is the `statemachine:clang:O0` shape: the
    /// case arms were never found, and an empty successor list reads downstream
    /// as a function that simply ended.
    #[test]
    fn an_unresolved_computed_transfer_is_indirect_not_an_ending() {
        let lf = blocks(&[(
            0x00,
            vec![Op::IndirectJump {
                target: Value::Reg(VReg::phys("rax")),
                index: None,
            }],
            vec![],
        )]);
        assert_eq!(
            terminals_of(&lf, &[vec![]]),
            vec![vec![TerminalKind::Indirect]]
        );
    }

    /// A block with no successors and nothing that transfers control has lost its
    /// outgoing flow. Reporting zero edges is what makes that undetectable.
    #[test]
    fn a_block_that_proves_nothing_reports_unknown_not_silence() {
        let lf = blocks(&[
            (0x00, vec![Op::Nop], vec![]),
            (0x10, vec![], vec![]),
            (
                0x20,
                vec![Op::Intrinsic {
                    name: "undecoded_bytes".into(),
                    ins: Vec::new(),
                    outs: Vec::new(),
                    reads_mem: true,
                    writes_mem: true,
                }],
                vec![],
            ),
        ]);
        assert_eq!(
            terminals_of(&lf, &[vec![], vec![], vec![]]),
            vec![
                vec![TerminalKind::Unknown],
                vec![TerminalKind::Unknown],
                vec![TerminalKind::Unknown],
            ],
            "an undecodable block's outgoing flow is unknown, not absent"
        );
    }

    /// A conditional return with no successor at all: the returning side is named
    /// and the side that continued is reported missing rather than assumed away.
    #[test]
    fn a_conditional_return_with_no_successor_reports_the_lost_side() {
        let lf = blocks(&[(
            0x00,
            vec![Op::CondReturn {
                cond: VReg::Flag(Flag::Z),
                inverted: false,
            }],
            vec![],
        )]);
        assert_eq!(
            terminals_of(&lf, &[vec![]]),
            vec![vec![TerminalKind::ConditionalReturn, TerminalKind::Unknown]]
        );
    }

    /// The totality invariant: no block has zero ways out.
    #[test]
    fn every_block_has_at_least_one_way_out() {
        let lf = blocks(&[
            (0x00, vec![cj(0x20)], vec![0x10, 0x20]),
            (0x10, vec![call(0x900)], vec![]),
            (0x20, vec![Op::Return], vec![]),
            (0x30, vec![], vec![]),
        ]);
        let succs = vec![vec![1, 2], vec![], vec![], vec![]];
        let edges = classify(&lf, &succs, |_, _| false);
        let terminals = classify_terminals(&lf, &succs);

        for block in 0..lf.blocks.len() {
            assert!(
                !edges[block].is_empty() || !terminals[block].is_empty(),
                "block {block} accounts for no outgoing control at all"
            );
        }
    }

    /// Every terminal kind is reachable from some real shape — the sibling of
    /// `every_edge_kind_is_produced_by_some_shape`, for the same reason.
    #[test]
    fn every_terminal_kind_is_produced_by_some_shape() {
        let mut seen: HashSet<TerminalKind> = HashSet::new();
        let specs: Vec<(Vec<Op>, Vec<u64>)> = vec![
            (vec![Op::Return], vec![]),
            (
                vec![Op::CondReturn {
                    cond: VReg::Flag(Flag::Z),
                    inverted: false,
                }],
                vec![],
            ),
            (
                vec![
                    Op::Call {
                        target: CallTarget::Direct(0x900),
                        effects: Some(crate::ir::types::CallEffects {
                            is_tail_call: true,
                            ..Default::default()
                        }),
                    },
                    Op::Return,
                ],
                vec![],
            ),
            (vec![call(0x900)], vec![]),
            (vec![Op::Jump { target: 0x9000 }], vec![]),
            (
                vec![Op::IndirectJump {
                    target: Value::Reg(VReg::phys("rax")),
                    index: None,
                }],
                vec![],
            ),
            (vec![Op::Nop], vec![]),
        ];
        for (ops, succ) in specs {
            let lf = blocks(&[(0x00, ops, succ)]);
            for row in classify_terminals(&lf, &[vec![]]) {
                seen.extend(row.iter().map(|e| e.kind));
            }
        }
        for k in [
            TerminalKind::Return,
            TerminalKind::ConditionalReturn,
            TerminalKind::TailCall,
            TerminalKind::Call,
            TerminalKind::Direct,
            TerminalKind::Indirect,
            TerminalKind::Unknown,
        ] {
            assert!(seen.contains(&k), "no shape produced {k:?}: {seen:?}");
        }
    }

    /// How often does an unexplained edge actually appear on real input?
    ///
    /// `EdgeKind::Unknown` is the honest label, but a label that fires routinely
    /// would mean the graphs handed to structuring have been carrying transfers
    /// nothing accounts for all along. Measured rather than assumed, in the shape
    /// of `no_owned_block_in_the_sample_corpus_is_undecodable`: across every
    /// sample binary this test can find, no successor edge is unexplained, and
    /// every block accounts for some outgoing control. If either stops being
    /// true the printed VAs are a finding, not a nuisance to relax.
    #[test]
    fn the_sample_corpus_has_no_unexplained_edge_and_no_silent_block() {
        use crate::analysis::cfg::analyze_functions_bytes;
        use crate::analysis::cfg::Budgets;
        use crate::core::binary::Arch;
        use std::path::Path;

        let mut lifted = 0usize;
        let mut unexplained: Vec<(u64, usize, usize)> = Vec::new();
        let mut silent: Vec<(u64, u64)> = Vec::new();
        let mut census: std::collections::BTreeMap<String, usize> = Default::default();
        for (rel, arch) in [
            (
                "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2",
                Arch::X86_64,
            ),
            (
                "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-gcc-O0",
                Arch::X86_64,
            ),
            ("samples/containers/hello-cpp-g++-O0", Arch::X86_64),
            (
                "samples/binaries/platforms/linux/arm64/export/cross/arm64/hello-arm64-gcc",
                Arch::AArch64,
            ),
        ] {
            let path = Path::new(rel);
            if !path.exists() {
                continue;
            }
            let data = std::fs::read(path).expect("read sample");
            let budgets = Budgets {
                max_functions: 64,
                max_blocks: 512,
                max_instructions: 40_000,
                timeout_ms: 4000,
                total_timeout_ms: 0,
            };
            let (funcs, _cg) = analyze_functions_bytes(&data, &budgets);
            for f in &funcs {
                let Ok(lf) = crate::ir::lift_function::lift_function_from_bytes(&data, f, arch)
                else {
                    continue;
                };
                lifted += 1;
                let index: std::collections::HashMap<u64, usize> = lf
                    .blocks
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (b.start_va, i))
                    .collect();
                let succs: Vec<Vec<usize>> = lf
                    .blocks
                    .iter()
                    .map(|b| {
                        b.succs
                            .iter()
                            .filter_map(|va| index.get(va).copied())
                            .collect()
                    })
                    .collect();
                let edges = classify(&lf, &succs, |_, _| false);
                let terminals = classify_terminals(&lf, &succs);
                for (block, row) in edges.iter().enumerate() {
                    for edge in row {
                        if edge.kind == EdgeKind::Unknown {
                            unexplained.push((lf.entry_va, block, edge.to));
                        }
                    }
                }
                for (block, row) in terminals.iter().enumerate() {
                    for edge in row {
                        *census.entry(format!("{:?}", edge.kind)).or_default() += 1;
                    }
                    if edges[block].is_empty() && row.is_empty() {
                        silent.push((lf.entry_va, lf.blocks[block].start_va));
                    }
                }
            }
        }
        assert!(lifted > 0, "no sample binary was available to measure");
        assert!(
            unexplained.is_empty(),
            "{} successor edge(s) no terminator explains across {lifted} functions: {:x?}",
            unexplained.len(),
            unexplained
        );
        assert!(
            silent.is_empty(),
            "{} block(s) account for no outgoing control at all: {:x?}",
            silent.len(),
            silent
        );
        // The census is the point of the exercise: these blocks previously
        // produced no edge of any kind, so the counts below were all zero and
        // indistinguishable from each other.
        assert!(
            census.values().sum::<usize>() > 0,
            "no terminal edge was classified across {lifted} functions"
        );
        eprintln!("[terminal-census] {lifted} functions: {census:?}");
    }
}
