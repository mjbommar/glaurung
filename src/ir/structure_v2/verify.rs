//! Independent fidelity checks for a shadow region candidate.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ConditionDag, ConditionNode, DuplicatedTail, LocalRegions, LoopForest, RegionCandidate,
    StructuredRegion, StructuredTree, Terminal, Transfer, MAX_TAIL_DUPLICATION_BLOCKS,
    MAX_TAIL_DUPLICATION_INSTRUCTIONS, MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS,
};
use crate::ir::structure::Cfg;

/// A concrete disagreement between a candidate and its source CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateError {
    BlockMissing {
        block: usize,
    },
    BlockDuplicated {
        block: usize,
    },
    BlockOutOfRange {
        block: usize,
    },
    EdgeMissing {
        from: usize,
        to: usize,
    },
    EdgeInvented {
        from: usize,
        to: usize,
    },
    TransferKindInvalid {
        from: usize,
        to: usize,
    },
    TerminalMismatch {
        block: usize,
    },
    DuplicatedTailInvalid {
        source_block: usize,
        cloned_at_predecessor: usize,
    },
    SwitchEvidenceMismatch {
        dispatch: usize,
    },
    SwitchDefaultEvidenceMismatch {
        guard: usize,
        target: usize,
    },
}

/// A disagreement between a recovered tree and its verified flat candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    BlockMissing {
        block: usize,
    },
    BlockDuplicated {
        block: usize,
    },
    BlockOutOfRange {
        block: usize,
    },
    LeafMismatch {
        block: usize,
    },
    BranchConditionInvalid {
        block: usize,
    },
    SwitchInvalid {
        dispatch: usize,
    },
    LoopInvalid {
        header: usize,
    },
    LoopExitInvalid {
        header: usize,
        target: usize,
    },
    LocalRegionInvalid {
        region: usize,
    },
    LocalExitInvalid {
        region: usize,
        target: usize,
    },
    DuplicatedTailMissing {
        source_block: usize,
        cloned_at_predecessor: usize,
    },
    DuplicatedTailInvented {
        source_block: usize,
        cloned_at_predecessor: usize,
    },
    ControlTransferMissing {
        from: usize,
        to: usize,
    },
    ControlTransferInvented {
        from: usize,
        to: usize,
    },
}

pub(super) fn verify_tree(
    candidate: &RegionCandidate,
    conditions: &ConditionDag,
    loops: &LoopForest,
    locals: &LocalRegions,
    duplicated_tails: &[DuplicatedTail],
    tree: &StructuredTree,
) -> Vec<TreeError> {
    let mut errors = Vec::new();
    let mut leaves: Vec<Option<BlockRegionView<'_>>> = vec![None; candidate.blocks().len()];
    let mut controls = Vec::new();
    let mut materialized_tails = Vec::new();
    visit_tree(
        &tree.root,
        candidate,
        conditions,
        loops,
        &mut leaves,
        &mut controls,
        &mut materialized_tails,
        &mut errors,
    );
    let mut seen_local_regions = BTreeSet::new();
    for definition in &tree.local_regions {
        let evidence = locals
            .evidence()
            .iter()
            .find(|evidence| evidence.region == definition.region);
        let block_ids: Vec<_> = definition.blocks.iter().map(|block| block.block).collect();
        if !seen_local_regions.insert(definition.region)
            || evidence.is_none_or(|evidence| evidence.blocks != block_ids)
        {
            errors.push(TreeError::LocalRegionInvalid {
                region: definition.region,
            });
        }
        for block in &definition.blocks {
            record_leaf(
                block.block,
                BlockRegionView::Block(block),
                candidate,
                &mut leaves,
                &mut errors,
            );
            controls.extend(block.transfers.iter().filter_map(|transfer| {
                matches!(
                    transfer,
                    Transfer::Break { .. } | Transfer::Continue { .. } | Transfer::LocalGoto { .. }
                )
                .then_some((block.block, *transfer))
            }));
        }
        let mut seen_targets = BTreeSet::new();
        for exit in &definition.exits {
            let is_direct_exit = definition.blocks.iter().any(|block| {
                block.transfers.iter().any(|transfer| {
                    transfer_target(transfer) == exit.target
                        && !matches!(transfer, Transfer::LocalGoto { .. })
                })
            });
            if !seen_targets.insert(exit.target) || !is_direct_exit {
                errors.push(TreeError::LocalExitInvalid {
                    region: definition.region,
                    target: exit.target,
                });
            }
            visit_tree(
                &exit.region,
                candidate,
                conditions,
                loops,
                &mut leaves,
                &mut controls,
                &mut materialized_tails,
                &mut errors,
            );
        }
    }
    for evidence in locals.evidence() {
        if !seen_local_regions.contains(&evidence.region) {
            errors.push(TreeError::LocalRegionInvalid {
                region: evidence.region,
            });
        }
    }
    let mut expected_tails = duplicated_tails.to_vec();
    expected_tails.retain(|tail| {
        !controls.iter().any(|(from, transfer)| {
            *from == tail.cloned_at_predecessor
                && matches!(transfer, Transfer::Break { to, .. } if *to == tail.source_block)
        })
    });
    for (source_block, blocks, cloned_at_predecessor) in materialized_tails {
        if let Some(position) = expected_tails.iter().position(|tail| {
            tail.source_block == source_block
                && tail.blocks == blocks
                && tail.cloned_at_predecessor == cloned_at_predecessor
        }) {
            expected_tails.remove(position);
        } else {
            errors.push(TreeError::DuplicatedTailInvented {
                source_block,
                cloned_at_predecessor,
            });
        }
    }
    for tail in expected_tails {
        errors.push(TreeError::DuplicatedTailMissing {
            source_block: tail.source_block,
            cloned_at_predecessor: tail.cloned_at_predecessor,
        });
    }
    for (block, leaf) in leaves.into_iter().enumerate() {
        if leaf.is_none() {
            errors.push(TreeError::BlockMissing { block });
        }
    }
    let mut expected_controls: Vec<(usize, Transfer)> = candidate
        .blocks()
        .iter()
        .flat_map(|block| {
            block.transfers.iter().filter_map(|transfer| {
                matches!(
                    transfer,
                    Transfer::Break { .. } | Transfer::Continue { .. } | Transfer::LocalGoto { .. }
                )
                .then_some((block.block, *transfer))
            })
        })
        .collect();
    for (from, transfer) in controls {
        if let Some(position) = expected_controls
            .iter()
            .position(|expected| *expected == (from, transfer))
        {
            expected_controls.remove(position);
        } else {
            errors.push(TreeError::ControlTransferInvented {
                from,
                to: transfer_target(&transfer),
            });
        }
    }
    for (from, transfer) in expected_controls {
        errors.push(TreeError::ControlTransferMissing {
            from,
            to: transfer_target(&transfer),
        });
    }
    errors
}

#[derive(Clone, Copy)]
enum BlockRegionView<'a> {
    Block(&'a super::BlockRegion),
    Return,
}

fn visit_tree<'a>(
    region: &'a StructuredRegion,
    candidate: &'a RegionCandidate,
    conditions: &ConditionDag,
    loops: &LoopForest,
    leaves: &mut [Option<BlockRegionView<'a>>],
    controls: &mut Vec<(usize, Transfer)>,
    materialized_tails: &mut Vec<(usize, Vec<usize>, usize)>,
    errors: &mut Vec<TreeError>,
) {
    match region {
        StructuredRegion::Empty => {}
        StructuredRegion::Block(actual) => {
            record_leaf(
                actual.block,
                BlockRegionView::Block(actual),
                candidate,
                leaves,
                errors,
            );
        }
        StructuredRegion::Return { block } => {
            record_leaf(*block, BlockRegionView::Return, candidate, leaves, errors);
        }
        StructuredRegion::DuplicatedReturn {
            source_block,
            blocks,
            cloned_at_predecessor,
        } => materialized_tails.push((*source_block, blocks.clone(), *cloned_at_predecessor)),
        StructuredRegion::Sequence(regions) => {
            for region in regions {
                visit_tree(
                    region,
                    candidate,
                    conditions,
                    loops,
                    leaves,
                    controls,
                    materialized_tails,
                    errors,
                );
            }
        }
        StructuredRegion::If {
            source_block,
            condition,
            then_region,
            else_region,
        } => {
            if !matches!(
                conditions.node(*condition),
                Some(ConditionNode::Branch { block, .. }) if block == source_block
            ) {
                errors.push(TreeError::BranchConditionInvalid {
                    block: *source_block,
                });
            }
            visit_tree(
                then_region,
                candidate,
                conditions,
                loops,
                leaves,
                controls,
                materialized_tails,
                errors,
            );
            if let Some(else_region) = else_region {
                visit_tree(
                    else_region,
                    candidate,
                    conditions,
                    loops,
                    leaves,
                    controls,
                    materialized_tails,
                    errors,
                );
            }
        }
        StructuredRegion::Switch {
            guard,
            dispatch,
            cases,
            default,
        } => {
            if let Some(block) = candidate
                .blocks()
                .iter()
                .find(|block| block.block == *dispatch)
            {
                record_leaf(
                    *dispatch,
                    BlockRegionView::Block(block),
                    candidate,
                    leaves,
                    errors,
                );
            } else {
                errors.push(TreeError::SwitchInvalid {
                    dispatch: *dispatch,
                });
            }
            let evidence = candidate
                .switches()
                .iter()
                .find(|evidence| evidence.dispatch == *dispatch);
            if evidence.is_none_or(|evidence| {
                evidence.cases.len() != cases.len()
                    || evidence.cases.iter().zip(cases).any(|(expected, actual)| {
                        expected.target != actual.target || expected.values != actual.values
                    })
            }) {
                errors.push(TreeError::SwitchInvalid {
                    dispatch: *dispatch,
                });
            }
            if default.as_ref().is_some_and(|actual| {
                candidate.switch_defaults().iter().all(|expected| {
                    expected.guard != guard.unwrap_or(*dispatch)
                        || expected.dispatch != Some(*dispatch)
                        || expected.target != actual.target
                        || expected.taken != actual.taken
                })
            }) {
                errors.push(TreeError::SwitchInvalid {
                    dispatch: *dispatch,
                });
            }
            for case in cases {
                visit_tree(
                    &case.region,
                    candidate,
                    conditions,
                    loops,
                    leaves,
                    controls,
                    materialized_tails,
                    errors,
                );
            }
            if let Some(default) = default {
                visit_tree(
                    &default.region,
                    candidate,
                    conditions,
                    loops,
                    leaves,
                    controls,
                    materialized_tails,
                    errors,
                );
            }
        }
        StructuredRegion::Loop {
            header,
            kind,
            body,
            exits,
        } => {
            let Some(loop_info) = loops.by_header(*header) else {
                errors.push(TreeError::LoopInvalid { header: *header });
                return;
            };
            if loop_info.kind != *kind {
                errors.push(TreeError::LoopInvalid { header: *header });
            }
            visit_tree(
                body,
                candidate,
                conditions,
                loops,
                leaves,
                controls,
                materialized_tails,
                errors,
            );
            let mut seen_targets = std::collections::BTreeSet::new();
            for exit in exits {
                if !seen_targets.insert(exit.target)
                    || !loop_info.exits.iter().any(|(_, to)| *to == exit.target)
                {
                    errors.push(TreeError::LoopExitInvalid {
                        header: *header,
                        target: exit.target,
                    });
                }
                visit_tree(
                    &exit.region,
                    candidate,
                    conditions,
                    loops,
                    leaves,
                    controls,
                    materialized_tails,
                    errors,
                );
            }
        }
        StructuredRegion::Break {
            from,
            header,
            to,
            taken,
        } => controls.push((
            *from,
            Transfer::Break {
                header: *header,
                to: *to,
                taken: *taken,
            },
        )),
        StructuredRegion::Continue {
            from,
            header,
            taken,
        } => controls.push((
            *from,
            Transfer::Continue {
                header: *header,
                taken: *taken,
            },
        )),
        StructuredRegion::LocalGoto {
            from,
            to,
            taken,
            region,
        } => controls.push((
            *from,
            Transfer::LocalGoto {
                to: *to,
                taken: *taken,
                region: *region,
            },
        )),
        StructuredRegion::SharedGoto { from, to, taken } => {
            let expected = match taken {
                Some(taken) => Transfer::Branch {
                    to: *to,
                    taken: *taken,
                },
                None => Transfer::Flow { to: *to },
            };
            if !candidate
                .blocks()
                .iter()
                .any(|block| block.block == *from && block.transfers.contains(&expected))
            {
                errors.push(TreeError::ControlTransferInvented {
                    from: *from,
                    to: *to,
                });
            }
        }
    }
}

fn record_leaf<'a>(
    block: usize,
    leaf: BlockRegionView<'a>,
    candidate: &'a RegionCandidate,
    leaves: &mut [Option<BlockRegionView<'a>>],
    errors: &mut Vec<TreeError>,
) {
    let Some(slot) = leaves.get_mut(block) else {
        errors.push(TreeError::BlockOutOfRange { block });
        return;
    };
    if slot.is_some() {
        errors.push(TreeError::BlockDuplicated { block });
        return;
    }
    let expected = candidate
        .blocks()
        .iter()
        .find(|region| region.block == block);
    let matches = match (leaf, expected) {
        (BlockRegionView::Block(actual), Some(expected)) => actual == expected,
        (BlockRegionView::Return, Some(expected)) => {
            expected.terminal == Some(Terminal::Return) && expected.transfers.is_empty()
        }
        _ => false,
    };
    if !matches {
        errors.push(TreeError::LeafMismatch { block });
    }
    *slot = Some(leaf);
}

pub(super) fn verify_candidate(
    cfg: &Cfg,
    loops: &LoopForest,
    locals: &LocalRegions,
    duplicated_tails: &[DuplicatedTail],
    candidate: &RegionCandidate,
) -> Vec<CandidateError> {
    let mut errors = Vec::new();
    let mut owners = vec![0usize; cfg.succs.len()];
    let mut actual_edges: BTreeMap<(usize, usize), usize> = BTreeMap::new();

    for block_region in &candidate.blocks {
        let block = block_region.block;
        if block >= cfg.succs.len() {
            errors.push(CandidateError::BlockOutOfRange { block });
            continue;
        }
        owners[block] += 1;
        let expected_terminal = cfg.succs[block].is_empty().then(|| {
            if cfg.ends_in_return[block] {
                Terminal::Return
            } else {
                Terminal::Unknown
            }
        });
        if block_region.terminal != expected_terminal {
            errors.push(CandidateError::TerminalMismatch { block });
        }

        for transfer in &block_region.transfers {
            let to = transfer_target(transfer);
            *actual_edges.entry((block, to)).or_default() += 1;
            if !transfer_kind_is_valid(cfg, loops, locals, block, transfer) {
                errors.push(CandidateError::TransferKindInvalid { from: block, to });
            }
        }
    }

    for (block, count) in owners.into_iter().enumerate() {
        match count {
            0 => errors.push(CandidateError::BlockMissing { block }),
            1 => {}
            _ => errors.push(CandidateError::BlockDuplicated { block }),
        }
    }

    let mut expected_edges: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    for (from, successors) in cfg.succs.iter().enumerate() {
        for &to in successors {
            *expected_edges.entry((from, to)).or_default() += 1;
        }
    }
    for (&(from, to), &expected) in &expected_edges {
        let actual = actual_edges.get(&(from, to)).copied().unwrap_or(0);
        for _ in actual..expected {
            errors.push(CandidateError::EdgeMissing { from, to });
        }
    }
    for (&(from, to), &actual) in &actual_edges {
        let expected = expected_edges.get(&(from, to)).copied().unwrap_or(0);
        for _ in expected..actual {
            errors.push(CandidateError::EdgeInvented { from, to });
        }
    }
    verify_switch_evidence(cfg, candidate, &mut errors);
    verify_duplicated_tails(cfg, duplicated_tails, &mut errors);
    errors
}

fn verify_switch_evidence(
    cfg: &Cfg,
    candidate: &RegionCandidate,
    errors: &mut Vec<CandidateError>,
) {
    let expected_switches = cfg
        .edges
        .iter()
        .enumerate()
        .filter_map(|(dispatch, edges)| {
            let cases = edges
                .iter()
                .enumerate()
                .filter(|(_, edge)| edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchCase)
                .map(|(position, edge)| super::SwitchCaseEvidence {
                    target: edge.to,
                    values: cfg.case_labels[dispatch][position].clone(),
                })
                .collect::<Vec<_>>();
            (!cases.is_empty()).then_some(super::SwitchEvidence { dispatch, cases })
        })
        .collect::<Vec<_>>();
    if candidate.switches != expected_switches {
        let dispatches = candidate
            .switches
            .iter()
            .map(|switch| switch.dispatch)
            .chain(expected_switches.iter().map(|switch| switch.dispatch))
            .collect::<BTreeSet<_>>();
        errors.extend(
            dispatches
                .into_iter()
                .map(|dispatch| CandidateError::SwitchEvidenceMismatch { dispatch }),
        );
    }

    let expected_defaults = cfg
        .edges
        .iter()
        .enumerate()
        .flat_map(|(guard, edges)| {
            edges.iter().filter_map(move |edge| {
                (edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchDefault).then(|| {
                    let dispatch = cfg.succs[guard].iter().copied().find(|successor| {
                        *successor != edge.to
                            && cfg.edges[*successor].iter().any(|candidate| {
                                candidate.kind == crate::ir::cfg_edges::EdgeKind::SwitchCase
                            })
                    });
                    super::SwitchDefaultEvidence {
                        guard,
                        target: edge.to,
                        dispatch,
                        taken: cfg.cond_taken[guard] == Some(edge.to),
                    }
                })
            })
        })
        .collect::<Vec<_>>();
    if candidate.switch_defaults != expected_defaults {
        let defaults = candidate
            .switch_defaults
            .iter()
            .map(|default| (default.guard, default.target))
            .chain(
                expected_defaults
                    .iter()
                    .map(|default| (default.guard, default.target)),
            )
            .collect::<BTreeSet<_>>();
        errors.extend(defaults.into_iter().map(|(guard, target)| {
            CandidateError::SwitchDefaultEvidenceMismatch { guard, target }
        }));
    }
}

fn verify_duplicated_tails(
    cfg: &Cfg,
    duplicated_tails: &[DuplicatedTail],
    errors: &mut Vec<CandidateError>,
) {
    let mut seen = std::collections::BTreeSet::new();
    let mut total_instructions = 0usize;
    for tail in duplicated_tails {
        total_instructions = total_instructions.saturating_add(tail.instruction_count);
        let blocks_in_range = tail.blocks.iter().all(|block| *block < cfg.succs.len());
        let unique_blocks =
            tail.blocks.iter().copied().collect::<BTreeSet<_>>().len() == tail.blocks.len();
        let linear_edges = blocks_in_range
            && tail
                .blocks
                .windows(2)
                .all(|pair| cfg.succs[pair[0]].as_slice() == [pair[1]]);
        let terminal_return = blocks_in_range
            && tail
                .blocks
                .last()
                .is_some_and(|block| cfg.succs[*block].is_empty() && cfg.ends_in_return[*block]);
        let instruction_count = blocks_in_range.then(|| {
            tail.blocks
                .iter()
                .map(|block| cfg.block_instruction_counts[*block])
                .fold(0usize, usize::saturating_add)
        });
        let valid = tail.source_block < cfg.succs.len()
            && tail.canonical_predecessor < cfg.succs.len()
            && tail.cloned_at_predecessor < cfg.succs.len()
            && tail.blocks.first() == Some(&tail.source_block)
            && !tail.blocks.is_empty()
            && tail.blocks.len() <= MAX_TAIL_DUPLICATION_BLOCKS
            && unique_blocks
            && linear_edges
            && terminal_return
            && instruction_count == Some(tail.instruction_count)
            && tail.instruction_count <= MAX_TAIL_DUPLICATION_INSTRUCTIONS
            && total_instructions <= MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS
            && cfg.preds[tail.source_block].len() >= 2
            && cfg.preds[tail.source_block].first() == Some(&tail.canonical_predecessor)
            && cfg.preds[tail.source_block]
                .binary_search(&tail.cloned_at_predecessor)
                .is_ok()
            && tail.cloned_at_predecessor != tail.canonical_predecessor
            && seen.insert((tail.source_block, tail.cloned_at_predecessor));
        if !valid {
            errors.push(CandidateError::DuplicatedTailInvalid {
                source_block: tail.source_block,
                cloned_at_predecessor: tail.cloned_at_predecessor,
            });
        }
    }
}

fn transfer_target(transfer: &Transfer) -> usize {
    match transfer {
        Transfer::Flow { to }
        | Transfer::Branch { to, .. }
        | Transfer::Break { to, .. }
        | Transfer::LocalGoto { to, .. } => *to,
        Transfer::Continue { header, .. } => *header,
    }
}

fn transfer_kind_is_valid(
    cfg: &Cfg,
    loops: &LoopForest,
    locals: &LocalRegions,
    from: usize,
    transfer: &Transfer,
) -> bool {
    let to = transfer_target(transfer);
    let conditional = cfg.cond_taken[from].filter(|_| cfg.succs[from].len() == 2);
    let expected_taken = conditional.map(|target| target == to);
    match transfer {
        Transfer::Continue { header, taken } => {
            locals.region_for_block(*header).is_none()
                && loops.is_back_edge(from, *header)
                && *taken == expected_taken
        }
        Transfer::Break { header, to, taken } => {
            locals.region_for_block(*to).is_none()
                && loops.innermost_containing(from).is_some_and(|loop_info| {
                    loop_info.header == *header
                        && loop_info.blocks.binary_search(to).is_err()
                        && *taken == expected_taken
                })
        }
        Transfer::Branch { taken, .. } => {
            locals.region_for_block(to).is_none()
                && !loops.is_back_edge(from, to)
                && loops
                    .innermost_containing(from)
                    .is_none_or(|loop_info| loop_info.blocks.binary_search(&to).is_ok())
                && expected_taken == Some(*taken)
        }
        Transfer::Flow { .. } => {
            locals.region_for_block(to).is_none()
                && !loops.is_back_edge(from, to)
                && loops
                    .innermost_containing(from)
                    .is_none_or(|loop_info| loop_info.blocks.binary_search(&to).is_ok())
                && expected_taken.is_none()
        }
        Transfer::LocalGoto { to, taken, region } => {
            locals.region_for_block(*to) == Some(*region) && *taken == expected_taken
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op, VReg, Value};

    #[test]
    fn verifier_rejects_a_missing_block_and_edge() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1100],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1104,
                    instrs: vec![LlirInstr {
                        va: 0x1100,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
            ],
        };
        let cfg = Cfg::from(&function, &compute_ssa(&function));
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let duplicated_tails = super::super::cleanup::plan_tail_duplication(&cfg, &locals);
        let errors = verify_candidate(
            &cfg,
            &loops,
            &locals,
            &duplicated_tails,
            &RegionCandidate {
                blocks: vec![],
                switches: vec![],
                switch_defaults: vec![],
            },
        );
        assert!(errors.contains(&CandidateError::BlockMissing { block: 0 }));
        assert!(errors.contains(&CandidateError::BlockMissing { block: 1 }));
        assert!(errors.contains(&CandidateError::EdgeMissing { from: 0, to: 1 }));
    }

    #[test]
    fn verifier_rejects_forged_switch_case_values() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::IndirectJump {
                            target: Value::Reg(VReg::phys("target")),
                            index: Some(Value::Reg(VReg::phys("index"))),
                        },
                    }],
                    succs: vec![0x1100, 0x1200, 0x1300],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1104,
                    instrs: vec![LlirInstr {
                        va: 0x1100,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
                LlirBlock {
                    start_va: 0x1200,
                    end_va: 0x1204,
                    instrs: vec![LlirInstr {
                        va: 0x1200,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
                LlirBlock {
                    start_va: 0x1300,
                    end_va: 0x1304,
                    instrs: vec![LlirInstr {
                        va: 0x1300,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
            ],
        };
        let cfg = Cfg::from(&function, &compute_ssa(&function));
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let mut candidate = RegionCandidate::from_cfg(&cfg, &loops, &locals).expect("candidate");
        candidate.switches[0].cases[0].values = vec![99];

        let errors = verify_candidate(&cfg, &loops, &locals, &[], &candidate);
        assert!(errors.contains(&CandidateError::SwitchEvidenceMismatch { dispatch: 0 }));
    }

    #[test]
    fn tree_verifier_rejects_duplicate_ownership_and_forged_branch_identity() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::CondJump {
                            cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                            target: 0x1100,
                            inverted: false,
                        },
                    }],
                    succs: vec![0x1100, 0x1200],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1104,
                    instrs: vec![LlirInstr {
                        va: 0x1100,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
                LlirBlock {
                    start_va: 0x1200,
                    end_va: 0x1204,
                    instrs: vec![LlirInstr {
                        va: 0x1200,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
            ],
        };
        let ssa = compute_ssa(&function);
        let cfg = Cfg::from(&function, &ssa);
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let predicates = cfg.branch_predicates();
        let conditions =
            ConditionDag::from_cfg(&cfg, &loops, &locals, &predicates).expect("condition DAG");
        let candidate = RegionCandidate::from_cfg(&cfg, &loops, &locals).expect("candidate");
        let branch = conditions.branch_condition(0).expect("branch atom");
        let mut forged_leaf = candidate.blocks()[0].clone();
        forged_leaf.transfers.clear();
        let forged = StructuredTree {
            root: StructuredRegion::Sequence(vec![
                StructuredRegion::Block(forged_leaf),
                StructuredRegion::If {
                    source_block: 2,
                    condition: branch,
                    then_region: Box::new(StructuredRegion::Return { block: 1 }),
                    else_region: Some(Box::new(StructuredRegion::Return { block: 1 })),
                },
                StructuredRegion::Break {
                    from: 0,
                    header: 0,
                    to: 1,
                    taken: Some(true),
                },
                StructuredRegion::DuplicatedReturn {
                    source_block: 1,
                    blocks: vec![1],
                    cloned_at_predecessor: 0,
                },
            ]),
            local_regions: Vec::new(),
        };

        let errors = verify_tree(&candidate, &conditions, &loops, &locals, &[], &forged);
        assert!(errors.contains(&TreeError::LeafMismatch { block: 0 }));
        assert!(errors.contains(&TreeError::BranchConditionInvalid { block: 2 }));
        assert!(errors.contains(&TreeError::BlockDuplicated { block: 1 }));
        assert!(errors.contains(&TreeError::BlockMissing { block: 2 }));
        assert!(errors.contains(&TreeError::ControlTransferInvented { from: 0, to: 1 }));
        assert!(errors.contains(&TreeError::DuplicatedTailInvented {
            source_block: 1,
            cloned_at_predecessor: 0,
        }));
    }

    #[test]
    fn tree_verifier_rejects_a_missing_local_region_definition() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::CondJump {
                            cond: crate::ir::types::VReg::Flag(crate::ir::types::Flag::Z),
                            target: 0x1200,
                            inverted: false,
                        },
                    }],
                    succs: vec![0x1200, 0x1100],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1104,
                    instrs: vec![LlirInstr {
                        va: 0x1100,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1200],
                },
                LlirBlock {
                    start_va: 0x1200,
                    end_va: 0x1204,
                    instrs: vec![LlirInstr {
                        va: 0x1200,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1100],
                },
            ],
        };
        let ssa = compute_ssa(&function);
        let cfg = Cfg::from(&function, &ssa);
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let predicates = cfg.branch_predicates();
        let conditions =
            ConditionDag::from_cfg(&cfg, &loops, &locals, &predicates).expect("condition DAG");
        let candidate = RegionCandidate::from_cfg(&cfg, &loops, &locals).expect("candidate");
        let entry = candidate.blocks()[0].clone();
        let mut root = vec![StructuredRegion::Block(entry.clone())];
        root.extend(entry.transfers.iter().map(|transfer| match transfer {
            Transfer::LocalGoto { to, taken, region } => StructuredRegion::LocalGoto {
                from: entry.block,
                to: *to,
                taken: *taken,
                region: *region,
            },
            other => panic!("entry transfer should enter the local region: {other:?}"),
        }));
        let tree = StructuredTree {
            root: StructuredRegion::Sequence(root),
            local_regions: Vec::new(),
        };

        let errors = verify_tree(&candidate, &conditions, &loops, &locals, &[], &tree);
        assert!(errors.contains(&TreeError::LocalRegionInvalid { region: 0 }));
        assert!(errors.contains(&TreeError::BlockMissing { block: 1 }));
        assert!(errors.contains(&TreeError::BlockMissing { block: 2 }));
    }

    #[test]
    fn verifier_rejects_forged_non_linear_tail_provenance() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                LlirBlock {
                    start_va: 0x1000,
                    end_va: 0x1004,
                    instrs: vec![LlirInstr {
                        va: 0x1000,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1100, 0x1200],
                },
                LlirBlock {
                    start_va: 0x1100,
                    end_va: 0x1104,
                    instrs: vec![LlirInstr {
                        va: 0x1100,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1300],
                },
                LlirBlock {
                    start_va: 0x1200,
                    end_va: 0x1204,
                    instrs: vec![LlirInstr {
                        va: 0x1200,
                        op: Op::Nop,
                    }],
                    succs: vec![0x1300],
                },
                LlirBlock {
                    start_va: 0x1300,
                    end_va: 0x1304,
                    instrs: vec![LlirInstr {
                        va: 0x1300,
                        op: Op::Return,
                    }],
                    succs: vec![],
                },
            ],
        };
        let cfg = Cfg::from(&function, &compute_ssa(&function));
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let candidate = RegionCandidate::from_cfg(&cfg, &loops, &locals).expect("candidate");
        let forged = [DuplicatedTail {
            source_block: 3,
            blocks: vec![3, 1],
            canonical_predecessor: 1,
            cloned_at_predecessor: 2,
            instruction_count: 2,
        }];

        let errors = verify_candidate(&cfg, &loops, &locals, &forged, &candidate);

        assert!(errors.contains(&CandidateError::DuplicatedTailInvalid {
            source_block: 3,
            cloned_at_predecessor: 2,
        }));
    }
}
