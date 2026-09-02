//! Independent fidelity checks for a shadow region candidate.

use std::collections::BTreeMap;

use super::{
    DuplicatedTail, LocalRegions, LoopForest, RegionCandidate, Terminal, Transfer,
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
    verify_duplicated_tails(cfg, duplicated_tails, &mut errors);
    errors
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
        let valid = tail.source_block < cfg.succs.len()
            && tail.canonical_predecessor < cfg.succs.len()
            && tail.cloned_at_predecessor < cfg.succs.len()
            && cfg.succs[tail.source_block].is_empty()
            && cfg.ends_in_return[tail.source_block]
            && cfg.block_instruction_counts[tail.source_block] == tail.instruction_count
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
    use crate::ir::types::{LlirBlock, LlirFunction, LlirInstr, Op};

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
        let duplicated_tails = super::super::cleanup::plan_tail_duplication(&cfg);
        let errors = verify_candidate(
            &cfg,
            &loops,
            &locals,
            &duplicated_tails,
            &RegionCandidate { blocks: vec![] },
        );
        assert!(errors.contains(&CandidateError::BlockMissing { block: 0 }));
        assert!(errors.contains(&CandidateError::BlockMissing { block: 1 }));
        assert!(errors.contains(&CandidateError::EdgeMissing { from: 0, to: 1 }));
    }

    #[test]
    fn verifier_rejects_forged_nonterminal_tail_provenance() {
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
            source_block: 1,
            canonical_predecessor: 0,
            cloned_at_predecessor: 2,
            instruction_count: 1,
        }];

        let errors = verify_candidate(&cfg, &loops, &locals, &forged, &candidate);

        assert!(errors.contains(&CandidateError::DuplicatedTailInvalid {
            source_block: 1,
            cloned_at_predecessor: 2,
        }));
    }
}
