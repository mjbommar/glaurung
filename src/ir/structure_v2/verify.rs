//! Independent fidelity checks for a shadow region candidate.

use std::collections::BTreeMap;

use super::{LoopForest, RegionCandidate, Terminal, Transfer};
use crate::ir::structure::Cfg;

/// A concrete disagreement between a candidate and its source CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateError {
    BlockMissing { block: usize },
    BlockDuplicated { block: usize },
    BlockOutOfRange { block: usize },
    EdgeMissing { from: usize, to: usize },
    EdgeInvented { from: usize, to: usize },
    TransferKindInvalid { from: usize, to: usize },
    TerminalMismatch { block: usize },
}

pub(super) fn verify_candidate(
    cfg: &Cfg,
    loops: &LoopForest,
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
            if !transfer_kind_is_valid(cfg, loops, block, transfer) {
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
    errors
}

fn transfer_target(transfer: &Transfer) -> usize {
    match transfer {
        Transfer::Flow { to } | Transfer::Branch { to, .. } | Transfer::Break { to, .. } => *to,
        Transfer::Continue { header, .. } => *header,
    }
}

fn transfer_kind_is_valid(cfg: &Cfg, loops: &LoopForest, from: usize, transfer: &Transfer) -> bool {
    let to = transfer_target(transfer);
    let conditional = cfg.cond_taken[from].filter(|_| cfg.succs[from].len() == 2);
    let expected_taken = conditional.map(|target| target == to);
    match transfer {
        Transfer::Continue { header, taken } => {
            loops.is_back_edge(from, *header) && *taken == expected_taken
        }
        Transfer::Break { header, to, taken } => {
            loops.innermost_containing(from).is_some_and(|loop_info| {
                loop_info.header == *header
                    && loop_info.blocks.binary_search(to).is_err()
                    && *taken == expected_taken
            })
        }
        Transfer::Branch { taken, .. } => {
            !loops.is_back_edge(from, to)
                && loops
                    .innermost_containing(from)
                    .is_none_or(|loop_info| loop_info.blocks.binary_search(&to).is_ok())
                && expected_taken == Some(*taken)
        }
        Transfer::Flow { .. } => {
            !loops.is_back_edge(from, to)
                && loops
                    .innermost_containing(from)
                    .is_none_or(|loop_info| loop_info.blocks.binary_search(&to).is_ok())
                && expected_taken.is_none()
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
        let errors = verify_candidate(
            &cfg,
            &LoopForest::from_cfg(&cfg),
            &RegionCandidate { blocks: vec![] },
        );
        assert!(errors.contains(&CandidateError::BlockMissing { block: 0 }));
        assert!(errors.contains(&CandidateError::BlockMissing { block: 1 }));
        assert!(errors.contains(&CandidateError::EdgeMissing { from: 0, to: 1 }));
    }
}
