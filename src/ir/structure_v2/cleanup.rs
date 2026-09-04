//! Bounded cleanup plans applied only after exact region recovery.

use super::LocalRegions;
use crate::ir::structure::Cfg;

/// Ceiling for cloning one straight-line tail ending in return.
pub const MAX_TAIL_DUPLICATION_INSTRUCTIONS: usize = 8;

/// A cleanup tail stays local rather than becoming a second structurer.
pub const MAX_TAIL_DUPLICATION_BLOCKS: usize = 4;

/// Maximum total cloned instructions planned for one function.
pub const MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS: usize = 64;

/// Provenance for one planned clone of an input straight-line return tail.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicatedTail {
    pub source_block: usize,
    pub blocks: Vec<usize>,
    pub canonical_predecessor: usize,
    pub cloned_at_predecessor: usize,
    pub instruction_count: usize,
}

fn linear_return_tail(cfg: &Cfg, source_block: usize) -> Option<(Vec<usize>, usize)> {
    let mut blocks = Vec::new();
    let mut instruction_count = 0usize;
    let mut block = source_block;
    loop {
        if blocks.contains(&block) || blocks.len() == MAX_TAIL_DUPLICATION_BLOCKS {
            return None;
        }
        blocks.push(block);
        instruction_count = instruction_count.saturating_add(cfg.block_instruction_counts[block]);
        if instruction_count > MAX_TAIL_DUPLICATION_INSTRUCTIONS {
            return None;
        }
        match cfg.succs[block].as_slice() {
            [] if cfg.ends_in_return[block] => return Some((blocks, instruction_count)),
            [successor] => block = *successor,
            _ => return None,
        }
    }
}

/// Plan deterministic clones for small shared straight-line tails ending in
/// return. Every cloned block and the complete instruction budget are recorded
/// so verification can reject a forged branch, cycle, or oversized chain.
pub(super) fn plan_tail_duplication(cfg: &Cfg, locals: &LocalRegions) -> Vec<DuplicatedTail> {
    let mut duplicated = Vec::new();
    let mut planned_instructions = 0usize;
    for source_block in 0..cfg.succs.len() {
        let predecessors = &cfg.preds[source_block];
        if predecessors.len() < 2 {
            continue;
        }
        let Some((blocks, instruction_count)) = linear_return_tail(cfg, source_block) else {
            continue;
        };
        let canonical_predecessor = predecessors[0];
        for cloned_at_predecessor in predecessors[1..].iter().copied() {
            // Local labelled regions retain their input blocks and exits as a
            // separate definition. Their transfers are not tree-builder clone
            // sites, so never promise a materialization there.
            if locals
                .evidence()
                .iter()
                .any(|region| region.blocks.contains(&cloned_at_predecessor))
            {
                continue;
            }
            if planned_instructions.saturating_add(instruction_count)
                > MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS
            {
                break;
            }
            duplicated.push(DuplicatedTail {
                source_block,
                blocks: blocks.clone(),
                canonical_predecessor,
                cloned_at_predecessor,
                instruction_count,
            });
            planned_instructions += instruction_count;
        }
    }
    duplicated
}
