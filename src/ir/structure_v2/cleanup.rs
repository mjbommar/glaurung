//! Bounded cleanup plans applied only after exact region recovery.

use crate::ir::structure::Cfg;

/// Initial ceiling for cloning one terminal return block.
pub const MAX_TAIL_DUPLICATION_INSTRUCTIONS: usize = 8;

/// Maximum total cloned instructions planned for one function.
pub const MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS: usize = 64;

/// Provenance for one planned clone of an input return block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicatedTail {
    pub source_block: usize,
    pub canonical_predecessor: usize,
    pub cloned_at_predecessor: usize,
    pub instruction_count: usize,
}

/// Plan deterministic clones for small, shared, terminal return blocks.
pub(super) fn plan_tail_duplication(cfg: &Cfg) -> Vec<DuplicatedTail> {
    let mut duplicated = Vec::new();
    let mut planned_instructions = 0usize;
    for source_block in 0..cfg.succs.len() {
        let predecessors = &cfg.preds[source_block];
        let instruction_count = cfg.block_instruction_counts[source_block];
        if !cfg.succs[source_block].is_empty()
            || !cfg.ends_in_return[source_block]
            || predecessors.len() < 2
            || instruction_count > MAX_TAIL_DUPLICATION_INSTRUCTIONS
        {
            continue;
        }
        let canonical_predecessor = predecessors[0];
        for cloned_at_predecessor in predecessors[1..].iter().copied() {
            if planned_instructions.saturating_add(instruction_count)
                > MAX_TOTAL_TAIL_DUPLICATION_INSTRUCTIONS
            {
                break;
            }
            duplicated.push(DuplicatedTail {
                source_block,
                canonical_predecessor,
                cloned_at_predecessor,
                instruction_count,
            });
            planned_instructions += instruction_count;
        }
    }
    duplicated
}
