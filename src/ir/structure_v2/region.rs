//! Typed, non-rendering region candidate for shadow comparison.

use super::LoopForest;
use crate::ir::structure::Cfg;

/// One explicit representation of a CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transfer {
    Flow {
        to: usize,
    },
    Branch {
        to: usize,
        taken: bool,
    },
    Continue {
        header: usize,
        taken: Option<bool>,
    },
    Break {
        header: usize,
        to: usize,
        taken: Option<bool>,
    },
}

/// Why a block has no successor edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    Return,
    Unknown,
}

/// One block, owned once, with every outgoing transfer attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRegion {
    pub block: usize,
    pub transfers: Vec<Transfer>,
    pub terminal: Option<Terminal>,
}

/// Initial region algebra: exact block ownership and typed local transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionCandidate {
    pub(super) blocks: Vec<BlockRegion>,
}

impl RegionCandidate {
    pub(super) fn from_cfg(cfg: &Cfg, loops: &LoopForest) -> Option<Self> {
        let blocks = (0..cfg.succs.len())
            .map(|block| {
                let conditional = cfg.cond_taken[block].filter(|_| cfg.succs[block].len() == 2);
                let transfers = cfg.succs[block]
                    .iter()
                    .copied()
                    .map(|to| {
                        let taken = conditional.map(|target| to == target);
                        if loops.is_back_edge(block, to) {
                            return Transfer::Continue { header: to, taken };
                        }
                        if let Some(loop_info) = loops.innermost_containing(block) {
                            if loop_info.blocks.binary_search(&to).is_err() {
                                return Transfer::Break {
                                    header: loop_info.header,
                                    to,
                                    taken,
                                };
                            }
                        }
                        match taken {
                            Some(taken) => Transfer::Branch { to, taken },
                            None => Transfer::Flow { to },
                        }
                    })
                    .collect();
                let terminal = cfg.succs[block].is_empty().then(|| {
                    if cfg.ends_in_return[block] {
                        Terminal::Return
                    } else {
                        Terminal::Unknown
                    }
                });
                BlockRegion {
                    block,
                    transfers,
                    terminal,
                }
            })
            .collect();
        Some(Self { blocks })
    }

    pub fn blocks(&self) -> &[BlockRegion] {
        &self.blocks
    }

    pub fn transfers(&self) -> impl Iterator<Item = &Transfer> {
        self.blocks.iter().flat_map(|block| &block.transfers)
    }

    pub fn transfer_count(&self) -> usize {
        self.transfers().count()
    }
}
