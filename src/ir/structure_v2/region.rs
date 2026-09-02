//! Typed, non-rendering region candidate for shadow comparison.

use super::{LocalRegions, LoopForest};
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
    LocalGoto {
        to: usize,
        taken: Option<bool>,
        region: usize,
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

/// One destination of a CFG-proven indirect dispatch and the raw table slots
/// that select it. Multiple values may share one target after case folding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCaseEvidence {
    pub target: usize,
    pub values: Vec<i64>,
}

/// Typed case ownership for one resolved indirect dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchEvidence {
    pub dispatch: usize,
    pub cases: Vec<SwitchCaseEvidence>,
}

/// A range-guard edge bypassing a resolved dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchDefaultEvidence {
    pub guard: usize,
    pub target: usize,
    pub dispatch: Option<usize>,
    pub taken: bool,
}

/// Initial region algebra: exact block ownership and typed local transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionCandidate {
    pub(super) blocks: Vec<BlockRegion>,
    pub(super) switches: Vec<SwitchEvidence>,
    pub(super) switch_defaults: Vec<SwitchDefaultEvidence>,
}

impl RegionCandidate {
    pub(super) fn from_cfg(cfg: &Cfg, loops: &LoopForest, locals: &LocalRegions) -> Option<Self> {
        let blocks = (0..cfg.succs.len())
            .map(|block| {
                let conditional = cfg.cond_taken[block].filter(|_| cfg.succs[block].len() == 2);
                let transfers = cfg.succs[block]
                    .iter()
                    .copied()
                    .map(|to| {
                        let taken = conditional.map(|target| to == target);
                        if let Some(region) = locals.region_for_block(to) {
                            return Transfer::LocalGoto { to, taken, region };
                        }
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
        let switches = cfg
            .edges
            .iter()
            .enumerate()
            .filter_map(|(dispatch, edges)| {
                let cases = edges
                    .iter()
                    .enumerate()
                    .filter(|(_, edge)| edge.kind == crate::ir::cfg_edges::EdgeKind::SwitchCase)
                    .map(|(position, edge)| SwitchCaseEvidence {
                        target: edge.to,
                        values: cfg.case_labels[dispatch][position].clone(),
                    })
                    .collect::<Vec<_>>();
                (!cases.is_empty()).then_some(SwitchEvidence { dispatch, cases })
            })
            .collect();
        let switch_defaults = cfg
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
                        SwitchDefaultEvidence {
                            guard,
                            target: edge.to,
                            dispatch,
                            taken: cfg.cond_taken[guard] == Some(edge.to),
                        }
                    })
                })
            })
            .collect();
        Some(Self {
            blocks,
            switches,
            switch_defaults,
        })
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

    pub fn switches(&self) -> &[SwitchEvidence] {
        &self.switches
    }

    pub fn switch_defaults(&self) -> &[SwitchDefaultEvidence] {
        &self.switch_defaults
    }
}
