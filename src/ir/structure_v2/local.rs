//! Reproducible evidence for irreducible local-labelled regions.

use super::LoopForest;
use crate::ir::structure::Cfg;

/// Why a local goto is honest rather than a structuring failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HonestGotoEvidence {
    pub region: usize,
    pub blocks: Vec<usize>,
    pub entry_targets: Vec<usize>,
    pub property: &'static str,
}

/// Residual strongly connected regions after natural back edges are removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalRegions {
    evidence: Vec<HonestGotoEvidence>,
    block_regions: Vec<Option<usize>>,
    unclassified_cycles: bool,
}

impl LocalRegions {
    pub(super) fn from_cfg(cfg: &Cfg, loops: &LoopForest) -> Self {
        let mut components = strongly_connected_components(cfg, loops);
        components.retain(|blocks| {
            blocks.len() > 1
                || cfg.succs[blocks[0]]
                    .iter()
                    .any(|&to| to == blocks[0] && !loops.is_back_edge(blocks[0], to))
        });
        components.sort_by_key(|blocks| blocks[0]);

        let mut evidence = Vec::new();
        let mut block_regions = vec![None; cfg.succs.len()];
        let mut unclassified_cycles = false;
        for blocks in components {
            let block_set: std::collections::BTreeSet<_> = blocks.iter().copied().collect();
            let mut entry_targets = Vec::new();
            if block_set.contains(&0) {
                entry_targets.push(0);
            }
            for (from, successors) in cfg.succs.iter().enumerate() {
                if block_set.contains(&from) {
                    continue;
                }
                for &to in successors {
                    if block_set.contains(&to) {
                        entry_targets.push(to);
                    }
                }
            }
            entry_targets.sort_unstable();
            entry_targets.dedup();
            let has_dominating_header = blocks.iter().copied().any(|header| {
                blocks
                    .iter()
                    .copied()
                    .all(|block| cfg.dominates(header, block))
            });
            if entry_targets.len() < 2 || has_dominating_header {
                unclassified_cycles = true;
                continue;
            }

            let region = evidence.len();
            for &block in &blocks {
                block_regions[block] = Some(region);
            }
            evidence.push(HonestGotoEvidence {
                region,
                blocks,
                entry_targets,
                property: "irreducible_scc_multiple_entries_no_dominating_header",
            });
        }
        Self {
            evidence,
            block_regions,
            unclassified_cycles,
        }
    }

    pub fn evidence(&self) -> &[HonestGotoEvidence] {
        &self.evidence
    }

    pub(super) fn region_for_block(&self, block: usize) -> Option<usize> {
        self.block_regions.get(block).copied().flatten()
    }

    pub(super) fn is_internal_edge(&self, from: usize, to: usize) -> bool {
        self.region_for_block(from)
            .is_some_and(|region| self.region_for_block(to) == Some(region))
    }

    pub(super) fn has_unclassified_cycles(&self) -> bool {
        self.unclassified_cycles
    }
}

fn strongly_connected_components(cfg: &Cfg, loops: &LoopForest) -> Vec<Vec<usize>> {
    struct Tarjan<'a> {
        cfg: &'a Cfg,
        loops: &'a LoopForest,
        next_index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        components: Vec<Vec<usize>>,
    }

    impl Tarjan<'_> {
        fn visit(&mut self, block: usize) {
            let index = self.next_index;
            self.next_index += 1;
            self.indices[block] = Some(index);
            self.lowlink[block] = index;
            self.stack.push(block);
            self.on_stack[block] = true;

            for &successor in &self.cfg.succs[block] {
                if self.loops.is_back_edge(block, successor) {
                    continue;
                }
                if self.indices[successor].is_none() {
                    self.visit(successor);
                    self.lowlink[block] = self.lowlink[block].min(self.lowlink[successor]);
                } else if self.on_stack[successor] {
                    self.lowlink[block] = self.lowlink[block]
                        .min(self.indices[successor].expect("on-stack block has an index"));
                }
            }

            if self.lowlink[block] == index {
                let mut component = Vec::new();
                loop {
                    let member = self.stack.pop().expect("Tarjan root owns a stack member");
                    self.on_stack[member] = false;
                    component.push(member);
                    if member == block {
                        break;
                    }
                }
                component.sort_unstable();
                self.components.push(component);
            }
        }
    }

    let count = cfg.succs.len();
    let mut tarjan = Tarjan {
        cfg,
        loops,
        next_index: 0,
        indices: vec![None; count],
        lowlink: vec![0; count],
        stack: Vec::new(),
        on_stack: vec![false; count],
        components: Vec::new(),
    };
    for block in 0..count {
        if tarjan.indices[block].is_none() {
            tarjan.visit(block);
        }
    }
    tarjan.components
}
