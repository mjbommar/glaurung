//! Dominance-derived natural-loop forest for the shadow structurer.

use std::collections::BTreeSet;

use crate::ir::structure::Cfg;

/// Whether a natural loop tests before or after its first body execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    PreTested,
    PostTested,
    Endless,
}

/// One natural loop and every edge that leaves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopInfo {
    pub header: usize,
    pub latches: Vec<usize>,
    pub blocks: Vec<usize>,
    pub exits: Vec<(usize, usize)>,
    pub parent: Option<usize>,
    pub kind: LoopKind,
}

/// Deterministically ordered natural loops, outermost before nested loops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoopForest {
    loops: Vec<LoopInfo>,
    back_edges: BTreeSet<(usize, usize)>,
}

impl LoopForest {
    pub(super) fn from_cfg(cfg: &Cfg) -> Self {
        let mut loops = Vec::new();
        let mut back_edges = BTreeSet::new();
        for header in 0..cfg.succs.len() {
            let mut latches = cfg.dominating_tails(header);
            if latches.is_empty() {
                continue;
            }
            latches.sort_unstable();
            for &latch in &latches {
                back_edges.insert((latch, header));
            }

            let body_set = cfg.natural_loop_body_of(header);
            let mut blocks: Vec<usize> = body_set.iter().copied().collect();
            blocks.sort_unstable();
            let mut exits = Vec::new();
            for &block in &blocks {
                for &successor in &cfg.succs[block] {
                    if !body_set.contains(&successor) {
                        exits.push((block, successor));
                    }
                }
            }
            exits.sort_unstable();
            exits.dedup();

            let post_tested = latches.iter().copied().any(|latch| {
                cfg.succs[latch].contains(&header)
                    && cfg.succs[latch]
                        .iter()
                        .any(|successor| !body_set.contains(successor))
            });
            let pre_tested = cfg.succs[header]
                .iter()
                .any(|successor| !body_set.contains(successor));
            // A conditional latch proves that repetition is post-tested even
            // when short-circuit lowering also gives the header an exit. The
            // real gcc-O0 `dowhile_atleastonce` shape has both; letting the
            // header exit win misclassifies the source loop as pre-tested.
            let kind = if post_tested {
                LoopKind::PostTested
            } else if pre_tested {
                LoopKind::PreTested
            } else {
                LoopKind::Endless
            };
            loops.push(LoopInfo {
                header,
                latches,
                blocks,
                exits,
                parent: None,
                kind,
            });
        }

        loops
            .sort_by_key(|loop_info| (std::cmp::Reverse(loop_info.blocks.len()), loop_info.header));
        for child in 0..loops.len() {
            let child_blocks: BTreeSet<_> = loops[child].blocks.iter().copied().collect();
            loops[child].parent = (0..loops.len())
                .filter(|&candidate| candidate != child)
                .filter(|&candidate| loops[candidate].blocks.len() > child_blocks.len())
                .filter(|&candidate| {
                    child_blocks
                        .iter()
                        .all(|block| loops[candidate].blocks.binary_search(block).is_ok())
                })
                .min_by_key(|&candidate| loops[candidate].blocks.len());
        }

        Self { loops, back_edges }
    }

    pub fn loops(&self) -> &[LoopInfo] {
        &self.loops
    }

    pub fn len(&self) -> usize {
        self.loops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.loops.is_empty()
    }

    pub(super) fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.back_edges.contains(&(from, to))
    }

    pub(super) fn innermost_containing(&self, block: usize) -> Option<&LoopInfo> {
        self.loops
            .iter()
            .filter(|loop_info| loop_info.blocks.binary_search(&block).is_ok())
            .min_by_key(|loop_info| loop_info.blocks.len())
    }
}
