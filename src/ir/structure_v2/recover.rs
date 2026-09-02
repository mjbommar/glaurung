//! Deterministic structured-tree recovery for shadow candidates.

use super::{
    BlockRegion, ConditionDag, ConditionId, LoopForest, LoopInfo, LoopKind, RegionCandidate,
    Terminal, Transfer,
};
use crate::ir::structure::Cfg;

/// A structured, non-rendering view of one verified CFG region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuredRegion {
    Empty,
    Block(BlockRegion),
    Return {
        block: usize,
    },
    Sequence(Vec<StructuredRegion>),
    If {
        source_block: usize,
        condition: ConditionId,
        then_region: Box<StructuredRegion>,
        else_region: Option<Box<StructuredRegion>>,
    },
    Loop {
        header: usize,
        kind: LoopKind,
        body: Box<StructuredRegion>,
        exits: Vec<LoopExitRegion>,
    },
    Break {
        from: usize,
        header: usize,
        to: usize,
        taken: Option<bool>,
    },
    Continue {
        from: usize,
        header: usize,
        taken: Option<bool>,
    },
}

/// A path selected by one typed `break` target before exits reconverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopExitRegion {
    pub target: usize,
    pub region: Box<StructuredRegion>,
}

/// One verified structured tree rooted at the function entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredTree {
    pub root: StructuredRegion,
}

pub(super) fn recover_tree(
    cfg: &Cfg,
    conditions: &ConditionDag,
    candidate: &RegionCandidate,
    loops: &LoopForest,
) -> Option<StructuredTree> {
    if cfg.succs.is_empty() {
        return Some(StructuredTree {
            root: StructuredRegion::Empty,
        });
    }
    let mut builder = TreeBuilder {
        cfg,
        conditions,
        candidate,
        loops,
        active_loops: Vec::new(),
        owned: vec![false; cfg.succs.len()],
        active: vec![false; cfg.succs.len()],
    };
    let root = builder.build(0, None)?;
    builder
        .owned
        .iter()
        .all(|owned| *owned)
        .then_some(StructuredTree { root })
}

struct TreeBuilder<'a> {
    cfg: &'a Cfg,
    conditions: &'a ConditionDag,
    candidate: &'a RegionCandidate,
    loops: &'a LoopForest,
    active_loops: Vec<usize>,
    owned: Vec<bool>,
    active: Vec<bool>,
}

impl TreeBuilder<'_> {
    fn build(&mut self, block: usize, stop: Option<usize>) -> Option<StructuredRegion> {
        if Some(block) == stop {
            return Some(StructuredRegion::Empty);
        }
        if block >= self.cfg.succs.len() || self.owned[block] || self.active[block] {
            return None;
        }
        if !self.active_loops.contains(&block) {
            if let Some(loop_info) = self.loops.by_header(block).cloned() {
                return self.build_loop(&loop_info, stop);
            }
        }
        self.active[block] = true;
        self.owned[block] = true;

        let leaf = self.leaf(block)?;
        if let Some(loop_header) = self.active_loops.last().copied() {
            let has_loop_control = self
                .candidate_block(block)?
                .transfers
                .iter()
                .any(|transfer| {
                    matches!(
                        transfer,
                        Transfer::Break { header, .. } | Transfer::Continue { header, .. }
                            if *header == loop_header
                    )
                });
            if has_loop_control {
                let result = self.build_loop_block(block, loop_header, leaf);
                self.active[block] = false;
                return result;
            }
        }
        let result = match self.cfg.succs[block].as_slice() {
            [] => Some(leaf),
            [successor] => {
                let continuation = self.build(*successor, stop)?;
                Some(sequence([leaf, continuation]))
            }
            [first, second] => self.build_conditional(block, *first, *second, stop, leaf),
            _ => None,
        };
        self.active[block] = false;
        result
    }

    fn build_loop(
        &mut self,
        loop_info: &LoopInfo,
        stop: Option<usize>,
    ) -> Option<StructuredRegion> {
        self.active_loops.push(loop_info.header);
        let body = self.build(loop_info.header, None);
        self.active_loops.pop();
        let body = body?;

        let mut exits: Vec<usize> = loop_info.exits.iter().map(|(_, to)| *to).collect();
        exits.sort_unstable();
        exits.dedup();
        let (exit_regions, continuation) = match exits.as_slice() {
            [] => (Vec::new(), None),
            [continuation] => (Vec::new(), Some(*continuation)),
            _ => {
                let join = self.cfg.immediate_postdominator(loop_info.header)?;
                let mut regions = Vec::with_capacity(exits.len());
                for target in exits {
                    if target != join {
                        regions.push(LoopExitRegion {
                            target,
                            region: Box::new(self.build(target, Some(join))?),
                        });
                    }
                }
                (regions, Some(join))
            }
        };
        let loop_region = StructuredRegion::Loop {
            header: loop_info.header,
            kind: loop_info.kind,
            body: Box::new(body),
            exits: exit_regions,
        };
        if let Some(continuation) = continuation {
            Some(sequence([loop_region, self.build(continuation, stop)?]))
        } else {
            Some(loop_region)
        }
    }

    fn build_loop_block(
        &mut self,
        block: usize,
        loop_header: usize,
        leaf: StructuredRegion,
    ) -> Option<StructuredRegion> {
        let transfers = self.candidate_block(block)?.transfers.clone();
        match transfers.as_slice() {
            [transfer] => Some(sequence([
                leaf,
                self.build_loop_transfer(block, loop_header, transfer)?,
            ])),
            [first, second] => {
                let (taken, other) = match (transfer_taken(first), transfer_taken(second)) {
                    (Some(true), Some(false)) => (first, second),
                    (Some(false), Some(true)) => (second, first),
                    _ => return None,
                };
                Some(sequence([
                    leaf,
                    StructuredRegion::If {
                        source_block: block,
                        condition: self.conditions.branch_condition(block)?,
                        then_region: Box::new(self.build_loop_transfer(
                            block,
                            loop_header,
                            taken,
                        )?),
                        else_region: Some(Box::new(self.build_loop_transfer(
                            block,
                            loop_header,
                            other,
                        )?)),
                    },
                ]))
            }
            _ => None,
        }
    }

    fn build_loop_transfer(
        &mut self,
        from: usize,
        loop_header: usize,
        transfer: &Transfer,
    ) -> Option<StructuredRegion> {
        match transfer {
            Transfer::Break { header, to, taken } if *header == loop_header => {
                Some(StructuredRegion::Break {
                    from,
                    header: *header,
                    to: *to,
                    taken: *taken,
                })
            }
            Transfer::Continue { header, taken } if *header == loop_header => {
                Some(StructuredRegion::Continue {
                    from,
                    header: *header,
                    taken: *taken,
                })
            }
            Transfer::Flow { to }
            | Transfer::Branch { to, .. }
            | Transfer::LocalGoto { to, .. } => self.build(*to, None),
            Transfer::Break { .. } | Transfer::Continue { .. } => None,
        }
    }

    fn build_conditional(
        &mut self,
        block: usize,
        first: usize,
        second: usize,
        stop: Option<usize>,
        leaf: StructuredRegion,
    ) -> Option<StructuredRegion> {
        let taken = self.cfg.cond_taken[block]?;
        let other = if first == taken {
            second
        } else if second == taken {
            first
        } else {
            return None;
        };
        let condition = self.conditions.branch_condition(block)?;
        let join = self
            .cfg
            .immediate_postdominator(block)
            .filter(|join| Some(*join) != stop);
        let snapshot = self.owned.clone();
        let then_region = self.build(taken, join);
        let else_region = self.build(other, join);
        let (Some(then_region), Some(else_region)) = (then_region, else_region) else {
            self.owned = snapshot;
            return None;
        };
        let conditional = StructuredRegion::If {
            source_block: block,
            condition,
            then_region: Box::new(then_region),
            else_region: (!matches!(else_region, StructuredRegion::Empty))
                .then_some(Box::new(else_region)),
        };
        let mut parts = vec![leaf, conditional];
        if let Some(join) = join {
            parts.push(self.build(join, stop)?);
        }
        Some(sequence(parts))
    }

    fn leaf(&self, block: usize) -> Option<StructuredRegion> {
        let region = self.candidate_block(block)?;
        if region.terminal == Some(Terminal::Return) {
            Some(StructuredRegion::Return { block })
        } else {
            Some(StructuredRegion::Block(region.clone()))
        }
    }

    fn candidate_block(&self, block: usize) -> Option<&BlockRegion> {
        self.candidate
            .blocks()
            .iter()
            .find(|region| region.block == block)
    }
}

fn transfer_taken(transfer: &Transfer) -> Option<bool> {
    match transfer {
        Transfer::Branch { taken, .. } => Some(*taken),
        Transfer::Break { taken, .. }
        | Transfer::Continue { taken, .. }
        | Transfer::LocalGoto { taken, .. } => *taken,
        Transfer::Flow { .. } => None,
    }
}

fn sequence(regions: impl IntoIterator<Item = StructuredRegion>) -> StructuredRegion {
    let mut flattened = Vec::new();
    for region in regions {
        match region {
            StructuredRegion::Empty => {}
            StructuredRegion::Sequence(nested) => flattened.extend(nested),
            region => flattened.push(region),
        }
    }
    match flattened.len() {
        0 => StructuredRegion::Empty,
        1 => flattened.pop().expect("one region"),
        _ => StructuredRegion::Sequence(flattened),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ssa::compute_ssa;
    use crate::ir::structure_v2::{LocalRegions, LoopForest, RegionCandidate};
    use crate::ir::types::{Flag, LlirBlock, LlirFunction, LlirInstr, Op, VReg};

    fn block(start_va: u64, op: Op, successors: Vec<u64>) -> LlirBlock {
        LlirBlock {
            start_va,
            end_va: start_va + 4,
            instrs: vec![LlirInstr { va: start_va, op }],
            succs: successors,
        }
    }

    #[test]
    fn diamond_recovers_one_if_and_one_shared_join() {
        let function = LlirFunction {
            entry_va: 0x1000,
            blocks: vec![
                block(
                    0x1000,
                    Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x1100,
                        inverted: false,
                    },
                    vec![0x1100, 0x1200],
                ),
                block(0x1100, Op::Nop, vec![0x1300]),
                block(0x1200, Op::Nop, vec![0x1300]),
                block(0x1300, Op::Return, vec![]),
            ],
        };
        let ssa = compute_ssa(&function);
        let cfg = Cfg::from(&function, &ssa);
        let loops = LoopForest::from_cfg(&cfg);
        let locals = LocalRegions::from_cfg(&cfg, &loops);
        let predicates = cfg.branch_predicates(&function, &ssa);
        let conditions = ConditionDag::from_cfg(&cfg, &loops, &locals, &predicates)
            .expect("diamond condition DAG");
        let candidate = RegionCandidate::from_cfg(&cfg, &loops, &locals).expect("candidate");

        let tree = recover_tree(&cfg, &conditions, &candidate, &loops).expect("structured diamond");
        assert_eq!(
            tree,
            recover_tree(&cfg, &conditions, &candidate, &loops)
                .expect("deterministic second recovery")
        );
        let StructuredRegion::Sequence(parts) = tree.root else {
            panic!("diamond root must be a sequence");
        };
        assert!(matches!(parts[0], StructuredRegion::Block(ref region) if region.block == 0));
        assert!(matches!(
            parts[1],
            StructuredRegion::If {
                source_block: 0,
                condition,
                ref then_region,
                else_region: Some(ref else_region),
            } if condition == conditions.branch_condition(0).expect("branch atom")
                && matches!(**then_region, StructuredRegion::Block(ref region) if region.block == 1)
                && matches!(**else_region, StructuredRegion::Block(ref region) if region.block == 2)
        ));
        assert_eq!(parts[2], StructuredRegion::Return { block: 3 });
    }
}
