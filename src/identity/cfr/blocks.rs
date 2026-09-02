//! CFR-C: the block-order-independent control-flow labelling.
//!
//! Nobody in the survey stores block order -- not BinExport, not BSim, not
//! WARP, not Diaphora -- because it is the compiler's choice, not the
//! program's. What is kept is the shape: each block is seeded with
//! `(in_degree << 8) | out_degree`, which is a function of the CFG's *relations*
//! and of nothing else, and one Weisfeiler-Lehman round mixes in the
//! predecessors' seeds.
//!
//! Two refinements make the labelling say more than degree counting:
//!
//! * **Edges carry which path they are.** A predecessor mixes in with a
//!   different constant depending on whether this block is its taken or its
//!   fallthrough successor, so a feature records how control arrived. The
//!   constants are BSim's (`0x777`, and `0x777 ^ 0x7abc7abc`), kept verbatim so
//!   a future comparison against Ghidra's own vectors has one fewer difference
//!   to explain.
//! * **Semantics land in the same feature as topology.** At each *root*
//!   operation -- call, indirect jump, store, conditional jump, return -- the
//!   block's label is fused with the CFR-G label of the value that operation
//!   produced. Without the fusion a block of six stores and a block of six
//!   calls with the same degrees are the same feature.

use std::collections::BTreeMap;

use super::dominators::Dominators;
use super::graph::{block_adjacency, CfrGraph};
use super::wl::{compress, DATAFLOW_ITERATIONS};
use crate::ir::types::{LlirBlock, LlirFunction, Op};
use crate::ir::use_def::InstrAddr;

/// Mixing constant for an edge taken when the branch condition holds.
pub const TRUE_EDGE_CONSTANT: u64 = 0x777;

/// Mixing constant for an edge taken when the branch condition does not hold.
pub const FALSE_EDGE_CONSTANT: u64 = 0x777 ^ 0x7abc_7abc;

/// Mixing constant for an edge with no condition attached.
pub const UNCONDITIONAL_EDGE_CONSTANT: u64 = 0x0f1e_2d3c;

/// Mixing constant for one arm of a computed multi-way transfer.
pub const SWITCH_EDGE_CONSTANT: u64 = 0x5a5a_c3c3;

/// Extra mixing applied to an edge whose target dominates its source.
pub const BACK_EDGE_CONSTANT: u64 = 0xb1cd_e5ed;

/// How control reaches a block from one predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CfgEdgeKind {
    /// The branch was taken.
    CondTrue,
    /// The branch was not taken (the fallthrough).
    CondFalse,
    /// The predecessor had exactly one way out.
    Unconditional,
    /// One arm of a computed multi-way transfer.
    Switch,
}

impl CfgEdgeKind {
    /// The constant this edge kind mixes with.
    pub fn constant(self) -> u64 {
        match self {
            CfgEdgeKind::CondTrue => TRUE_EDGE_CONSTANT,
            CfgEdgeKind::CondFalse => FALSE_EDGE_CONSTANT,
            CfgEdgeKind::Unconditional => UNCONDITIONAL_EDGE_CONSTANT,
            CfgEdgeKind::Switch => SWITCH_EDGE_CONSTANT,
        }
    }
}

/// One classified control-flow edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: CfgEdgeKind,
    /// The target dominates the source: this edge closes a loop.
    ///
    /// Computed from dominators this module owns (see
    /// [`super::dominators`]) rather than from `structure_v2`, so a change to
    /// the decompiler's region recovery cannot move a stored signature.
    pub is_back_edge: bool,
}

/// The classified control-flow skeleton of one function.
#[derive(Debug, Clone, Default)]
pub struct BlockGraph {
    /// `(in_degree << 8) | out_degree`, by block index.
    seeds: Vec<u64>,
    edges: Vec<CfgEdge>,
    predecessors: Vec<Vec<usize>>,
}

impl BlockGraph {
    /// Every classified edge, in `(from, to)` order.
    pub fn edges(&self) -> &[CfgEdge] {
        &self.edges
    }

    /// The degree seed of each block.
    pub fn seeds(&self) -> &[u64] {
        &self.seeds
    }
}

/// Classify a function's control-flow edges and seed its blocks.
pub fn classify(function: &LlirFunction) -> BlockGraph {
    let (successors, predecessors) = block_adjacency(function);
    let count = function.blocks.len();
    let entry = function
        .blocks
        .iter()
        .position(|block| block.start_va == function.entry_va)
        .unwrap_or(0);
    let dominators = Dominators::compute(entry, &successors);

    let seeds: Vec<u64> = (0..count)
        .map(|block| {
            let in_degree = predecessors[block].len().min(u8::MAX as usize) as u64;
            let out_degree = successors[block].len().min(u8::MAX as usize) as u64;
            (in_degree << 8) | out_degree
        })
        .collect();

    let mut edges = Vec::new();
    for from in 0..count {
        let kinds = edge_kinds(&function.blocks[from], &successors[from], function);
        for (index, to) in successors[from].iter().copied().enumerate() {
            edges.push(CfgEdge {
                from,
                to,
                kind: kinds[index],
                is_back_edge: dominators.dominates(to, from),
            });
        }
    }
    BlockGraph {
        seeds,
        edges,
        predecessors,
    }
}

/// The kind of each outgoing edge of `block`, positionally aligned with
/// `successors`.
fn edge_kinds(
    block: &LlirBlock,
    successors: &[usize],
    function: &LlirFunction,
) -> Vec<CfgEdgeKind> {
    let terminator = block.instrs.iter().rev().find_map(|instruction| {
        matches!(
            instruction.op,
            Op::Jump { .. }
                | Op::CondJump { .. }
                | Op::IndirectJump { .. }
                | Op::CondReturn { .. }
                | Op::CondReturnValue { .. }
                | Op::Return
                | Op::ReturnValue { .. }
        )
        .then_some(&instruction.op)
    });
    let default = if successors.len() > 1 {
        CfgEdgeKind::Switch
    } else {
        CfgEdgeKind::Unconditional
    };
    match terminator {
        // A computed transfer's arms are all the same kind: which index
        // selected which arm is jump-table layout, not program structure.
        Some(Op::IndirectJump { .. }) => vec![CfgEdgeKind::Switch; successors.len()],
        Some(Op::CondJump {
            target, inverted, ..
        }) if successors.len() == 2 => {
            let (taken, not_taken) = if *inverted {
                (CfgEdgeKind::CondFalse, CfgEdgeKind::CondTrue)
            } else {
                (CfgEdgeKind::CondTrue, CfgEdgeKind::CondFalse)
            };
            successors
                .iter()
                .map(|successor| {
                    if function.blocks[*successor].start_va == *target {
                        taken
                    } else {
                        not_taken
                    }
                })
                .collect()
        }
        // The taken path leaves the function, so the only surviving edge is
        // the one control follows when the condition does not hold.
        Some(Op::CondReturn { .. } | Op::CondReturnValue { .. }) if successors.len() == 1 => {
            vec![CfgEdgeKind::CondFalse]
        }
        _ => vec![default; successors.len()],
    }
}

/// The refined label of every block: one Weisfeiler-Lehman round.
pub fn refine(graph: &BlockGraph) -> Vec<u64> {
    let mut incoming: Vec<u64> = vec![0; graph.seeds.len()];
    for edge in &graph.edges {
        let mut constant = edge.kind.constant();
        if edge.is_back_edge {
            constant ^= BACK_EDGE_CONSTANT;
        }
        let mut buffer = [0u8; 16];
        buffer[..8].copy_from_slice(&constant.to_le_bytes());
        buffer[8..].copy_from_slice(&graph.seeds[edge.from].to_le_bytes());
        // Order-independent over predecessors, because predecessor order is
        // block layout order and block layout order is masked.
        incoming[edge.to] = incoming[edge.to].wrapping_add(compress(&buffer));
    }
    graph
        .seeds
        .iter()
        .enumerate()
        .map(|(block, seed)| {
            let mut buffer = [0u8; 24];
            buffer[..8].copy_from_slice(&seed.to_le_bytes());
            buffer[8..16].copy_from_slice(&incoming[block].to_le_bytes());
            buffer[16..].copy_from_slice(&(graph.predecessors[block].len() as u64).to_le_bytes());
            compress(&buffer)
        })
        .collect()
}

/// Whether an operation is a *root*: a place the block's control label and the
/// dataflow label of what it computed are fused into one feature.
///
/// BSim's root set verbatim: `CALL`, `CALLIND`, `STORE`, `CBRANCH`, `RETURN`.
pub fn is_root_op(op: &Op) -> bool {
    matches!(
        op,
        Op::Call { .. }
            | Op::IndirectJump { .. }
            | Op::Store { .. }
            | Op::CondStore { .. }
            | Op::CondJump { .. }
            | Op::CondReturn { .. }
            | Op::CondReturnValue { .. }
            | Op::Return
            | Op::ReturnValue { .. }
    )
}

/// The control-flow feature multiset of one function.
///
/// Four families: the degree seeds, the refined block labels, one feature per
/// classified edge, and the fused root features.
pub fn block_features(
    function: &LlirFunction,
    dataflow: &CfrGraph,
    dataflow_rows: &[Vec<u64>],
) -> Vec<u32> {
    let graph = classify(function);
    let refined = refine(&graph);
    let mut out: Vec<u32> = Vec::with_capacity(graph.seeds.len() * 3 + graph.edges.len());

    for seed in &graph.seeds {
        let mut buffer = [0u8; 16];
        buffer[..8].copy_from_slice(b"cfrc:sd\0");
        buffer[8..].copy_from_slice(&seed.to_le_bytes());
        out.push(compress(&buffer) as u32);
    }
    for label in &refined {
        out.push(*label as u32);
    }
    for edge in &graph.edges {
        let mut buffer = [0u8; 32];
        buffer[..8].copy_from_slice(b"cfrc:ed\0");
        buffer[8..16].copy_from_slice(&edge.kind.constant().to_le_bytes());
        buffer[16..24].copy_from_slice(&graph.seeds[edge.from].to_le_bytes());
        buffer[24..].copy_from_slice(&graph.seeds[edge.to].to_le_bytes());
        let mut feature = compress(&buffer);
        if edge.is_back_edge {
            feature ^= BACK_EDGE_CONSTANT;
        }
        out.push(feature as u32);
    }

    let final_row = dataflow_rows.get(DATAFLOW_ITERATIONS);
    let mut fused: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    for (block_idx, block) in function.blocks.iter().enumerate() {
        for (instr_idx, instruction) in block.instrs.iter().enumerate() {
            if !is_root_op(&instruction.op) {
                continue;
            }
            let addr = InstrAddr {
                block_idx,
                instr_idx,
            };
            let expression = dataflow
                .node_for(addr)
                .and_then(|node| final_row.and_then(|row| row.get(node as usize)).copied())
                .unwrap_or(0);
            let mut buffer = [0u8; 24];
            buffer[..8].copy_from_slice(b"cfrc:rt\0");
            buffer[8..16].copy_from_slice(&refined[block_idx].to_le_bytes());
            buffer[16..].copy_from_slice(&expression.to_le_bytes());
            fused.insert((block_idx, instr_idx), compress(&buffer));
        }
    }
    out.extend(fused.into_values().map(|feature| feature as u32));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{Flag, LlirInstr, VReg};

    fn block(start: u64, ops: Vec<Op>, succs: Vec<u64>) -> LlirBlock {
        LlirBlock {
            start_va: start,
            end_va: start + ops.len() as u64,
            instrs: ops
                .into_iter()
                .enumerate()
                .map(|(index, op)| LlirInstr {
                    va: start + index as u64,
                    op,
                })
                .collect(),
            succs,
        }
    }

    #[test]
    fn a_conditional_branch_labels_its_two_edges_differently() {
        let function = LlirFunction {
            entry_va: 0x10,
            blocks: vec![
                block(
                    0x10,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x30,
                        inverted: false,
                    }],
                    vec![0x30, 0x20],
                ),
                block(0x20, vec![Op::Return], vec![]),
                block(0x30, vec![Op::Return], vec![]),
            ],
        };
        let graph = classify(&function);
        let kinds: Vec<CfgEdgeKind> = graph.edges().iter().map(|edge| edge.kind).collect();
        assert!(kinds.contains(&CfgEdgeKind::CondTrue));
        assert!(kinds.contains(&CfgEdgeKind::CondFalse));
    }

    #[test]
    fn an_inverted_branch_swaps_which_edge_is_the_taken_one() {
        let make = |inverted: bool| LlirFunction {
            entry_va: 0x10,
            blocks: vec![
                block(
                    0x10,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x30,
                        inverted,
                    }],
                    vec![0x30, 0x20],
                ),
                block(0x20, vec![Op::Return], vec![]),
                block(0x30, vec![Op::Return], vec![]),
            ],
        };
        let straight = classify(&make(false));
        let inverted = classify(&make(true));
        assert_ne!(straight.edges()[0].kind, inverted.edges()[0].kind);
    }

    #[test]
    fn a_latch_edge_is_marked_as_a_back_edge() {
        let function = LlirFunction {
            entry_va: 0x10,
            blocks: vec![
                block(0x10, vec![Op::Jump { target: 0x20 }], vec![0x20]),
                block(
                    0x20,
                    vec![Op::CondJump {
                        cond: VReg::Flag(Flag::Z),
                        target: 0x20,
                        inverted: false,
                    }],
                    vec![0x20, 0x30],
                ),
                block(0x30, vec![Op::Return], vec![]),
            ],
        };
        let graph = classify(&function);
        let latch = graph
            .edges()
            .iter()
            .find(|edge| edge.from == 1 && edge.to == 1)
            .expect("self-loop edge");
        assert!(latch.is_back_edge);
    }
}
