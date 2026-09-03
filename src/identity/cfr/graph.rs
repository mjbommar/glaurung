//! CFR-G: the operator-typed SSA dataflow graph.
//!
//! Nodes are SSA values and memory states; edges are positionally labelled
//! operand edges, memory-dependence edges, and control-dependence edges. The
//! construction runs over LLIR *after* SSA and *before* structuring, because
//! `structure_v2` introduces `BinOp::LogicalAnd` / `BinOp::LogicalOr` -- source
//! level, short-circuit, left-to-right operators that do not belong in a
//! machine-semantics graph.
//!
//! Four things are removed rather than represented:
//!
//! * **Unconditional jumps and NOPs** get no node at all. Both are pure layout,
//!   and layout is the first row of the mask table.
//! * **Pure copies** are forwarded to their source. A copy is register
//!   allocation, which is masked.
//! * **Trivial phis** -- those whose incoming values all resolve to one node
//!   once self-references are dropped -- are forwarded the same way. This is
//!   Braun et al.'s rule, and it is what BSim's "shadow varnode" elimination
//!   does with the dominator tree.
//! * **Dead computations** are dropped by reverse reachability from the graph's
//!   roots (memory writes, calls, intrinsics, terminators). This is the
//!   "dead flag computations" row of the mask table: an `x86` `cmp` writes six
//!   flags and a `jne` reads one, and the other five must not become features.

use std::collections::{BTreeMap, BTreeSet};

use super::commutativity::{op_mixing, Mixing};
use super::dominators::Dominators;
use super::labels::{
    ArityClass, BinOpKind, CalleeClass, CmpOpKind, ConstBucket, NodeLabel, OpKind, UnOpKind,
    ValueClass, WidthClass,
};
use super::operands::{operands, Operand};
use super::prune::{live_nodes, shadow_forwarding};
use super::stack::stack_derived_values;
use super::widths::{self, WidthCensus, WidthInference};
use super::CfrSettings;
use crate::ir::ssa::{SsaInfo, SsaValue};
use crate::ir::types::{CallTarget, LlirFunction, Op};
use crate::ir::use_def::InstrAddr;

/// Index of a node in a [`CfrGraph`].
pub type NodeId = u32;

/// What a dependence edge represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// A positional operand of an operation.
    Operand,
    /// A memory-state dependence: this operation reads or follows that state.
    Memory,
    /// A control dependence: this state is reached only under that predicate.
    Control,
}

impl EdgeKind {
    /// Stable discriminant mixed into the Weisfeiler-Lehman round.
    pub fn tag(self) -> u8 {
        match self {
            EdgeKind::Operand => 0,
            EdgeKind::Memory => 1,
            EdgeKind::Control => 2,
        }
    }
}

/// One input edge of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub kind: EdgeKind,
    /// Operand position, or `0` for memory and control edges.
    pub position: u8,
    pub target: NodeId,
}

/// One node: a label, a mixing rule, and its inputs.
#[derive(Debug, Clone)]
pub struct CfrNode {
    pub label: NodeLabel,
    pub mixing: Mixing,
    pub inputs: Vec<Edge>,
}

/// The dataflow graph of one function.
#[derive(Debug, Clone, Default)]
pub struct CfrGraph {
    nodes: Vec<CfrNode>,
    /// The node produced by each instruction, for CFR-C's root fusion.
    instruction_nodes: BTreeMap<(usize, usize), NodeId>,
    width_census: WidthCensus,
}

impl CfrGraph {
    /// Every node, in construction order.
    pub fn nodes(&self) -> &[CfrNode] {
        &self.nodes
    }

    /// The CFR-G node an instruction produced, if it produced one.
    pub fn node_for(&self, addr: InstrAddr) -> Option<NodeId> {
        self.instruction_nodes
            .get(&(addr.block_idx, addr.instr_idx))
            .copied()
    }

    /// How much of the function width inference could resolve.
    pub fn width_census(&self) -> WidthCensus {
        self.width_census
    }
}

/// Everything the graph needs from the image, supplied by the caller so the
/// builder itself never opens a file.
pub struct GraphContext<'a> {
    pub settings: CfrSettings,
    /// PLT / import-stub address to external symbol name.
    pub external_names: &'a BTreeMap<u64, String>,
    /// Whether an address lands in a mapped section of the image.
    pub is_mapped_address: &'a dyn Fn(u64) -> bool,
    /// Register names that hold a stack or frame pointer on this target.
    pub stack_registers: &'a BTreeSet<&'static str>,
}

/// Node identities, so the same SSA value or literal is one node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NodeKey {
    Value(SsaValue),
    Const(i64),
    Addr(u64),
    MemEntry(usize),
    MemDef(usize, usize),
    Terminator(usize, usize),
    Absent,
}

struct Builder<'a> {
    function: &'a LlirFunction,
    ssa: &'a SsaInfo,
    context: &'a GraphContext<'a>,
    widths: WidthInference,
    stack_values: BTreeSet<SsaValue>,
    /// Successor block indices, resolved once from the VA-keyed edge lists.
    successors: Vec<Vec<usize>>,
    /// The transpose of [`Builder::successors`].
    predecessors: Vec<Vec<usize>>,
    nodes: Vec<CfrNode>,
    by_key: BTreeMap<NodeKey, NodeId>,
    instruction_nodes: BTreeMap<(usize, usize), NodeId>,
    roots: BTreeSet<NodeId>,
}

/// Build the CFR-G of one function.
pub fn build(function: &LlirFunction, ssa: &SsaInfo, context: &GraphContext<'_>) -> CfrGraph {
    let widths = widths::infer(function, ssa);
    let census = widths.census();
    let stack_values = stack_derived_values(function, ssa, context.stack_registers);
    let (successors, predecessors) = block_adjacency(function);
    let mut builder = Builder {
        function,
        ssa,
        context,
        widths,
        stack_values,
        successors,
        predecessors,
        nodes: Vec::new(),
        by_key: BTreeMap::new(),
        instruction_nodes: BTreeMap::new(),
        roots: BTreeSet::new(),
    };
    builder.create_nodes();
    let exit_states = builder.wire_dataflow();
    builder.wire_memory_merges(&exit_states);
    builder.wire_control_dependence();
    let graph = builder.finish();
    CfrGraph {
        width_census: census,
        ..graph
    }
}

impl<'a> Builder<'a> {
    fn push(&mut self, key: NodeKey, label: NodeLabel, mixing: Mixing) -> NodeId {
        if let Some(existing) = self.by_key.get(&key) {
            return *existing;
        }
        let id = self.nodes.len() as NodeId;
        self.nodes.push(CfrNode {
            label: label.apply_settings(self.context.settings),
            mixing,
            inputs: Vec::new(),
        });
        self.by_key.insert(key, id);
        id
    }

    /// Phase one: one node per memory state, per phi, and per value-producing
    /// or effectful instruction. Created before any edge is wired because a phi
    /// refers forward to definitions that appear later in the block order.
    fn create_nodes(&mut self) {
        let block_count = self.function.blocks.len();
        for block in 0..block_count {
            let predecessors = self.predecessors_of(block).len();
            self.push(
                NodeKey::MemEntry(block),
                NodeLabel::plain(
                    OpKind::MemEntry,
                    WidthClass::Unknown,
                    predecessors,
                    ValueClass::Derived,
                ),
                Mixing::Commutative,
            );
        }
        for phi in &self.ssa.phis {
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            let width = self.widths.class_of(&result);
            let key = NodeKey::Value(result);
            self.push(
                key,
                NodeLabel::plain(OpKind::Phi, width, phi.incoming.len(), ValueClass::Phi),
                Mixing::Commutative,
            );
        }
        for block_idx in 0..block_count {
            for instr_idx in 0..self.function.blocks[block_idx].instrs.len() {
                self.create_instruction_nodes(block_idx, instr_idx);
            }
        }
    }

    fn create_instruction_nodes(&mut self, block_idx: usize, instr_idx: usize) {
        let op = self.function.blocks[block_idx].instrs[instr_idx].op.clone();
        let addr = InstrAddr {
            block_idx,
            instr_idx,
        };
        let arity = operands(&op).len();
        let defs = self.ssa.def_values(self.function, addr);
        let mut primary: Option<NodeId> = None;

        for (index, value) in defs.iter().enumerate() {
            let kind = self.op_kind_of(&op);
            let width = self.widths.class_of(value);
            let mut label = NodeLabel::plain(kind, width, arity, self.value_class_of(value));
            label.callee = self.callee_class_of(&op);
            let mixing = op_mixing(&label.op_kind);
            let id = self.push(NodeKey::Value(value.clone()), label, mixing);
            if index == 0 {
                primary = Some(id);
            }
        }

        if writes_memory(&op) {
            let label = NodeLabel {
                callee: self.callee_class_of(&op),
                ..NodeLabel::plain(
                    self.op_kind_of(&op),
                    WidthClass::Unknown,
                    arity,
                    ValueClass::Derived,
                )
            };
            let mixing = op_mixing(&label.op_kind);
            let id = self.push(NodeKey::MemDef(block_idx, instr_idx), label, mixing);
            self.roots.insert(id);
            primary = primary.or(Some(id));
        }

        if is_terminator(&op) {
            let label = NodeLabel::plain(
                self.op_kind_of(&op),
                WidthClass::Unknown,
                arity,
                ValueClass::Derived,
            );
            let mixing = op_mixing(&label.op_kind);
            let id = self.push(NodeKey::Terminator(block_idx, instr_idx), label, mixing);
            self.roots.insert(id);
            primary = primary.or(Some(id));
        }

        // A call or a declared-opaque intrinsic is an effect whether or not
        // anything reads its result, so it anchors reachability.
        if matches!(
            op,
            Op::Call { .. } | Op::Intrinsic { .. } | Op::Unknown { .. }
        ) {
            if let Some(id) = primary {
                self.roots.insert(id);
            }
        }
        if let Some(id) = primary {
            self.instruction_nodes.insert((block_idx, instr_idx), id);
        }
    }

    /// Phase two: operand and memory edges, walking each block in order so the
    /// memory chain is built in program order. Returns each block's exit state.
    fn wire_dataflow(&mut self) -> Vec<NodeId> {
        let block_count = self.function.blocks.len();
        let mut exit_states = Vec::with_capacity(block_count);

        for phi_index in 0..self.ssa.phis.len() {
            let phi = self.ssa.phis[phi_index].clone();
            let result = SsaValue {
                base: phi.base.clone(),
                version: phi.dst_version,
            };
            let Some(target) = self.by_key.get(&NodeKey::Value(result)).copied() else {
                continue;
            };
            for (position, (_, version)) in phi.incoming.iter().enumerate() {
                let incoming = SsaValue {
                    base: phi.base.clone(),
                    version: *version,
                };
                let source = self.resolve_value(&incoming);
                self.nodes[target as usize].inputs.push(Edge {
                    kind: EdgeKind::Operand,
                    position: position.min(u8::MAX as usize) as u8,
                    target: source,
                });
            }
        }

        for block_idx in 0..block_count {
            let mut memory_state = self.by_key[&NodeKey::MemEntry(block_idx)];
            for instr_idx in 0..self.function.blocks[block_idx].instrs.len() {
                memory_state = self.wire_instruction(block_idx, instr_idx, memory_state);
            }
            exit_states.push(memory_state);
        }
        exit_states
    }

    fn wire_instruction(
        &mut self,
        block_idx: usize,
        instr_idx: usize,
        memory_state: NodeId,
    ) -> NodeId {
        let op = self.function.blocks[block_idx].instrs[instr_idx].op.clone();
        let addr = InstrAddr {
            block_idx,
            instr_idx,
        };
        let mut operand_edges: Vec<Edge> = Vec::new();
        for (position, operand) in operands(&op).into_iter().enumerate() {
            let target = self.resolve_operand(addr, operand);
            operand_edges.push(Edge {
                kind: EdgeKind::Operand,
                position: position.min(u8::MAX as usize) as u8,
                target,
            });
        }

        let reads = reads_memory(&op);
        for value in self.ssa.def_values(self.function, addr) {
            let Some(id) = self.by_key.get(&NodeKey::Value(value)).copied() else {
                continue;
            };
            self.nodes[id as usize]
                .inputs
                .extend_from_slice(&operand_edges);
            if reads {
                self.nodes[id as usize].inputs.push(Edge {
                    kind: EdgeKind::Memory,
                    position: 0,
                    target: memory_state,
                });
            }
        }
        if let Some(id) = self.by_key.get(&NodeKey::Terminator(block_idx, instr_idx)) {
            let id = *id;
            self.nodes[id as usize]
                .inputs
                .extend_from_slice(&operand_edges);
        }
        if let Some(id) = self.by_key.get(&NodeKey::MemDef(block_idx, instr_idx)) {
            let id = *id;
            self.nodes[id as usize]
                .inputs
                .extend_from_slice(&operand_edges);
            self.nodes[id as usize].inputs.push(Edge {
                kind: EdgeKind::Memory,
                position: 0,
                target: memory_state,
            });
            return id;
        }
        memory_state
    }

    /// Phase three: a block's entry memory state merges its predecessors' exit
    /// states. Cyclic by construction around a loop, which the relabelling
    /// handles: WL is an iteration, not a traversal.
    fn wire_memory_merges(&mut self, exit_states: &[NodeId]) {
        for block in 0..self.function.blocks.len() {
            let entry = self.by_key[&NodeKey::MemEntry(block)];
            self.roots.insert(entry);
            for predecessor in self.predecessors_of(block) {
                let Some(state) = exit_states.get(predecessor).copied() else {
                    continue;
                };
                self.nodes[entry as usize].inputs.push(Edge {
                    kind: EdgeKind::Memory,
                    position: 0,
                    target: state,
                });
            }
        }
    }

    /// Phase four: control dependence, attached to block-entry memory states.
    ///
    /// Every effectful node in a block hangs off that block's memory chain, so
    /// one edge per (block, controlling predicate) reaches all of them through
    /// the relabelling and costs `O(control dependences)` rather than
    /// `O(control dependences * nodes)`.
    fn wire_control_dependence(&mut self) {
        let block_count = self.function.blocks.len();
        if block_count == 0 {
            return;
        }
        // Post-dominators are the dominators of the reversed graph rooted at a
        // virtual exit, which is node `block_count`.
        let mut reverse: Vec<Vec<usize>> = vec![Vec::new(); block_count + 1];
        for block in 0..block_count {
            let successors = self.successors_of(block);
            if successors.is_empty() {
                reverse[block_count].push(block);
            }
            for successor in successors {
                reverse[successor].push(block);
            }
        }
        let post = Dominators::compute(block_count, &reverse);

        for block in 0..block_count {
            let successors = self.successors_of(block);
            if successors.len() < 2 {
                continue;
            }
            let Some(predicate) = self.branch_predicate_node(block) else {
                continue;
            };
            let stop = post.idom(block);
            for successor in successors {
                let mut walk = Some(successor);
                let mut guard = block_count + 1;
                while let Some(current) = walk {
                    if Some(current) == stop || guard == 0 {
                        break;
                    }
                    guard -= 1;
                    let entry = self.by_key[&NodeKey::MemEntry(current)];
                    self.nodes[entry as usize].inputs.push(Edge {
                        kind: EdgeKind::Control,
                        position: 0,
                        target: predicate,
                    });
                    if current == block {
                        break;
                    }
                    walk = post.idom(current);
                }
            }
        }
    }

    /// The CFR-G node of the value a block's conditional terminator tests.
    fn branch_predicate_node(&self, block: usize) -> Option<NodeId> {
        let instrs = &self.function.blocks[block].instrs;
        for (instr_idx, instruction) in instrs.iter().enumerate().rev() {
            if !is_terminator(&instruction.op) {
                continue;
            }
            let node = self.instruction_nodes.get(&(block, instr_idx))?;
            return Some(*node);
        }
        None
    }

    fn resolve_operand(&mut self, addr: InstrAddr, operand: Operand) -> NodeId {
        match operand {
            Operand::Reg { use_index } => {
                match self.ssa.use_value_ref(self.function, addr, use_index) {
                    Some(value) => {
                        let value = value.clone();
                        self.resolve_value(&value)
                    }
                    // An unnumbered read is a hole in the SSA tables, not a
                    // value: give it the same label an absent operand gets so
                    // it cannot masquerade as a live-in.
                    None => self.absent_node(),
                }
            }
            Operand::Const(constant) => self.const_node(constant),
            Operand::Addr(address) => self.addr_node(address),
            Operand::Absent => self.absent_node(),
        }
    }

    /// The node for an SSA value, creating a live-in node when nothing defines
    /// it inside this function.
    fn resolve_value(&mut self, value: &SsaValue) -> NodeId {
        if let Some(existing) = self.by_key.get(&NodeKey::Value(value.clone())) {
            return *existing;
        }
        let width = self.widths.class_of(value);
        let class = if value.version == 0 {
            ValueClass::FunctionInput
        } else {
            // A non-zero version with no producing node: the definition was an
            // operation the projection masks (a jump, a NOP). Not an input.
            ValueClass::Derived
        };
        self.push(
            NodeKey::Value(value.clone()),
            NodeLabel::plain(OpKind::LiveIn, width, 0, class),
            Mixing::Positional,
        )
    }

    fn const_node(&mut self, constant: i64) -> NodeId {
        let mapped = (self.context.is_mapped_address)(constant as u64);
        let class = if mapped {
            ValueClass::GlobalAddr
        } else {
            ValueClass::Const
        };
        let label = NodeLabel {
            const_bucket: Some(ConstBucket::classify(constant)),
            ..NodeLabel::plain(OpKind::Const, WidthClass::Unknown, 0, class)
        };
        self.push(NodeKey::Const(constant), label, Mixing::Positional)
    }

    fn addr_node(&mut self, address: u64) -> NodeId {
        let label = NodeLabel {
            const_bucket: Some(ConstBucket::classify_addr(address)),
            ..NodeLabel::plain(
                OpKind::Const,
                WidthClass::Unknown,
                0,
                ValueClass::GlobalAddr,
            )
        };
        self.push(NodeKey::Addr(address), label, Mixing::Positional)
    }

    fn absent_node(&mut self) -> NodeId {
        self.push(
            NodeKey::Absent,
            NodeLabel::plain(OpKind::Absent, WidthClass::Unknown, 0, ValueClass::Const),
            Mixing::Positional,
        )
    }

    fn value_class_of(&self, value: &SsaValue) -> ValueClass {
        if self.stack_values.contains(value) {
            ValueClass::StackAddr
        } else {
            ValueClass::Derived
        }
    }

    fn op_kind_of(&self, op: &Op) -> OpKind {
        match op {
            Op::Assign { .. } => OpKind::Assign,
            Op::Undef { .. } => OpKind::Undef,
            Op::Bin { op, .. } => OpKind::Bin(BinOpKind::of(*op)),
            Op::Un { op, .. } => OpKind::Un(UnOpKind::of(*op)),
            Op::Cmp { op, .. } => OpKind::Cmp(CmpOpKind::of(*op)),
            Op::Load { .. } => OpKind::Load,
            Op::CondLoad { .. } => OpKind::CondLoad,
            Op::Store { .. } => OpKind::Store,
            Op::CondStore { .. } => OpKind::CondStore,
            Op::IndirectJump { .. } => OpKind::IndirectJump,
            Op::CondJump { .. } => OpKind::CondJump,
            Op::CondReturn { .. } | Op::CondReturnValue { .. } => OpKind::CondReturn,
            Op::Call { .. } => OpKind::Call,
            Op::Return | Op::ReturnValue { .. } => OpKind::Return,
            Op::ZExt { .. } => OpKind::ZExt,
            Op::SExt { .. } => OpKind::SExt,
            Op::Trunc { .. } => OpKind::Trunc,
            Op::Extract { .. } => OpKind::Extract,
            Op::Concat { .. } => OpKind::Concat,
            Op::Ite { .. } => OpKind::Ite,
            Op::Intrinsic { name, .. } => OpKind::Intrinsic(name.clone()),
            Op::Unknown { .. } => OpKind::Unlifted,
            // Masked: pure layout. These never reach here because no node is
            // created for them, but the mapping must be total.
            Op::Jump { .. } | Op::Nop => OpKind::Unlifted,
        }
    }

    fn callee_class_of(&self, op: &Op) -> CalleeClass {
        let Op::Call { target, effects } = op else {
            return CalleeClass::NotACall;
        };
        match target {
            CallTarget::Indirect(_) => CalleeClass::Indirect,
            CallTarget::Direct(address) => {
                if let Some(name) = self.context.external_names.get(address) {
                    return CalleeClass::External(name.clone());
                }
                // An internal callee's name is a private detail a rebuild may
                // change or inline away; its argument count is what survives.
                let arity = effects.as_ref().map_or(0, |effects| {
                    if effects.args_are_exact || !effects.proven_args.is_empty() {
                        effects.proven_args.len()
                    } else {
                        effects.args.len()
                    }
                });
                CalleeClass::Internal(ArityClass::of(arity))
            }
        }
    }

    fn successors_of(&self, block: usize) -> Vec<usize> {
        self.successors[block].clone()
    }

    fn predecessors_of(&self, block: usize) -> Vec<usize> {
        self.predecessors[block].clone()
    }

    /// Phase five: shadow elimination, dead-code removal, and compaction.
    fn finish(self) -> CfrGraph {
        let Builder {
            mut nodes,
            instruction_nodes,
            roots,
            ..
        } = self;
        let forward = shadow_forwarding(&nodes);
        for node in nodes.iter_mut() {
            for edge in node.inputs.iter_mut() {
                edge.target = forward[edge.target as usize];
            }
        }
        let live = live_nodes(&nodes, &roots, &forward);

        let mut remap = vec![u32::MAX; nodes.len()];
        let mut kept: Vec<CfrNode> = Vec::with_capacity(live.len());
        for (id, node) in nodes.into_iter().enumerate() {
            if !live.contains(&(id as NodeId)) {
                continue;
            }
            remap[id] = kept.len() as NodeId;
            kept.push(node);
        }
        for node in kept.iter_mut() {
            node.inputs
                .retain(|edge| remap[edge.target as usize] != u32::MAX);
            for edge in node.inputs.iter_mut() {
                edge.target = remap[edge.target as usize];
            }
        }
        let instruction_nodes = instruction_nodes
            .into_iter()
            .filter_map(|(key, id)| {
                let forwarded = forward[id as usize];
                let mapped = remap[forwarded as usize];
                (mapped != u32::MAX).then_some((key, mapped))
            })
            .collect();
        CfrGraph {
            nodes: kept,
            instruction_nodes,
            width_census: WidthCensus::default(),
        }
    }
}

/// Successor and predecessor block indices, resolved from VA-keyed edge lists.
///
/// `LlirBlock::succs` holds addresses, and every consumer that resolves them by
/// scanning the block list pays `O(blocks)` per edge. A function is allowed
/// 2,048 blocks here, so that is four million comparisons for a graph the
/// builder walks several times.
pub(crate) fn block_adjacency(function: &LlirFunction) -> (Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let count = function.blocks.len();
    let by_va: BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start_va, index))
        .collect();
    let mut successors: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (index, block) in function.blocks.iter().enumerate() {
        for target in &block.succs {
            if let Some(successor) = by_va.get(target).copied() {
                successors[index].push(successor);
                predecessors[successor].push(index);
            }
        }
    }
    (successors, predecessors)
}

/// Whether the operation observes the memory state.
fn reads_memory(op: &Op) -> bool {
    match op {
        Op::Load { .. } | Op::CondLoad { .. } => true,
        Op::Call { .. } | Op::Unknown { .. } => true,
        Op::Intrinsic { reads_mem, .. } => *reads_mem,
        _ => false,
    }
}

/// Whether the operation produces a new memory state.
fn writes_memory(op: &Op) -> bool {
    match op {
        Op::Store { .. } | Op::CondStore { .. } => true,
        Op::Call { .. } | Op::Unknown { .. } => true,
        Op::Intrinsic { writes_mem, .. } => *writes_mem,
        _ => false,
    }
}

/// Whether the operation transfers control out of its block conditionally or
/// out of the function. `Op::Jump` is excluded on purpose: it is layout.
fn is_terminator(op: &Op) -> bool {
    matches!(
        op,
        Op::CondJump { .. }
            | Op::CondReturn { .. }
            | Op::CondReturnValue { .. }
            | Op::IndirectJump { .. }
            | Op::Return
            | Op::ReturnValue { .. }
    )
}
