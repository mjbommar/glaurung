//! Fixed-point definedness queries over verified MIR.
//!
//! This is EPIC 5's minimum query surface: `definition`, `uses`,
//! `all_paths_defined`, `value_at`, `clobbers_between`, a reaching-definition
//! set, and `memory_version`. Two rules shape every answer here:
//!
//! * Rule 5 — unknown calls and instructions clobber conservatively; unknown
//!   never means "no effect".
//! * Rule 8 — a failed proof returns an explicit unknown carrying its reason.
//!   It never returns a plausible value.
//!
//! Consequently these queries are deliberately *stricter* than the raw SSA
//! use-def edges they are built from. An unannotated call declares no register
//! effect, so the use edge after it still names the pre-call value;
//! [`DefinitionOracle::value_at`] answers [`UnknownReason::OpaqueInstruction`]
//! instead of repeating that claim. Narrowing that answer needs target-owned
//! call and intrinsic clobber contracts, which are EPIC 4 work.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::ir::types::VReg;

use super::model::{
    BlockId, Definition, EffectCompleteness, InstructionId, MemoryAccessId, MemoryDefinition,
    MemoryRegion, MemoryValueId, MirFunction, MirInstruction, StorageId, UseId, ValueId,
};

/// A position in a function's instruction stream.
///
/// A point names the gap immediately *before* the instruction at `index` in
/// `block`. `index == block.instructions.len()` is the gap after the block's
/// last instruction, i.e. the block's outgoing edges. Phis of a block execute
/// on the incoming edges, so they are already applied at `index == 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramPoint {
    pub block: BlockId,
    pub index: usize,
}

impl ProgramPoint {
    /// The point after this block's phis and before its first instruction.
    pub fn block_entry(block: BlockId) -> Self {
        Self { block, index: 0 }
    }

    /// The point after this block's last instruction.
    pub fn block_exit(function: &MirFunction, block: BlockId) -> Option<Self> {
        Some(Self {
            block,
            index: function.blocks().get(block.0)?.instructions.len(),
        })
    }

    /// The point immediately before `instruction` executes.
    pub fn before(function: &MirFunction, instruction: InstructionId) -> Option<Self> {
        let record = function.instructions().get(instruction.0)?;
        Some(Self {
            block: record.block,
            index: record.index,
        })
    }

    /// The point immediately after `instruction` executes.
    pub fn after(function: &MirFunction, instruction: InstructionId) -> Option<Self> {
        let record = function.instructions().get(instruction.0)?;
        Some(Self {
            block: record.block,
            index: record.index + 1,
        })
    }
}

/// Why a definedness proof failed. Rule 8: never a guess, always a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownReason {
    /// The storage is not in this function's arena.
    UnknownStorage(StorageId),
    /// The value is not in this function's arena.
    UnknownValue(ValueId),
    /// The point does not name a real position in this function.
    InvalidPoint(ProgramPoint),
    /// The point lies in a block that is not reachable from the entry block.
    UnreachablePoint(ProgramPoint),
    /// An instruction whose register write set MIR cannot enumerate executes on
    /// a path to the point (see [`EffectCompleteness::Opaque`]).
    OpaqueInstruction(InstructionId),
    /// No control-flow path runs from `from` to `to`, so the question posed has
    /// no answer to give.
    NoPath {
        from: ProgramPoint,
        to: ProgramPoint,
    },
    /// The value is not the proved state of its own storage at the origin
    /// point, so asking what happens to it after that point is ill-posed.
    ValueNotHeldAtOrigin { value: ValueId, at: ProgramPoint },
    /// A phi edge names a value this function does not own.
    BrokenPhiEdge(ValueId),
}

/// The proved state of a storage or a memory region at a program point.
///
/// Rule 6: every reachable use resolves to a precise definition state. When
/// more than one definition reaches, the whole proved set is retained —
/// collapsing it to one plausible member is exactly the guess this type exists
/// to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionState<T> {
    /// Exactly one definition reaches the point on every path.
    Exact(T),
    /// Several definitions reach the point and MIR has no merged identity for
    /// them. `undefined_path` records that at least one path arrives with no
    /// MIR definition of the storage at all.
    Set {
        values: Vec<T>,
        undefined_path: bool,
    },
    /// No MIR definition reaches the point on any path. The machine location
    /// still holds bits; MIR simply has no identity for them here.
    NoDefinition,
    /// The point lies in a block unreachable from the entry block.
    Unreachable,
    /// The proof failed. Never a guess.
    Unknown(UnknownReason),
}

impl<T: Copy> DefinitionState<T> {
    /// The single proved definition, or `None` for every other state.
    pub fn exact(&self) -> Option<T> {
        match self {
            Self::Exact(value) => Some(*value),
            _ => None,
        }
    }

    /// Whether this state is a proof rather than an explicit failure.
    pub fn is_proved(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// The reason a proof failed, if it failed.
    pub fn unknown_reason(&self) -> Option<&UnknownReason> {
        match self {
            Self::Unknown(reason) => Some(reason),
            _ => None,
        }
    }
}

/// The state of a register storage at a program point.
pub type StorageState = DefinitionState<ValueId>;
/// The state of one memory region at a program point.
pub type MemoryState = DefinitionState<MemoryValueId>;

/// One proved way a storage stops holding a value between two points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClobberKind {
    /// An instruction output writes the storage with a different value.
    Definition {
        instruction: InstructionId,
        value: ValueId,
    },
    /// An instruction MIR cannot enumerate may write the storage.
    Opaque { instruction: InstructionId },
    /// Entering this block merges a different value into the storage.
    Phi { block: BlockId, value: ValueId },
}

/// Whether anything may overwrite a value between two program points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClobberAnswer {
    /// No writer of the value's storage lies on any path between the points.
    None,
    /// Every proved may-writer, in deterministic order. Never a count.
    Clobbered(Vec<ClobberKind>),
    /// The proof failed. Never a guess.
    Unknown(UnknownReason),
}

/// The proved set of definitions that reach a use, with phis resolved through.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReachingSet {
    definitions: Vec<ValueId>,
    phis: Vec<ValueId>,
    incomplete: Vec<UnknownReason>,
}

impl ReachingSet {
    /// The non-phi definitions reaching the use, sorted and deduplicated. Each
    /// is an `Input`, `InstructionOutput`, `Undef`, `UnknownEffect`, or
    /// `Unreachable` definition; ask [`DefinitionOracle::definition`] which.
    pub fn definitions(&self) -> &[ValueId] {
        &self.definitions
    }

    /// The phi values traversed to prove the set, sorted and deduplicated.
    pub fn phis(&self) -> &[ValueId] {
        &self.phis
    }

    /// Whether the traversal proved the whole set.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
    }

    /// Reasons the set is not complete.
    pub fn incomplete_reasons(&self) -> &[UnknownReason] {
        &self.incomplete
    }

    /// The single reaching definition, if the set is complete and a singleton.
    pub fn single(&self) -> Option<ValueId> {
        match (self.is_complete(), self.definitions.as_slice()) {
            (true, [value]) => Some(*value),
            _ => None,
        }
    }
}

/// The lattice the forward walkers iterate. `Bottom` is "no path has arrived
/// here yet"; `Unknown` is top and absorbs everything.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reaching<T: Ord + Copy> {
    Bottom,
    Known {
        values: BTreeSet<T>,
        undefined_path: bool,
    },
    Unknown(UnknownReason),
}

impl<T: Ord + Copy> Reaching<T> {
    fn undefined() -> Self {
        Self::Known {
            values: BTreeSet::new(),
            undefined_path: true,
        }
    }

    fn exactly(value: T) -> Self {
        Self::Known {
            values: BTreeSet::from([value]),
            undefined_path: false,
        }
    }

    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bottom, other) => other,
            (owned, Self::Bottom) => owned,
            (unknown @ Self::Unknown(_), _) => unknown,
            (_, unknown @ Self::Unknown(_)) => unknown,
            (
                Self::Known {
                    mut values,
                    undefined_path,
                },
                Self::Known {
                    values: other,
                    undefined_path: other_undefined,
                },
            ) => {
                values.extend(other);
                Self::Known {
                    values,
                    undefined_path: undefined_path || other_undefined,
                }
            }
        }
    }

    fn finish(self) -> DefinitionState<T> {
        match self {
            // No path reached the point, yet the point was proved reachable:
            // the walker is the only thing that could be wrong, so say so
            // rather than inventing a state.
            Self::Bottom => DefinitionState::NoDefinition,
            Self::Unknown(reason) => DefinitionState::Unknown(reason),
            Self::Known {
                values,
                undefined_path,
            } => match (values.len(), undefined_path) {
                (0, _) => DefinitionState::NoDefinition,
                (1, false) => DefinitionState::Exact(*values.iter().next().expect("one value")),
                _ => DefinitionState::Set {
                    values: values.into_iter().collect(),
                    undefined_path,
                },
            },
        }
    }
}

pub struct DefinitionOracle<'a> {
    function: &'a MirFunction,
    all_paths_defined: Vec<bool>,
    uses_by_value: Vec<Vec<UseId>>,
    memory_uses_by_value: Vec<Vec<MemoryAccessId>>,
}

impl<'a> DefinitionOracle<'a> {
    pub fn new(function: &'a MirFunction) -> Self {
        let mut defined = function
            .values()
            .iter()
            .map(|value| {
                matches!(
                    value.definition,
                    Definition::Input
                        | Definition::InstructionOutput { .. }
                        | Definition::Phi { .. }
                        | Definition::UnknownEffect { .. }
                )
            })
            .collect::<Vec<_>>();
        let mut changed = true;
        while changed {
            changed = false;
            for value in function.values() {
                let next = match &value.definition {
                    Definition::InstructionOutput { instruction, .. } => function.instructions()
                        [instruction.0]
                        .uses
                        .iter()
                        .all(|use_| defined[function.use_(*use_).value.0]),
                    Definition::Phi { incoming, .. } => {
                        !incoming.is_empty()
                            && incoming.iter().all(|(_, incoming)| defined[incoming.0])
                    }
                    _ => continue,
                };
                if !next && defined[value.id.0] {
                    defined[value.id.0] = false;
                    changed = true;
                }
            }
        }
        let mut uses_by_value = vec![Vec::new(); function.values().len()];
        for use_ in function.uses() {
            if let Some(uses) = uses_by_value.get_mut(use_.value.0) {
                uses.push(use_.id);
            }
        }
        let mut memory_uses_by_value = vec![Vec::new(); function.memory_values().len()];
        for access in function.memory_accesses() {
            if let Some(uses) = memory_uses_by_value.get_mut(access.input.0) {
                uses.push(access.id);
            }
        }
        Self {
            function,
            all_paths_defined: defined,
            uses_by_value,
            memory_uses_by_value,
        }
    }

    pub fn all_paths_defined(&self, use_: UseId) -> bool {
        self.function
            .uses()
            .get(use_.0)
            .and_then(|use_| self.all_paths_defined.get(use_.value.0))
            .copied()
            .unwrap_or(false)
    }

    pub fn value_is_all_paths_defined(&self, value: ValueId) -> bool {
        self.all_paths_defined
            .get(value.0)
            .copied()
            .unwrap_or(false)
    }

    pub fn definition(&self, value: ValueId) -> Option<&'a Definition> {
        self.function
            .values()
            .get(value.0)
            .map(|value| &value.definition)
    }

    pub fn uses(&self, value: ValueId) -> &[UseId] {
        self.uses_by_value
            .get(value.0)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn memory_definition(&self, value: MemoryValueId) -> Option<&'a MemoryDefinition> {
        self.function
            .memory_values()
            .get(value.0)
            .map(|value| &value.definition)
    }

    pub fn memory_uses(&self, value: MemoryValueId) -> &[MemoryAccessId] {
        self.memory_uses_by_value
            .get(value.0)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    // ------------------------------------------------------------ value_at --

    /// The value `storage` provably holds at `point`.
    ///
    /// The answer is a forward fixed point over the reachable CFG seeded with
    /// the function's explicit `Input` value for the storage, killed by every
    /// instruction output naming the storage, overridden by the storage's phi
    /// on entry to each block, and driven to
    /// [`UnknownReason::OpaqueInstruction`] by any instruction whose register
    /// write set MIR cannot enumerate. A later definition recovers from that
    /// unknown, because a named output is authoritative for its own storage
    /// even on an otherwise opaque instruction.
    ///
    /// Lifter temporaries are exempt from opaque clobbering: `VReg::Temp` has
    /// no machine existence, so no callee can write it.
    pub fn value_at(&self, storage: StorageId, point: ProgramPoint) -> StorageState {
        if self.function.storages().get(storage.0).is_none() {
            return DefinitionState::Unknown(UnknownReason::UnknownStorage(storage));
        }
        match self.validate(point) {
            Ok(()) => {}
            Err(state) => return state,
        }

        let machine_state = !matches!(self.function.storages()[storage.0].register, VReg::Temp(_));
        let mut initial = Reaching::undefined();
        let mut phi_at = BTreeMap::new();
        for value in self.function.values() {
            if value.storage != storage {
                continue;
            }
            match value.definition {
                Definition::Input => initial = Reaching::exactly(value.id),
                Definition::Phi { block, .. } => {
                    phi_at.entry(block).or_insert(value.id);
                }
                _ => {}
            }
        }

        self.solve(
            point,
            initial,
            |block| phi_at.get(&block).copied(),
            |instruction, state| {
                if machine_state && instruction.register_effects == EffectCompleteness::Opaque {
                    *state = Reaching::Unknown(UnknownReason::OpaqueInstruction(instruction.id));
                }
                for output in &instruction.outputs {
                    if self.function.value(*output).storage == storage {
                        *state = Reaching::exactly(*output);
                    }
                }
            },
        )
        .finish()
    }

    /// The memory state of `region` at `point`.
    ///
    /// MemorySSA already owns conservative call and unknown-instruction
    /// clobbers as explicit `Clobber` accesses, and every region has an
    /// explicit entry state, so this walker trusts the region's own access
    /// chain rather than adding a second opaque rule on top of it.
    pub fn memory_version(&self, region: MemoryRegion, point: ProgramPoint) -> MemoryState {
        match self.validate(point) {
            Ok(()) => {}
            Err(state) => return state,
        }

        let mut initial = Reaching::undefined();
        let mut phi_at = BTreeMap::new();
        for value in self.function.memory_values() {
            if value.region != region {
                continue;
            }
            match value.definition {
                MemoryDefinition::Entry { .. } => initial = Reaching::exactly(value.id),
                MemoryDefinition::Phi { block, .. } => {
                    phi_at.entry(block).or_insert(value.id);
                }
                MemoryDefinition::InstructionOutput { .. } => {}
            }
        }

        self.solve(
            point,
            initial,
            |block| phi_at.get(&block).copied(),
            |instruction, state| {
                for access in &instruction.memory_effects {
                    let access = &self.function.memory_accesses()[access.0];
                    if access.region != region {
                        continue;
                    }
                    if let Some(output) = access.output {
                        *state = Reaching::exactly(output);
                    }
                }
            },
        )
        .finish()
    }

    /// Reject a point that names no real position, or one that cannot execute.
    fn validate<T: Copy>(&self, point: ProgramPoint) -> Result<(), DefinitionState<T>> {
        let Some(block) = self.function.blocks().get(point.block.0) else {
            return Err(DefinitionState::Unknown(UnknownReason::InvalidPoint(point)));
        };
        if point.index > block.instructions.len() {
            return Err(DefinitionState::Unknown(UnknownReason::InvalidPoint(point)));
        }
        if !block.reachable {
            return Err(DefinitionState::Unreachable);
        }
        Ok(())
    }

    /// Forward fixed point over reachable blocks, evaluated at `point`.
    fn solve<T: Ord + Copy>(
        &self,
        point: ProgramPoint,
        initial: Reaching<T>,
        phi_at: impl Fn(BlockId) -> Option<T>,
        transfer: impl Fn(&MirInstruction, &mut Reaching<T>),
    ) -> Reaching<T> {
        let blocks = self.function.blocks();
        let entry_in = |incoming: Reaching<T>, block: BlockId| match phi_at(block) {
            Some(value) => Reaching::exactly(value),
            None => incoming,
        };
        let run = |state: &mut Reaching<T>, block: BlockId, upto: usize| {
            for instruction in blocks[block.0].instructions.iter().take(upto) {
                transfer(&self.function.instructions()[instruction.0], state);
            }
        };

        let mut block_entry = vec![Reaching::Bottom; blocks.len()];
        let mut block_exit = vec![Reaching::Bottom; blocks.len()];
        block_entry[self.function.entry.0] = entry_in(initial.clone(), self.function.entry);
        let mut changed = true;
        while changed {
            changed = false;
            for block in blocks.iter().filter(|block| block.reachable) {
                let mut incoming = if block.id == self.function.entry {
                    initial.clone()
                } else {
                    Reaching::Bottom
                };
                for predecessor in &block.predecessors {
                    if blocks[predecessor.0].reachable {
                        incoming = incoming.join(block_exit[predecessor.0].clone());
                    }
                }
                let next = entry_in(incoming, block.id);
                if next != block_entry[block.id.0] {
                    block_entry[block.id.0] = next;
                    changed = true;
                }
                let mut exit = block_entry[block.id.0].clone();
                run(&mut exit, block.id, block.instructions.len());
                if exit != block_exit[block.id.0] {
                    block_exit[block.id.0] = exit;
                    changed = true;
                }
            }
        }

        let mut state = block_entry[point.block.0].clone();
        run(&mut state, point.block, point.index);
        state
    }

    // ---------------------------------------------------- clobbers_between --

    /// Whether anything may overwrite `value` on any path from `from` to `to`.
    ///
    /// The answer is exact over the point graph, so a loop back edge that
    /// re-enters the interval is accounted for even when `to` textually
    /// precedes `from`. Three things clobber: an instruction output naming the
    /// storage with a different value, an instruction whose register write set
    /// MIR cannot enumerate, and a phi that merges a different value into the
    /// storage across a traversed edge.
    ///
    /// The value's own re-definition is not a clobber: SSA identity is what is
    /// being tracked, so writing the same `ValueId` again preserves it.
    ///
    /// Fails closed when either point is invalid or unreachable, when no path
    /// runs from `from` to `to`, or when `value` is not the proved state of its
    /// own storage at `from`.
    pub fn clobbers_between(
        &self,
        value: ValueId,
        from: ProgramPoint,
        to: ProgramPoint,
    ) -> ClobberAnswer {
        let Some(record) = self.function.values().get(value.0) else {
            return ClobberAnswer::Unknown(UnknownReason::UnknownValue(value));
        };
        let storage = record.storage;
        for point in [from, to] {
            if let Err(state) = self.validate::<ValueId>(point) {
                return ClobberAnswer::Unknown(match state {
                    DefinitionState::Unknown(reason) => reason,
                    _ => UnknownReason::UnreachablePoint(point),
                });
            }
        }
        match self.value_at(storage, from) {
            DefinitionState::Exact(held) if held == value => {}
            DefinitionState::Unknown(reason) => return ClobberAnswer::Unknown(reason),
            _ => {
                return ClobberAnswer::Unknown(UnknownReason::ValueNotHeldAtOrigin {
                    value,
                    at: from,
                })
            }
        }

        let graph = PointGraph::new(self.function);
        let forward = graph.reach(from, Direction::Forward);
        if !forward[graph.index(to)] {
            return ClobberAnswer::Unknown(UnknownReason::NoPath { from, to });
        }
        let backward = graph.reach(to, Direction::Backward);

        let machine_state = !matches!(self.function.storages()[storage.0].register, VReg::Temp(_));
        let mut sites = Vec::new();
        for block in self
            .function
            .blocks()
            .iter()
            .filter(|block| block.reachable)
        {
            for (index, instruction) in block.instructions.iter().enumerate() {
                let entered = forward[graph.index(ProgramPoint {
                    block: block.id,
                    index,
                })];
                let left = backward[graph.index(ProgramPoint {
                    block: block.id,
                    index: index + 1,
                })];
                if !entered || !left {
                    continue;
                }
                let instruction = &self.function.instructions()[instruction.0];
                let written = instruction
                    .outputs
                    .iter()
                    .find(|output| self.function.value(**output).storage == storage);
                match written {
                    Some(output) if *output != value => sites.push(ClobberKind::Definition {
                        instruction: instruction.id,
                        value: *output,
                    }),
                    Some(_) => {}
                    None if machine_state
                        && instruction.register_effects == EffectCompleteness::Opaque =>
                    {
                        sites.push(ClobberKind::Opaque {
                            instruction: instruction.id,
                        })
                    }
                    None => {}
                }
            }
        }

        for phi in self.function.values() {
            if phi.storage != storage || phi.id == value {
                continue;
            }
            let Definition::Phi { block, incoming } = &phi.definition else {
                continue;
            };
            if !backward[graph.index(ProgramPoint::block_entry(*block))] {
                continue;
            }
            let merged = incoming.iter().find(|(predecessor, source)| {
                *source != value
                    && self
                        .function
                        .blocks()
                        .get(predecessor.0)
                        .is_some_and(|predecessor| {
                            predecessor.reachable
                                && forward[graph.index(ProgramPoint {
                                    block: predecessor.id,
                                    index: predecessor.instructions.len(),
                                })]
                        })
            });
            if let Some((_, source)) = merged {
                sites.push(ClobberKind::Phi {
                    block: *block,
                    value: *source,
                });
            }
        }

        if sites.is_empty() {
            ClobberAnswer::None
        } else {
            sites.sort_by_key(order_key);
            ClobberAnswer::Clobbered(sites)
        }
    }

    // ------------------------------------------------------- reaching sets --

    /// The proved set of definitions reaching a use, resolving through phis.
    pub fn reaching_definitions(&self, use_: UseId) -> ReachingSet {
        match self.function.uses().get(use_.0) {
            Some(record) => self.reaching_definitions_of_value(record.value),
            None => ReachingSet {
                incomplete: vec![UnknownReason::UnknownValue(ValueId(usize::MAX))],
                ..Default::default()
            },
        }
    }

    /// The proved set of definitions a value resolves to, resolving through
    /// phis. Phi cycles terminate: each value is expanded at most once.
    pub fn reaching_definitions_of_value(&self, value: ValueId) -> ReachingSet {
        let mut definitions = BTreeSet::new();
        let mut phis = BTreeSet::new();
        let mut incomplete = Vec::new();
        let mut seen = BTreeSet::from([value]);
        let mut queue = VecDeque::from([value]);
        while let Some(current) = queue.pop_front() {
            let Some(record) = self.function.values().get(current.0) else {
                incomplete.push(UnknownReason::UnknownValue(current));
                continue;
            };
            let Definition::Phi { incoming, .. } = &record.definition else {
                definitions.insert(current);
                continue;
            };
            phis.insert(current);
            if incoming.is_empty() {
                incomplete.push(UnknownReason::BrokenPhiEdge(current));
            }
            for (_, source) in incoming {
                if self.function.values().get(source.0).is_none() {
                    incomplete.push(UnknownReason::BrokenPhiEdge(current));
                    continue;
                }
                if seen.insert(*source) {
                    queue.push_back(*source);
                }
            }
        }
        ReachingSet {
            definitions: definitions.into_iter().collect(),
            phis: phis.into_iter().collect(),
            incomplete,
        }
    }
}

fn order_key(site: &ClobberKind) -> (usize, usize) {
    match site {
        ClobberKind::Definition { instruction, .. } | ClobberKind::Opaque { instruction } => {
            (0, instruction.0)
        }
        ClobberKind::Phi { block, .. } => (1, block.0),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Forward,
    Backward,
}

/// The gap-level control-flow graph: one node per [`ProgramPoint`].
///
/// Instruction-level reachability is what makes `clobbers_between` exact around
/// loops. Block-level reachability cannot distinguish "the interval re-enters
/// this block" from "this block merely lies between the two blocks".
struct PointGraph {
    offsets: Vec<usize>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
}

impl PointGraph {
    fn new(function: &MirFunction) -> Self {
        let mut offsets = Vec::with_capacity(function.blocks().len());
        let mut total = 0;
        for block in function.blocks() {
            offsets.push(total);
            total += block.instructions.len() + 1;
        }
        let mut successors = vec![Vec::new(); total];
        for block in function.blocks() {
            let base = offsets[block.id.0];
            for index in 0..block.instructions.len() {
                successors[base + index].push(base + index + 1);
            }
            let exit = base + block.instructions.len();
            for successor in &block.successors {
                successors[exit].push(offsets[successor.0]);
            }
        }
        let mut predecessors = vec![Vec::new(); total];
        for (node, edges) in successors.iter().enumerate() {
            for successor in edges {
                predecessors[*successor].push(node);
            }
        }
        Self {
            offsets,
            successors,
            predecessors,
        }
    }

    fn index(&self, point: ProgramPoint) -> usize {
        self.offsets[point.block.0] + point.index
    }

    fn reach(&self, seed: ProgramPoint, direction: Direction) -> Vec<bool> {
        let edges = match direction {
            Direction::Forward => &self.successors,
            Direction::Backward => &self.predecessors,
        };
        let mut reached = vec![false; edges.len()];
        let mut queue = VecDeque::from([self.index(seed)]);
        reached[self.index(seed)] = true;
        while let Some(node) = queue.pop_front() {
            for next in &edges[node] {
                if !reached[*next] {
                    reached[*next] = true;
                    queue.push_back(*next);
                }
            }
        }
        reached
    }
}
