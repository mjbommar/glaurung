//! Stable, arena-backed MIR identities and records.

use crate::ir::memory_objects::{MemoryObject, MemoryObjectModel, ObjectId};
use crate::ir::types::{VReg, Width};
use crate::target::TargetSpec;

pub use crate::ir::memory_ssa::{MemoryAccessKind, MemoryRegion};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub usize);
    };
}

id_type!(BlockId);
id_type!(InstructionId);
id_type!(StorageId);
id_type!(ValueId);
id_type!(UseId);
id_type!(MemoryValueId);
id_type!(MemoryAccessId);

/// Exact owner of a memory state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryDefinition {
    Entry {
        region: MemoryRegion,
    },
    InstructionOutput {
        access: MemoryAccessId,
    },
    Phi {
        block: BlockId,
        region: MemoryRegion,
        /// `None` is the implicit function-entry edge of a looping entry block.
        incoming: Vec<(Option<BlockId>, MemoryValueId)>,
    },
}

/// One stable memory-state identity in the MIR arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirMemoryValue {
    pub id: MemoryValueId,
    pub region: MemoryRegion,
    pub definition: MemoryDefinition,
}

/// One instruction's use and optional definition of a memory region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirMemoryAccess {
    pub id: MemoryAccessId,
    pub instruction: InstructionId,
    pub region: MemoryRegion,
    pub kind: MemoryAccessKind,
    pub input: MemoryValueId,
    pub output: Option<MemoryValueId>,
    /// Canonical object observed by this exact effect, when its address has a
    /// proven affine MIR identity.
    pub object: Option<ObjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    Input,
    InstructionOutput {
        instruction: InstructionId,
        output_index: usize,
    },
    Phi {
        block: BlockId,
        incoming: Vec<(BlockId, ValueId)>,
    },
    Undef {
        instruction: InstructionId,
        reason: String,
    },
    UnknownEffect {
        instruction: InstructionId,
        output_index: usize,
    },
    Unreachable {
        block: BlockId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirStorage {
    pub id: StorageId,
    pub register: VReg,
    pub width: Option<Width>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirValue {
    pub id: ValueId,
    pub storage: StorageId,
    pub width: Option<Width>,
    pub definition: Definition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirUse {
    pub id: UseId,
    pub instruction: InstructionId,
    pub index: usize,
    pub value: ValueId,
    pub storage: StorageId,
    pub width: Option<Width>,
}

/// How completely MIR enumerates one instruction's *register* effects.
///
/// Non-negotiable rule 5: unknown calls and instructions clobber
/// conservatively, and unknown never means "no effect". An unannotated call
/// contributes no register definition at all, so the raw SSA use edge after it
/// still names the pre-call value. Marking the instruction [`Opaque`] is what
/// lets the definedness queries refuse to repeat that claim instead of
/// silently carrying a stale value across the callee.
///
/// This is about the *footprint*, not the values. A multi-output intrinsic
/// declares exactly which storages it writes, so it is [`Complete`] even though
/// each declared output is a [`Definition::UnknownEffect`] value.
///
/// [`Opaque`]: EffectCompleteness::Opaque
/// [`Complete`]: EffectCompleteness::Complete
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EffectCompleteness {
    /// Every storage this instruction may write has a MIR output value.
    Complete,
    /// The instruction may write machine storages MIR cannot name.
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirInstruction {
    pub id: InstructionId,
    pub block: BlockId,
    pub index: usize,
    pub source_va: u64,
    pub uses: Vec<UseId>,
    pub outputs: Vec<ValueId>,
    pub memory_effects: Vec<MemoryAccessId>,
    /// Whether [`Self::outputs`] is the complete register write set.
    pub register_effects: EffectCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirBlock {
    pub id: BlockId,
    pub start_va: u64,
    pub end_va: u64,
    pub predecessors: Vec<BlockId>,
    pub successors: Vec<BlockId>,
    pub instructions: Vec<InstructionId>,
    pub reachable: bool,
}

#[derive(Debug, Clone)]
pub struct MirFunction {
    pub target: TargetSpec,
    pub entry: BlockId,
    pub(crate) blocks: Vec<MirBlock>,
    pub(crate) instructions: Vec<MirInstruction>,
    pub(crate) storages: Vec<MirStorage>,
    pub(crate) values: Vec<MirValue>,
    pub(crate) uses: Vec<MirUse>,
    pub(crate) memory_values: Vec<MirMemoryValue>,
    pub(crate) memory_accesses: Vec<MirMemoryAccess>,
    pub(crate) object_model: MemoryObjectModel,
}

impl MirFunction {
    pub fn blocks(&self) -> &[MirBlock] {
        &self.blocks
    }

    pub fn instructions(&self) -> &[MirInstruction] {
        &self.instructions
    }

    pub fn storages(&self) -> &[MirStorage] {
        &self.storages
    }

    pub fn values(&self) -> &[MirValue] {
        &self.values
    }

    pub fn uses(&self) -> &[MirUse] {
        &self.uses
    }

    pub fn memory_values(&self) -> &[MirMemoryValue] {
        &self.memory_values
    }

    pub fn memory_accesses(&self) -> &[MirMemoryAccess] {
        &self.memory_accesses
    }

    pub fn objects(&self) -> &[MemoryObject] {
        self.object_model.objects()
    }

    pub fn object_for_value(&self, value: ValueId) -> Option<&MemoryObject> {
        self.object_model.object_for_value(value)
    }

    pub fn value(&self, id: ValueId) -> &MirValue {
        &self.values[id.0]
    }

    pub fn use_(&self, id: UseId) -> &MirUse {
        &self.uses[id.0]
    }

    pub fn memory_value(&self, id: MemoryValueId) -> &MirMemoryValue {
        &self.memory_values[id.0]
    }

    #[cfg(test)]
    pub(crate) fn use_mut_for_test(&mut self, id: UseId) -> &mut MirUse {
        &mut self.uses[id.0]
    }

    #[cfg(test)]
    pub(crate) fn storage_mut_for_test(&mut self, id: StorageId) -> &mut MirStorage {
        &mut self.storages[id.0]
    }

    #[cfg(test)]
    pub(crate) fn memory_access_mut_for_test(
        &mut self,
        id: MemoryAccessId,
    ) -> &mut MirMemoryAccess {
        &mut self.memory_accesses[id.0]
    }

    #[cfg(test)]
    pub(crate) fn memory_value_mut_for_test(&mut self, id: MemoryValueId) -> &mut MirMemoryValue {
        &mut self.memory_values[id.0]
    }
}
