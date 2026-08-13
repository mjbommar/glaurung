//! Stable, arena-backed MIR identities and records.

use crate::ir::types::{VReg, Width};
use crate::target::TargetSpec;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirInstruction {
    pub id: InstructionId,
    pub block: BlockId,
    pub index: usize,
    pub source_va: u64,
    pub uses: Vec<UseId>,
    pub outputs: Vec<ValueId>,
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

    pub fn value(&self, id: ValueId) -> &MirValue {
        &self.values[id.0]
    }

    pub fn use_(&self, id: UseId) -> &MirUse {
        &self.uses[id.0]
    }

    #[cfg(test)]
    pub(crate) fn use_mut_for_test(&mut self, id: UseId) -> &mut MirUse {
        &mut self.uses[id.0]
    }

    #[cfg(test)]
    pub(crate) fn storage_mut_for_test(&mut self, id: StorageId) -> &mut MirStorage {
        &mut self.storages[id.0]
    }
}
