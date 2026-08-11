//! Common inferred memory objects and affine access paths.
//!
//! This is the compatibility seam for aggregate recovery while the decompiler
//! migrates from the legacy structured AST to MIR.  The facts are deliberately
//! independent of C spelling and debug formats: an object has an identity, a
//! base value, observed byte accesses, layout constraints, and explicit
//! conflicts.  The current collector consumes prepared AST because that is
//! where promoted stack cursors exist today; future MIR and DWARF/PDB adapters
//! should populate the same model instead of adding more renderer-only hints.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::types::VReg;

mod ast;

pub(crate) use ast::infer_from_ast;

/// Stable identity within one inferred object model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ObjectId(u32);

/// Stable identity of one reaching memory state in the eventual MIR adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct MemoryVersionId(u32);

/// How one memory access observes an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum AccessRole {
    Read,
    Write,
}

/// Provenance available at the current compatibility boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum AccessSource {
    /// Pre-order statement ordinal in the prepared AST.
    AstStatement(u32),
}

/// One affine byte access relative to an object cursor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct AccessPath {
    pub(crate) object: ObjectId,
    pub(crate) offset: i64,
    pub(crate) width: u8,
    pub(crate) alignment: u8,
    pub(crate) role: AccessRole,
    pub(crate) source: AccessSource,
    /// Filled by the MIR/MemorySSA adapter when that owner is installed.
    pub(crate) memory_version: Option<MemoryVersionId>,
}

/// Why an observed object cannot yet receive a concrete layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum LayoutConflict {
    MissingOrigin,
    ConflictingOrigins,
    MissingStride,
    ConflictingStrides,
    UnclassifiedDefinition,
    ZeroWidthAccess,
    NegativeOffset,
    AccessPastStride,
    NonAddressUse,
}

/// Conservative origin classification for a cursor value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ObjectOrigin {
    GlobalPointerSlot(u64),
    Address(u64),
    StackObject(VReg),
    CallResult(AccessSource),
    Copy { base: VReg, offset: i64 },
    Null,
}

/// One inferred memory object and its retained constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemoryObject {
    pub(crate) id: ObjectId,
    pub(crate) base: VReg,
    pub(crate) origins: Vec<ObjectOrigin>,
    pub(crate) accesses: Vec<AccessPath>,
    pub(crate) stride: Option<u64>,
    pub(crate) extent: Option<u64>,
    pub(crate) conflicts: BTreeSet<LayoutConflict>,
}

/// Deterministic function-local object model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MemoryObjectModel {
    objects: Vec<MemoryObject>,
    by_base: BTreeMap<VReg, ObjectId>,
}

impl MemoryObjectModel {
    pub(crate) fn object_for_base(&self, base: &VReg) -> Option<&MemoryObject> {
        let id = self.by_base.get(base)?;
        self.objects.get(id.0 as usize)
    }

    /// Whether this base has one conflict-free, concretely bounded layout.
    pub(crate) fn has_conflict_free_extent(&self, base: &VReg) -> bool {
        let Some(object) = self.object_for_base(base) else {
            return false;
        };
        object.extent.is_some() && !object.accesses.is_empty() && object.conflicts.is_empty()
    }
}

#[cfg(test)]
#[path = "memory_objects_tests.rs"]
mod tests;
