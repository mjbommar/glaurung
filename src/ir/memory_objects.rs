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

use crate::ir::memory_ssa::{MemoryRegion, MemoryVersionId};
use crate::ir::mir::{InstructionId, MemoryAccessId, MemoryValueId, ValueId};
use crate::ir::types::VReg;
use crate::ir::use_def::InstrAddr;

mod ast;
pub(crate) mod llir;
pub(crate) mod mir;

pub(crate) use ast::infer_from_ast;

/// Stable identity within one inferred object model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub usize);

/// Stable identity of an object root or of the exact cursor lifetime used by
/// an access. Legacy adapters retain register identities until they migrate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjectIdentity {
    LegacyRegister(VReg),
    MirValue(ValueId),
    AbsoluteAddress(u64),
    TlsAddress { segment: String, offset: i64 },
}

impl From<VReg> for ObjectIdentity {
    fn from(value: VReg) -> Self {
        Self::LegacyRegister(value)
    }
}

impl From<ValueId> for ObjectIdentity {
    fn from(value: ValueId) -> Self {
        Self::MirValue(value)
    }
}

/// How one memory access observes an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccessRole {
    Read,
    Write,
}

/// Provenance available at the current compatibility boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccessSource {
    /// Pre-order statement ordinal in the prepared AST.
    AstStatement(u32),
    /// Exact instruction position in the LLIR CFG.
    LlirInstruction(InstrAddr),
    /// Stable instruction identity in typed MIR.
    MirInstruction(InstructionId),
}

/// Reaching memory state attached to an access at its owning IR boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryStateIdentity {
    Llir(MemoryVersionId),
    Mir(MemoryValueId),
}

/// One affine byte access relative to an object cursor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccessPath {
    pub object: ObjectId,
    /// Exact value lifetime used to compute this access, distinct from the
    /// canonical object root after affine-copy unification.
    pub cursor: ObjectIdentity,
    pub offset: i64,
    pub width: u8,
    pub alignment: u8,
    pub role: AccessRole,
    pub source: AccessSource,
    /// Alias region selected by target/image-backed LLIR classification.
    pub memory_region: Option<MemoryRegion>,
    /// Exact reaching state at the adapter boundary.
    pub memory_state: Option<MemoryStateIdentity>,
    /// Exact MIR memory-effect owner when this access came from typed MIR.
    pub mir_access: Option<MemoryAccessId>,
}

/// Why an observed object cannot yet receive a concrete layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LayoutConflict {
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
pub enum ObjectOrigin {
    GlobalPointerSlot(u64),
    Address(u64),
    TlsAddress { segment: String, offset: i64 },
    StackObject(VReg),
    CallResult(AccessSource),
    ParameterPointee(ValueId),
    StackValue(ValueId),
    Copy { base: VReg, offset: i64 },
    Null,
}

/// One inferred memory object and its retained constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryObject {
    pub id: ObjectId,
    pub identity: ObjectIdentity,
    pub origins: Vec<ObjectOrigin>,
    pub accesses: Vec<AccessPath>,
    pub stride: Option<u64>,
    pub extent: Option<u64>,
    pub conflicts: BTreeSet<LayoutConflict>,
}

/// Deterministic function-local object model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryObjectModel {
    objects: Vec<MemoryObject>,
    by_identity: BTreeMap<ObjectIdentity, ObjectId>,
}

#[derive(Debug, Clone)]
pub(super) struct RawAccess {
    cursor: ObjectIdentity,
    offset: i64,
    width: u8,
    role: AccessRole,
    source: AccessSource,
    memory_region: Option<MemoryRegion>,
    memory_state: Option<MemoryStateIdentity>,
    mir_access: Option<MemoryAccessId>,
}

#[derive(Debug, Clone, Default)]
struct ObjectObservations {
    origins: Vec<ObjectOrigin>,
    accesses: Vec<RawAccess>,
    aliases: BTreeSet<ObjectIdentity>,
    strides: Vec<i64>,
    conflicts: BTreeSet<LayoutConflict>,
}

/// Shared deterministic reducer from adapter observations to object layouts.
#[derive(Debug, Clone, Default)]
pub(super) struct MemoryObjectBuilder {
    observations: BTreeMap<ObjectIdentity, ObjectObservations>,
}

impl MemoryObjectBuilder {
    pub(super) fn observe_access(&mut self, object: impl Into<ObjectIdentity>, access: RawAccess) {
        self.observations
            .entry(object.into())
            .or_default()
            .accesses
            .push(access);
    }

    pub(super) fn observe_alias(
        &mut self,
        object: impl Into<ObjectIdentity>,
        alias: impl Into<ObjectIdentity>,
    ) {
        self.observations
            .entry(object.into())
            .or_default()
            .aliases
            .insert(alias.into());
    }

    pub(super) fn observe_stride(&mut self, base: impl Into<ObjectIdentity>, stride: i64) {
        self.observations
            .entry(base.into())
            .or_default()
            .strides
            .push(stride);
    }

    pub(super) fn observe_origin(&mut self, base: impl Into<ObjectIdentity>, origin: ObjectOrigin) {
        let origins = &mut self.observations.entry(base.into()).or_default().origins;
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }

    pub(super) fn conflict(&mut self, base: impl Into<ObjectIdentity>, conflict: LayoutConflict) {
        self.observations
            .entry(base.into())
            .or_default()
            .conflicts
            .insert(conflict);
    }

    pub(super) fn finish(self) -> MemoryObjectModel {
        let mut objects = Vec::new();
        let mut by_identity = BTreeMap::new();
        for (identity, observation) in self.observations {
            if observation.accesses.is_empty() {
                continue;
            }
            let id = ObjectId(objects.len());
            let mut conflicts = observation.conflicts;
            let origins = observation.origins;
            if origins.is_empty() {
                conflicts.insert(LayoutConflict::MissingOrigin);
            } else if !origins_compatible(&origins) {
                conflicts.insert(LayoutConflict::ConflictingOrigins);
            }
            if observation.accesses.iter().any(|access| access.width == 0) {
                conflicts.insert(LayoutConflict::ZeroWidthAccess);
            }

            let stride_set = observation
                .strides
                .into_iter()
                .filter_map(i64::checked_abs)
                .filter_map(|stride| u64::try_from(stride).ok())
                .filter(|stride| *stride != 0)
                .collect::<BTreeSet<_>>();
            let stride = match stride_set.len() {
                0 => {
                    conflicts.insert(LayoutConflict::MissingStride);
                    None
                }
                1 => stride_set.first().copied(),
                _ => {
                    conflicts.insert(LayoutConflict::ConflictingStrides);
                    None
                }
            };

            let mut access_paths = observation
                .accesses
                .into_iter()
                .map(|access| AccessPath {
                    object: id,
                    cursor: access.cursor,
                    offset: access.offset,
                    width: access.width,
                    alignment: inferred_alignment(access.offset, access.width),
                    role: access.role,
                    source: access.source,
                    memory_region: access.memory_region,
                    memory_state: access.memory_state,
                    mir_access: access.mir_access,
                })
                .collect::<Vec<_>>();
            access_paths.sort();
            access_paths.dedup();

            let extent = stride.and_then(|stride| {
                if access_paths.iter().any(|access| access.offset < 0) {
                    conflicts.insert(LayoutConflict::NegativeOffset);
                    return None;
                }
                let fits = access_paths.iter().all(|access| {
                    u64::try_from(access.offset)
                        .ok()
                        .and_then(|offset| offset.checked_add(u64::from(access.width)))
                        .is_some_and(|end| end <= stride)
                });
                if !fits {
                    conflicts.insert(LayoutConflict::AccessPastStride);
                    return None;
                }
                Some(stride)
            });

            by_identity.insert(identity.clone(), id);
            for alias in observation.aliases {
                by_identity.insert(alias, id);
            }
            objects.push(MemoryObject {
                id,
                identity,
                origins,
                accesses: access_paths,
                stride,
                extent,
                conflicts,
            });
        }
        MemoryObjectModel {
            objects,
            by_identity,
        }
    }
}

fn origins_compatible(origins: &[ObjectOrigin]) -> bool {
    let non_null = origins
        .iter()
        .filter(|origin| !matches!(origin, ObjectOrigin::Null))
        .collect::<Vec<_>>();
    let Some(first) = non_null.first() else {
        return false;
    };
    non_null.iter().all(|origin| *origin == *first)
}

fn inferred_alignment(offset: i64, width: u8) -> u8 {
    let width = width.max(1);
    let offset = offset.unsigned_abs();
    let mut alignment = 1u8;
    while alignment < width
        && alignment <= u8::MAX / 2
        && offset.is_multiple_of(u64::from(alignment.saturating_mul(2)))
    {
        alignment = alignment.saturating_mul(2);
    }
    alignment.min(width)
}

impl MemoryObjectModel {
    pub fn objects(&self) -> &[MemoryObject] {
        &self.objects
    }

    pub fn object(&self, id: ObjectId) -> Option<&MemoryObject> {
        self.objects.get(id.0)
    }

    pub fn object_for_identity(&self, identity: &ObjectIdentity) -> Option<&MemoryObject> {
        let id = self.by_identity.get(identity)?;
        self.object(*id)
    }

    pub fn object_for_value(&self, value: ValueId) -> Option<&MemoryObject> {
        self.object_for_identity(&ObjectIdentity::MirValue(value))
    }

    pub(crate) fn object_for_base(&self, base: &VReg) -> Option<&MemoryObject> {
        self.object_for_identity(&ObjectIdentity::LegacyRegister(base.clone()))
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
