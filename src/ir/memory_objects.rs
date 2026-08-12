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
use crate::ir::types::VReg;
use crate::ir::use_def::InstrAddr;

mod ast;
pub(crate) mod llir;

pub(crate) use ast::infer_from_ast;

/// Stable identity within one inferred object model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ObjectId(u32);

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
    /// Exact instruction position in the LLIR CFG.
    LlirInstruction(InstrAddr),
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
    /// Alias region selected by target/image-backed LLIR classification.
    pub(crate) memory_region: Option<MemoryRegion>,
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

#[derive(Debug, Clone)]
pub(super) struct RawAccess {
    offset: i64,
    width: u8,
    role: AccessRole,
    source: AccessSource,
    memory_region: Option<MemoryRegion>,
    memory_version: Option<MemoryVersionId>,
}

#[derive(Debug, Clone, Default)]
struct ObjectObservations {
    origins: Vec<ObjectOrigin>,
    accesses: Vec<RawAccess>,
    strides: Vec<i64>,
    conflicts: BTreeSet<LayoutConflict>,
}

/// Shared deterministic reducer from adapter observations to object layouts.
#[derive(Debug, Clone, Default)]
pub(super) struct MemoryObjectBuilder {
    observations: BTreeMap<VReg, ObjectObservations>,
}

impl MemoryObjectBuilder {
    pub(super) fn observe_access(
        &mut self,
        base: VReg,
        offset: i64,
        width: u8,
        role: AccessRole,
        source: AccessSource,
        memory_region: Option<MemoryRegion>,
        memory_version: Option<MemoryVersionId>,
    ) {
        self.observations
            .entry(base.clone())
            .or_default()
            .accesses
            .push(RawAccess {
                offset,
                width,
                role,
                source,
                memory_region,
                memory_version,
            });
    }

    pub(super) fn observe_stride(&mut self, base: VReg, stride: i64) {
        self.observations
            .entry(base)
            .or_default()
            .strides
            .push(stride);
    }

    pub(super) fn observe_origin(&mut self, base: VReg, origin: ObjectOrigin) {
        self.observations
            .entry(base)
            .or_default()
            .origins
            .push(origin);
    }

    pub(super) fn conflict(&mut self, base: VReg, conflict: LayoutConflict) {
        self.observations
            .entry(base)
            .or_default()
            .conflicts
            .insert(conflict);
    }

    pub(super) fn finish(self) -> MemoryObjectModel {
        let mut objects = Vec::new();
        let mut by_base = BTreeMap::new();
        for (base, observation) in self.observations {
            if observation.accesses.is_empty() {
                continue;
            }
            let id = ObjectId(objects.len() as u32);
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
                    offset: access.offset,
                    width: access.width,
                    alignment: inferred_alignment(access.offset, access.width),
                    role: access.role,
                    source: access.source,
                    memory_region: access.memory_region,
                    memory_version: access.memory_version,
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

            by_base.insert(base.clone(), id);
            objects.push(MemoryObject {
                id,
                base,
                origins,
                accesses: access_paths,
                stride,
                extent,
                conflicts,
            });
        }
        MemoryObjectModel { objects, by_base }
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
