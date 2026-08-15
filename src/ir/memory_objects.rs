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

use crate::ir::memory_ssa::MemoryRegion;
use crate::ir::mir::{InstructionId, MemoryAccessId, MemoryValueId, ValueId};
use crate::ir::types::VReg;

mod ast;
pub(crate) mod mir;
mod partition;

pub(crate) use ast::infer_from_ast;
pub use partition::{
    BoundaryEvidence, ExtentBounds, ObjectPartition, PartitionBoundary, PartitionConflict,
    PartitionExtent,
};

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
    /// Stable instruction identity in typed MIR.
    MirInstruction(InstructionId),
}

/// Reaching memory state attached to an access at its owning IR boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryStateIdentity {
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
    /// Offset, in this object's byte coordinate, of each machine register whose
    /// value was used as an address cursor into it.
    ///
    /// This is the MIR half of the join to
    /// [`crate::ir::stack_locals::StackLocalFacts::frame_coordinates`], which
    /// publishes `(base, disp)` per promoted local NAME. The two models place
    /// their zero differently — the AST anchors on a named base register, MIR
    /// on the root pointer value — and this map is the only evidence that
    /// relates them.
    ///
    /// A register observed at two different offsets keeps BOTH (rule 3: a
    /// conflict is retained, the evidence that produced it is not destroyed).
    /// `resolve_frame_coordinate` turns that into an explicit
    /// [`FrameCoordinate::AmbiguousBase`] instead of picking a winner —
    /// binding a proven extent through an ambiguous base would attach it to the
    /// wrong bytes, and dropping the register would misreport it as a base this
    /// object is not addressed through at all.
    pub base_offsets: BTreeMap<String, BTreeSet<i64>>,
}

/// Where one AST frame coordinate lands in the object model, or why it does not.
///
/// Rule 8: a failed proof is an explicit, distinguishable unknown, never an
/// absent fact that a caller could read as "no evidence against".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCoordinate {
    /// The coordinate resolved to exactly one object and byte offset.
    Resolved { object: ObjectId, offset: i64 },
    /// No object in this model is addressed through that base.
    UnknownBase,
    /// The base addresses more than one object, or the same object at more
    /// than one offset, so it names no fixed bytes.
    AmbiguousBase,
    /// The displacement does not fit the object's coordinate.
    OffsetOverflow,
}

/// Deterministic function-local object model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryObjectModel {
    objects: Vec<MemoryObject>,
    by_identity: BTreeMap<ObjectIdentity, ObjectId>,
    /// One partition per object, in `ObjectId` order.
    partitions: Vec<ObjectPartition>,
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
    partition_conflicts: BTreeSet<PartitionConflict>,
    base_offsets: BTreeMap<String, BTreeSet<i64>>,
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

    /// Record that `register` held this object's address at `offset` in its own
    /// coordinate. Only an adapter that resolved the cursor affinely may say
    /// this; the reduction below withholds a register seen at two offsets.
    pub(super) fn observe_base_offset(
        &mut self,
        base: impl Into<ObjectIdentity>,
        register: &str,
        offset: i64,
    ) {
        self.observations
            .entry(base.into())
            .or_default()
            .base_offsets
            .entry(register.to_string())
            .or_default()
            .insert(offset);
    }

    /// Report an access this adapter could not model in the object's own
    /// coordinate. The partition must not bound any variable once one exists.
    pub(super) fn partition_conflict(
        &mut self,
        base: impl Into<ObjectIdentity>,
        conflict: PartitionConflict,
    ) {
        self.observations
            .entry(base.into())
            .or_default()
            .partition_conflicts
            .insert(conflict);
    }

    pub(super) fn finish(self) -> MemoryObjectModel {
        let mut objects = Vec::new();
        let mut by_identity = BTreeMap::new();
        let mut partition_conflicts = Vec::new();
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
            partition_conflicts.push(observation.partition_conflicts);
            let base_offsets = observation.base_offsets;
            objects.push(MemoryObject {
                id,
                identity,
                origins,
                accesses: access_paths,
                stride,
                extent,
                conflicts,
                base_offsets,
            });
        }
        let partitions = objects
            .iter()
            .zip(&partition_conflicts)
            .map(|(object, conflicts)| partition::partition_object(object, conflicts))
            .collect();
        MemoryObjectModel {
            objects,
            by_identity,
            partitions,
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

    /// The per-variable byte partition of one object's observed accesses.
    pub fn partition(&self, id: ObjectId) -> Option<&ObjectPartition> {
        self.partitions.get(id.0)
    }

    /// Translate one AST frame coordinate into this model's byte coordinate.
    ///
    /// `base`/`disp` is exactly the pair
    /// [`crate::ir::stack_locals::StackLocalFacts::frame_coordinates`] publishes
    /// for a promoted local. Composing this with [`Self::partition`] and
    /// [`ObjectPartition::bounds_at`] is the whole join from a promoted-local
    /// NAME to evidence-backed byte bounds:
    ///
    /// ```text
    /// name --frame_coordinates--> (base, disp)
    ///      --resolve_frame_coordinate--> (object, offset)
    ///      --partition(object).bounds_at(offset)--> at_least / at_most, or a refusal
    /// ```
    ///
    /// Two base spellings exist and they mean different things. The pass mints
    /// `entry_rsp`/`entry_sp` for the architectural entry stack pointer, which
    /// is the object's own root — offset zero, no register lookup, and true on
    /// every target regardless of what the machine calls that register. Every
    /// other spelling names a machine register, and only
    /// [`MemoryObject::base_offsets`] can say where that register pointed.
    pub fn resolve_frame_coordinate(&self, base: &str, disp: i64) -> FrameCoordinate {
        let base = crate::ir::abi::ssa_base(base);
        let mut claims = self.objects.iter().filter_map(|object| {
            if matches!(base, "entry_rsp" | "entry_sp") {
                return object
                    .origins
                    .iter()
                    .any(|origin| matches!(origin, ObjectOrigin::StackValue(_)))
                    .then_some((object.id, Some(0)));
            }
            let offsets = object.base_offsets.get(base)?;
            let mut offsets = offsets.iter().copied();
            let first = offsets.next();
            Some((object.id, offsets.next().is_none().then_some(first?)))
        });
        let Some((object, offset)) = claims.next() else {
            return FrameCoordinate::UnknownBase;
        };
        if claims.next().is_some() {
            return FrameCoordinate::AmbiguousBase;
        }
        // One object, but the register pointed at more than one of its offsets.
        let Some(offset) = offset else {
            return FrameCoordinate::AmbiguousBase;
        };
        match offset.checked_add(disp) {
            Some(offset) => FrameCoordinate::Resolved { object, offset },
            None => FrameCoordinate::OffsetOverflow,
        }
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

#[cfg(test)]
#[path = "memory_objects/partition_tests.rs"]
mod partition_tests;
