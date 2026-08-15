//! Partition one root-keyed memory object into per-variable byte extents.
//!
//! The MIR adapter keys every stack access by the frame's root pointer value,
//! so a whole frame arrives as one object carrying every observed offset. A
//! source variable question ("which bytes belong to the local at -20?") cannot
//! be asked of that shape at all. This module answers it from the accesses
//! themselves, and only from them.
//!
//! Two things separate the answer from a guess:
//!
//! * A **covered run** is a maximal contiguous span of bytes some access
//!   touches. Runs are separated by bytes no access reaches.
//! * Inside a run, every position where an access begins or ends is a
//!   *candidate* variable boundary. A candidate that some single access spans
//!   is [`BoundaryEvidence::Spanned`]: one machine access treats both sides as
//!   one storage unit. A candidate no access spans is
//!   [`BoundaryEvidence::Abutting`]: the accesses neither join nor separate the
//!   two sides.
//!
//! So the model never claims an exact variable layout. It reports a lower and
//! an upper bound ([`ExtentBounds`]) and refuses to report anything at all when
//! an unmodelled access could touch bytes it never saw
//! ([`PartitionConflict`]).

use std::collections::{BTreeMap, BTreeSet};

use super::{LayoutConflict, MemoryObject, ObjectId};

/// Why a partition cannot bound any variable in this object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PartitionConflict {
    /// An access rooted at this object was observed but could not be placed in
    /// its coordinate: a scaled index, or a memory effect the adapter could not
    /// attach. Unobserved bytes may join any two extents.
    UnmodeledAccess,
    /// A pointer into this object reached an operand position that is not a
    /// modelled address, so a callee or an unmodelled operation may touch bytes
    /// this model never observed.
    EscapedRoot,
    /// The object is walked by a cursor with a stride, so a constant offset no
    /// longer names fixed bytes.
    UnboundedCursor,
    /// A pointer into this object was merged at a control-flow join with a
    /// coordinate the adapter could not equate to it, so the merged value
    /// reaches bytes of this object that no observed access names.
    MergedPointer,
    /// The object carries a retained layout conflict that invalidates its
    /// offset coordinate.
    UnresolvedCoordinate,
}

/// What the accesses say about one candidate variable boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BoundaryEvidence {
    /// One access spans this position: both sides are written or read as a
    /// single storage unit. That is machine evidence, not proof that the two
    /// sides belong to one *source* variable.
    Spanned,
    /// Accesses meet at this position and none spans it: the evidence neither
    /// joins nor separates the two sides.
    Abutting,
}

/// One candidate variable boundary interior to a covered run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PartitionBoundary {
    pub at: i64,
    pub evidence: BoundaryEvidence,
}

/// A maximal contiguous span of observed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionExtent {
    pub start: i64,
    pub end: i64,
    /// Interior candidate boundaries, ascending.
    pub boundaries: Vec<PartitionBoundary>,
    /// Indices into [`MemoryObject::accesses`], ascending.
    pub accesses: Vec<usize>,
}

/// Bounds on the extent of the variable that owns one byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentBounds {
    /// Bytes joined to this offset by a CHAIN of overlapping accesses: the
    /// variable is at least this wide.
    ///
    /// The interval between two adjacent [`BoundaryEvidence::Abutting`]
    /// positions contains only spanned positions, and the accesses that span
    /// them necessarily overlap pairwise, so every byte in it is transitively
    /// joined. That is weaker than "one access covers all of it": an inlined
    /// `memcpy` emitting overlapping wide loads can chain across a real source
    /// boundary and widen this bound past the true variable. It is still a
    /// bound on machine evidence, and it is the direction that fails closed —
    /// merging two variables loses a boundary, where narrowing would invent one.
    pub at_least: (i64, i64),
    /// The covered run: no observed access joins this offset to anything outside.
    pub at_most: (i64, i64),
}

/// The per-variable view of one root-keyed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectPartition {
    pub object: ObjectId,
    /// Covered runs, ascending and disjoint.
    pub extents: Vec<PartitionExtent>,
    pub conflicts: BTreeSet<PartitionConflict>,
}

impl ObjectPartition {
    /// The covered run containing `offset`, conflicts notwithstanding.
    pub fn extent_at(&self, offset: i64) -> Option<&PartitionExtent> {
        self.extents
            .iter()
            .find(|extent| extent.start <= offset && offset < extent.end)
    }

    /// Bounds on the variable owning `offset`, or `None` when the evidence does
    /// not support any bound.
    pub fn bounds_at(&self, offset: i64) -> Option<ExtentBounds> {
        if !self.conflicts.is_empty() {
            return None;
        }
        let extent = self.extent_at(offset)?;
        let start = extent
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary.evidence == BoundaryEvidence::Abutting && boundary.at <= offset
            })
            .map(|boundary| boundary.at)
            .next_back()
            .unwrap_or(extent.start);
        let end = extent
            .boundaries
            .iter()
            .filter(|boundary| {
                boundary.evidence == BoundaryEvidence::Abutting && boundary.at > offset
            })
            .map(|boundary| boundary.at)
            .next()
            .unwrap_or(extent.end);
        Some(ExtentBounds {
            at_least: (start, end),
            at_most: (extent.start, extent.end),
        })
    }
}

/// Layout conflicts that invalidate the object's offset coordinate itself.
fn invalidates_coordinate(conflict: LayoutConflict) -> bool {
    match conflict {
        LayoutConflict::MissingOrigin
        | LayoutConflict::ConflictingOrigins
        | LayoutConflict::UnclassifiedDefinition
        | LayoutConflict::ZeroWidthAccess
        | LayoutConflict::NonAddressUse => true,
        // Stride facts describe an array layout over the coordinate; they do
        // not make the coordinate wrong.
        LayoutConflict::MissingStride
        | LayoutConflict::ConflictingStrides
        | LayoutConflict::NegativeOffset
        | LayoutConflict::AccessPastStride => false,
    }
}

/// Partition one finished object from its accesses and the adapter's explicit
/// unmodelled-access reports.
pub(super) fn partition_object(
    object: &MemoryObject,
    observed: &BTreeSet<PartitionConflict>,
) -> ObjectPartition {
    let mut conflicts = observed.clone();
    if object.stride.is_some() {
        conflicts.insert(PartitionConflict::UnboundedCursor);
    }
    for conflict in &object.conflicts {
        if invalidates_coordinate(*conflict) {
            conflicts.insert(PartitionConflict::UnresolvedCoordinate);
        }
    }

    // One interval per access, deduplicated by footprint but keeping every
    // contributing access index.
    let mut footprints = BTreeMap::<(i64, i64), Vec<usize>>::new();
    for (index, access) in object.accesses.iter().enumerate() {
        let Some(end) = access.offset.checked_add(i64::from(access.width)) else {
            conflicts.insert(PartitionConflict::UnresolvedCoordinate);
            continue;
        };
        if end <= access.offset {
            conflicts.insert(PartitionConflict::UnresolvedCoordinate);
            continue;
        }
        footprints
            .entry((access.offset, end))
            .or_default()
            .push(index);
    }

    let mut extents = Vec::<PartitionExtent>::new();
    for ((start, end), accesses) in footprints {
        match extents.last_mut() {
            Some(extent) if start <= extent.end => {
                extent.end = extent.end.max(end);
                extent.accesses.extend(accesses);
            }
            _ => extents.push(PartitionExtent {
                start,
                end,
                boundaries: Vec::new(),
                accesses,
            }),
        }
    }

    for extent in &mut extents {
        extent.accesses.sort_unstable();
        extent.accesses.dedup();
        let footprints = extent
            .accesses
            .iter()
            .map(|index| {
                let access = &object.accesses[*index];
                (access.offset, access.offset + i64::from(access.width))
            })
            .collect::<BTreeSet<_>>();
        let candidates = footprints
            .iter()
            .flat_map(|(start, end)| [*start, *end])
            .filter(|position| *position > extent.start && *position < extent.end)
            .collect::<BTreeSet<_>>();
        extent.boundaries = candidates
            .into_iter()
            .map(|at| PartitionBoundary {
                at,
                evidence: if footprints
                    .iter()
                    .any(|(start, end)| *start < at && at < *end)
                {
                    BoundaryEvidence::Spanned
                } else {
                    BoundaryEvidence::Abutting
                },
            })
            .collect();
    }

    ObjectPartition {
        object: object.id,
        extents,
        conflicts,
    }
}
