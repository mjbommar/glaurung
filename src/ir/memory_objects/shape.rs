//! Say what SHAPE occupies a bounded region of a memory object.
//!
//! [`super::partition`] answers "which bytes belong to one variable". This
//! module answers the next question — array, aggregate, or overlapping storage
//! — and it answers far fewer of them than the question suggests, because most
//! of the distinctions the C type system draws leave no trace in the machine.
//!
//! # What the accesses can and cannot separate
//!
//! Two shape differences change the *bytes*, so getting them wrong is a
//! wrong-code bug:
//!
//! * an **element stride**, which changes what `a[i]` addresses, and
//! * **overlap**, which changes how large the object is.
//!
//! Everything else is spelling. `int a[2]`, `struct { int x, y; }`, and a
//! four-byte-aligned pair of unrelated locals that the allocator happened to
//! place adjacently all produce the same loads and stores at the same offsets,
//! and an inlined block copy of `char buf[7]` produces exactly the footprints
//! of `struct { int a; short b; char c; }`. No amount of access evidence
//! separates those, so this module does not pretend to: it reports the proven
//! **cells** ([`ObjectShape::Cells`]) and declines to name them.
//!
//! Union versus punned struct is the same story with a sharper edge. Given
//!
//! ```c
//! union  { uint32_t w; struct { uint16_t lo, hi; } h; } u;   // write u.w, read u.h.lo, u.h.hi
//! struct { uint16_t lo, hi; } s;                             // write *(uint32_t *)&s, read s.lo, s.hi
//! ```
//!
//! both emit a 4-byte access at +0 and 2-byte accesses at +0 and +2. The
//! footprint sets are *identical*, so [`ObjectShape::Overlapping`] is where
//! this module stops. Choosing `union` there would fabricate a storage
//! aliasing the source never wrote; choosing `struct` would fabricate a size.
//!
//! Bitfields leave no evidence here at all. The sub-byte partition of
//! `struct { unsigned a : 3, b : 5; }` lives in the mask and shift arithmetic
//! applied to the loaded *value*; the memory operations only ever name the
//! whole container, so the classifier sees one storage unit and says so —
//! [`ObjectShape::Scalar`] when the container is always touched at one width,
//! [`ObjectShape::Overlapping`] when the compiler reaches individual fields
//! with narrower accesses, which GCC does. Both are true statements about the
//! storage. Neither is a bitfield claim, and this module makes none, because
//! it holds no bitfield evidence. Note that the second verdict is *the same
//! verdict a union gets* — a third source shape collapsing onto one machine
//! shape, which is the point.
//!
//! # The one positive shape claim
//!
//! [`super::IndexedAccess`] is the exception. A scaled-index address encodes a
//! stride that no aggregate spelling can imitate, and the affine base proves
//! where index zero lands. That yields [`ObjectShape::Array`], and it is the
//! only finding here that survives the object being otherwise unbounded — the
//! very access that proves it is also the one that made the partition refuse.
//!
//! Its element COUNT is deliberately absent. Nothing in the address arithmetic
//! bounds the index, and the covered runs cannot be trusted in an object that
//! has an unmodelled access in it, which an indexed access always is. Rule 8:
//! the end of the region is an explicit `None`, not a guess.

use std::collections::BTreeMap;

use super::partition::{BoundaryEvidence, ObjectPartition, PartitionConflict, PartitionExtent};
use super::MemoryObject;

/// Why a region carries no shape claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ShapeRefusal {
    /// The partition refused to bound any variable in this object, so no
    /// region of it is a region of anything in particular.
    UnboundedObject,
    /// A runtime index scales into this region by a stride that is not the
    /// width of the access using it, so the access reads only PART of the
    /// indexed unit and nothing observed says what the rest of it is.
    ///
    /// `(%rbp,%rax,16)` with a 4-byte load is an array of 16-byte elements
    /// whose first field is being read — but it is equally a 4-byte-element
    /// array walked with a pre-multiplied index, and the address arithmetic
    /// alone does not choose. [`ObjectShape::Array`] promises that each access
    /// reads exactly one unit; here that promise cannot be kept.
    UnprovenIndexStride,
    /// Two runtime-indexed accesses at the same offset disagree about the
    /// stride. Both observations are retained on the object; neither wins.
    ConflictingIndexStrides,
}

/// What occupies one region of an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectShape {
    /// Exactly one access footprint, and it is the whole region: one storage
    /// unit of that width. A bitfield container looks exactly like this.
    Scalar { width: u8 },
    /// A runtime index scales into this region by `element` bytes per unit and
    /// each access reads exactly one such unit. The region's end is not proven.
    ///
    /// "Array" here is a claim about *storage*, not spelling: the bytes at
    /// `start` are addressed as a sequence of `element`-byte units. Whether
    /// the source called a unit an element or a struct is the same undecidable
    /// question as [`ObjectShape::Cells`].
    Array { element: u8 },
    /// Two or more storage units the accesses prove separable, ascending,
    /// disjoint, and covering the region exactly. An aggregate, but *which*
    /// aggregate is not decidable here: see the module documentation.
    ///
    /// Each cell carries its own shape, which is always [`Self::Scalar`] or
    /// [`Self::Overlapping`] — a cell is bounded by positions no access spans,
    /// so it can neither be subdivided further nor contain an indexed region
    /// this model would have refused instead.
    Cells { cells: Vec<ShapeFinding> },
    /// Access footprints in this region overlap. A union and a struct read
    /// through a pun produce the same evidence, so neither is claimed.
    ///
    /// `container` is the width of the single footprint that covers the whole
    /// region, when one exists — the widest storage unit the machine treats
    /// these bytes as. That is proven; what aliases inside it is not.
    Overlapping { container: Option<u8> },
    /// No claim, with the reason.
    Unclassified(ShapeRefusal),
}

/// What occupies one region of an object, in that object's byte coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeFinding {
    pub start: i64,
    /// One past the last byte, or `None` when the evidence proves where the
    /// region begins but not where it ends.
    pub end: Option<i64>,
    pub shape: ObjectShape,
}

/// Whether the object's byte coordinate itself still means anything.
///
/// An unmodelled or escaping access leaves the coordinate intact and only
/// costs the partition its bounds. A walking cursor or a broken origin does
/// not: a constant offset then names no fixed bytes, and an
/// [`ObjectShape::Array`] anchored at one would be anchored at nothing.
fn coordinate_holds(partition: &ObjectPartition) -> bool {
    !partition.conflicts.iter().any(|conflict| {
        matches!(
            conflict,
            PartitionConflict::UnboundedCursor | PartitionConflict::UnresolvedCoordinate
        )
    })
}

/// Classify every region of one object the evidence reaches.
///
/// Findings are ascending by start offset and never overlap in practice: an
/// object with a runtime-indexed access always carries
/// [`PartitionConflict::UnmodeledAccess`], so its covered runs are all
/// refused, and an object without one contributes no array findings.
pub(super) fn classify_object(
    object: &MemoryObject,
    partition: &ObjectPartition,
) -> Vec<ShapeFinding> {
    let mut findings = Vec::new();

    for extent in &partition.extents {
        let shape = if partition.conflicts.is_empty() {
            classify_extent(object, extent)
        } else {
            ObjectShape::Unclassified(ShapeRefusal::UnboundedObject)
        };
        findings.push(ShapeFinding {
            start: extent.start,
            end: Some(extent.end),
            shape,
        });
    }

    if coordinate_holds(partition) {
        let mut indexed = BTreeMap::<i64, Vec<(u8, u8)>>::new();
        for access in &object.indexed_accesses {
            indexed
                .entry(access.offset)
                .or_default()
                .push((access.stride, access.width));
        }
        for (offset, units) in indexed {
            findings.push(ShapeFinding {
                start: offset,
                end: None,
                shape: classify_indexed_region(&units),
            });
        }
    }

    findings.sort_by_key(|finding| (finding.start, finding.end));
    findings
}

/// Classify the runtime-indexed accesses that share one base offset, as
/// `(stride, width)` pairs.
///
/// The pairs come from an ascending, deduplicated list, so a disagreement about
/// the stride shows up between adjacent entries.
fn classify_indexed_region(units: &[(u8, u8)]) -> ObjectShape {
    let Some((stride, _)) = units.first() else {
        return ObjectShape::Unclassified(ShapeRefusal::UnprovenIndexStride);
    };
    if units.iter().any(|(other, _)| other != stride) {
        return ObjectShape::Unclassified(ShapeRefusal::ConflictingIndexStrides);
    }
    // Every access must read exactly one unit of the stride it walks; see
    // `ShapeRefusal::UnprovenIndexStride` for what a partial read leaves open.
    if units.iter().all(|(stride, width)| stride == width) {
        ObjectShape::Array { element: *stride }
    } else {
        ObjectShape::Unclassified(ShapeRefusal::UnprovenIndexStride)
    }
}

/// Classify one covered run of a partition that refused nothing.
fn classify_extent(object: &MemoryObject, extent: &PartitionExtent) -> ObjectShape {
    // An abutting boundary is a position no single access treats as interior
    // to one storage unit, so it separates two of them.
    let mut edges = Vec::new();
    let mut cursor = extent.start;
    for boundary in &extent.boundaries {
        if boundary.evidence == BoundaryEvidence::Abutting {
            edges.push((cursor, boundary.at));
            cursor = boundary.at;
        }
    }
    edges.push((cursor, extent.end));

    if let [(start, end)] = edges.as_slice() {
        return classify_cell(object, extent, *start, *end);
    }
    ObjectShape::Cells {
        cells: edges
            .into_iter()
            .map(|(start, end)| ShapeFinding {
                start,
                end: Some(end),
                shape: classify_cell(object, extent, start, end),
            })
            .collect(),
    }
}

/// Classify one indivisible storage unit: either a single footprint owns it,
/// or several overlapping ones do.
///
/// Every footprint of the enclosing run lies wholly inside exactly one cell,
/// because a cell edge is a position no access spans.
fn classify_cell(
    object: &MemoryObject,
    extent: &PartitionExtent,
    start: i64,
    end: i64,
) -> ObjectShape {
    let mut footprints = extent
        .accesses
        .iter()
        .map(|index| {
            let access = &object.accesses[*index];
            (access.offset, access.width)
        })
        .filter(|(offset, _)| *offset >= start && *offset < end)
        .collect::<Vec<_>>();
    footprints.sort_unstable();
    footprints.dedup();
    let covers = |(offset, width): &(i64, u8)| *offset == start && i64::from(*width) == end - start;
    match footprints.as_slice() {
        [only] if covers(only) => ObjectShape::Scalar { width: only.1 },
        _ => ObjectShape::Overlapping {
            container: footprints
                .iter()
                .find(|f| covers(f))
                .map(|(_, width)| *width),
        },
    }
}
