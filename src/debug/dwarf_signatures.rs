//! Source-level call signatures, recovered from DWARF as EXECUTABLE contracts.
//!
//! # Why this is separate from [`crate::debug::dwarf`]
//!
//! That module answers "what does this function look like" and spells types as
//! C-like strings (`"int"`, `"struct foo *"`). A string is the right answer for
//! a renderer and the wrong one for a caller: to actually invoke a recovered
//! function through `ctypes` the harness needs the exact width and signedness of
//! every scalar, the layout of every aggregate, and a refusal — not a guess —
//! for anything it cannot marshal. So this module produces a structured
//! [`DwarfType`] instead, and is deliberately CONSERVATIVE: an unsupported type
//! yields `None` for the whole signature, which degrades that function to the
//! structural lane rather than executing it against a contract nobody can state.
//!
//! # Why it exists at all
//!
//! `tools/diff_decompile.py` had a second, independent DWARF reader built on
//! pyelftools — a duplicate parser used by nothing but the test harness, and the
//! source of the crashes chased on 2026-08-12: cross-CU references resolved
//! against the wrong compilation unit, `DW_FORM_strp` offsets that report
//! `value=None`, and abbrev tables decoded lazily with the wrong CU. A Rust
//! object under test is the thing that turns those up (a `cdylib` carries the
//! fixture plus std, core, alloc and panic_unwind — 13 units), and every one of
//! them was a defect in the harness rather than in Glaurung.
//!
//! Reading the same DWARF through the same `gimli` code the product uses removes
//! that class of failure outright, and makes a harness crash mean something.
//!
//! # What is refused, and why refusing is the point
//!
//! * a float that is not binary32/binary64 — x87's 80-bit `long double`,
//!   `_Float16`, ARM's `__fp16`. Their bit patterns are not exactly stateable
//!   here and a lossy Python `float` would compare equal when it should not;
//! * an integer that is not 1/2/4/8 bytes;
//! * a bit-field, or a struct member whose location is not a plain constant
//!   offset;
//! * an array with no stateable bound — a flexible array member, `int v[]` —
//!   because dividing a declared size by an element size would invent an
//!   extent nobody wrote;
//! * any pointer to an aggregate other than a link back to the struct being
//!   described, which is encoded nominally as [`DwarfType::SelfPointer`]
//!   instead of recursing forever.
//!
//! # What a FLOATING-POINT struct member is not
//!
//! It used to be on that list, with the reason "the SysV eightbyte classifier
//! puts an all-float aggregate in SSE registers rather than INTEGER ones, so
//! supporting one would mean guessing an ABI this cannot state". Nothing here
//! ever classified an eightbyte: the harness hands the descriptor to `ctypes`,
//! and libffi applies the platform's own return- and argument-class rules to
//! the layout. Declining the member did not avoid a guess, it withheld the one
//! shape whose classification is most worth checking.
//!
//! Measured on 2026-08-18, that refusal was silently dropping SIX functions
//! from `197_homogeneous_float_aggregates` and `195_by_value_aggregates` — the
//! two fixtures written to exercise exactly these classes — and every one of
//! their cells reported `structural` with the detail "signature not recoverable
//! from DWARF" rather than a verdict. The aggregate-return work therefore had
//! no executable coverage at all outside all-integer shapes.
//!
//! The same measurement found two more shapes with the same symptom and the
//! same non-reason: an ARRAY member and a UNION. Both are now described
//! ([`DwarfType::Array`], [`DwarfType::Union`]), and both were verified against
//! the C ABI before the descriptor existed — `libffi` returns
//! `union {int64_t; double;}` and `struct {int32_t v[2];}` by value correctly
//! through `ctypes`, so the descriptor is the only thing that was missing.

use std::collections::HashSet;

use object::{Object, ObjectSection};

/// One executable type contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwarfType {
    /// No `DW_AT_type`, which DWARF uses for `void`.
    Void,
    /// An integer of this byte width (1, 2, 4 or 8).
    Int { width: u8, signed: bool },
    /// IEEE binary32 or binary64, by byte width (4 or 8).
    Float { width: u8 },
    /// A data pointer. `konst` records a `const`-qualified pointee, which the
    /// harness needs to spell the rebuilt declaration.
    Pointer {
        pointee: Box<DwarfType>,
        konst: bool,
    },
    /// A pointer back to the aggregate currently being described. Encoded
    /// nominally: embedding the descriptor recursively would not terminate, and
    /// the harness only needs its width to marshal one.
    SelfPointer { width: u8 },
    /// A plain data struct, fields in ascending offset order.
    ///
    /// `name` is the tag or typedef spelling, and is `Some` only where a
    /// POINTER refers to it — the harness needs it to declare the pointee in
    /// the rebuilt translation unit, and a by-value aggregate is declared
    /// inline where no name is required.
    Struct {
        byte_size: u64,
        fields: Vec<DwarfField>,
        name: Option<String>,
    },
    /// A UNION: every member at offset zero, sharing one storage.
    ///
    /// Deliberately its own variant rather than a `Struct` whose members all
    /// sit at offset zero. The harness builds an exact `ctypes` layout from
    /// these descriptors, and `_struct_ctype` refuses overlapping members on
    /// purpose — a union spelled as a struct would either be rejected or, worse,
    /// silently laid out sequentially at the wrong size.
    ///
    /// Members are named for reading the SAME bytes back at each declared type,
    /// which is the only thing a differential can do with a union: a snapshot
    /// records every member's view of one storage, and two builds that agree on
    /// all of them agree on the bytes.
    Union {
        byte_size: u64,
        fields: Vec<DwarfField>,
        name: Option<String>,
    },
    /// A fixed-length array of `count` elements.
    ///
    /// `count` is required, not inferred from the byte size: a flexible or
    /// unbounded array member has no marshallable extent, and dividing a
    /// declared size by an element size would invent one.
    Array { element: Box<DwarfType>, count: u64 },
}

/// One struct member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfField {
    pub name: String,
    pub offset: u64,
    pub ty: DwarfType,
}

/// One function's executable contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfSignature {
    pub name: String,
    /// Entry VA from `DW_AT_low_pc`. Zero when the subprogram is described only
    /// by `DW_AT_ranges`; the caller supplies the address from the dynamic
    /// symbol table in that case, exactly as the previous reader did.
    pub va: u64,
    pub parameters: Vec<DwarfType>,
    pub result: DwarfType,
}

/// `DW_ATE_*` encodings accepted as signed integers.
const SIGNED_ENCODINGS: [u16; 3] = [0x05, 0x06, 0x0d];
/// `DW_ATE_*` encodings accepted as unsigned integers.
const UNSIGNED_ENCODINGS: [u16; 4] = [0x02, 0x07, 0x08, 0x0e];
/// `DW_ATE_float`.
const FLOAT_ENCODING: u16 = 0x04;
/// Ceiling on an aggregate this harness will marshal.
const MAX_STRUCT_BYTES: u64 = 256;
/// Bound on any wrapper chain (`typedef`/`const`/`volatile`) walk.
const MAX_WRAPPER_DEPTH: usize = 16;

type Slice<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;
type Unit<'a> = gimli::Unit<Slice<'a>, usize>;

/// Every subprogram whose complete signature this can state exactly.
///
/// A function with an unsupported parameter or result type is ABSENT rather
/// than partially described: a caller that executed it would be marshalling
/// through a contract this reader declined to make.
pub fn extract_dwarf_signatures(data: &[u8]) -> Vec<DwarfSignature> {
    let Ok(object) = crate::decompile::profile::parse_object(data) else {
        return Vec::new();
    };
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load_section = |id: gimli::SectionId| -> Result<Slice<'_>, ()> {
        match object.section_by_name(id.name()) {
            Some(section) => match section.data() {
                Ok(bytes) => Ok(gimli::EndianSlice::new(bytes, endian)),
                Err(_) => Ok(gimli::EndianSlice::new(&[], endian)),
            },
            None => Ok(gimli::EndianSlice::new(&[], endian)),
        }
    };
    let Ok(dwarf) = gimli::Dwarf::load(&load_section) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        collect_unit_signatures(&dwarf, &unit, &mut out);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.va.cmp(&b.va)));
    out.dedup_by(|a, b| a.name == b.name && a.va == b.va);
    merge_abstract_instances(&mut out);
    out
}

/// Fold each function's ABSTRACT instance into its concrete one.
///
/// An optimising compiler emits two DIEs for a function it also inlined: an
/// abstract instance carrying the source-level parameter list and no address,
/// and a concrete out-of-line instance carrying `DW_AT_low_pc` whose own
/// `DW_TAG_formal_parameter` children may have been optimised away entirely.
/// Taking the concrete DIE alone reports `cpp_lambda_capture()` for a function
/// the source declares as `cpp_lambda_capture(int, int)`, and a caller that
/// believed it would pass no arguments at all.
///
/// The address comes from the concrete instance and the parameters from
/// whichever instance still has them. Entries left with no address are dropped:
/// the caller identifies a function by where it is.
fn merge_abstract_instances(signatures: &mut Vec<DwarfSignature>) {
    use std::collections::HashMap;

    let mut parameters_by_name: HashMap<&str, Vec<DwarfType>> = HashMap::new();
    for signature in signatures.iter() {
        if signature.parameters.is_empty() {
            continue;
        }
        let entry = parameters_by_name
            .entry(signature.name.as_str())
            .or_default();
        if entry.len() < signature.parameters.len() {
            *entry = signature.parameters.clone();
        }
    }
    let adopted: Vec<Option<Vec<DwarfType>>> = signatures
        .iter()
        .map(|signature| {
            signature
                .parameters
                .is_empty()
                .then(|| parameters_by_name.get(signature.name.as_str()).cloned())
                .flatten()
        })
        .collect();
    for (signature, adopted) in signatures.iter_mut().zip(adopted) {
        if let Some(parameters) = adopted {
            signature.parameters = parameters;
        }
    }
    // An abstract instance has no address of its own; once its parameters have
    // been adopted it carries nothing the caller can use.
    let addressed: std::collections::HashSet<&str> = signatures
        .iter()
        .filter(|signature| signature.va != 0)
        .map(|signature| signature.name.as_str())
        .collect::<std::collections::HashSet<_>>()
        .iter()
        .copied()
        .collect();
    let addressed: std::collections::HashSet<String> =
        addressed.into_iter().map(str::to_string).collect();
    signatures.retain(|signature| signature.va != 0 || !addressed.contains(&signature.name));
}

fn collect_unit_signatures(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    out: &mut Vec<DwarfSignature>,
) {
    // Same cursor shape as `debug::dwarf`: `next_depth()` before `next_entry()`,
    // and a `None` current entry is the sibling terminator, not the end.
    let mut cursor = unit.entries();
    // Depth of the subprogram currently being collected, so only its OWN
    // formal parameters are gathered and not a nested lexical block's.
    let mut current: Option<(String, u64, Vec<DwarfType>, DwarfType, isize)> = None;
    let mut rejected = false;

    loop {
        let depth = cursor.next_depth();
        match cursor.next_entry() {
            Ok(true) => {}
            _ => break,
        }
        let Some(entry) = cursor.current() else {
            continue;
        };
        if let Some((_, _, _, _, subprogram_depth)) = &current {
            if depth <= *subprogram_depth {
                finish(&mut current, &mut rejected, out);
            }
        }
        match entry.tag() {
            gimli::DW_TAG_subprogram => {
                // A subprogram NESTED inside the one being collected does not
                // end it. C++ puts a lambda's `operator()` inside the class
                // type inside the enclosing function, so treating any
                // `DW_TAG_subprogram` as a terminator closed
                // `cpp_lambda_capture` before its own formal parameters were
                // reached and reported it as taking none. Its parameters are
                // excluded by the depth test below, which is what makes
                // skipping it here safe.
                if current
                    .as_ref()
                    .is_some_and(|(_, _, _, _, subprogram_depth)| depth > *subprogram_depth)
                {
                    continue;
                }
                finish(&mut current, &mut rejected, out);
                if matches!(
                    entry.attr_value(gimli::DW_AT_declaration),
                    Some(gimli::AttributeValue::Flag(true))
                ) {
                    continue;
                }
                let Some(name) = subprogram_name(dwarf, unit, entry) else {
                    continue;
                };
                let va = match inherited(unit, entry, gimli::DW_AT_low_pc) {
                    Some(gimli::AttributeValue::Addr(address)) => address,
                    _ => 0,
                };
                // A subprogram with no `DW_AT_type` returns `void`; one whose
                // type this reader cannot state is refused outright.
                let result = match inherited(unit, entry, gimli::DW_AT_type) {
                    Some(value) => match describe(dwarf, unit, value, &mut HashSet::new(), 0) {
                        Some(ty) => ty,
                        None => {
                            rejected = true;
                            DwarfType::Void
                        }
                    },
                    _ => DwarfType::Void,
                };
                current = Some((name, va, Vec::new(), result, depth));
            }
            gimli::DW_TAG_formal_parameter => {
                let Some((_, _, parameters, _, subprogram_depth)) = &mut current else {
                    continue;
                };
                // Only the subprogram's own children, never an inlined callee's.
                if depth != *subprogram_depth + 1 {
                    continue;
                }
                match inherited(unit, entry, gimli::DW_AT_type) {
                    Some(value) => match describe(dwarf, unit, value, &mut HashSet::new(), 0) {
                        // A `void` parameter is not a parameter, and a
                        // signature that claims one cannot be called.
                        Some(DwarfType::Void) | None => rejected = true,
                        Some(ty) => parameters.push(ty),
                    },
                    _ => rejected = true,
                }
            }
            _ => {}
        }
    }
    finish(&mut current, &mut rejected, out);
}

fn finish(
    current: &mut Option<(String, u64, Vec<DwarfType>, DwarfType, isize)>,
    rejected: &mut bool,
    out: &mut Vec<DwarfSignature>,
) {
    let Some((name, va, parameters, result, _)) = current.take() else {
        *rejected = false;
        return;
    };
    if !*rejected {
        out.push(DwarfSignature {
            name,
            va,
            parameters,
            result,
        });
    }
    *rejected = false;
}

/// An attribute resolved through a bounded `DW_AT_abstract_origin` /
/// `DW_AT_specification` chain.
///
/// A C++ member function carries its name on the out-of-line SPECIFICATION and
/// an optimised-out inline carries its type on the ABSTRACT ORIGIN, so reading
/// the defining DIE alone loses both. Mirrors `debug::dwarf::inherited_attr_value`.
fn inherited<'a>(
    unit: &Unit<'a>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
    attribute: gimli::DwAt,
) -> Option<gimli::AttributeValue<Slice<'a>, usize>> {
    if let Some(value) = entry.attr_value(attribute) {
        return Some(value);
    }
    let mut offset = match entry
        .attr_value(gimli::DW_AT_abstract_origin)
        .or_else(|| entry.attr_value(gimli::DW_AT_specification))?
    {
        gimli::AttributeValue::UnitRef(offset) => offset,
        _ => return None,
    };
    for _ in 0..MAX_WRAPPER_DEPTH {
        let current = unit.entry(offset).ok()?;
        if let Some(value) = current.attr_value(attribute) {
            return Some(value);
        }
        let next = current
            .attr_value(gimli::DW_AT_abstract_origin)
            .or_else(|| current.attr_value(gimli::DW_AT_specification))?;
        let gimli::AttributeValue::UnitRef(next) = next else {
            return None;
        };
        if next == offset {
            return None;
        }
        offset = next;
    }
    None
}

fn subprogram_name<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &Unit<'a>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
) -> Option<String> {
    // `DW_AT_name`, not the linkage name: the harness loads the function
    // through the DYNAMIC SYMBOL table, and that is the spelling it finds
    // there for the C fixtures this executes.
    let value = inherited(unit, entry, gimli::DW_AT_name)?;
    let text = dwarf.attr_string(unit, value).ok()?;
    let text = text.to_string().ok()?;
    (!text.is_empty()).then(|| text.to_string())
}

/// Peel `typedef`/`const`/`volatile` wrappers, reporting whether a `const` was
/// crossed. Returns the offset of the first entry that is not a wrapper.
fn peel<'a>(
    unit: &Unit<'a>,
    mut offset: gimli::UnitOffset<usize>,
) -> Option<(gimli::UnitOffset<usize>, bool)> {
    let mut konst = false;
    for _ in 0..MAX_WRAPPER_DEPTH {
        let entry = unit.entry(offset).ok()?;
        match entry.tag() {
            gimli::DW_TAG_const_type => konst = true,
            gimli::DW_TAG_typedef | gimli::DW_TAG_volatile_type => {}
            _ => return Some((offset, konst)),
        }
        // A `const void` has no inner type; it is not describable here.
        let gimli::AttributeValue::UnitRef(next) = entry.attr_value(gimli::DW_AT_type)? else {
            return None;
        };
        if next == offset {
            return None;
        }
        offset = next;
    }
    None
}

fn describe(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    value: gimli::AttributeValue<Slice<'_>, usize>,
    open_structs: &mut HashSet<usize>,
    depth: usize,
) -> Option<DwarfType> {
    if depth > MAX_WRAPPER_DEPTH {
        return None;
    }
    // Only intra-unit references are followed. A `DW_FORM_ref_addr` into
    // another compilation unit is exactly the case the pyelftools reader
    // resolved against the wrong abbrev table and crashed on; refusing it
    // degrades the function to `structural`, which is the fail-closed answer.
    let gimli::AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    let (offset, _) = peel(unit, offset)?;
    let entry = unit.entry(offset).ok()?;
    match entry.tag() {
        gimli::DW_TAG_base_type => describe_base(&entry),
        gimli::DW_TAG_enumeration_type => {
            // An enum is an integer of its own width for every ABI here.
            let width = u8::try_from(byte_size(&entry)?).ok()?;
            matches!(width, 1 | 2 | 4 | 8).then_some(DwarfType::Int {
                width,
                signed: true,
            })
        }
        gimli::DW_TAG_pointer_type => describe_pointer(dwarf, unit, &entry, open_structs, depth),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_union_type => {
            describe_aggregate(dwarf, unit, &entry, offset, open_structs, depth)
        }
        gimli::DW_TAG_array_type => {
            describe_array(dwarf, unit, &entry, offset, open_structs, depth)
        }
        _ => None,
    }
}

/// A fixed-length array, as the element type and the element COUNT.
///
/// The count comes from the `DW_TAG_subrange_type` child, never from
/// `DW_AT_byte_size / sizeof(element)`: an array whose bound the producer
/// omitted (a flexible member, `int v[]`) has no extent to marshal, and
/// deriving one from a size would hand the harness an invented length.
/// Multi-dimensional arrays — several subranges under one `DW_TAG_array_type` —
/// nest right to left, which is the layout C gives them.
fn describe_array(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    offset: gimli::UnitOffset<usize>,
    open_structs: &mut HashSet<usize>,
    depth: usize,
) -> Option<DwarfType> {
    let element = describe(
        dwarf,
        unit,
        entry.attr_value(gimli::DW_AT_type)?,
        open_structs,
        depth + 1,
    )?;
    // An array OF pointers or of nothing has no layout this harness can state,
    // for the same reason the member filter refuses those types directly.
    if !matches!(
        element,
        DwarfType::Int { .. }
            | DwarfType::Float { .. }
            | DwarfType::Struct { .. }
            | DwarfType::Union { .. }
            | DwarfType::Array { .. }
    ) {
        return None;
    }
    let counts = subrange_counts(unit, offset)?;
    let mut result = element;
    for count in counts.into_iter().rev() {
        result = DwarfType::Array {
            element: Box::new(result),
            count,
        };
    }
    Some(result)
}

/// Ceiling on an array extent this harness will materialise. A vector is built
/// per element per call, so an unbounded one is a harness hang rather than a
/// verdict.
const MAX_ARRAY_ELEMENTS: u64 = 4096;

/// Every dimension of one `DW_TAG_array_type`, outermost first.
///
/// `None` when any dimension has no stateable bound, which is what makes a
/// flexible array member degrade the whole signature to `structural`.
fn subrange_counts(unit: &Unit<'_>, offset: gimli::UnitOffset<usize>) -> Option<Vec<u64>> {
    let mut counts = Vec::new();
    let mut cursor = unit.entries_at_offset(offset).ok()?;
    let base = cursor.next_depth();
    if !matches!(cursor.next_entry(), Ok(true)) {
        return None;
    }
    loop {
        let level = cursor.next_depth();
        match cursor.next_entry() {
            Ok(true) => {}
            _ => break,
        }
        if level <= base {
            break;
        }
        let Some(entry) = cursor.current() else {
            continue;
        };
        if entry.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let count = match entry.attr_value(gimli::DW_AT_count) {
            Some(value) => constant(&value)?,
            None => constant(&entry.attr_value(gimli::DW_AT_upper_bound)?)?.checked_add(1)?,
        };
        if !(1..=MAX_ARRAY_ELEMENTS).contains(&count) {
            return None;
        }
        counts.push(count);
    }
    (!counts.is_empty()).then_some(counts)
}

/// A DWARF constant-class attribute as a `u64`, or `None` for every other form.
fn constant(value: &gimli::AttributeValue<Slice<'_>, usize>) -> Option<u64> {
    match value {
        gimli::AttributeValue::Udata(value) => Some(*value),
        gimli::AttributeValue::Data1(value) => Some(u64::from(*value)),
        gimli::AttributeValue::Data2(value) => Some(u64::from(*value)),
        gimli::AttributeValue::Data4(value) => Some(u64::from(*value)),
        gimli::AttributeValue::Data8(value) => Some(*value),
        gimli::AttributeValue::Sdata(value) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn describe_base(entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>) -> Option<DwarfType> {
    let encoding = match entry.attr_value(gimli::DW_AT_encoding)? {
        gimli::AttributeValue::Encoding(encoding) => encoding.0 as u16,
        gimli::AttributeValue::Udata(value) => u16::try_from(value).ok()?,
        _ => return None,
    };
    if encoding == FLOAT_ENCODING {
        // No default width for a float: an absent `byte_size` would silently
        // pick a format, and picking the wrong one misreads every bit.
        let width = u8::try_from(byte_size(entry)?).ok()?;
        return matches!(width, 4 | 8).then_some(DwarfType::Float { width });
    }
    let signed = SIGNED_ENCODINGS.contains(&encoding);
    if !signed && !UNSIGNED_ENCODINGS.contains(&encoding) {
        return None;
    }
    let width = u8::try_from(byte_size(entry).unwrap_or(4)).ok()?;
    matches!(width, 1 | 2 | 4 | 8).then_some(DwarfType::Int { width, signed })
}

fn describe_pointer(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    open_structs: &mut HashSet<usize>,
    depth: usize,
) -> Option<DwarfType> {
    let pointer_width = u8::try_from(byte_size(entry).unwrap_or(8)).ok()?;
    // `void *`: describable, and the harness allocates it as a byte buffer.
    let Some(target) = entry.attr_value(gimli::DW_AT_type) else {
        return Some(DwarfType::Pointer {
            pointee: Box::new(DwarfType::Int {
                width: 1,
                signed: false,
            }),
            konst: false,
        });
    };
    let gimli::AttributeValue::UnitRef(target_offset) = target else {
        return None;
    };
    let (peeled, konst) = peel(unit, target_offset)?;
    // The one aggregate pointer that can be materialised without inventing
    // object ownership is a link back to the struct being described.
    if open_structs.contains(&peeled.0) {
        return Some(DwarfType::SelfPointer {
            width: pointer_width,
        });
    }
    let pointee = describe(
        dwarf,
        unit,
        gimli::AttributeValue::UnitRef(target_offset),
        open_structs,
        depth + 1,
    )?;
    // `void *` with an explicit `void` pointee is not describable; a pointer to
    // an aggregate is, and carries the aggregate's NAME so the rebuilt unit can
    // declare it.
    if matches!(pointee, DwarfType::Void) {
        return None;
    }
    let pointee = match pointee {
        DwarfType::Struct {
            byte_size, fields, ..
        } => DwarfType::Struct {
            byte_size,
            fields,
            name: aggregate_name(dwarf, unit, target_offset),
        },
        DwarfType::Union {
            byte_size, fields, ..
        } => DwarfType::Union {
            byte_size,
            fields,
            name: aggregate_name(dwarf, unit, target_offset),
        },
        other => other,
    };
    Some(DwarfType::Pointer {
        pointee: Box::new(pointee),
        konst,
    })
}

/// A struct or a union, distinguished by the DIE's own tag.
///
/// One reader for both because the member walk is identical — DWARF gives a
/// union's members `DW_AT_data_member_location` 0, or omits it. Only the
/// resulting VARIANT differs, and it differs because the harness lays the two
/// out differently.
fn describe_aggregate(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    offset: gimli::UnitOffset<usize>,
    open_structs: &mut HashSet<usize>,
    depth: usize,
) -> Option<DwarfType> {
    let is_union = entry.tag() == gimli::DW_TAG_union_type;
    let size = byte_size(entry)?;
    if !(1..=MAX_STRUCT_BYTES).contains(&size) {
        return None;
    }
    if !open_structs.insert(offset.0) {
        return None;
    }
    let result =
        aggregate_fields(dwarf, unit, offset, open_structs, depth, is_union).map(|fields| {
            if is_union {
                DwarfType::Union {
                    byte_size: size,
                    fields,
                    name: None,
                }
            } else {
                DwarfType::Struct {
                    byte_size: size,
                    fields,
                    name: None,
                }
            }
        });
    open_structs.remove(&offset.0);
    result
}

fn aggregate_fields(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    offset: gimli::UnitOffset<usize>,
    open_structs: &mut HashSet<usize>,
    depth: usize,
    is_union: bool,
) -> Option<Vec<DwarfField>> {
    let mut fields = Vec::new();
    let mut cursor = unit.entries_at_offset(offset).ok()?;
    // Step onto the struct itself; everything after it up to the matching
    // depth is its subtree.
    let base = cursor.next_depth();
    if !matches!(cursor.next_entry(), Ok(true)) {
        return None;
    }
    let mut member_depth = None;
    let mut index = 0usize;
    loop {
        let level = cursor.next_depth();
        match cursor.next_entry() {
            Ok(true) => {}
            _ => break,
        }
        if level <= base {
            break;
        }
        let Some(entry) = cursor.current() else {
            continue;
        };
        if entry.tag() != gimli::DW_TAG_member {
            continue;
        }
        // Immediate members only: an anonymous inner aggregate's members are
        // described by their own descriptor, not flattened into this one.
        match member_depth {
            Some(expected) if level != expected => continue,
            Some(_) => {}
            None => member_depth = Some(level),
        }
        // A bit-field has no plain byte offset, so its layout cannot be stated.
        if entry.attr_value(gimli::DW_AT_bit_size).is_some() {
            return None;
        }
        // A union member's location is zero, and producers are free to omit
        // the attribute entirely for it. A STRUCT member with no location has
        // no stateable offset and still refuses the whole shape.
        let location = match entry.attr_value(gimli::DW_AT_data_member_location) {
            Some(value) => constant(&value)?,
            None if is_union => 0,
            None => return None,
        };
        if is_union && location != 0 {
            return None;
        }
        let ty = describe(
            dwarf,
            unit,
            entry.attr_value(gimli::DW_AT_type)?,
            open_structs,
            depth + 1,
        )?;
        // A member this reader can state exactly. `Float` is included: see the
        // module header — libffi, not this module, classifies the eightbytes,
        // and refusing the member only removed the shapes worth checking.
        // `Void` and `Pointer` are still refused: a `void` member is not a
        // member, and a pointer to another object would make the harness invent
        // ownership it has no way to state.
        if !matches!(
            ty,
            DwarfType::Int { .. }
                | DwarfType::Float { .. }
                | DwarfType::Struct { .. }
                | DwarfType::Union { .. }
                | DwarfType::Array { .. }
                | DwarfType::SelfPointer { .. }
        ) {
            return None;
        }
        let name = entry
            .attr_value(gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value))
            .unwrap_or_else(|| format!("field{index}"));
        index += 1;
        fields.push(DwarfField {
            name,
            offset: location,
            ty,
        });
    }
    if fields.is_empty() {
        return None;
    }
    // Stable, so a union's members — all at offset zero — keep DECLARATION
    // order. The harness compares member snapshots positionally against the
    // other build's, and two orders of the same union would compare a member's
    // view of the storage against a different member's.
    fields.sort_by_key(|field| field.offset);
    Some(fields)
}

/// A `DW_AT_name` resolved through `.debug_str` when it is held there.
fn attribute_string(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    value: gimli::AttributeValue<Slice<'_>, usize>,
) -> Option<String> {
    let text = dwarf.attr_string(unit, value).ok()?;
    let text = text.to_string().ok()?;
    (!text.is_empty()).then(|| text.to_string())
}

/// The first name on an aggregate's wrapper chain: the typedef spelling if the
/// reference goes through one, else the struct's own tag.
fn aggregate_name(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    mut offset: gimli::UnitOffset<usize>,
) -> Option<String> {
    for _ in 0..MAX_WRAPPER_DEPTH {
        let entry = unit.entry(offset).ok()?;
        if let Some(name) = entry
            .attr_value(gimli::DW_AT_name)
            .and_then(|value| attribute_string(dwarf, unit, value))
        {
            return Some(name);
        }
        let gimli::AttributeValue::UnitRef(next) = entry.attr_value(gimli::DW_AT_type)? else {
            return None;
        };
        if next == offset {
            return None;
        }
        offset = next;
    }
    None
}

fn byte_size(entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>) -> Option<u64> {
    constant(&entry.attr_value(gimli::DW_AT_byte_size)?)
}
