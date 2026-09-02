//! DWARF subprogram extraction (#157, v1).
//!
//! Walks compilation units in `.debug_info`, pulls every
//! `DW_TAG_subprogram` entry, and resolves its name + address ranges
//! into a flat list of [`DwarfFunction`]s that Glaurung's CFG analyser
//! can use as authoritative seeds.
//!
//! Handles both forms of address coverage:
//! - **Contiguous**: `DW_AT_low_pc` + `DW_AT_high_pc` (often offset-form
//!   on DWARF 4+) → one chunk.
//! - **Non-contiguous**: `DW_AT_ranges` pointing into `.debug_ranges`
//!   (DWARF 4) or `.debug_rnglists` (DWARF 5) → many chunks. This is
//!   the canonical source for `<fn>.cold` splits and EH funclets.
//!
//! Errors are swallowed at section boundaries so a malformed CU never
//! poisons the whole analysis. The caller gets best-effort coverage.

use std::collections::HashSet;
use std::convert::TryInto;

use object::{Object, ObjectSection};

/// One DWARF-discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfFunction {
    /// Entry virtual address (the primary range listed by the producer).
    ///
    /// Optimizing compilers may place a cold split below the hot entry in the
    /// address space. Sorting by VA would therefore turn `foo.cold` into the
    /// semantic entry even though the range list deliberately names the hot
    /// chunk first.
    pub entry_va: u64,
    /// All address ranges that belong to this function. Always at least
    /// one element when `entry_va` is set; `chunks[0]` is the entry chunk.
    pub chunks: Vec<DwarfRange>,
    /// Best-effort name. Prefers `DW_AT_linkage_name` (mangled, fully
    /// qualified) over `DW_AT_name` (unqualified) so cross-tool matching
    /// stays consistent.
    pub name: Option<String>,
    /// `DW_AT_name` of the surrounding compilation unit.
    pub source_file: Option<String>,
    /// `DW_AT_language` of the surrounding compilation unit, decoded to
    /// a short string ("C", "C++", "Fortran77", "Rust", ...).
    pub language: Option<String>,
    /// Count of `DW_TAG_formal_parameter` children. Roughly = arity.
    pub param_count: u32,
    /// Source-level parameter contracts in declaration order. A concrete
    /// optimized subprogram may inherit each type through its parameter DIE's
    /// `DW_AT_abstract_origin`.
    pub parameter_types: Vec<DwarfParameterType>,
    /// Source parameter names in declaration order. Missing or invalid names
    /// remain `None`; callers must not invent a spelling from positional data.
    pub parameter_names: Vec<Option<String>>,
    /// Whether the subprogram declared a prototype (`DW_AT_prototyped`).
    pub prototyped: bool,
    /// Authoritative source-level return contract from `DW_AT_type`.
    /// Absence of that attribute on a concrete subprogram means `void`;
    /// an unsupported reference stays `Unknown` rather than being guessed.
    pub return_type: DwarfReturnType,
    /// Source variables with a fixed frame-relative location and known size.
    /// These are authoritative object boundaries for stack-slot promotion.
    pub stack_objects: Vec<DwarfStackObject>,
    /// Source locals whose optimized value resides in a machine register over
    /// one or more address ranges.
    pub register_locals: Vec<DwarfRegisterLocal>,
}

/// Coordinate used by a variable's ``DW_OP_fbreg`` location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfStackBase {
    /// ``DW_AT_frame_base`` is a concrete architectural register.
    Register(u16),
    /// ``DW_AT_frame_base`` is ``DW_OP_call_frame_cfa``.
    CallFrameCfa,
}

/// One fixed-size source object resident in a function's stack frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfStackObject {
    pub base: DwarfStackBase,
    pub offset: i64,
    pub byte_size: u16,
    pub aggregate: bool,
    pub source_name: Option<String>,
    pub c_type: Option<String>,
}

/// One source local recovered from debug information.
///
/// `locations` is empty only when DWARF explicitly describes the optimized
/// value as a constant stack value. Such a local retains its declaration but
/// has no machine-register identity to rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwarfRegisterLocation {
    pub start: u64,
    pub end: u64,
    pub register: u16,
}

/// An optimized source local described by a DWARF location list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfRegisterLocal {
    pub source_name: String,
    pub c_type: String,
    pub locations: Vec<DwarfRegisterLocation>,
}

/// Source-level output contract attached to a DWARF subprogram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwarfReturnType {
    /// The subprogram has no `DW_AT_type`, which DWARF uses for `void`.
    Void,
    /// A concrete referenced type resolved to a C-like spelling.
    Type(String),
    /// A type attribute exists but this reader cannot resolve it safely.
    Unknown,
}

/// One source-level parameter type recovered from DWARF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwarfParameterType {
    /// A concrete referenced type resolved to a C-like spelling.
    Type(String),
    /// The parameter exists, but its declared type cannot be resolved safely.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DwarfRange {
    pub start: u64,
    pub size: u64,
}

/// One DWARF-discovered struct / enum / typedef.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfType {
    pub kind: DwarfTypeKind,
    /// Canonical name (`DW_AT_name`). Anonymous types use a synthetic
    /// `anon_<offset>` name.
    pub name: String,
    /// Total size in bytes (`DW_AT_byte_size`), zero if unknown.
    pub byte_size: u64,
    /// Struct fields (offset, name, c_type, size). Empty for non-structs.
    pub fields: Vec<DwarfField>,
    /// Enum variants (name, value). Empty for non-enums.
    pub variants: Vec<DwarfEnumVariant>,
    /// For typedefs, the alias target's c_type rendering; empty otherwise.
    pub typedef_target: Option<String>,
    /// `DW_AT_name` of the surrounding compilation unit.
    pub source_file: Option<String>,
}

impl DwarfType {
    /// Whether two records describe the same layout, ignoring which
    /// compilation unit emitted them. A header included by many units yields
    /// the same definition repeatedly; that repetition is not disagreement.
    fn is_same_definition(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.name == other.name
            && self.byte_size == other.byte_size
            && self.fields == other.fields
            && self.variants == other.variants
            && self.typedef_target == other.typedef_target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DwarfTypeKind {
    Struct,
    Union,
    Enum,
    Typedef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfField {
    pub offset: u64,
    pub name: String,
    pub c_type: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfEnumVariant {
    pub name: String,
    pub value: i64,
}

/// Read DWARF subprograms from `data` (the full binary bytes). Returns
/// an empty Vec if the binary has no DWARF or parsing fails — callers
/// should treat this as "DWARF unavailable, fall back to symbols/heuristics."
pub fn extract_dwarf_functions(data: &[u8]) -> Vec<DwarfFunction> {
    let obj = match crate::decompile::profile::parse_object(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section =
        |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, ()> {
            let name = id.name();
            match obj.section_by_name(name) {
                Some(sec) => match sec.uncompressed_data() {
                    Ok(cow) => {
                        // SAFETY: leaking is fine — analysis is short-lived
                        // per-call, and EndianSlice needs a borrow lasting
                        // longer than the `Cow`. The buffer is dropped when
                        // the leaked `Vec` is reclaimed at process exit; for
                        // a CLI / one-shot pipeline this is bounded and small.
                        let buf: &'static [u8] = Box::leak(cow.into_owned().into_boxed_slice());
                        Ok(gimli::EndianSlice::new(buf, endian))
                    }
                    Err(_) => Ok(gimli::EndianSlice::new(&[], endian)),
                },
                None => Ok(gimli::EndianSlice::new(&[], endian)),
            }
        };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut funcs: Vec<DwarfFunction> = Vec::new();
    let mut iter = dwarf.units();
    while let Ok(Some(header)) = iter.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let unit_lang = unit_language(&dwarf, &unit);
        let unit_name = unit_name(&dwarf, &unit);

        // Walk the unit's DIE stream, tracking depth manually. For each
        // subprogram we encounter, count formal_parameter direct children
        // (depth == subprogram_depth + 1).
        //
        // We use `next_entry` + `next_depth` rather than `next_dfs` so we
        // can observe null DIEs (sibling-list terminators) and track
        // depth precisely. `entries_tree` was unreliable on clang
        // `-gdwarf-5` output in practice.
        let mut cursor = unit.entries();
        // Each frame: (subprogram offset, direct parameter offsets, variable
        // offsets anywhere in this subprogram, depth).
        // Retaining the actual DIE identities is essential at -O2: GCC puts
        // their types on abstract parameter DIEs and only their locations on
        // the concrete children.
        let mut open: Vec<(
            gimli::UnitOffset<usize>,
            Vec<gimli::UnitOffset<usize>>,
            Vec<gimli::UnitOffset<usize>>,
            isize,
        )> = Vec::new();
        let mut emitted: Vec<(
            gimli::UnitOffset<usize>,
            Vec<gimli::UnitOffset<usize>>,
            Vec<gimli::UnitOffset<usize>>,
        )> = Vec::new();

        loop {
            let depth_of_next = cursor.next_depth();
            match cursor.next_entry() {
                Ok(true) => {}
                _ => break,
            }
            // Pop any subprograms whose subtree we've left.
            while let Some((_, _, _, sub_depth)) = open.last() {
                if depth_of_next <= *sub_depth {
                    if let Some((off, parameters, variables, _)) = open.pop() {
                        emitted.push((off, parameters, variables));
                    }
                } else {
                    break;
                }
            }
            let entry = match cursor.current() {
                Some(e) => e,
                None => continue, // null DIE (sibling terminator)
            };
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    open.push((entry.offset(), Vec::new(), Vec::new(), depth_of_next));
                }
                gimli::DW_TAG_formal_parameter => {
                    if let Some(top) = open.last_mut() {
                        if depth_of_next == top.3 + 1 {
                            top.1.push(entry.offset());
                        }
                    }
                }
                gimli::DW_TAG_variable => {
                    if let Some(top) = open.last_mut() {
                        top.2.push(entry.offset());
                    }
                }
                _ => {}
            }
        }
        while let Some((off, parameters, variables, _)) = open.pop() {
            emitted.push((off, parameters, variables));
        }

        for (off, parameter_offsets, variable_offsets) in emitted {
            let entry = match unit.entry(off) {
                Ok(e) => e,
                Err(_) => continue,
            };

            if matches!(
                entry.attr_value(gimli::DW_AT_declaration),
                Some(gimli::AttributeValue::Flag(true))
            ) {
                continue;
            }

            // Keep addressless declaration DIEs as declaration evidence. The
            // program image can join them to a defined text symbol by name;
            // discovery consumers continue to ignore their empty range list.
            let chunks = collect_ranges(&dwarf, &unit, &entry).unwrap_or_default();
            let entry_va = chunks.first().map(|range| range.start).unwrap_or(0);

            let name = pick_name(&dwarf, &unit, &entry);
            let prototyped = matches!(
                inherited_attr_value(&unit, &entry, gimli::DW_AT_prototyped),
                Some(gimli::AttributeValue::Flag(true))
            );
            let return_type = match inherited_attr_value(&unit, &entry, gimli::DW_AT_type) {
                None => DwarfReturnType::Void,
                Some(type_attr) => _resolve_type_string(&dwarf, &unit, type_attr)
                    .map(DwarfReturnType::Type)
                    .unwrap_or(DwarfReturnType::Unknown),
            };
            let parameter_types = parameter_offsets
                .iter()
                .map(|parameter_offset| {
                    let Ok(parameter) = unit.entry(*parameter_offset) else {
                        return DwarfParameterType::Unknown;
                    };
                    inherited_attr_value(&unit, &parameter, gimli::DW_AT_type)
                        .and_then(|type_attr| _resolve_type_string(&dwarf, &unit, type_attr))
                        .map(DwarfParameterType::Type)
                        .unwrap_or(DwarfParameterType::Unknown)
                })
                .collect::<Vec<_>>();
            let parameter_names = parameter_offsets
                .iter()
                .map(|parameter_offset| {
                    unit.entry(*parameter_offset)
                        .ok()
                        .and_then(|parameter| inherited_name_of(&dwarf, &unit, &parameter))
                })
                .collect::<Vec<_>>();
            let param_count = parameter_types.len() as u32;
            let stack_objects = dwarf_stack_objects_for_subprogram(
                &dwarf,
                &unit,
                &entry,
                variable_offsets.iter().copied(),
            );
            let register_locals = dwarf_register_locals_for_subprogram(
                &dwarf,
                &unit,
                &chunks,
                variable_offsets.into_iter(),
            );

            funcs.push(DwarfFunction {
                entry_va,
                chunks,
                name,
                source_file: unit_name.clone(),
                language: unit_lang.clone(),
                param_count,
                parameter_types,
                parameter_names,
                prototyped,
                return_type,
                stack_objects,
                register_locals,
            });
        }
    }

    funcs
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type Slice<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;
type Unit<'a> = gimli::Unit<Slice<'a>, usize>;

/// Resolve an attribute through the concrete DIE's abstract-origin or
/// specification chain.
///
/// Clang O2 commonly emits the address range on a concrete `DW_TAG_subprogram`
/// while leaving its name, prototype, and return type on an abstract subprogram.
/// Treating the concrete DIE's missing `DW_AT_type` as `void` discards an
/// authoritative source contract.  The chain is bounded and same-unit only;
/// unsupported cross-unit references remain unknown rather than being guessed.
fn inherited_attr_value<'a>(
    unit: &Unit<'a>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
    attribute: gimli::DwAt,
) -> Option<gimli::AttributeValue<Slice<'a>, usize>> {
    let mut offset = entry.offset();
    for _ in 0..16 {
        let current = unit.entry(offset).ok()?;
        if let Some(value) = current.attr_value(attribute) {
            return Some(value);
        }
        let reference = current
            .attr_value(gimli::DW_AT_abstract_origin)
            .or_else(|| current.attr_value(gimli::DW_AT_specification));
        let Some(gimli::AttributeValue::UnitRef(next)) = reference else {
            return None;
        };
        if next == offset {
            return None;
        }
        offset = next;
    }
    None
}

fn single_expression_operation<'a>(
    unit: &Unit<'a>,
    value: gimli::AttributeValue<Slice<'a>, usize>,
) -> Option<gimli::Operation<Slice<'a>, usize>> {
    let gimli::AttributeValue::Exprloc(expression) = value else {
        return None;
    };
    let mut operations = expression.operations(unit.encoding());
    let operation = operations.next().ok()??;
    if operations.next().ok()?.is_some() {
        return None;
    }
    Some(operation)
}

fn referenced_type_info<'a>(
    unit: &Unit<'a>,
    value: gimli::AttributeValue<Slice<'a>, usize>,
) -> Option<(u64, bool)> {
    let gimli::AttributeValue::UnitRef(offset) = value else {
        return None;
    };
    referenced_type_info_at(unit, offset, &mut HashSet::new())
}

fn referenced_type_info_at<'a>(
    unit: &Unit<'a>,
    offset: gimli::UnitOffset<usize>,
    seen: &mut HashSet<gimli::UnitOffset<usize>>,
) -> Option<(u64, bool)> {
    if !seen.insert(offset) || seen.len() > 32 {
        return None;
    }
    let entry = unit.entry(offset).ok()?;
    let aggregate = matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_array_type
    );
    let direct_size = _byte_size_of(&entry);
    if direct_size != 0 {
        return Some((direct_size, aggregate));
    }

    let gimli::AttributeValue::UnitRef(element_or_wrapped) =
        inherited_attr_value(unit, &entry, gimli::DW_AT_type)?
    else {
        return None;
    };
    if entry.tag() == gimli::DW_TAG_array_type {
        let elements = dwarf_array_element_count(unit, offset)?;
        let (element_size, _) = referenced_type_info_at(unit, element_or_wrapped, seen)?;
        return element_size.checked_mul(elements).map(|size| (size, true));
    }
    referenced_type_info_at(unit, element_or_wrapped, seen)
}

fn dwarf_integer(value: gimli::AttributeValue<Slice<'_>, usize>) -> Option<i128> {
    match value {
        gimli::AttributeValue::Sdata(value) => Some(i128::from(value)),
        gimli::AttributeValue::Udata(value) => Some(i128::from(value)),
        gimli::AttributeValue::Data1(value) => Some(i128::from(value)),
        gimli::AttributeValue::Data2(value) => Some(i128::from(value)),
        gimli::AttributeValue::Data4(value) => Some(i128::from(value)),
        gimli::AttributeValue::Data8(value) => Some(i128::from(value)),
        _ => None,
    }
}

fn dwarf_subrange_count(
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    default_lower_bound: Option<i128>,
) -> Option<u64> {
    if let Some(count) = entry.attr_value(gimli::DW_AT_count).and_then(dwarf_integer) {
        return u64::try_from(count).ok();
    }
    let upper = entry
        .attr_value(gimli::DW_AT_upper_bound)
        .and_then(dwarf_integer)?;
    let lower = entry
        .attr_value(gimli::DW_AT_lower_bound)
        .and_then(dwarf_integer)
        .or(default_lower_bound)?;
    u64::try_from(upper.checked_sub(lower)?.checked_add(1)?).ok()
}

fn dwarf_array_element_count<'a>(unit: &Unit<'a>, offset: gimli::UnitOffset<usize>) -> Option<u64> {
    let mut unit_entries = unit.entries();
    let unit_entry = unit_entries.next_dfs().ok().flatten()?;
    let default_lower_bound = match unit_entry.attr_value(gimli::DW_AT_language) {
        Some(gimli::AttributeValue::Language(language)) => language
            .default_lower_bound()
            .and_then(|bound| i128::try_from(bound).ok()),
        _ => None,
    };
    let mut tree = unit.entries_tree(Some(offset)).ok()?;
    let root = tree.root().ok()?;
    let mut children = root.children();
    let mut elements = 1u64;
    let mut dimensions = 0usize;
    while let Some(child) = children.next().ok()? {
        if child.entry().tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        elements =
            elements.checked_mul(dwarf_subrange_count(child.entry(), default_lower_bound)?)?;
        dimensions += 1;
    }
    (dimensions != 0).then_some(elements)
}

fn dwarf_stack_objects_for_subprogram<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &Unit<'a>,
    subprogram: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
    variables: impl Iterator<Item = gimli::UnitOffset<usize>>,
) -> Vec<DwarfStackObject> {
    let base = match inherited_attr_value(unit, subprogram, gimli::DW_AT_frame_base)
        .and_then(|value| single_expression_operation(unit, value))
    {
        Some(gimli::Operation::Register { register }) => DwarfStackBase::Register(register.0),
        Some(gimli::Operation::CallFrameCFA) => DwarfStackBase::CallFrameCfa,
        _ => return Vec::new(),
    };
    let mut objects = variables
        .filter_map(|offset| {
            let variable = unit.entry(offset).ok()?;
            let offset = match inherited_attr_value(unit, &variable, gimli::DW_AT_location)
                .and_then(|value| single_expression_operation(unit, value))
            {
                Some(gimli::Operation::FrameOffset { offset }) => offset,
                _ => return None,
            };
            let type_attr = inherited_attr_value(unit, &variable, gimli::DW_AT_type)?;
            let (byte_size, aggregate) = referenced_type_info(unit, type_attr)?;
            let byte_size = u16::try_from(byte_size).ok().filter(|size| *size != 0)?;
            Some(DwarfStackObject {
                base,
                offset,
                byte_size,
                aggregate,
                source_name: inherited_name_of(dwarf, unit, &variable),
                c_type: _resolve_type_string(dwarf, unit, type_attr),
            })
        })
        .collect::<Vec<_>>();
    objects.sort_by_key(|object| (object.offset, object.byte_size, object.aggregate));
    let mut merged: Vec<DwarfStackObject> = Vec::new();
    for object in objects {
        if let Some(existing) = merged.last_mut().filter(|existing| {
            existing.base == object.base
                && existing.offset == object.offset
                && existing.byte_size == object.byte_size
                && existing.aggregate == object.aggregate
        }) {
            if existing.source_name != object.source_name {
                existing.source_name = None;
            }
            if existing.c_type != object.c_type {
                existing.c_type = None;
            }
        } else {
            merged.push(object);
        }
    }
    merged
}

fn dwarf_register_locals_for_subprogram<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &Unit<'a>,
    subprogram_ranges: &[DwarfRange],
    variables: impl Iterator<Item = gimli::UnitOffset<usize>>,
) -> Vec<DwarfRegisterLocal> {
    let mut locals = Vec::new();
    for offset in variables {
        let Ok(variable) = unit.entry(offset) else {
            continue;
        };
        let Some(source_name) = inherited_name_of(dwarf, unit, &variable) else {
            continue;
        };
        let Some(type_attr) = inherited_attr_value(unit, &variable, gimli::DW_AT_type) else {
            continue;
        };
        let Some(c_type) = _resolve_type_string(dwarf, unit, type_attr) else {
            continue;
        };
        let Some(location_attr) = inherited_attr_value(unit, &variable, gimli::DW_AT_location)
        else {
            continue;
        };
        let mut locations = Vec::new();
        let mut declaration_only = false;
        if let gimli::AttributeValue::Exprloc(expression) = location_attr {
            if let Some(register) = single_register_expression(unit, expression.clone()) {
                locations.extend(subprogram_ranges.iter().filter_map(|range| {
                    let end = range.start.checked_add(range.size)?;
                    (range.start < end).then_some(DwarfRegisterLocation {
                        start: range.start,
                        end,
                        register,
                    })
                }));
            } else {
                declaration_only = constant_stack_value_expression(unit.encoding(), expression);
            }
        } else if let Ok(Some(mut entries)) = dwarf.attr_locations(unit, location_attr) {
            while let Ok(Some(entry)) = entries.next() {
                let Some(register) = single_register_expression(unit, entry.data.clone()) else {
                    declaration_only |=
                        constant_stack_value_expression(unit.encoding(), entry.data);
                    continue;
                };
                if entry.range.begin >= entry.range.end {
                    continue;
                }
                locations.push(DwarfRegisterLocation {
                    start: entry.range.begin,
                    end: entry.range.end,
                    register,
                });
            }
        }
        if locations.is_empty() && !declaration_only {
            continue;
        }
        locations.sort_by_key(|location| (location.start, location.end, location.register));
        locations.dedup();
        locals.push(DwarfRegisterLocal {
            source_name,
            c_type,
            locations,
        });
    }
    locals.sort_by(|left, right| left.source_name.cmp(&right.source_name));
    locals
}

fn single_register_expression<'a>(
    unit: &Unit<'a>,
    expression: gimli::Expression<Slice<'a>>,
) -> Option<u16> {
    let mut operations = expression.operations(unit.encoding());
    let gimli::Operation::Register { register } = operations.next().ok()?? else {
        return None;
    };
    if operations.next().ok()?.is_some() {
        return None;
    }
    Some(register.0)
}

fn constant_stack_value_expression<'a>(
    encoding: gimli::Encoding,
    expression: gimli::Expression<Slice<'a>>,
) -> bool {
    let mut operations = expression.operations(encoding);
    if !matches!(
        operations.next(),
        Ok(Some(
            gimli::Operation::UnsignedConstant { .. } | gimli::Operation::SignedConstant { .. }
        ))
    ) {
        return false;
    }
    matches!(operations.next(), Ok(Some(gimli::Operation::StackValue)))
        && matches!(operations.next(), Ok(None))
}

fn inherited_name_of<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &Unit<'a>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
) -> Option<String> {
    let value = inherited_attr_value(unit, entry, gimli::DW_AT_name)?;
    dwarf
        .attr_string(unit, value)
        .ok()?
        .to_string()
        .ok()
        .map(|name| name.to_string())
}

fn pick_name<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &Unit<'a>,
    entry: &gimli::DebuggingInformationEntry<Slice<'a>, usize>,
) -> Option<String> {
    // DW_AT_linkage_name (mangled) wins — matches what's in the symbol
    // table. Fall back to DW_AT_name (unqualified) only if absent.
    for attr in [
        gimli::DW_AT_linkage_name,
        gimli::DW_AT_MIPS_linkage_name,
        gimli::DW_AT_name,
    ] {
        if let Some(v) = inherited_attr_value(unit, entry, attr) {
            if let Ok(s) = dwarf.attr_string(unit, v) {
                if let Ok(t) = s.to_string() {
                    if !t.is_empty() {
                        return Some(t.to_string());
                    }
                }
            }
        }
    }
    None
}

fn unit_name(dwarf: &gimli::Dwarf<Slice<'_>>, unit: &Unit<'_>) -> Option<String> {
    let mut cursor = unit.entries();
    let entry = cursor.next_dfs().ok().flatten()?;
    let v = entry.attr_value(gimli::DW_AT_name)?;
    let s = dwarf.attr_string(unit, v).ok()?;
    Some(s.to_string().ok()?.to_string())
}

fn unit_language(_dwarf: &gimli::Dwarf<Slice<'_>>, unit: &Unit<'_>) -> Option<String> {
    let mut cursor = unit.entries();
    let entry = cursor.next_dfs().ok().flatten()?;
    let v = entry.attr_value(gimli::DW_AT_language)?;
    if let gimli::AttributeValue::Language(l) = v {
        return Some(language_name(l).to_string());
    }
    None
}

fn language_name(l: gimli::DwLang) -> &'static str {
    match l {
        gimli::DW_LANG_C | gimli::DW_LANG_C89 | gimli::DW_LANG_C99 | gimli::DW_LANG_C11 => "C",
        gimli::DW_LANG_C_plus_plus
        | gimli::DW_LANG_C_plus_plus_03
        | gimli::DW_LANG_C_plus_plus_11
        | gimli::DW_LANG_C_plus_plus_14 => "C++",
        gimli::DW_LANG_Rust => "Rust",
        gimli::DW_LANG_Go => "Go",
        gimli::DW_LANG_Fortran77 => "Fortran77",
        gimli::DW_LANG_Fortran90 => "Fortran90",
        gimli::DW_LANG_Fortran95 => "Fortran95",
        gimli::DW_LANG_Fortran03 => "Fortran03",
        gimli::DW_LANG_Fortran08 => "Fortran08",
        gimli::DW_LANG_Ada83 | gimli::DW_LANG_Ada95 => "Ada",
        gimli::DW_LANG_ObjC => "ObjectiveC",
        gimli::DW_LANG_ObjC_plus_plus => "ObjectiveC++",
        gimli::DW_LANG_Swift => "Swift",
        gimli::DW_LANG_Java => "Java",
        gimli::DW_LANG_D => "D",
        gimli::DW_LANG_Python => "Python",
        _ => "Unknown",
    }
}

/// Resolve a subprogram's address coverage. Handles both
/// (low_pc, high_pc) — including the DWARF 4+ offset form — and
/// `DW_AT_ranges` pointing into `.debug_ranges` / `.debug_rnglists`.
fn collect_ranges(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> Result<Vec<DwarfRange>, gimli::Error> {
    // Case 1: DW_AT_ranges → range list (multi-chunk).
    // Use ranges_offset_from_raw + ranges to handle DWARF-5 .debug_rnglists.
    if let Some(ranges_attr) = entry.attr_value(gimli::DW_AT_ranges) {
        if let Some(offset) = dwarf.attr_ranges_offset(unit, ranges_attr)? {
            let mut iter = dwarf.ranges(unit, offset)?;
            let mut out = Vec::new();
            while let Some(r) = iter.next()? {
                if r.end > r.begin {
                    out.push(DwarfRange {
                        start: r.begin,
                        size: r.end - r.begin,
                    });
                }
            }
            return Ok(out);
        }
    }

    // Case 2: low_pc + high_pc (single chunk). Use `attr_address` so
    // DWARF 5's `DW_FORM_addrx` (index into `.debug_addr`) and the
    // legacy `DW_FORM_addr` both resolve uniformly.
    let low_pc_attr = match entry.attr_value(gimli::DW_AT_low_pc) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let low_pc = match dwarf.attr_address(unit, low_pc_attr)? {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let high_pc_attr = match entry.attr_value(gimli::DW_AT_high_pc) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let end = match high_pc_attr {
        // Absolute high_pc — try as address first.
        gimli::AttributeValue::Addr(a) => a,
        gimli::AttributeValue::DebugAddrIndex(_) => {
            match dwarf.attr_address(unit, high_pc_attr)? {
                Some(a) => a,
                None => return Ok(Vec::new()),
            }
        }
        // Offset form — high_pc encodes (end - low_pc).
        gimli::AttributeValue::Udata(off) => low_pc.saturating_add(off),
        gimli::AttributeValue::Data1(d) => low_pc.saturating_add(d as u64),
        gimli::AttributeValue::Data2(d) => low_pc.saturating_add(d as u64),
        gimli::AttributeValue::Data4(d) => low_pc.saturating_add(d as u64),
        gimli::AttributeValue::Data8(d) => low_pc.saturating_add(d),
        gimli::AttributeValue::Sdata(d) => {
            let d_u: u64 = d.try_into().unwrap_or(0);
            low_pc.saturating_add(d_u)
        }
        _ => return Ok(Vec::new()),
    };
    if end <= low_pc {
        return Ok(Vec::new());
    }
    Ok(vec![DwarfRange {
        start: low_pc,
        size: end - low_pc,
    }])
}

// ---------------------------------------------------------------------------
// Type extraction (DW_TAG_structure_type, _enumeration_type, _typedef)
// ---------------------------------------------------------------------------

/// Read DWARF type definitions from `data`. Returns an empty Vec if the
/// binary has no DWARF or parsing fails. Like
/// `extract_dwarf_functions`, this is best-effort — malformed CUs are
/// silently skipped.
pub fn extract_dwarf_types(data: &[u8]) -> Vec<DwarfType> {
    let obj = match crate::decompile::profile::parse_object(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section =
        |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, ()> {
            let name = id.name();
            match obj.section_by_name(name) {
                Some(sec) => match sec.uncompressed_data() {
                    Ok(cow) => {
                        let buf: &'static [u8] = Box::leak(cow.into_owned().into_boxed_slice());
                        Ok(gimli::EndianSlice::new(buf, endian))
                    }
                    Err(_) => Ok(gimli::EndianSlice::new(&[], endian)),
                },
                None => Ok(gimli::EndianSlice::new(&[], endian)),
            }
        };

    let dwarf = match gimli::Dwarf::load(&load_section) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut out: Vec<DwarfType> = Vec::new();
    let mut iter = dwarf.units();
    while let Ok(Some(header)) = iter.next() {
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let unit_src = unit_name(&dwarf, &unit);

        // Walk DIEs depth-tracked so we can pair fields/variants with
        // their parent struct/enum.
        let mut cursor = unit.entries();
        // Stack of in-progress builders.
        let mut open: Vec<(DwarfType, isize)> = Vec::new();
        let mut emitted: Vec<DwarfType> = Vec::new();

        loop {
            let depth_of_next = cursor.next_depth();
            match cursor.next_entry() {
                Ok(true) => {}
                _ => break,
            }
            // Pop builders we've left.
            while let Some((_t, parent_depth)) = open.last() {
                if depth_of_next <= *parent_depth {
                    let (t, _) = open.pop().unwrap();
                    emitted.push(t);
                } else {
                    break;
                }
            }
            let entry = match cursor.current() {
                Some(e) => e,
                None => continue,
            };
            match entry.tag() {
                gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                    if let Some(t) = _build_struct_or_class(&dwarf, &unit, entry, &unit_src, false)
                    {
                        open.push((t, depth_of_next));
                    }
                }
                gimli::DW_TAG_union_type => {
                    if let Some(t) = _build_struct_or_class(&dwarf, &unit, entry, &unit_src, true) {
                        open.push((t, depth_of_next));
                    }
                }
                gimli::DW_TAG_enumeration_type => {
                    if let Some(t) = _build_enum(&dwarf, &unit, entry, &unit_src) {
                        open.push((t, depth_of_next));
                    }
                }
                gimli::DW_TAG_typedef => {
                    if let Some(t) = _build_typedef(&dwarf, &unit, entry, &unit_src) {
                        // Typedefs have no children we care about, emit immediately.
                        emitted.push(t);
                    }
                }
                gimli::DW_TAG_member => {
                    // Add to the most recent open struct/union.
                    if let Some((parent, parent_depth)) = open.last_mut() {
                        if depth_of_next == *parent_depth + 1
                            && matches!(parent.kind, DwarfTypeKind::Struct | DwarfTypeKind::Union)
                        {
                            if let Some(field) = _build_field(&dwarf, &unit, entry) {
                                parent.fields.push(field);
                            }
                        }
                    }
                }
                gimli::DW_TAG_enumerator => {
                    if let Some((parent, parent_depth)) = open.last_mut() {
                        if depth_of_next == *parent_depth + 1
                            && matches!(parent.kind, DwarfTypeKind::Enum)
                        {
                            if let Some(v) = _build_enum_variant(&dwarf, &unit, entry) {
                                parent.variants.push(v);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        while let Some((t, _)) = open.pop() {
            emitted.push(t);
        }
        materialize_anonymous_aggregate_typedefs(&mut emitted);
        out.extend(emitted);
    }

    // DWARF repeats the same definition in every compilation unit that
    // included it; collapse those exact repetitions to the first occurrence.
    // Records that genuinely disagree are all retained: two units may legally
    // define one struct tag with different layouts, and deduplicating by name
    // alone would silently promote whichever unit happened to link first into
    // an authoritative layout. Consumers select from the retained set.
    let mut by_name: std::collections::HashMap<(DwarfTypeKind, String), Vec<usize>> =
        std::collections::HashMap::new();
    let mut retained: Vec<DwarfType> = Vec::with_capacity(out.len());
    for record in out {
        let slot = by_name
            .entry((record.kind, record.name.clone()))
            .or_default();
        if slot
            .iter()
            .any(|&index| retained[index].is_same_definition(&record))
        {
            continue;
        }
        slot.push(retained.len());
        retained.push(record);
    }
    retained
}

/// Give an anonymous aggregate the public name of a direct typedef alias.
///
/// Clang represents `typedef struct { ... } Name;` as two DIEs: an unnamed
/// structure and a typedef that references it.  Keeping only the synthetic
/// `anon_<offset>` layout loses the identity used by function prototypes.
/// Retain that diagnostic layout and add an equivalent named layout so typed
/// consumers can join `Name *` back to its authoritative fields.
fn materialize_anonymous_aggregate_typedefs(types: &mut Vec<DwarfType>) {
    let aliases = types
        .iter()
        .filter(|candidate| candidate.kind == DwarfTypeKind::Typedef)
        .filter_map(|candidate| {
            let target = candidate.typedef_target.as_deref()?;
            let (kind, name) = target
                .strip_prefix("struct ")
                .map(|name| (DwarfTypeKind::Struct, name))
                .or_else(|| {
                    target
                        .strip_prefix("union ")
                        .map(|name| (DwarfTypeKind::Union, name))
                })?;
            name.starts_with("anon_")
                .then_some((kind, name.to_string(), candidate.name.clone()))
        })
        .collect::<Vec<_>>();
    for (kind, target, alias) in aliases {
        if types
            .iter()
            .any(|candidate| candidate.kind == kind && candidate.name == alias)
        {
            continue;
        }
        let Some(mut layout) = types
            .iter()
            .find(|candidate| candidate.kind == kind && candidate.name == target)
            .cloned()
        else {
            continue;
        };
        layout.name = alias;
        types.push(layout);
    }
}

fn _name_of(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> Option<String> {
    let v = entry.attr_value(gimli::DW_AT_name)?;
    let s = dwarf.attr_string(unit, v).ok()?;
    s.to_string().ok().map(|t| t.to_string())
}

fn _byte_size_of(entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>) -> u64 {
    match entry.attr_value(gimli::DW_AT_byte_size) {
        Some(gimli::AttributeValue::Udata(v)) => v,
        Some(gimli::AttributeValue::Data1(v)) => v as u64,
        Some(gimli::AttributeValue::Data2(v)) => v as u64,
        Some(gimli::AttributeValue::Data4(v)) => v as u64,
        Some(gimli::AttributeValue::Data8(v)) => v,
        _ => 0,
    }
}

fn _resolved_type_byte_size(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    type_attr: gimli::AttributeValue<Slice<'_>>,
    depth: usize,
) -> u64 {
    if depth >= 32 {
        return 0;
    }
    let gimli::AttributeValue::UnitRef(offset) = type_attr else {
        return 0;
    };
    let Ok(entry) = unit.entry(offset) else {
        return 0;
    };
    let direct = _byte_size_of(&entry);
    if direct != 0 {
        return direct;
    }
    match entry.tag() {
        gimli::DW_TAG_pointer_type | gimli::DW_TAG_reference_type => {
            u64::from(unit.encoding().address_size)
        }
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type => entry.attr_value(gimli::DW_AT_type).map_or(0, |target| {
            _resolved_type_byte_size(dwarf, unit, target, depth + 1)
        }),
        // An array's extent is element size times every dimension. Neither gcc
        // nor clang emits `DW_AT_byte_size` on `DW_TAG_array_type`, so the size
        // recorded for a member spelled `uint32_t[]` was ZERO, and every
        // consumer that reads a member's extent read a member with none.
        // `return_class::classify_fields` treats a zero-size member as
        // unplaceable and declines the whole aggregate, which is why a
        // sixteen-byte `struct mv203_narrow { uint32_t q[4]; }` had no System V
        // return or parameter class at all.
        gimli::DW_TAG_array_type => {
            let element = entry.attr_value(gimli::DW_AT_type).map_or(0, |target| {
                _resolved_type_byte_size(dwarf, unit, target, depth + 1)
            });
            _array_element_count(unit, offset)
                .and_then(|count| element.checked_mul(count))
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// The total element count of one `DW_TAG_array_type`, multiplied over every
/// dimension, or `None` when any dimension has no stateable bound.
///
/// A flexible array member (`int v[]`) genuinely has no extent, and inventing
/// one from a size would be worse than reporting none: the zero it keeps is
/// what makes every downstream reader decline the shape rather than place it
/// wrongly. Multi-dimensional arrays are several `DW_TAG_subrange_type`
/// children of ONE array entry, so the dimensions multiply.
fn _array_element_count(unit: &Unit<'_>, offset: gimli::UnitOffset<usize>) -> Option<u64> {
    let mut total: Option<u64> = None;
    let mut cursor = unit.entries_at_offset(offset).ok()?;
    let base = cursor.next_depth();
    if !matches!(cursor.next_entry(), Ok(true)) {
        return None;
    }
    loop {
        let level = cursor.next_depth();
        if !matches!(cursor.next_entry(), Ok(true)) || level <= base {
            break;
        }
        let Some(entry) = cursor.current() else {
            continue;
        };
        if entry.tag() != gimli::DW_TAG_subrange_type {
            continue;
        }
        let count = match entry.attr_value(gimli::DW_AT_count) {
            Some(value) => _constant_attribute(&value)?,
            None => {
                _constant_attribute(&entry.attr_value(gimli::DW_AT_upper_bound)?)?.checked_add(1)?
            }
        };
        total = Some(total.unwrap_or(1).checked_mul(count)?);
    }
    total
}

/// A DWARF constant-class attribute as a `u64`, or `None` for every other form.
fn _constant_attribute(value: &gimli::AttributeValue<Slice<'_>, usize>) -> Option<u64> {
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

fn _build_struct_or_class(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    source_file: &Option<String>,
    is_union: bool,
) -> Option<DwarfType> {
    // Skip declaration-only entries.
    if matches!(
        entry.attr_value(gimli::DW_AT_declaration),
        Some(gimli::AttributeValue::Flag(true))
    ) {
        return None;
    }
    let name =
        _name_of(dwarf, unit, entry).unwrap_or_else(|| format!("anon_{:x}", entry.offset().0));
    let kind = if is_union {
        DwarfTypeKind::Union
    } else {
        DwarfTypeKind::Struct
    };
    Some(DwarfType {
        kind,
        name,
        byte_size: _byte_size_of(entry),
        fields: Vec::new(),
        variants: Vec::new(),
        typedef_target: None,
        source_file: source_file.clone(),
    })
}

fn _build_enum(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    source_file: &Option<String>,
) -> Option<DwarfType> {
    if matches!(
        entry.attr_value(gimli::DW_AT_declaration),
        Some(gimli::AttributeValue::Flag(true))
    ) {
        return None;
    }
    let name =
        _name_of(dwarf, unit, entry).unwrap_or_else(|| format!("anon_enum_{:x}", entry.offset().0));
    Some(DwarfType {
        kind: DwarfTypeKind::Enum,
        name,
        byte_size: _byte_size_of(entry),
        fields: Vec::new(),
        variants: Vec::new(),
        typedef_target: None,
        source_file: source_file.clone(),
    })
}

fn _build_typedef(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
    source_file: &Option<String>,
) -> Option<DwarfType> {
    let name = _name_of(dwarf, unit, entry)?;
    let target_attr = entry.attr_value(gimli::DW_AT_type);
    let target = target_attr.and_then(|v| _resolve_type_string(dwarf, unit, v));
    Some(DwarfType {
        kind: DwarfTypeKind::Typedef,
        name,
        byte_size: target_attr.map_or(0, |target| _resolved_type_byte_size(dwarf, unit, target, 0)),
        fields: Vec::new(),
        variants: Vec::new(),
        typedef_target: target,
        source_file: source_file.clone(),
    })
}

fn _build_field(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> Option<DwarfField> {
    let name = _name_of(dwarf, unit, entry).unwrap_or_else(|| String::from("?"));
    let offset = match entry.attr_value(gimli::DW_AT_data_member_location) {
        Some(gimli::AttributeValue::Udata(v)) => v,
        Some(gimli::AttributeValue::Data1(v)) => v as u64,
        Some(gimli::AttributeValue::Data2(v)) => v as u64,
        Some(gimli::AttributeValue::Data4(v)) => v as u64,
        Some(gimli::AttributeValue::Data8(v)) => v,
        _ => 0,
    };
    let type_attr = entry.attr_value(gimli::DW_AT_type);
    let c_type = type_attr
        .and_then(|v| _resolve_type_string(dwarf, unit, v))
        .unwrap_or_else(|| String::from("/* unknown */"));
    Some(DwarfField {
        offset,
        name,
        c_type,
        size: type_attr.map_or(0, |target| _resolved_type_byte_size(dwarf, unit, target, 0)),
    })
}

fn _build_enum_variant(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> Option<DwarfEnumVariant> {
    let name = _name_of(dwarf, unit, entry)?;
    let value = match entry.attr_value(gimli::DW_AT_const_value) {
        Some(gimli::AttributeValue::Sdata(v)) => v,
        Some(gimli::AttributeValue::Udata(v)) => v as i64,
        Some(gimli::AttributeValue::Data1(v)) => v as i64,
        Some(gimli::AttributeValue::Data2(v)) => v as i64,
        Some(gimli::AttributeValue::Data4(v)) => v as i64,
        Some(gimli::AttributeValue::Data8(v)) => v as i64,
        _ => return None,
    };
    Some(DwarfEnumVariant { name, value })
}

fn prepend_type_qualifier(inner: &str, qualifier: &str) -> String {
    if inner.split_whitespace().next() == Some(qualifier) {
        inner.to_string()
    } else {
        format!("{qualifier} {inner}")
    }
}

/// Resolve a `DW_AT_type` reference to a printable C-ish type string.
/// Best-effort: handles base types (DW_TAG_base_type), pointers, refs,
/// arrays (as `T[]`), const/volatile qualifiers, and forwards to named
/// types by their `DW_AT_name`. Anonymous / unresolvable types render
/// as `/* unknown */`.
fn _resolve_type_string(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    type_attr: gimli::AttributeValue<Slice<'_>>,
) -> Option<String> {
    let off = match type_attr {
        gimli::AttributeValue::UnitRef(o) => o,
        _ => return None,
    };
    let entry = unit.entry(off).ok()?;
    let kind = entry.tag();
    match kind {
        gimli::DW_TAG_base_type | gimli::DW_TAG_typedef => {
            Some(_name_of(dwarf, unit, &entry).unwrap_or_else(|| "/* unknown */".to_string()))
        }
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => Some(format!(
            "struct {}",
            _name_of(dwarf, unit, &entry).unwrap_or_else(|| format!("anon_{:x}", off.0))
        )),
        gimli::DW_TAG_union_type => Some(format!(
            "union {}",
            _name_of(dwarf, unit, &entry).unwrap_or_else(|| format!("anon_{:x}", off.0))
        )),
        gimli::DW_TAG_enumeration_type => _name_of(dwarf, unit, &entry)
            .map(|name| format!("enum {name}"))
            .or_else(|| Some("/* unknown */".to_string())),
        gimli::DW_TAG_pointer_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(format!("{} *", inner))
        }
        gimli::DW_TAG_reference_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(format!("{} &", inner))
        }
        gimli::DW_TAG_const_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(prepend_type_qualifier(&inner, "const"))
        }
        gimli::DW_TAG_volatile_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(prepend_type_qualifier(&inner, "volatile"))
        }
        gimli::DW_TAG_array_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(format!("{}[]", inner))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_returns_empty() {
        let funcs = extract_dwarf_functions(&[]);
        assert!(funcs.is_empty());
    }

    #[test]
    fn non_dwarf_buffer_returns_empty() {
        // 64 bytes of garbage — should not panic.
        let funcs = extract_dwarf_functions(&[0xAA; 64]);
        assert!(funcs.is_empty());
    }

    #[test]
    fn repeated_type_qualifier_is_not_rendered_twice() {
        assert_eq!(prepend_type_qualifier("char *", "const"), "const char *");
        assert_eq!(
            prepend_type_qualifier("const char *", "const"),
            "const char *"
        );
    }

    #[test]
    fn literal_stack_value_is_a_declaration_only_local_location() {
        let bytes = [
            gimli::constants::DW_OP_lit0.0 as u8,
            gimli::constants::DW_OP_stack_value.0 as u8,
        ];
        let expression = gimli::Expression(gimli::EndianSlice::new(
            &bytes,
            gimli::RunTimeEndian::Little,
        ));
        let encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 4,
        };

        assert!(constant_stack_value_expression(encoding, expression));
    }

    #[test]
    fn empty_buffer_has_no_types() {
        assert!(extract_dwarf_types(&[]).is_empty());
    }

    #[test]
    fn direct_typedef_materializes_anonymous_struct_layout() {
        let mut types = vec![
            DwarfType {
                kind: DwarfTypeKind::Typedef,
                name: "BstNode".to_string(),
                byte_size: 0,
                fields: Vec::new(),
                variants: Vec::new(),
                typedef_target: Some("struct anon_107".to_string()),
                source_file: Some("bst.c".to_string()),
            },
            DwarfType {
                kind: DwarfTypeKind::Struct,
                name: "anon_107".to_string(),
                byte_size: 12,
                fields: vec![DwarfField {
                    offset: 0,
                    name: "key".to_string(),
                    c_type: "int32_t".to_string(),
                    size: 0,
                }],
                variants: Vec::new(),
                typedef_target: None,
                source_file: Some("bst.c".to_string()),
            },
        ];

        materialize_anonymous_aggregate_typedefs(&mut types);

        let alias = types
            .iter()
            .find(|candidate| {
                candidate.kind == DwarfTypeKind::Struct && candidate.name == "BstNode"
            })
            .expect("typedef alias should own an equivalent struct layout");
        assert_eq!(alias.byte_size, 12);
        assert_eq!(alias.fields[0].name, "key");
    }

    #[test]
    fn extracts_struct_with_fields_from_clang_debug() {
        let path =
            "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let types = extract_dwarf_types(&bytes);
        assert!(!types.is_empty(), "DWARF type reader returned no types");
        // Must have at least one struct with at least one field.
        let with_fields = types
            .iter()
            .filter(|t| t.kind == DwarfTypeKind::Struct && !t.fields.is_empty())
            .count();
        assert!(
            with_fields >= 1,
            "expected at least one struct with fields; got 0 of {} types",
            types.len()
        );
    }

    /// An ARRAY member reports the extent of the whole array.
    ///
    /// Neither gcc nor clang emits `DW_AT_byte_size` on `DW_TAG_array_type`, so
    /// `_resolved_type_byte_size` used to answer ZERO for a member spelled
    /// `uint32_t[]` and every consumer that asks how many bytes a member covers
    /// got a member covering none. `return_class::classify_fields` treats a
    /// zero-size member as unplaceable, which is why `struct mv203_narrow`
    /// — sixteen plain bytes — had no System V class at all.
    ///
    /// Read from a decompiler fixture because that is where a struct with an
    /// array member exists; the objects are generated, so a missing one is a
    /// skip rather than a failure, matching the sample-binary tests above.
    #[test]
    fn an_array_member_reports_the_whole_arrays_extent() {
        let path = "tests/decompiler_fixtures/build/203_string_move_copies-gcc-O0.so";
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let types = extract_dwarf_types(&bytes);
        let narrow = types
            .iter()
            .find(|layout| layout.name == "mv203_narrow")
            .expect("fixture 203 declares struct mv203_narrow");
        let [member] = narrow.fields.as_slice() else {
            panic!("expected exactly one member, got {:?}", narrow.fields);
        };
        assert_eq!(member.c_type, "uint32_t[]");
        assert_eq!(member.size, 16, "four uint32_t elements is sixteen bytes");
        assert_eq!(narrow.byte_size, 16);
    }

    /// End-to-end against a real ELF with DWARF: we expect to recover
    /// `main` with at least one parameter (argc) so the param-counting
    /// path is exercised. Skip if the sample binary isn't present.
    #[test]
    fn extracts_main_with_params_from_clang_debug() {
        let path =
            "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return, // sample absent — silently skip
        };
        let funcs = extract_dwarf_functions(&bytes);
        assert!(!funcs.is_empty(), "DWARF reader returned 0 functions");
        let main = funcs.iter().find(|f| f.name.as_deref() == Some("main"));
        assert!(
            main.is_some(),
            "main not found in DWARF — names seen: {:?}",
            funcs
                .iter()
                .filter_map(|f| f.name.as_deref())
                .take(10)
                .collect::<Vec<_>>()
        );
        let m = main.unwrap();
        assert!(!m.chunks.is_empty(), "main has no chunks");
        assert!(
            m.param_count >= 1,
            "main should have at least 1 parameter (argc), got {}",
            m.param_count
        );
    }
}
