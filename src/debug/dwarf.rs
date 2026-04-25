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

use std::convert::TryInto;

use object::{Object, ObjectSection};

/// One DWARF-discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfFunction {
    /// Entry virtual address (lowest address across all chunks).
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
    /// Whether the subprogram declared a prototype (`DW_AT_prototyped`).
    pub prototyped: bool,
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
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, ()> {
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
        // Each frame: (subprogram offset, param count seen, subprogram depth).
        let mut open: Vec<(gimli::UnitOffset<usize>, u32, isize)> = Vec::new();
        let mut emitted: Vec<(gimli::UnitOffset<usize>, u32)> = Vec::new();

        loop {
            let depth_of_next = cursor.next_depth();
            match cursor.next_entry() {
                Ok(true) => {}
                _ => break,
            }
            // Pop any subprograms whose subtree we've left.
            while let Some(&(off, count, sub_depth)) = open.last() {
                if depth_of_next <= sub_depth {
                    emitted.push((off, count));
                    open.pop();
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
                    open.push((entry.offset(), 0, depth_of_next));
                }
                gimli::DW_TAG_formal_parameter => {
                    if let Some(top) = open.last_mut() {
                        if depth_of_next == top.2 + 1 {
                            top.1 += 1;
                        }
                    }
                }
                _ => {}
            }
        }
        while let Some((off, count, _)) = open.pop() {
            emitted.push((off, count));
        }

        for (off, param_count) in emitted {
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

            let chunks = match collect_ranges(&dwarf, &unit, &entry) {
                Ok(rs) if !rs.is_empty() => rs,
                _ => continue,
            };
            let entry_va = chunks.iter().map(|r| r.start).min().unwrap_or(0);

            let name = pick_name(&dwarf, &unit, &entry);
            let prototyped = matches!(
                entry.attr_value(gimli::DW_AT_prototyped),
                Some(gimli::AttributeValue::Flag(true))
            );

            funcs.push(DwarfFunction {
                entry_va,
                chunks,
                name,
                source_file: unit_name.clone(),
                language: unit_lang.clone(),
                param_count,
                prototyped,
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

fn pick_name(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> Option<String> {
    // DW_AT_linkage_name (mangled) wins — matches what's in the symbol
    // table. Fall back to DW_AT_name (unqualified) only if absent.
    for attr in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name, gimli::DW_AT_name] {
        if let Some(v) = entry.attr_value(attr) {
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

fn unit_name(
    dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
) -> Option<String> {
    let mut cursor = unit.entries();
    let entry = cursor.next_dfs().ok().flatten()?;
    let v = entry.attr_value(gimli::DW_AT_name)?;
    let s = dwarf.attr_string(unit, v).ok()?;
    Some(s.to_string().ok()?.to_string())
}

fn unit_language(
    _dwarf: &gimli::Dwarf<Slice<'_>>,
    unit: &Unit<'_>,
) -> Option<String> {
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
                    out.push(DwarfRange { start: r.begin, size: r.end - r.begin });
                }
            }
            out.sort_unstable_by_key(|r| r.start);
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
    Ok(vec![DwarfRange { start: low_pc, size: end - low_pc }])
}

// ---------------------------------------------------------------------------
// Type extraction (DW_TAG_structure_type, _enumeration_type, _typedef)
// ---------------------------------------------------------------------------

/// Read DWARF type definitions from `data`. Returns an empty Vec if the
/// binary has no DWARF or parsing fails. Like
/// `extract_dwarf_functions`, this is best-effort — malformed CUs are
/// silently skipped.
pub fn extract_dwarf_types(data: &[u8]) -> Vec<DwarfType> {
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<gimli::EndianSlice<'_, gimli::RunTimeEndian>, ()> {
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
                    if let Some(t) = _build_struct_or_class(&dwarf, &unit, entry, &unit_src, false) {
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
                            && matches!(
                                parent.kind,
                                DwarfTypeKind::Struct | DwarfTypeKind::Union
                            )
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
        out.extend(emitted);
    }

    // Dedup by (kind, name) — DWARF often emits the same type in many
    // CUs. Keep the first seen, which is also the richest with the
    // current ordering.
    let mut seen: std::collections::HashSet<(DwarfTypeKind, String)> =
        std::collections::HashSet::new();
    out.retain(|t| seen.insert((t.kind, t.name.clone())));
    out
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

fn _byte_size_of(
    entry: &gimli::DebuggingInformationEntry<Slice<'_>, usize>,
) -> u64 {
    match entry.attr_value(gimli::DW_AT_byte_size) {
        Some(gimli::AttributeValue::Udata(v)) => v,
        Some(gimli::AttributeValue::Data1(v)) => v as u64,
        Some(gimli::AttributeValue::Data2(v)) => v as u64,
        Some(gimli::AttributeValue::Data4(v)) => v as u64,
        Some(gimli::AttributeValue::Data8(v)) => v,
        _ => 0,
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
    let name = _name_of(dwarf, unit, entry)
        .unwrap_or_else(|| format!("anon_{:x}", entry.offset().0));
    let kind = if is_union { DwarfTypeKind::Union } else { DwarfTypeKind::Struct };
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
    let name = _name_of(dwarf, unit, entry)
        .unwrap_or_else(|| format!("anon_enum_{:x}", entry.offset().0));
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
    let target = entry
        .attr_value(gimli::DW_AT_type)
        .and_then(|v| _resolve_type_string(dwarf, unit, v));
    Some(DwarfType {
        kind: DwarfTypeKind::Typedef,
        name,
        byte_size: _byte_size_of(entry),
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
    let c_type = entry
        .attr_value(gimli::DW_AT_type)
        .and_then(|v| _resolve_type_string(dwarf, unit, v))
        .unwrap_or_else(|| String::from("/* unknown */"));
    Some(DwarfField {
        offset,
        name,
        c_type,
        size: _byte_size_of(entry),
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
        gimli::DW_TAG_base_type
        | gimli::DW_TAG_structure_type
        | gimli::DW_TAG_union_type
        | gimli::DW_TAG_class_type
        | gimli::DW_TAG_enumeration_type
        | gimli::DW_TAG_typedef => Some(
            _name_of(dwarf, unit, &entry).unwrap_or_else(|| "/* unknown */".to_string()),
        ),
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
            Some(format!("const {}", inner))
        }
        gimli::DW_TAG_volatile_type => {
            let inner = entry
                .attr_value(gimli::DW_AT_type)
                .and_then(|v| _resolve_type_string(dwarf, unit, v))
                .unwrap_or_else(|| "void".to_string());
            Some(format!("volatile {}", inner))
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
    fn empty_buffer_has_no_types() {
        assert!(extract_dwarf_types(&[]).is_empty());
    }

    #[test]
    fn extracts_struct_with_fields_from_clang_debug() {
        let path = "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug";
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
        assert!(with_fields >= 1,
                "expected at least one struct with fields; got 0 of {} types",
                types.len());
    }

    /// End-to-end against a real ELF with DWARF: we expect to recover
    /// `main` with at least one parameter (argc) so the param-counting
    /// path is exercised. Skip if the sample binary isn't present.
    #[test]
    fn extracts_main_with_params_from_clang_debug() {
        let path = "samples/binaries/platforms/linux/amd64/export/native/clang/debug/hello-clang-debug";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return, // sample absent — silently skip
        };
        let funcs = extract_dwarf_functions(&bytes);
        assert!(!funcs.is_empty(), "DWARF reader returned 0 functions");
        let main = funcs.iter().find(|f| f.name.as_deref() == Some("main"));
        assert!(main.is_some(), "main not found in DWARF — names seen: {:?}",
                funcs.iter().filter_map(|f| f.name.as_deref()).take(10).collect::<Vec<_>>());
        let m = main.unwrap();
        assert!(!m.chunks.is_empty(), "main has no chunks");
        assert!(m.param_count >= 1,
                "main should have at least 1 parameter (argc), got {}",
                m.param_count);
    }
}
