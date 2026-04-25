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
