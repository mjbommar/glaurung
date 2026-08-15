//! Jump-table detection for switch-statement reconstruction (#177).
//!
//! Modern compilers lower dense `switch (x) { case 0: ...; case 1: ...; }`
//! statements into one of two patterns on x86_64:
//!
//! 1. **Absolute-pointer table** — an array of u64 (or u32 on 32-bit)
//!    code pointers in `.rodata`, each pointing into `.text`. The
//!    dispatch looks like `mov rax, [reg*8 + table]; jmp rax`. These
//!    are structurally identical to vtables and already get picked up
//!    by `analysis::vtable::discover_vtables`. We surface them here
//!    too for completeness, with a slightly looser policy (run length
//!    >= 4 vs vtable's 3) so we don't double-count short sequences.
//!
//! 2. **Relative-offset table** — an array of i32 offsets, each
//!    encoding `(target_va - table_va)` (GCC) or `(target_va -
//!    func_start_va)` (older clang). The dispatch is
//!    `lea r1, [rip + table]; movsxd r2, [r1 + idx*4]; add r1, r2;
//!    jmp r1`. Without recognizing this pattern, the analyser misses
//!    every switch case as a discoverable function entry / CFG edge.
//!
//! v1 ships pattern (2) — the harder case (1) overlap is left to the
//! existing vtable walker. Output is `(table_va, [target_va, ...])`
//! tuples; the cfg pass adds the targets as discovery seeds.

use std::collections::BTreeSet;

use object::{Object, ObjectSection, SectionKind};

/// A detected relative-offset jump table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    /// VA at which the table starts.
    pub table_va: u64,
    /// Inferred target VAs (resolved from offsets).
    pub targets: Vec<u64>,
}

/// Which check refused to decode a table at a dispatch-proven address.
///
/// Every decode path in this module used to answer `None`. Two dozen `?` and
/// early-return sites across the four decode functions - an entry budget, a
/// section-bounds miss, a non-executable target, a target that lands inside its
/// own table, an absent extent, a parse failure - arrived at the caller as the
/// same bare nothing, and
/// [`crate::analysis::dispatch::Resolution`] then collapsed all of them into one
/// `NoTableAt`. That is design rule 8's failure mode exactly: the proof ran, it
/// knew precisely what went wrong, and the answer was dropped on the floor.
///
/// The variants carry the operands the check compared, not just its name, so a
/// consumer can act on them: `EntryCountAboveCeiling` names a ceiling that could
/// be raised, `NonExecutableTarget` names the VA that failed the region test,
/// and `NoSectionCovers` says whether the table address is even mapped.
///
/// [`Self::label`] is the stable histogram key; [`std::fmt::Display`] is the
/// human detail. Keeping them separate is what lets a census rank causes without
/// having to parse a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableDecline {
    /// The dispatch's guard proved an extent of zero entries.
    ZeroEntries,
    /// The proven extent is above [`MAX_TABLE_ENTRIES`]. The bound is a real
    /// dataflow fact, so this is a budget refusal, not a soundness one.
    EntryCountAboveCeiling { requested: usize, ceiling: usize },
    /// `entry_count * entry_size` overflowed `usize`.
    ExtentOverflow {
        entry_count: usize,
        entry_size: usize,
    },
    /// A `tbb`/`tbh` entry width this decoder does not model.
    UnsupportedEntrySize { entry_size: u8 },
    /// No single section holds all `byte_count` bytes at the table address. The
    /// dispatch named a place that is not mapped, or a table that straddles a
    /// section boundary - either way the bytes cannot be read.
    NoSectionCovers { table_va: u64, byte_count: usize },
    /// The byte-only entry point could not parse its input as an object file.
    ObjectParseFailed,
    /// Entry `index` resolved to a VA outside every executable region.
    NonExecutableTarget { index: usize, target: u64 },
    /// Entry `index` of a Thumb table resolved back INTO the table. Unsigned
    /// entries make that impossible for real code, so it is the signature of an
    /// over-long bound reading the case bodies that follow the table.
    TargetInsideTable { index: usize, target: u64 },
    /// Entry `index`'s target address arithmetic overflowed.
    TargetArithmeticOverflow { index: usize },
    /// No bounded decode was offered by the caller.
    /// [`crate::analysis::dispatch::DispatchTracker::resolve`] takes this path:
    /// it resolves against an already-scanned table index and holds no bytes to
    /// decode from.
    DecodeNotAttempted,
    /// The dispatch was understood and the whole-section scan found no table at
    /// the address it named, with no guard bound available to attempt an exact
    /// decode instead.
    ScanFoundNoTable,
    /// The guard's inclusive maximum does not fit a `usize` entry count.
    BoundExceedsAddressSpace { bound: u64 },
}

/// The largest table any decoder in this module will read.
pub const MAX_TABLE_ENTRIES: usize = 4096;

impl TableDecline {
    /// A stable, lowercase, underscore-separated key for histogramming.
    ///
    /// Deliberately value-free: a census that keys on the formatted detail gets
    /// one bucket per table address and ranks nothing.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ZeroEntries => "zero_entries",
            Self::EntryCountAboveCeiling { .. } => "entry_count_above_ceiling",
            Self::ExtentOverflow { .. } => "extent_overflow",
            Self::UnsupportedEntrySize { .. } => "unsupported_entry_size",
            Self::NoSectionCovers { .. } => "no_section_covers",
            Self::ObjectParseFailed => "object_parse_failed",
            Self::NonExecutableTarget { .. } => "non_executable_target",
            Self::TargetInsideTable { .. } => "target_inside_table",
            Self::TargetArithmeticOverflow { .. } => "target_arithmetic_overflow",
            Self::DecodeNotAttempted => "decode_not_attempted",
            Self::ScanFoundNoTable => "scan_found_no_table",
            Self::BoundExceedsAddressSpace { .. } => "bound_exceeds_address_space",
        }
    }
}

impl std::fmt::Display for TableDecline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroEntries => write!(f, "guard proved an extent of zero entries"),
            Self::EntryCountAboveCeiling { requested, ceiling } => {
                write!(f, "{requested} entries requested, ceiling is {ceiling}")
            }
            Self::ExtentOverflow {
                entry_count,
                entry_size,
            } => write!(f, "{entry_count} x {entry_size} bytes overflowed usize"),
            Self::UnsupportedEntrySize { entry_size } => {
                write!(f, "entry size {entry_size} is not 1 or 2")
            }
            Self::NoSectionCovers {
                table_va,
                byte_count,
            } => write!(f, "no section holds {byte_count} bytes at {table_va:#x}"),
            Self::ObjectParseFailed => write!(f, "input did not parse as an object file"),
            Self::NonExecutableTarget { index, target } => {
                write!(f, "entry {index} resolves to non-executable {target:#x}")
            }
            Self::TargetInsideTable { index, target } => {
                write!(f, "entry {index} resolves to {target:#x}, inside the table")
            }
            Self::TargetArithmeticOverflow { index } => {
                write!(f, "entry {index} target address overflowed")
            }
            Self::DecodeNotAttempted => write!(f, "caller offered no bounded decode"),
            Self::ScanFoundNoTable => write!(f, "section scan found no table at this address"),
            Self::BoundExceedsAddressSpace { bound } => {
                write!(f, "guard bound {bound} does not fit an entry count")
            }
        }
    }
}

/// Decode exactly `entry_count` relative offsets at a dispatch-proven table
/// address.
///
/// Whole-section scanning cannot reliably separate adjacent tables: offsets
/// from the next table can still land in executable memory when interpreted
/// relative to the previous table's base.  A guarded dispatch supplies the
/// missing extent, so this path uses that proof instead of guessing an end.
///
/// `image` is the session's already indexed view of `data`. A dispatching
/// function is resolved once per indirect branch, so reopening the object here
/// cost one parse per switch statement; when an image is supplied the same
/// section table is read from it instead. `data` remains the fallback for the
/// byte-only compatibility entry points.
pub fn decode_bounded_relative_jump_table<F>(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    table_va: u64,
    entry_count: usize,
    is_executable_va: F,
) -> Result<JumpTable, TableDecline>
where
    F: Fn(u64) -> bool,
{
    if entry_count == 0 {
        return Err(TableDecline::ZeroEntries);
    }
    if entry_count > MAX_TABLE_ENTRIES {
        return Err(TableDecline::EntryCountAboveCeiling {
            requested: entry_count,
            ceiling: MAX_TABLE_ENTRIES,
        });
    }
    let byte_count = entry_count
        .checked_mul(4)
        .ok_or(TableDecline::ExtentOverflow {
            entry_count,
            entry_size: 4,
        })?;

    // The first section that actually holds the bytes owns the answer: if its
    // entries do not decode, a later section cannot hold the same VA range, so
    // reporting that section's decline is reporting THE decline. Only when no
    // section covers the range at all is the miss about the address itself.
    let mut decline = TableDecline::NoSectionCovers {
        table_va,
        byte_count,
    };

    if let Some(image) = image {
        let little_endian = image.endianness() == crate::core::binary::Endianness::Little;
        for section in image.sections() {
            let Some(entries) =
                section_entries(section.address(), section.data(), table_va, byte_count)
            else {
                continue;
            };
            match decode_relative_entries(
                entries,
                table_va,
                entry_count,
                little_endian,
                &is_executable_va,
            ) {
                Ok(targets) => return Ok(JumpTable { table_va, targets }),
                Err(why) => {
                    decline = why;
                    continue;
                }
            }
        }
        return Err(decline);
    }

    let object = crate::decompile::profile::parse_object(data)
        .map_err(|_| TableDecline::ObjectParseFailed)?;
    let little_endian = object.is_little_endian();
    for section in object.sections() {
        let Ok(bytes) = section.data() else {
            continue;
        };
        let Some(entries) = section_entries(section.address(), bytes, table_va, byte_count) else {
            continue;
        };
        match decode_relative_entries(
            entries,
            table_va,
            entry_count,
            little_endian,
            &is_executable_va,
        ) {
            Ok(targets) => return Ok(JumpTable { table_va, targets }),
            Err(why) => {
                decline = why;
                continue;
            }
        }
    }
    Err(decline)
}

/// Exactly `byte_count` bytes at `table_va` inside one section, when they fit.
fn section_entries(
    section_va: u64,
    bytes: &[u8],
    table_va: u64,
    byte_count: usize,
) -> Option<&[u8]> {
    let offset = usize::try_from(table_va.checked_sub(section_va)?).ok()?;
    bytes.get(offset..offset.checked_add(byte_count)?)
}

/// Decode the inline table of a Thumb-2 `tbb`/`tbh` table branch.
///
/// `tbb [Rn, Rm]` and `tbh [Rn, Rm, lsl #1]` load an unsigned byte/halfword from
/// a table at `Rn`, double it, and add it to `pc`. Compilers always emit them
/// with `Rn == pc`, which in Thumb state reads as *this instruction's address +
/// 4* — i.e. the byte immediately after the 4-byte encoding — so the table is
/// **inline in `.text`**, not in `.rodata`, and its entries are unsigned
/// halfword-counts forward from the table's own start:
///
/// ```text
/// cmp   r5, #239
/// bhi.w default
/// tbh   [pc, r5, lsl #1]     ; table_va = here + 4
/// .short (case0 - table_va)/2, (case1 - table_va)/2, ...
/// ```
///
/// This is a different encoding from [`decode_bounded_relative_jump_table`] in
/// every respect that matters — entry width, signedness, scale, and which
/// section it lives in — so it gets its own decoder rather than a parameter.
///
/// `entry_count` must come from the dispatch's own range check. There is no way
/// to find the end of the table by scanning: past the last entry lie the case
/// bodies, whose instruction bytes are perfectly good unsigned offsets and
/// decode to targets that are still executable.
///
/// # Soundness check
///
/// Entries are unsigned, so every target is at or after `table_va`. A target
/// that lands *inside the table* is therefore impossible in real code, and a
/// count that overruns the table produces exactly that: the first over-read
/// entry is an instruction byte from the arm that follows the table, which is a
/// small number and resolves back into the table. Requiring every target to be
/// at or past the table's end is what makes an over-long bound fail closed.
///
/// `image` is the session's indexed view of `data`; see
/// [`decode_bounded_relative_jump_table`] for why it is preferred over
/// reopening the object.
pub fn decode_thumb_table_branch<F>(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    table_va: u64,
    entry_size: u8,
    entry_count: usize,
    is_executable_va: F,
) -> Result<JumpTable, TableDecline>
where
    F: Fn(u64) -> bool,
{
    if !matches!(entry_size, 1 | 2) {
        return Err(TableDecline::UnsupportedEntrySize { entry_size });
    }
    if entry_count == 0 {
        return Err(TableDecline::ZeroEntries);
    }
    if entry_count > MAX_TABLE_ENTRIES {
        return Err(TableDecline::EntryCountAboveCeiling {
            requested: entry_count,
            ceiling: MAX_TABLE_ENTRIES,
        });
    }
    let byte_count =
        entry_count
            .checked_mul(usize::from(entry_size))
            .ok_or(TableDecline::ExtentOverflow {
                entry_count,
                entry_size: usize::from(entry_size),
            })?;

    if let Some(image) = image {
        let little_endian = image.endianness() == crate::core::binary::Endianness::Little;
        for section in image.sections() {
            let Some(entries) =
                section_entries(section.address(), section.data(), table_va, byte_count)
            else {
                continue;
            };
            let targets = decode_thumb_table_entries(
                entries,
                table_va,
                entry_size,
                little_endian,
                &is_executable_va,
            )?;
            return Ok(JumpTable { table_va, targets });
        }
        return Err(TableDecline::NoSectionCovers {
            table_va,
            byte_count,
        });
    }

    let object = crate::decompile::profile::parse_object(data)
        .map_err(|_| TableDecline::ObjectParseFailed)?;
    let little_endian = object.is_little_endian();
    for section in object.sections() {
        let Ok(bytes) = section.data() else {
            continue;
        };
        let Some(entries) = section_entries(section.address(), bytes, table_va, byte_count) else {
            continue;
        };
        let targets = decode_thumb_table_entries(
            entries,
            table_va,
            entry_size,
            little_endian,
            &is_executable_va,
        )?;
        return Ok(JumpTable { table_va, targets });
    }
    Err(TableDecline::NoSectionCovers {
        table_va,
        byte_count,
    })
}

/// The entry arithmetic of [`decode_thumb_table_branch`], on the exact bytes.
///
/// Separated for the same reason `decode_relative_entries` is: the encoding is
/// testable against real compiler output without standing up an ELF around it.
fn decode_thumb_table_entries<F>(
    entries: &[u8],
    table_va: u64,
    entry_size: u8,
    little_endian: bool,
    is_executable_va: &F,
) -> Result<Vec<u64>, TableDecline>
where
    F: Fn(u64) -> bool,
{
    let table_end = table_va
        .checked_add(entries.len() as u64)
        .ok_or(TableDecline::TargetArithmeticOverflow { index: 0 })?;
    let mut targets = Vec::with_capacity(entries.len() / usize::from(entry_size));
    for (index, entry) in entries.chunks_exact(usize::from(entry_size)).enumerate() {
        let raw = match entry {
            [byte] => u64::from(*byte),
            [low, high] if little_endian => u64::from(u16::from_le_bytes([*low, *high])),
            [high, low] => u64::from(u16::from_be_bytes([*high, *low])),
            _ => return Err(TableDecline::UnsupportedEntrySize { entry_size }),
        };
        let target = raw
            .checked_mul(2)
            .and_then(|scaled| table_va.checked_add(scaled))
            .ok_or(TableDecline::TargetArithmeticOverflow { index })?;
        if target < table_end {
            return Err(TableDecline::TargetInsideTable { index, target });
        }
        if !is_executable_va(target) {
            return Err(TableDecline::NonExecutableTarget { index, target });
        }
        targets.push(target);
    }
    Ok(targets)
}

fn decode_relative_entries<F>(
    bytes: &[u8],
    table_va: u64,
    entry_count: usize,
    little_endian: bool,
    is_executable_va: &F,
) -> Result<Vec<u64>, TableDecline>
where
    F: Fn(u64) -> bool,
{
    let byte_count = entry_count
        .checked_mul(4)
        .ok_or(TableDecline::ExtentOverflow {
            entry_count,
            entry_size: 4,
        })?;
    let entries = bytes
        .get(..byte_count)
        .ok_or(TableDecline::NoSectionCovers {
            table_va,
            byte_count,
        })?;
    let mut targets = Vec::with_capacity(entry_count);
    for (index, entry) in entries.chunks_exact(4).enumerate() {
        let bytes: [u8; 4] = [entry[0], entry[1], entry[2], entry[3]];
        let raw = if little_endian {
            i32::from_le_bytes(bytes)
        } else {
            i32::from_be_bytes(bytes)
        };
        let target = (table_va as i64).wrapping_add(raw as i64) as u64;
        if !is_executable_va(target) {
            return Err(TableDecline::NonExecutableTarget { index, target });
        }
        targets.push(target);
    }
    Ok(targets)
}

/// Scan rodata-shaped sections for relative-offset jump tables.
/// `is_executable_va` returns true for any VA that lies in an
/// executable region (passed in by the caller — `cfg.rs` already
/// has this information from `parse_exec_regions`).
///
/// Heuristic: a contiguous run of >= 4 i32 values, each interpreted
/// as `target = table_va + (i32) value`, all resolving to executable
/// VAs. Stops on the first non-resolving entry.
pub fn discover_jump_tables<F>(data: &[u8], is_executable_va: F) -> Vec<JumpTable>
where
    F: Fn(u64) -> bool,
{
    let obj = match crate::decompile::profile::parse_object(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    // There is deliberately no architecture guard here.
    //
    // This used to read `if !obj.is_64() && !obj.is_little_endian() { return
    // Vec::new(); }`, whose only effect is to reject 32-bit BIG-endian and
    // nothing else: 32-bit little-endian, 64-bit big-endian and 64-bit
    // little-endian all pass it. No reading of this decoder makes that a
    // meaningful set. The obvious repair - `||`, i.e. "64-bit little-endian
    // only" - is worse than the bug: i386 PIC lowers a switch to exactly this
    // table shape (`target = table_va + (i32)table[i]`), and the armv7 lanes of
    // `tools/arch_roundtrip.py` are 32-bit too, so `||` withdraws the scan from
    // architectures it currently serves in exchange for nothing.
    //
    // Every property this scan relies on is architecture-neutral: entries are
    // i32 whatever the pointer size, `endian_le` below parameterises the only
    // byte-order decision, and each candidate target must independently pass
    // `is_executable_va` before the run is accepted. The guard was protecting
    // against a decode bug that does not exist.
    let endian_le = obj.is_little_endian();

    let mut out: Vec<JumpTable> = Vec::new();
    let mut seen_tables: BTreeSet<u64> = BTreeSet::new();

    for sec in obj.sections() {
        // Only scan sections likely to hold rodata-style offset tables.
        // .rodata, .data.rel.ro, anything section-name-flagged readonly.
        let kind = sec.kind();
        let sec_name = sec.name().unwrap_or("");
        let scan = matches!(
            kind,
            SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel | SectionKind::Data
        ) || sec_name.starts_with(".rodata")
            || sec_name.contains("rel.ro");
        if !scan {
            continue;
        }
        let bytes = match sec.data() {
            Ok(b) => b,
            Err(_) => continue,
        };
        if bytes.len() < 16 {
            continue;
        }
        let vbase = sec.address();

        let mut i = 0usize;
        while i + 16 <= bytes.len() {
            let table_va = vbase + i as u64;
            // Treat each 4-byte value as a signed i32 offset relative
            // to the table's start; build the longest run that resolves.
            let mut run: Vec<u64> = Vec::new();
            let mut j = i;
            while j + 4 <= bytes.len() {
                let raw = if endian_le {
                    i32::from_le_bytes([bytes[j], bytes[j + 1], bytes[j + 2], bytes[j + 3]])
                } else {
                    i32::from_be_bytes([bytes[j], bytes[j + 1], bytes[j + 2], bytes[j + 3]])
                };
                let target = (table_va as i64).wrapping_add(raw as i64) as u64;
                if !is_executable_va(target) {
                    break;
                }
                run.push(target);
                j += 4;
            }
            if run.len() >= 4 && !seen_tables.contains(&table_va) {
                seen_tables.insert(table_va);
                out.push(JumpTable {
                    table_va,
                    targets: run,
                });
                i = j;
            } else {
                // Step by 4 (table entries are u32-aligned in practice).
                i += 4;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror the inner-loop logic on a synthetic byte buffer so the
    /// scan invariants are testable without a real ELF.
    fn _scan_section(bytes: &[u8], vbase: u64, exec_lo: u64, exec_hi: u64) -> Vec<JumpTable> {
        let is_exec = |va: u64| va >= exec_lo && va < exec_hi;
        let mut out: Vec<JumpTable> = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut i = 0usize;
        while i + 16 <= bytes.len() {
            let table_va = vbase + i as u64;
            let mut run = Vec::new();
            let mut j = i;
            while j + 4 <= bytes.len() {
                let raw = i32::from_le_bytes(bytes[j..j + 4].try_into().unwrap());
                let target = (table_va as i64).wrapping_add(raw as i64) as u64;
                if !is_exec(target) {
                    break;
                }
                run.push(target);
                j += 4;
            }
            if run.len() >= 4 && !seen.contains(&table_va) {
                seen.insert(table_va);
                out.push(JumpTable {
                    table_va,
                    targets: run,
                });
                i = j;
            } else {
                i += 4;
            }
        }
        out
    }

    fn _i32_le(v: i32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn detects_run_of_four_relative_targets() {
        // Table sits at VA 0x4000, .text spans [0x1000, 0x2000).
        // 4 consecutive offsets that resolve to 0x1100 / 0x1200 / 0x1300 / 0x1400.
        let table_va = 0x4000u64;
        let entries = [0x1100u64, 0x1200, 0x1300, 0x1400];
        let mut data = Vec::new();
        for tgt in &entries {
            let off = (*tgt as i64 - table_va as i64) as i32;
            data.extend_from_slice(&_i32_le(off));
        }
        // Trailing zero so the run terminates cleanly.
        data.extend_from_slice(&_i32_le(0));
        let tables = _scan_section(&data, table_va, 0x1000, 0x2000);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].table_va, table_va);
        assert_eq!(tables[0].targets, entries);
    }

    #[test]
    fn rejects_run_of_three() {
        let table_va = 0x4000u64;
        let mut data = Vec::new();
        for tgt in [0x1100, 0x1200, 0x1300] {
            let off = (tgt as i64 - table_va as i64) as i32;
            data.extend_from_slice(&_i32_le(off));
        }
        data.extend_from_slice(&_i32_le(0)); // breaker
        let tables = _scan_section(&data, table_va, 0x1000, 0x2000);
        assert!(tables.is_empty(), "3-entry runs are below the threshold");
    }

    #[test]
    fn ignores_offsets_pointing_outside_text() {
        let table_va = 0x4000u64;
        let mut data = Vec::new();
        for tgt in [0x9000, 0x9100, 0x9200, 0x9300] {
            let off = (tgt as i64 - table_va as i64) as i32;
            data.extend_from_slice(&_i32_le(off));
        }
        let tables = _scan_section(&data, table_va, 0x1000, 0x2000);
        assert!(tables.is_empty());
    }

    #[test]
    fn handles_negative_offsets_correctly() {
        // Table sits AHEAD of .text — entries are negative offsets
        // pointing back into earlier code. This is the GCC -O2 layout
        // when the function ends up before its own jump table.
        let table_va = 0x5000u64;
        let mut data = Vec::new();
        for tgt in [0x1000u64, 0x1080, 0x1100, 0x1180] {
            let off = (tgt as i64 - table_va as i64) as i32;
            data.extend_from_slice(&_i32_le(off));
        }
        let tables = _scan_section(&data, table_va, 0x1000, 0x2000);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].targets[0], 0x1000);
    }

    #[test]
    fn bounded_decode_recovers_an_adjacent_table_hidden_by_the_section_scan() {
        let first_va = 0x4000u64;
        let second_va = first_va + 16;
        let first_targets = [0x1100u64, 0x1120, 0x1140, 0x1160];
        let second_targets = [0x1200u64, 0x1220, 0x1240, 0x1260];
        let mut bytes = Vec::new();
        for target in first_targets {
            bytes.extend_from_slice(&_i32_le((target as i64 - first_va as i64) as i32));
        }
        for target in second_targets {
            bytes.extend_from_slice(&_i32_le((target as i64 - second_va as i64) as i32));
        }
        bytes.extend_from_slice(&_i32_le(0));

        let scanned = _scan_section(&bytes, first_va, 0x1000, 0x2000);
        assert_eq!(scanned.len(), 1, "the unbounded scan merges both tables");
        assert_eq!(scanned[0].table_va, first_va);

        let decoded = decode_relative_entries(&bytes[16..], second_va, 4, true, &|target| {
            (0x1000..0x2000).contains(&target)
        })
        .expect("the dispatch-proven extent must recover the second table");
        assert_eq!(decoded, second_targets);
    }

    /// `08_indirect_dispatch.c:dispatch_switch`, built by
    /// `arm-linux-gnueabihf-gcc -O2 -march=armv7-a -mthumb` (the `armv7` lane of
    /// `tools/arch_roundtrip.py`). The whole dispatch, verbatim:
    ///
    /// ```text
    /// 434: 2804        cmp  r0, #4
    /// 436: d81a        bhi.n 46e
    /// 438: e8df f000   tbb  [pc, r0]
    /// 43c: 09 0c 0f 14 03
    /// ```
    ///
    /// Bound 4 means five entries; `pc` at the `tbb` is `0x438 + 4 == 0x43c`.
    #[test]
    fn decodes_a_real_gcc_thumb_tbb_table() {
        let table_va = 0x43c;
        let entries = [0x09u8, 0x0c, 0x0f, 0x14, 0x03];
        let targets =
            decode_thumb_table_entries(&entries, table_va, 1, true, &|_target| true).unwrap();
        assert_eq!(targets, vec![0x44e, 0x454, 0x45a, 0x464, 0x442]);
    }

    /// `04_switch_shapes.c:shared_bodies` from the same build: four cases over
    /// two bodies, so entries repeat. The successor ORDER is what carries the
    /// case labels, so the repeats must survive decoding.
    ///
    /// ```text
    /// 6ac: 2803        cmp  r0, #3
    /// 6ae: d809        bhi.n 6c4
    /// 6b0: e8df f000   tbb  [pc, r0]
    /// 6b4: 05 02 05 02
    /// ```
    #[test]
    fn a_real_tbb_table_with_repeated_bodies_keeps_its_duplicate_targets() {
        let targets =
            decode_thumb_table_entries(&[0x05, 0x02, 0x05, 0x02], 0x6b4, 1, true, &|_t| true)
                .unwrap();
        assert_eq!(targets, vec![0x6be, 0x6b8, 0x6be, 0x6b8]);
    }

    /// An entry count larger than the guard proves reads the first case body's
    /// instruction bytes as offsets. Those are small, so they resolve back INTO
    /// the table — which is impossible for real code and is what makes the
    /// over-read fail closed instead of attaching a phantom arm.
    #[test]
    fn an_overlong_bound_is_refused_because_its_target_lands_inside_the_table() {
        // The real 5-entry table above, read as if the guard had proved 6.
        // Byte 5 is `0x2b`, the first byte of the arm at 0x442 (`cmp r1, r2`
        // is `4291`; the byte here is whatever follows — anything small).
        let entries = [0x09u8, 0x0c, 0x0f, 0x14, 0x03, 0x01];
        assert_eq!(
            decode_thumb_table_entries(&entries, 0x43c, 1, true, &|_t| true),
            Err(TableDecline::TargetInsideTable {
                index: 5,
                target: 0x43e
            }),
            "the over-read entry must name itself, not answer a bare None"
        );
    }

    /// `tbh` doubles a HALFWORD, which is how a 240-case switch reaches arms
    /// 6 KB away. betaflight's `mspProcessInCommand` (`bin_166.elf`, DecBench
    /// holdout) at `0x802818c`: `tbh [pc, r5, lsl #1]`, table at `0x8028190`.
    /// Entry 0 is `0x0d19`, entry 1 the shared default `0x00f3`.
    #[test]
    fn decodes_a_real_thumb_tbh_halfword_table() {
        let table_va = 0x8028190;
        let entries = [0x19u8, 0x0d, 0xf3, 0x00];
        let targets =
            decode_thumb_table_entries(&entries, table_va, 2, true, &|_target| true).unwrap();
        assert_eq!(targets, vec![0x8029bc2, 0x8028376]);
    }

    #[test]
    fn a_non_executable_thumb_target_refuses_the_whole_table() {
        assert_eq!(
            decode_thumb_table_entries(&[0x05, 0x02, 0x05, 0x02], 0x6b4, 1, true, &|target| {
                target != 0x6be
            }),
            Err(TableDecline::NonExecutableTarget {
                index: 0,
                target: 0x6be
            })
        );
    }

    /// The relative-entry decoder is endian-parameterised, not
    /// little-endian-only. This is the claim the deleted architecture guard in
    /// `discover_jump_tables` was implicitly disputing.
    #[test]
    fn relative_entries_decode_the_same_table_in_either_byte_order() {
        let table_va = 0x4000u64;
        let targets = [0x1100u64, 0x1200, 0x1300, 0x1400];
        let offsets: Vec<i32> = targets
            .iter()
            .map(|target| (*target as i64 - table_va as i64) as i32)
            .collect();
        let is_exec = |va: u64| (0x1000..0x2000).contains(&va);

        let little: Vec<u8> = offsets.iter().flat_map(|o| o.to_le_bytes()).collect();
        let big: Vec<u8> = offsets.iter().flat_map(|o| o.to_be_bytes()).collect();
        assert_eq!(
            decode_relative_entries(&little, table_va, 4, true, &is_exec),
            Ok(targets.to_vec())
        );
        assert_eq!(
            decode_relative_entries(&big, table_va, 4, false, &is_exec),
            Ok(targets.to_vec())
        );
    }

    /// A minimal ELF32/MSB image with `.text` at `0x1000` and a four-entry
    /// relative jump table at `0x2000` in `.rodata`.
    ///
    /// Hand-assembled rather than compiled because this machine has no
    /// big-endian cross toolchain - `tools/arch_roundtrip.py`'s six lanes are
    /// all little-endian and the sample tree contains no MSB object at all,
    /// which is precisely why the guard's one real effect went unnoticed. The
    /// bytes below are a genuine ELF: `object::read::File::parse` accepts it and
    /// reports the section addresses the scan reads. Mirrors the byte-level
    /// header builders in `formats/elf/headers.rs`.
    fn elf32_be_with_a_jump_table() -> Vec<u8> {
        const TEXT_VA: u32 = 0x1000;
        const RODATA_VA: u32 = 0x2000;
        let names = b"\0.text\0.rodata\0.shstrtab\0";
        let text_name = 1u32;
        let rodata_name = 7u32;
        let shstrtab_name = 15u32;

        // Four offsets that resolve to 0x1010/0x1020/0x1030/0x1040, then a zero
        // terminator (target 0x2000, outside .text) so the run ends cleanly.
        let mut rodata = Vec::new();
        for target in [0x1010u32, 0x1020, 0x1030, 0x1040] {
            rodata.extend_from_slice(&((target as i64 - RODATA_VA as i64) as i32).to_be_bytes());
        }
        rodata.extend_from_slice(&0i32.to_be_bytes());

        let text = vec![0x60u8; 0x40]; // ppc `nop`, contents never decoded here
        let text_off = 52u32;
        let rodata_off = text_off + text.len() as u32;
        let shstrtab_off = rodata_off + rodata.len() as u32;
        let shoff = shstrtab_off + names.len() as u32;

        let mut data = Vec::new();
        data.extend_from_slice(b"\x7fELF");
        data.push(1); // ELFCLASS32
        data.push(2); // ELFDATA2MSB
        data.push(1); // EV_CURRENT
        data.extend_from_slice(&[0u8; 9]);
        data.extend_from_slice(&2u16.to_be_bytes()); // ET_EXEC
        data.extend_from_slice(&20u16.to_be_bytes()); // EM_PPC
        data.extend_from_slice(&1u32.to_be_bytes()); // e_version
        data.extend_from_slice(&TEXT_VA.to_be_bytes()); // e_entry
        data.extend_from_slice(&0u32.to_be_bytes()); // e_phoff
        data.extend_from_slice(&shoff.to_be_bytes()); // e_shoff
        data.extend_from_slice(&0u32.to_be_bytes()); // e_flags
        data.extend_from_slice(&52u16.to_be_bytes()); // e_ehsize
        data.extend_from_slice(&0u16.to_be_bytes()); // e_phentsize
        data.extend_from_slice(&0u16.to_be_bytes()); // e_phnum
        data.extend_from_slice(&40u16.to_be_bytes()); // e_shentsize
        data.extend_from_slice(&4u16.to_be_bytes()); // e_shnum
        data.extend_from_slice(&3u16.to_be_bytes()); // e_shstrndx
        debug_assert_eq!(data.len(), 52);

        data.extend_from_slice(&text);
        data.extend_from_slice(&rodata);
        data.extend_from_slice(names);

        let mut section = |name: u32, kind: u32, flags: u32, addr: u32, off: u32, size: u32| {
            for field in [name, kind, flags, addr, off, size, 0, 0, 4, 0] {
                data.extend_from_slice(&field.to_be_bytes());
            }
        };
        section(0, 0, 0, 0, 0, 0); // SHT_NULL
        section(text_name, 1, 0x6, TEXT_VA, text_off, text.len() as u32); // ALLOC|EXECINSTR
        section(
            rodata_name,
            1,
            0x2,
            RODATA_VA,
            rodata_off,
            rodata.len() as u32,
        ); // ALLOC
        section(shstrtab_name, 3, 0, 0, shstrtab_off, names.len() as u32); // SHT_STRTAB
        data
    }

    /// 32-bit big-endian was the ONE architecture class the old guard rejected.
    ///
    /// `if !obj.is_64() && !obj.is_little_endian()` returns early for exactly
    /// this image and for no other, so before the guard was deleted this found
    /// zero tables in a file whose table is perfectly readable.
    #[test]
    fn a_32_bit_big_endian_image_is_scanned_like_every_other() {
        let data = elf32_be_with_a_jump_table();
        let parsed = crate::decompile::profile::parse_object(&data)
            .expect("the hand-built header must be a real ELF");
        assert!(!parsed.is_64(), "the test image must be ELFCLASS32");
        assert!(!parsed.is_little_endian(), "and ELFDATA2MSB");

        let tables = discover_jump_tables(&data, |va| (0x1000..0x1041).contains(&va));
        assert_eq!(
            tables,
            vec![JumpTable {
                table_va: 0x2000,
                targets: vec![0x1010, 0x1020, 0x1030, 0x1040],
            }]
        );
    }

    #[test]
    fn discover_jump_tables_smoke_on_real_binary() {
        // Just verify the public API doesn't crash on a real ELF.
        let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        let _ = discover_jump_tables(&bytes, |_va| true);
    }
}
