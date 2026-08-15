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
) -> Option<JumpTable>
where
    F: Fn(u64) -> bool,
{
    const MAX_ENTRIES: usize = 4096;
    if entry_count == 0 || entry_count > MAX_ENTRIES {
        return None;
    }
    let byte_count = entry_count.checked_mul(4)?;

    if let Some(image) = image {
        let little_endian = image.endianness() == crate::core::binary::Endianness::Little;
        for section in image.sections() {
            let Some(entries) =
                section_entries(section.address(), section.data(), table_va, byte_count)
            else {
                continue;
            };
            let Some(targets) = decode_relative_entries(
                entries,
                table_va,
                entry_count,
                little_endian,
                &is_executable_va,
            ) else {
                continue;
            };
            return Some(JumpTable { table_va, targets });
        }
        return None;
    }

    let object = crate::decompile::profile::parse_object(data).ok()?;
    let little_endian = object.is_little_endian();
    for section in object.sections() {
        let Ok(bytes) = section.data() else {
            continue;
        };
        let Some(entries) = section_entries(section.address(), bytes, table_va, byte_count) else {
            continue;
        };
        let Some(targets) = decode_relative_entries(
            entries,
            table_va,
            entry_count,
            little_endian,
            &is_executable_va,
        ) else {
            continue;
        };
        return Some(JumpTable { table_va, targets });
    }
    None
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
) -> Option<JumpTable>
where
    F: Fn(u64) -> bool,
{
    const MAX_ENTRIES: usize = 4096;
    if !matches!(entry_size, 1 | 2) || entry_count == 0 || entry_count > MAX_ENTRIES {
        return None;
    }
    let byte_count = entry_count.checked_mul(usize::from(entry_size))?;

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
            return Some(JumpTable { table_va, targets });
        }
        return None;
    }

    let object = crate::decompile::profile::parse_object(data).ok()?;
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
        return Some(JumpTable { table_va, targets });
    }
    None
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
) -> Option<Vec<u64>>
where
    F: Fn(u64) -> bool,
{
    let table_end = table_va.checked_add(entries.len() as u64)?;
    let mut targets = Vec::with_capacity(entries.len() / usize::from(entry_size));
    for entry in entries.chunks_exact(usize::from(entry_size)) {
        let raw = match entry {
            [byte] => u64::from(*byte),
            [low, high] if little_endian => u64::from(u16::from_le_bytes([*low, *high])),
            [high, low] => u64::from(u16::from_be_bytes([*high, *low])),
            _ => return None,
        };
        let target = table_va.checked_add(raw.checked_mul(2)?)?;
        if target < table_end || !is_executable_va(target) {
            return None;
        }
        targets.push(target);
    }
    Some(targets)
}

fn decode_relative_entries<F>(
    bytes: &[u8],
    table_va: u64,
    entry_count: usize,
    little_endian: bool,
    is_executable_va: &F,
) -> Option<Vec<u64>>
where
    F: Fn(u64) -> bool,
{
    let mut targets = Vec::with_capacity(entry_count);
    for entry in bytes.get(..entry_count.checked_mul(4)?)?.chunks_exact(4) {
        let raw = if little_endian {
            i32::from_le_bytes(entry.try_into().ok()?)
        } else {
            i32::from_be_bytes(entry.try_into().ok()?)
        };
        let target = (table_va as i64).wrapping_add(raw as i64) as u64;
        if !is_executable_va(target) {
            return None;
        }
        targets.push(target);
    }
    Some(targets)
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
    if !obj.is_64() && !obj.is_little_endian() {
        return Vec::new();
    }
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
        assert!(decode_thumb_table_entries(&entries, 0x43c, 1, true, &|_t| true).is_none());
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
        assert!(
            decode_thumb_table_entries(&[0x05, 0x02, 0x05, 0x02], 0x6b4, 1, true, &|target| {
                target != 0x6be
            })
            .is_none()
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
