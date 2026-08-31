//! The authoritative PE metadata tables, read as function-start seeds.
//!
//! Everything else that finds function starts on a PE guesses: the prologue,
//! thunk and raw-call sweeps in [`super::scan`] match byte patterns and hand
//! the parent *candidates* its gates may still reject. This module does not
//! guess. It walks two structures the linker wrote down on purpose --
//! `IMAGE_DIRECTORY_ENTRY_EXCEPTION` (`.pdata`) and
//! `IMAGE_DIRECTORY_ENTRY_EXPORT` -- and reports what they say.
//!
//! - [`parse_pdata_function_starts`] reads every `RUNTIME_FUNCTION`, which on
//!   x86-64 Windows exists for nearly every function, and returns its accepted
//!   starts plus a [`PdataSeedStats`](super::PdataSeedStats) census of the
//!   entries it rejected and why.
//! - [`parse_pe_export_function_starts`] walks the export directory, which the
//!   `object` crate's `dynamic_symbols()` does not surface for PE at all.
//!
//! The unwind-record predicates `unwind_info_flags`,
//! `unwind_info_has_chain_info` and `parse_unwind_chain_info` exist only to let
//! the `.pdata` walk follow `UNW_FLAG_CHAININFO` back to the primary record, so
//! a chained fragment is not mistaken for a function start; they are private to
//! this module and `unwind_info_tests` (below) is their test, moved here with
//! them.
//!
//! What stays elsewhere, because the call graph says so:
//! - `pe_va_to_file_off` is the general VA-to-offset walk, not a table reader,
//!   and nothing here calls it: the `.pdata` and export walks each build their
//!   own section index once per call instead of per lookup. It lives with the
//!   rest of the address plumbing in [`super::image_view`], alongside
//!   `ExecRegion`, `in_exec_regions` and `code_addr`.
//! - `PdataSeedStats` is declared in [`super::stats`] rather than here because
//!   it is a census, not a table: [`super::worklist`] reads ten of its fields
//!   directly when it folds them into `FunctionDiscoveryStats`.
//! - `align_up_u64` is the stride every region sweep starts from and belongs to
//!   [`super::scan`], which is its only caller.
//!
//! A sibling module sees all of those for free through `use super::*`, because
//! the parent re-exports them.

use super::*;

fn unwind_info_flags(data: &[u8], file_off: usize) -> Option<u8> {
    data.get(file_off).map(|first| first >> 3)
}

fn unwind_info_has_chain_info(data: &[u8], file_off: usize) -> bool {
    unwind_info_flags(data, file_off)
        .map(|flags| flags & 0x04 != 0)
        .unwrap_or(false)
}

fn parse_unwind_chain_info(data: &[u8], file_off: usize) -> Option<(u32, u32, u32)> {
    if !unwind_info_has_chain_info(data, file_off) {
        return None;
    }
    let unwind_code_count = *data.get(file_off + 2)? as usize;
    // UNWIND_CODE entries are 2 bytes and the optional trailer starts on
    // a 4-byte boundary, so odd code counts carry one 2-byte padding slot.
    let aligned_code_count = (unwind_code_count + 1) & !1;
    let chain_off = file_off.checked_add(4 + aligned_code_count * 2)?;
    let begin = u32::from_le_bytes(data.get(chain_off..chain_off + 4)?.try_into().ok()?);
    let end = u32::from_le_bytes(data.get(chain_off + 4..chain_off + 8)?.try_into().ok()?);
    let unwind = u32::from_le_bytes(data.get(chain_off + 8..chain_off + 12)?.try_into().ok()?);
    Some((begin, end, unwind))
}

/// Read every `RUNTIME_FUNCTION::BeginAddress` from the Win64 PE
/// exception directory (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`, index 3).
///
/// On x86-64 Windows the calling convention mandates an unwind record
/// in `.pdata` for every non-leaf function (and most leaf functions
/// emit one too). The exception directory is therefore a near-complete
/// function index, free for the asking, and the single highest-leverage
/// source of function starts on stripped Windows PE.
///
/// Returns an empty vector for non-PE32+ files, files missing the
/// exception directory, or 32-bit PEs (which use SEH on the stack and
/// don't have an equivalent table). ARM64 PE has a different unwind
/// format we don't yet decode.
pub(super) fn parse_pdata_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> (Vec<u64>, PdataSeedStats) {
    let mut stats = PdataSeedStats::default();
    if !arch.is_64_bit() {
        return (Vec::new(), stats);
    }
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return (Vec::new(), stats);
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };
    let e_lfanew = match read_u32(0x3c) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return (Vec::new(), stats);
    }
    let coff_off = e_lfanew + 4;
    let n_sections = match read_u16(coff_off + 2) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let opt_size = match read_u16(coff_off + 16) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let opt_off = coff_off + 20;
    if read_u16(opt_off) != Some(0x20B) {
        // not PE32+ (Win64)
        return (Vec::new(), stats);
    }
    let image_base = match read_u64(opt_off + 24) {
        Some(v) => v,
        None => return (Vec::new(), stats),
    };
    let num_dirs = match read_u32(opt_off + 108) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    if num_dirs < 4 {
        return (Vec::new(), stats);
    }
    let dd_off = opt_off + 112;
    let exc_rva = match read_u32(dd_off + 3 * 8) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    let exc_size = match read_u32(dd_off + 3 * 8 + 4) {
        Some(v) => v as usize,
        None => return (Vec::new(), stats),
    };
    if exc_rva == 0 || exc_size == 0 {
        return (Vec::new(), stats);
    }
    // Resolve RVAs to file offsets via the section table.
    let sec_off = opt_off + opt_size;
    let mut sections_view: Vec<(usize, usize, usize)> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = read_u32(s + 8).unwrap_or(0) as usize;
        let virt_addr = read_u32(s + 12).unwrap_or(0) as usize;
        let raw_sz = read_u32(s + 16).unwrap_or(0) as usize;
        let raw_ptr = read_u32(s + 20).unwrap_or(0) as usize;
        let span = std::cmp::max(virt_sz, raw_sz);
        sections_view.push((virt_addr, span, raw_ptr));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for (va, span, rp) in &sections_view {
            if rva >= *va && rva < *va + *span {
                return Some(rp + (rva - va));
            }
        }
        None
    };
    let exc_file_off = match rva_to_off(exc_rva) {
        Some(v) => v,
        None => return (Vec::new(), stats),
    };
    // Walk RUNTIME_FUNCTION entries (12 bytes each on x64:
    //   u32 BeginAddress, u32 EndAddress, u32 UnwindInfoAddress).
    let entry_size = 12usize;
    let n_entries = exc_size / entry_size;
    let cap = 2_000_000usize.min(n_entries);
    let mut starts = Vec::with_capacity(cap);
    let mut previous_range_end: Option<u32> = None;
    for i in 0..cap {
        let off = exc_file_off + i * entry_size;
        if off + 4 > data.len() {
            break;
        }
        let begin_rva = match read_u32(off) {
            Some(v) => v,
            None => break,
        };
        stats.entries = stats.entries.saturating_add(1);
        if begin_rva == 0 {
            stats.zero_begin_rejected = stats.zero_begin_rejected.saturating_add(1);
            stats.zero_begin_rejected_starts.push(image_base);
            continue;
        }
        let end_rva = match read_u32(off + 4) {
            Some(v) => v,
            None => break,
        };
        if end_rva <= begin_rva {
            stats.zero_size_rejected = stats.zero_size_rejected.saturating_add(1);
            stats
                .zero_size_rejected_starts
                .push(image_base + begin_rva as u64);
            continue;
        }
        if previous_range_end
            .map(|prev_end| begin_rva < prev_end)
            .unwrap_or(false)
        {
            stats.overlapping_entries = stats.overlapping_entries.saturating_add(1);
        }
        previous_range_end = Some(previous_range_end.map_or(end_rva, |prev| prev.max(end_rva)));
        let unwind_rva = match read_u32(off + 8) {
            Some(v) => v as usize,
            None => break,
        };
        if let Some(unwind_off) = rva_to_off(unwind_rva) {
            if unwind_info_has_chain_info(data, unwind_off) {
                stats.chained_unwind_rejected = stats.chained_unwind_rejected.saturating_add(1);
                stats
                    .chained_unwind_rejected_starts
                    .push(image_base + begin_rva as u64);
                if let Some((parent_begin, parent_end, _parent_unwind)) =
                    parse_unwind_chain_info(data, unwind_off)
                {
                    stats.chained_unwind_parsed = stats.chained_unwind_parsed.saturating_add(1);
                    if parent_begin != 0 && parent_end > parent_begin {
                        let parent_va = image_base + parent_begin as u64;
                        if in_exec_regions(regions, parent_va).is_some() {
                            stats.chained_parent_starts =
                                stats.chained_parent_starts.saturating_add(1);
                        }
                    }
                } else {
                    stats.chained_unwind_parse_failed =
                        stats.chained_unwind_parse_failed.saturating_add(1);
                }
                continue;
            }
        }
        let va = image_base + begin_rva as u64;
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        } else {
            stats.nonexec_rejected = stats.nonexec_rejected.saturating_add(1);
            stats.nonexec_rejected_starts.push(va);
        }
    }
    stats.accepted_starts = starts.len();
    (starts, stats)
}

/// Read every export-table function VA from a PE.
///
/// The `object` crate's `dynamic_symbols()` returns nothing for PE
/// targets even when the binary has an `IMAGE_DIRECTORY_ENTRY_EXPORT`
/// table (verified empirically on kernel32.dll: 1671 exports, 0
/// returned by `obj.dynamic_symbols()`). We walk the directory
/// directly to keep export-driven fn discovery working.
///
/// Without this seed source, kernel32.dll (~1700 exports, most of
/// them tiny `jmp [iat]` thunks not covered by `.pdata`) yields
/// only 58 % recall on the iter-14 comparison sweep. With it, every
/// `IMAGE_EXPORT_DIRECTORY::AddressOfFunctions[i]` lands as a seed.
///
/// Returns an empty vector for non-PE files or PEs with no export
/// directory.
pub(super) fn parse_pe_export_function_starts(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<u64> {
    if !arch.is_64_bit() && arch != BArch::X86 {
        return Vec::new();
    }
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return Vec::new();
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        data.get(off..off + 8).map(|b| {
            let lo = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as u64;
            (hi << 32) | lo
        })
    };
    let e_lfanew = match read_u32(0x3c) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Vec::new();
    }
    let coff_off = e_lfanew + 4;
    let n_sections = match read_u16(coff_off + 2) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_size = match read_u16(coff_off + 16) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let opt_off = coff_off + 20;
    let magic = match read_u16(opt_off) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let (image_base, dd_off) = if magic == 0x20B {
        let base = match read_u64(opt_off + 24) {
            Some(v) => v,
            None => return Vec::new(),
        };
        (base, opt_off + 112)
    } else if magic == 0x10B {
        let base = match read_u32(opt_off + 28) {
            Some(v) => v as u64,
            None => return Vec::new(),
        };
        (base, opt_off + 96)
    } else {
        return Vec::new();
    };
    // IMAGE_DIRECTORY_ENTRY_EXPORT = index 0
    let exp_rva = match read_u32(dd_off) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let exp_size = match read_u32(dd_off + 4) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if exp_rva == 0 || exp_size == 0 {
        return Vec::new();
    }
    // Resolve via section table.
    let sec_off = opt_off + opt_size;
    let mut sections_view: Vec<(usize, usize, usize, usize)> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = read_u32(s + 8).unwrap_or(0) as usize;
        let virt_addr = read_u32(s + 12).unwrap_or(0) as usize;
        let raw_sz = read_u32(s + 16).unwrap_or(0) as usize;
        let raw_ptr = read_u32(s + 20).unwrap_or(0) as usize;
        sections_view.push((virt_addr, std::cmp::max(virt_sz, raw_sz), raw_ptr, raw_sz));
    }
    let rva_to_off = |rva: usize| -> Option<usize> {
        for (va, span, rp, _rs) in &sections_view {
            if rva >= *va && rva < *va + *span {
                return Some(rp + (rva - va));
            }
        }
        None
    };
    let exp_off = match rva_to_off(exp_rva) {
        Some(v) => v,
        None => return Vec::new(),
    };
    // IMAGE_EXPORT_DIRECTORY layout:
    //   u32 Characteristics
    //   u32 TimeDateStamp
    //   u16 MajorVersion, u16 MinorVersion
    //   u32 Name (RVA)
    //   u32 Base
    //   u32 NumberOfFunctions
    //   u32 NumberOfNames
    //   u32 AddressOfFunctions (RVA -> array of u32 RVAs)
    //   u32 AddressOfNames     (RVA -> ...)
    //   u32 AddressOfNameOrdinals (RVA -> ...)
    if exp_off + 40 > data.len() {
        return Vec::new();
    }
    let n_funcs = match read_u32(exp_off + 0x14) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    let addr_of_funcs_rva = match read_u32(exp_off + 0x1c) {
        Some(v) => v as usize,
        None => return Vec::new(),
    };
    if n_funcs == 0 || addr_of_funcs_rva == 0 {
        return Vec::new();
    }
    let addrs_off = match rva_to_off(addr_of_funcs_rva) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let cap = std::cmp::min(n_funcs, 1_000_000);
    let mut starts = Vec::with_capacity(cap);
    for i in 0..cap {
        let off = addrs_off + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let rva = read_u32(off).unwrap_or(0) as u64;
        if rva == 0 {
            continue;
        }
        let va = image_base + rva;
        // Skip forwarder exports: their "address" actually points
        // inside the export directory itself (an ASCII string like
        // "NTDLL.RtlAddAccessAllowedAce"), NOT a code byte. The
        // forwarder RVA always falls inside the export directory
        // span [exp_rva, exp_rva + exp_size).
        let rva_us = rva as usize;
        if rva_us >= exp_rva && rva_us < exp_rva + exp_size {
            continue;
        }
        if in_exec_regions(regions, va).is_some() {
            starts.push(va);
        }
    }
    starts
}

#[cfg(test)]
mod unwind_info_tests {
    use super::{parse_unwind_chain_info, unwind_info_has_chain_info};

    #[test]
    fn detects_chaininfo_flag_in_unwind_info_header() {
        // UNWIND_INFO byte 0 packs Version in bits 0..2 and Flags in
        // bits 3..7. UNW_FLAG_CHAININFO is flag bit 0x04.
        let data = [0x01, (0x04 << 3) | 0x01, (0x03 << 3) | 0x01];
        assert!(!unwind_info_has_chain_info(&data, 0));
        assert!(unwind_info_has_chain_info(&data, 1));
        assert!(!unwind_info_has_chain_info(&data, 2));
    }

    #[test]
    fn missing_unwind_info_header_is_not_chained() {
        let data = [0x21];
        assert!(!unwind_info_has_chain_info(&data, 2));
    }

    #[test]
    fn parses_chained_runtime_function_trailer() {
        let mut data = vec![0x21, 0x05, 0x01, 0x00, 0xaa, 0xbb, 0x00, 0x00];
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x1234u32.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());

        assert_eq!(
            parse_unwind_chain_info(&data, 0),
            Some((0x1000, 0x1234, 0x2000))
        );
    }

    #[test]
    fn parse_chain_rejects_missing_trailer() {
        let data = [0x21, 0x05, 0x02, 0x00, 0xaa, 0xbb, 0xcc, 0xdd];
        assert_eq!(parse_unwind_chain_info(&data, 0), None);
    }
}
