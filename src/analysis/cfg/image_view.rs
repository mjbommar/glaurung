//! Where the code is, and how a VA becomes bytes.
//!
//! Every other module in `cfg` asks this one the same two questions: *is this
//! address executable*, and *which byte of `data` is it*. Both have more than
//! one answer depending on what the caller was handed, and keeping the choice
//! in one place is the point of the module:
//!
//! * a `ProgramImage` answers from its immutable mapping index;
//! * bare bytes answer through `analysis::entry`, and fall back to
//!   [`pe_va_to_file_off`], which walks the section headers directly rather
//!   than constructing a `PeParser` inside the discovery worklist;
//! * a file with no parseable container answers as a flat VA=0 region.
//!
//! Two distinctions here are load-bearing and easy to lose. [`indexed_code_offset`]
//! is not [`indexed_file_offset`]: in a relocatable object every section shares
//! address 0, and the general resolver hands back whichever section is listed
//! first -- so decoding must use the CODE resolver. And [`code_addr`] exists
//! because an ARM function symbol or branch target carries the Thumb bit in its
//! LSB, so the address you were given is one byte past the instruction stream.

use super::*;

use object::{Object, ObjectSection, ObjectSegment, SectionKind};

#[derive(Debug, Clone)]
pub(super) struct ExecRegion {
    pub(super) start: u64, // VA
    pub(super) end: u64,   // VA exclusive
    pub(super) _file_off_start: u64,
}

pub(super) fn parse_exec_regions(
    data: &[u8],
) -> (Vec<ExecRegion>, BArch, Endianness, Option<Address>) {
    let mut regions = Vec::new();
    let mut arch = BArch::Unknown;
    let mut endian = Endianness::Little;
    let mut entry: Option<Address> = None;
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
        arch = match obj.architecture() {
            object::Architecture::I386 => BArch::X86,
            object::Architecture::X86_64 => BArch::X86_64,
            object::Architecture::Arm => BArch::ARM,
            object::Architecture::Aarch64 => BArch::AArch64,
            object::Architecture::Mips => BArch::MIPS,
            object::Architecture::Mips64 => BArch::MIPS64,
            object::Architecture::PowerPc => BArch::PPC,
            object::Architecture::PowerPc64 => BArch::PPC64,
            object::Architecture::Riscv32 => BArch::RISCV,
            object::Architecture::Riscv64 => BArch::RISCV64,
            _ => BArch::Unknown,
        };
        // Default endian by architecture family; object::File doesn't expose global endianness
        endian = match arch {
            BArch::PPC | BArch::PPC64 => Endianness::Big,
            _ => Endianness::Little,
        };

        let raw_entry_va = obj.entry();
        if raw_entry_va != 0 {
            // ARM ELF entry points use bit zero as the Thumb-state marker,
            // exactly like STT_FUNC symbols and branch targets. Keep the
            // mode as function metadata, but seed CFG recovery at the actual
            // even code address so lifting never starts one byte late.
            let entry_va = code_addr(raw_entry_va, arch);
            let bits = if arch.is_64_bit() { 64 } else { 32 };
            if let Ok(a) = Address::new(AddressKind::VA, entry_va, bits, None, None) {
                entry = Some(a);
            }
        }

        // Prefer segments with execute permissions
        for seg in obj.segments() {
            let addr = seg.address();
            let size = seg.size();
            if size == 0 {
                continue;
            }
            let file = seg.file_range().0;
            // Heuristic: treat segments mapped into memory as candidate code; object doesn't expose perms uniformly across formats here
            // We will filter by sections if possible below.
            regions.push(ExecRegion {
                start: addr,
                end: addr.saturating_add(size),
                _file_off_start: file,
            });
        }

        // Refine by every section whose object-classified kind is Text.
        // Object's PE backend reads IMAGE_SCN_MEM_EXECUTE to set kind, so
        // this catches Win64 driver / kernel layouts where many code
        // sections exist with non-".text" names (PAGE, PAGELK, KVASCODE,
        // INIT, RETPOL, POOLCODE, ...). Previously we filtered with a
        // ".text" / "code" substring heuristic that dropped most of
        // ntoskrnl's executable bytes -- the dominant cause of the
        // 49 % recall observed on the ntoskrnl fixture in the iter 14
        // sweep.
        let mut refined = Vec::new();
        for sec in obj.sections() {
            let size = sec.size();
            if size == 0 {
                continue;
            }
            if sec.kind() != SectionKind::Text {
                // Fall back to the legacy name heuristic for formats
                // where object can't classify (e.g. some odd COFFs).
                let name = sec.name().unwrap_or("").to_ascii_lowercase();
                if !(name.contains(".text") || name.contains("code") || name == "text") {
                    continue;
                }
            }
            let addr = sec.address();
            if let Some((foff, _)) = sec.file_range() {
                refined.push(ExecRegion {
                    start: addr,
                    end: addr.saturating_add(size),
                    _file_off_start: foff,
                });
            }
        }
        if !refined.is_empty() {
            regions = refined;
        }
    }

    if regions.is_empty() {
        // As a last resort, decode from start of file as VA=0 range
        let (e, _conf) = heuristics::endianness::guess(data);
        endian = e;
        let (arch_guess, _ac) = heuristics::architecture::infer(data)
            .first()
            .cloned()
            .unwrap_or((BArch::Unknown, 0.0));
        arch = arch_guess;
        regions.push(ExecRegion {
            start: 0,
            end: data.len() as u64,
            _file_off_start: 0,
        });
        let bits = 64;
        entry = Address::new(AddressKind::VA, 0, bits, None, None).ok();
    }
    (regions, arch, endian, entry)
}

pub(super) fn parse_exec_regions_in(
    image: &crate::program::image::ProgramImage,
) -> (Vec<ExecRegion>, BArch, Endianness, Option<Address>) {
    let arch = image.arch();
    let endianness = image.endianness();
    let regions: Vec<ExecRegion> = image
        .executable_ranges()
        .map(|range| ExecRegion {
            start: range.start,
            end: range.end,
            _file_off_start: image
                .va_to_code_file_offset(range.start)
                .and_then(|offset| u64::try_from(offset).ok())
                .unwrap_or(0),
        })
        .collect();
    if regions.is_empty() {
        return parse_exec_regions(image.bytes());
    }
    let entry_va = image.normalize_function_entry(image.entry_va());
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let entry = (entry_va != 0)
        .then(|| Address::new(AddressKind::VA, entry_va, bits, None, None).ok())
        .flatten();
    (regions, arch, endianness, entry)
}

pub(super) fn in_exec_regions(regions: &[ExecRegion], va: u64) -> Option<&ExecRegion> {
    regions.iter().find(|r| va >= r.start && va < r.end)
}

pub(super) fn indexed_file_offset(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
) -> Option<usize> {
    image.map_or_else(
        || crate::analysis::entry::va_to_file_offset(data, va),
        |image| image.va_to_file_offset(va),
    )
}

pub(super) fn indexed_code_offset(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
) -> Option<usize> {
    image.map_or_else(
        || crate::analysis::entry::va_to_code_file_offset(data, va),
        |image| image.va_to_code_file_offset(va),
    )
}

pub(super) fn read_pointer_at_va(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    va: u64,
    bits: u8,
) -> Option<u64> {
    let file_off = indexed_file_offset(image, data, va).or_else(|| pe_va_to_file_off(data, va))?;
    if bits >= 64 {
        let raw = data.get(file_off..file_off + 8)?;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    } else {
        let raw = data.get(file_off..file_off + 4)?;
        Some(u32::from_le_bytes(raw.try_into().ok()?) as u64)
    }
}

pub(super) fn indirect_memory_target(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    ins: &Instruction,
    bits: u8,
) -> Option<u64> {
    let slot_va = memory_operand_va(ins)?;
    read_pointer_at_va(image, data, slot_va, bits)
}

/// Resolve a VA to a file offset by walking the section headers
/// directly. Used by the prologue-sanity gate during xref-target
/// promotion -- the existing `pe::sections::SectionTable` is built
/// per-PeParser instance; this helper avoids constructing one
/// inside the cfg worklist (where we already have raw `data` and
/// the `ExecRegion` list, but not the full section table).
#[allow(dead_code)]
pub(super) fn pe_va_to_file_off(data: &[u8], va: u64) -> Option<usize> {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let n_sections = u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().ok()?) as usize;
    let opt_off = coff_off + 20;
    let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().ok()?);
    let image_base = if magic == 0x20B {
        let b = data.get(opt_off + 24..opt_off + 32)?;
        let lo = u32::from_le_bytes(b[..4].try_into().ok()?) as u64;
        let hi = u32::from_le_bytes(b[4..].try_into().ok()?) as u64;
        (hi << 32) | lo
    } else if magic == 0x10B {
        u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().ok()?) as u64
    } else {
        return None;
    };
    if va < image_base {
        return None;
    }
    let rva = (va - image_base) as usize;
    let sec_off = opt_off + opt_size;
    for i in 0..n_sections {
        let s = sec_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let virt_sz = u32::from_le_bytes(data[s + 8..s + 12].try_into().ok()?) as usize;
        let virt_addr = u32::from_le_bytes(data[s + 12..s + 16].try_into().ok()?) as usize;
        let raw_sz = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?) as usize;
        let span = std::cmp::max(virt_sz, raw_sz);
        if rva >= virt_addr && rva < virt_addr + span {
            return Some(raw_ptr + (rva - virt_addr));
        }
    }
    None
}

/// Normalise a symbol/target VA to its code address. On ARM, function symbols
/// and branch targets for Thumb code carry the T-bit (LSB=1); the actual
/// instruction stream is at the even address, so clear it. No-op elsewhere.
pub(super) fn code_addr(va: u64, arch: BArch) -> u64 {
    if matches!(arch, BArch::ARM) {
        va & !1
    } else {
        va
    }
}
