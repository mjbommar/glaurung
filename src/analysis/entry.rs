//! Entrypoint and code window discovery helpers.
//!
//! This module centralizes high-level routines for locating the program entrypoint
//! and mapping virtual addresses to file offsets across common formats (ELF/PE/Mach-O).
//! Implementations are bounded and deterministic and avoid allocating large buffers.

use crate::core::binary::{Arch, Endianness, Format};
use object::{ObjectSection, ObjectSegment};

/// Entry info returned by `detect_entry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryInfo {
    pub format: Format,
    pub arch: Arch,
    pub endianness: Endianness,
    pub entry_va: u64,
    pub file_offset: Option<usize>,
}

/// Detect the entrypoint VA and map it to a file offset when possible.
pub fn detect_entry(data: &[u8]) -> Option<EntryInfo> {
    use object::read::Object;
    let obj = object::read::File::parse(data).ok()?;
    let fmt = match obj.format() {
        object::BinaryFormat::Elf => Format::ELF,
        object::BinaryFormat::Coff => Format::COFF,
        object::BinaryFormat::Pe => Format::PE,
        object::BinaryFormat::MachO => Format::MachO,
        _ => Format::Unknown,
    };
    let arch = match obj.architecture() {
        object::Architecture::I386 => Arch::X86,
        object::Architecture::X86_64 => Arch::X86_64,
        object::Architecture::Arm => Arch::ARM,
        object::Architecture::Aarch64 => Arch::AArch64,
        object::Architecture::Mips => Arch::MIPS,
        object::Architecture::Mips64 => Arch::MIPS64,
        object::Architecture::PowerPc => Arch::PPC,
        object::Architecture::PowerPc64 => Arch::PPC64,
        object::Architecture::Riscv32 => Arch::RISCV,
        object::Architecture::Riscv64 => Arch::RISCV64,
        _ => Arch::Unknown,
    };
    // Heuristic endianness from architecture default; object::File doesn’t expose global endian
    let end = match arch {
        Arch::PPC | Arch::PPC64 => Endianness::Big,
        _ => Endianness::Little,
    };
    let entry = obj.entry();
    // Try program headers (segments) first, which work for ELF and Mach-O
    let mut file_off = None;
    for seg in obj.segments() {
        let addr = seg.address();
        let size = seg.size();
        if entry >= addr && entry < addr.saturating_add(size) {
            let (off, _sz) = seg.file_range();
            let delta = entry - addr;
            file_off = off.checked_add(delta).map(|v| v as usize);
            break;
        }
    }
    if file_off.is_none() {
        // Fallback to section table
        for sec in obj.sections() {
            let addr = sec.address();
            let size = sec.size();
            if entry >= addr && entry < addr.saturating_add(size) {
                if let Some((off, _sz)) = sec.file_range() {
                    let delta = entry - addr;
                    file_off = off.checked_add(delta).map(|v| v as usize);
                    break;
                }
            }
        }
    }
    Some(EntryInfo {
        format: fmt,
        arch,
        endianness: end,
        entry_va: entry,
        file_offset: file_off,
    })
}

/// Map an arbitrary virtual address to a file offset using segments, then sections.
/// Returns Some(file_offset) if the VA is within a mapped file-backed region; otherwise None.
pub fn va_to_file_offset(data: &[u8], va: u64) -> Option<usize> {
    use object::read::Object;
    let obj = object::read::File::parse(data).ok()?;
    // Try program headers (segments) first
    for seg in obj.segments() {
        let addr = seg.address();
        let size = seg.size();
        if size == 0 {
            continue;
        }
        if va >= addr && va < addr.saturating_add(size) {
            let (off, _sz) = seg.file_range();
            let delta = va - addr;
            if let Some(v) = off.checked_add(delta) {
                return Some(v as usize);
            }
        }
    }
    // Fallback to sections
    for sec in obj.sections() {
        let addr = sec.address();
        let size = sec.size();
        if size == 0 {
            continue;
        }
        if va >= addr && va < addr.saturating_add(size) {
            if let Some((off, _sz)) = sec.file_range() {
                let delta = va - addr;
                if let Some(v) = off.checked_add(delta) {
                    return Some(v as usize);
                }
            }
        }
    }
    None
}
