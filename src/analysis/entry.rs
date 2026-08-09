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
    let obj = crate::decompile::profile::parse_object(data).ok()?;
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

/// Map a virtual address that is known to hold CODE to a file offset.
///
/// Identical to [`va_to_file_offset`] for a linked image, where program headers answer
/// first and section addresses are distinct. It exists for RELOCATABLE objects, where
/// every section has address 0: there, "the first section containing this address" is
/// whichever section happens to come first in the file, and the plain resolver decodes
/// whatever that is as instructions.
///
/// The consequence was not subtle. A clang `-c` object lists `.strtab` before `.text`,
/// so lifting a function at address 0x30 read the STRING TABLE and produced a body of
/// `insb` / `outsd` / branches on flags nobody set — syntactically valid C describing
/// nothing. gcc objects happened to work because gcc emits `.text` first. Preferring an
/// executable section resolves the ambiguity in the only direction that can be right
/// for code.
///
/// It does not make a relocatable object unambiguous: under `-ffunction-sections`
/// every `.text.*` shares address 0 too, and this picks the first. Distinguishing
/// those needs the symbol's section index, which the caller would have to carry.
pub fn va_to_code_file_offset(data: &[u8], va: u64) -> Option<usize> {
    use object::read::{Object, ObjectSection};
    use object::SectionKind;
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
        for sec in obj.sections() {
            if sec.kind() != SectionKind::Text || sec.size() == 0 {
                continue;
            }
            let addr = sec.address();
            if va >= addr && va < addr.saturating_add(sec.size()) {
                if let Some((off, _)) = sec.file_range() {
                    if let Some(v) = off.checked_add(va - addr) {
                        return Some(v as usize);
                    }
                }
            }
        }
    }
    va_to_file_offset(data, va)
}

/// Map an arbitrary virtual address to a file offset using segments, then sections.
/// Returns Some(file_offset) if the VA is within a mapped file-backed region; otherwise None.
///
/// For CODE addresses prefer [`va_to_code_file_offset`]: in a relocatable object every
/// section shares address 0, and this resolver will return whichever section appears
/// first — including a string or debug section.
pub fn va_to_file_offset(data: &[u8], va: u64) -> Option<usize> {
    use object::read::Object;
    let obj = crate::decompile::profile::parse_object(data).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64 relocatable object whose `.strtab` precedes `.text` in the
    /// section table — the layout clang `-c` produces. Both sections have address 0,
    /// because a relocatable object is not laid out yet.
    ///
    /// Synthesised rather than compiled: the ordering IS the fixture, and a committed
    /// binary would leave it to whichever toolchain built it.
    fn et_rel_with_strtab_first() -> Vec<u8> {
        const EHDR: usize = 64;
        const SHDR: usize = 64;
        let strtab = vec![b'A'; 16];
        let text = vec![0x90u8; 16];
        let shstr = b"\0.strtab\0.text\0.shstrtab\0".to_vec();

        let strtab_off = EHDR;
        let text_off = strtab_off + strtab.len();
        let shstr_off = text_off + text.len();
        let shoff = shstr_off + shstr.len();

        let mut out = vec![0u8; shoff + 4 * SHDR];
        out[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        out[16..18].copy_from_slice(&1u16.to_le_bytes()); // e_type = ET_REL
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
        out[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
        out[58..60].copy_from_slice(&(SHDR as u16).to_le_bytes()); // e_shentsize
        out[60..62].copy_from_slice(&4u16.to_le_bytes()); // e_shnum
        out[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx

        out[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
        out[text_off..text_off + text.len()].copy_from_slice(&text);
        out[shstr_off..shstr_off + shstr.len()].copy_from_slice(&shstr);

        // (name-index, sh_type, sh_flags, sh_offset, sh_size)
        let secs: [(u32, u32, u64, usize, usize); 4] = [
            (0, 0, 0, 0, 0),                     // SHT_NULL
            (1, 3, 0, strtab_off, strtab.len()), // .strtab   SHT_STRTAB
            (9, 1, 0x6, text_off, text.len()),   // .text     SHT_PROGBITS, ALLOC|EXECINSTR
            (15, 3, 0, shstr_off, shstr.len()),  // .shstrtab SHT_STRTAB
        ];
        for (i, (name, kind, flags, off, size)) in secs.iter().enumerate() {
            let b = shoff + i * SHDR;
            out[b..b + 4].copy_from_slice(&name.to_le_bytes());
            out[b + 4..b + 8].copy_from_slice(&kind.to_le_bytes());
            out[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
            // sh_addr stays 0: every section of a relocatable object shares address 0.
            out[b + 24..b + 32].copy_from_slice(&(*off as u64).to_le_bytes());
            out[b + 32..b + 40].copy_from_slice(&(*size as u64).to_le_bytes());
            out[b + 48..b + 56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
        }
        out
    }

    /// The hazard itself: with every section at address 0, the general resolver
    /// answers with whichever section the file happens to list first.
    #[test]
    fn the_plain_resolver_answers_with_the_first_section_at_that_address() {
        let data = et_rel_with_strtab_first();
        assert_eq!(
            va_to_file_offset(&data, 0),
            Some(64),
            "expected the .strtab bytes, which is exactly the problem"
        );
    }

    /// Code addresses must resolve to executable bytes whatever the section order.
    #[test]
    fn a_code_address_in_a_relocatable_object_resolves_to_text() {
        let data = et_rel_with_strtab_first();
        let off = va_to_code_file_offset(&data, 0).expect("code address must resolve");
        assert_eq!(off, 80, "expected the .text bytes");
        assert_eq!(data[off], 0x90, "resolved bytes must be the .text nops");
    }

    /// Inside `.text`, offsets track the address.
    #[test]
    fn a_code_address_resolves_at_the_right_offset_inside_text() {
        let data = et_rel_with_strtab_first();
        assert_eq!(va_to_code_file_offset(&data, 4), Some(84));
    }

    /// A linked image has real addresses and program headers; the code resolver must
    /// not change those answers.
    #[test]
    fn a_linked_image_resolves_identically_through_both_resolvers() {
        let path =
            std::path::Path::new("tests/decompiler_fixtures/build/02_integer_widths-gcc-O0.so");
        if !path.exists() {
            return; // fixture build is optional for this crate's unit tests
        }
        let data = std::fs::read(path).unwrap();
        for va in [0x1000u64, 0x11a3, 0x1351] {
            assert_eq!(
                va_to_code_file_offset(&data, va),
                va_to_file_offset(&data, va),
                "resolvers disagreed on a linked image at 0x{va:x}"
            );
        }
    }
}
