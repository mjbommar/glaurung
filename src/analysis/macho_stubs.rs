//! Mach-O stub / lazy-pointer / non-lazy-pointer → name resolver.
//!
//! Mach-O uses an *indirect symbol table* to associate slots in certain
//! sections (`__TEXT,__stubs`, `__DATA,__la_symbol_ptr`,
//! `__DATA_CONST,__got`, …) with entries of the regular symbol table.
//! Each such section's `reserved1` field is the starting index into the
//! indirect symbol table; `reserved2` gives the stub entry size when the
//! section type is `S_SYMBOL_STUBS`. Pointer sections use a fixed 8-byte
//! entry on 64-bit images.
//!
//! This module performs a direct, conservative parse of the Mach-O layout
//! (mirroring the style of `elf_plt.rs`) and returns a sorted, deduplicated
//! list of `(VA, name)` pairs suitable for name resolution. Returned names
//! have the Mach-O leading underscore stripped and an `@stub` / `@laptr` /
//! `@got` suffix indicating the source section, matching the `@plt` / `@iat`
//! conventions used by the ELF / PE resolvers.
//!
//! Coverage: 64-bit Mach-O only (`MH_MAGIC_64` / `MH_CIGAM_64`), single slice
//! (not fat). x86_64 and arm64 are both supported — the layout is identical
//! and `reserved2` encodes the architecture-specific stub size.

const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;

const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
const S_SYMBOL_STUBS: u32 = 0x8;
const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

const MACH_HEADER_64_SIZE: usize = 32;
const SEGMENT_COMMAND_64_SIZE: usize = 72;
const SECTION_64_SIZE: usize = 80;
const SYMTAB_COMMAND_SIZE: usize = 24;
const NLIST_64_SIZE: usize = 16;

/// Parameters extracted from LC_SYMTAB.
#[derive(Debug, Default, Clone, Copy)]
struct SymtabInfo {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

/// Parameters extracted from LC_DYSYMTAB.
#[derive(Debug, Default, Clone, Copy)]
struct DysymtabInfo {
    indirectsymoff: u32,
    nindirectsyms: u32,
}

/// An indirect-symbol-backed section (stubs or pointer table).
#[derive(Debug, Clone)]
struct IndirectSection {
    addr: u64,
    size: u64,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    suffix: &'static str,
}

fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > data.len() {
        return None;
    }
    let bytes: [u8; 4] = data[off..end].try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64(data: &[u8], off: usize, le: bool) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > data.len() {
        return None;
    }
    let bytes: [u8; 8] = data[off..end].try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn cstr_at(data: &[u8], off: usize, max_len: usize) -> Option<String> {
    let end = off.checked_add(max_len)?.min(data.len());
    if off >= end {
        return None;
    }
    let slice = &data[off..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..nul]).into_owned())
}

fn suffix_for_section_type(sect_type: u32) -> Option<&'static str> {
    match sect_type {
        S_SYMBOL_STUBS => Some("@stub"),
        S_LAZY_SYMBOL_POINTERS | S_LAZY_DYLIB_SYMBOL_POINTERS => Some("@laptr"),
        S_NON_LAZY_SYMBOL_POINTERS => Some("@got"),
        _ => None,
    }
}

fn normalize_name(raw: &str) -> String {
    // macOS C symbols carry a leading underscore. Strip it for parity with
    // ELF/PE naming ("_printf" → "printf").
    if let Some(stripped) = raw.strip_prefix('_') {
        stripped.to_string()
    } else {
        raw.to_string()
    }
}

/// Build a best-effort map of stub / lazy-pointer / non-lazy-pointer VAs to
/// imported symbol names for a 64-bit Mach-O image.
///
/// Returns an empty vector when the input is not a 64-bit Mach-O or when the
/// required load commands are missing / truncated.
pub fn macho_stubs_map(data: &[u8]) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = Vec::new();
    if data.len() < MACH_HEADER_64_SIZE {
        return out;
    }
    // Read magic to determine endianness and 64-bit-ness.
    let magic_le = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let le = match magic_le {
        MH_MAGIC_64 => true,
        MH_CIGAM_64 => false,
        _ => return out, // fat binary (0xcafebabe) and 32-bit (0xfeedface) not handled
    };
    let ncmds = match read_u32(data, 16, le) {
        Some(v) => v as usize,
        None => return out,
    };
    let sizeofcmds = match read_u32(data, 20, le) {
        Some(v) => v as usize,
        None => return out,
    };
    let cmds_start = MACH_HEADER_64_SIZE;
    let cmds_end = cmds_start.saturating_add(sizeofcmds).min(data.len());

    let mut sections: Vec<IndirectSection> = Vec::new();
    let mut symtab = SymtabInfo::default();
    let mut dysymtab = DysymtabInfo::default();

    let mut cursor = cmds_start;
    for _ in 0..ncmds {
        if cursor + 8 > cmds_end {
            break;
        }
        let cmd = match read_u32(data, cursor, le) {
            Some(v) => v,
            None => break,
        };
        let cmdsize = match read_u32(data, cursor + 4, le) {
            Some(v) => v as usize,
            None => break,
        };
        if cmdsize < 8 || cursor + cmdsize > cmds_end {
            break;
        }
        match cmd {
            LC_SEGMENT_64 => {
                // segment_command_64: cmd(4) cmdsize(4) segname(16) vmaddr(8) vmsize(8)
                //   fileoff(8) filesize(8) maxprot(4) initprot(4) nsects(4) flags(4)
                if cmdsize < SEGMENT_COMMAND_64_SIZE {
                    // malformed; skip
                    cursor += cmdsize;
                    continue;
                }
                let nsects = match read_u32(data, cursor + 64, le) {
                    Some(v) => v as usize,
                    None => 0,
                };
                let sects_start = cursor + SEGMENT_COMMAND_64_SIZE;
                for i in 0..nsects {
                    let soff = sects_start + i * SECTION_64_SIZE;
                    if soff + SECTION_64_SIZE > cursor + cmdsize {
                        break;
                    }
                    // section_64: sectname(16) segname(16) addr(8) size(8)
                    //   offset(4) align(4) reloff(4) nreloc(4)
                    //   flags(4) reserved1(4) reserved2(4) reserved3(4)
                    let addr = read_u64(data, soff + 32, le).unwrap_or(0);
                    let size = read_u64(data, soff + 40, le).unwrap_or(0);
                    let flags = read_u32(data, soff + 64, le).unwrap_or(0);
                    let reserved1 = read_u32(data, soff + 68, le).unwrap_or(0);
                    let reserved2 = read_u32(data, soff + 72, le).unwrap_or(0);
                    let sect_type = flags & SECTION_TYPE_MASK;
                    if let Some(suffix) = suffix_for_section_type(sect_type) {
                        sections.push(IndirectSection {
                            addr,
                            size,
                            flags,
                            reserved1,
                            reserved2,
                            suffix,
                        });
                    }
                }
            }
            LC_SYMTAB => {
                if cmdsize >= SYMTAB_COMMAND_SIZE {
                    symtab.symoff = read_u32(data, cursor + 8, le).unwrap_or(0);
                    symtab.nsyms = read_u32(data, cursor + 12, le).unwrap_or(0);
                    symtab.stroff = read_u32(data, cursor + 16, le).unwrap_or(0);
                    symtab.strsize = read_u32(data, cursor + 20, le).unwrap_or(0);
                }
            }
            LC_DYSYMTAB => {
                // dysymtab_command is 80 bytes; indirectsymoff is at offset 56, nindirectsyms at 60.
                if cmdsize >= 64 {
                    dysymtab.indirectsymoff = read_u32(data, cursor + 56, le).unwrap_or(0);
                    dysymtab.nindirectsyms = read_u32(data, cursor + 60, le).unwrap_or(0);
                }
            }
            _ => {}
        }
        cursor += cmdsize;
    }

    if sections.is_empty() || dysymtab.nindirectsyms == 0 || symtab.nsyms == 0 {
        return out;
    }
    let indsym_start = dysymtab.indirectsymoff as usize;
    let indsym_count = dysymtab.nindirectsyms as usize;
    let indsym_end = indsym_start.saturating_add(indsym_count.saturating_mul(4));
    if indsym_end > data.len() {
        return out;
    }
    let symtab_start = symtab.symoff as usize;
    let symtab_count = symtab.nsyms as usize;
    let symtab_end = symtab_start.saturating_add(symtab_count.saturating_mul(NLIST_64_SIZE));
    if symtab_end > data.len() {
        return out;
    }
    let strtab_start = symtab.stroff as usize;
    let strtab_end = strtab_start
        .saturating_add(symtab.strsize as usize)
        .min(data.len());
    if strtab_start >= strtab_end {
        return out;
    }

    let name_for_sym = |sym_idx: u32| -> Option<String> {
        let i = sym_idx as usize;
        if i >= symtab_count {
            return None;
        }
        let nlist_off = symtab_start + i * NLIST_64_SIZE;
        let n_strx = read_u32(data, nlist_off, le)?;
        let name_off = strtab_start.checked_add(n_strx as usize)?;
        if name_off >= strtab_end {
            return None;
        }
        cstr_at(data, name_off, strtab_end - name_off)
    };

    for sec in &sections {
        // Entry size: for stubs, reserved2. For pointer sections, 8 bytes on 64-bit.
        let sect_type = sec.flags & SECTION_TYPE_MASK;
        let entry_size: u64 = if sect_type == S_SYMBOL_STUBS {
            sec.reserved2 as u64
        } else {
            8
        };
        if entry_size == 0 {
            continue;
        }
        let slot_count = (sec.size / entry_size) as usize;
        for slot in 0..slot_count {
            let indsym_idx_pos = indsym_start + (sec.reserved1 as usize + slot) * 4;
            if indsym_idx_pos + 4 > data.len() {
                break;
            }
            let sym_idx = read_u32(data, indsym_idx_pos, le).unwrap_or(0);
            // Skip local / absolute markers used in __got / __la_symbol_ptr
            // for entries that don't correspond to an imported dynamic symbol
            // (e.g. dyld_stub_binder is often marked with ABS).
            if sym_idx == 0
                || (sym_idx & INDIRECT_SYMBOL_LOCAL) != 0
                || (sym_idx & INDIRECT_SYMBOL_ABS) != 0
            {
                continue;
            }
            let Some(raw_name) = name_for_sym(sym_idx) else {
                continue;
            };
            let va = sec.addr + (slot as u64) * entry_size;
            out.push((va, format!("{}{}", normalize_name(&raw_name), sec.suffix)));
        }
    }

    out.sort_by_key(|(va, _)| *va);
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn empty_input_returns_empty() {
        assert!(macho_stubs_map(&[]).is_empty());
    }

    #[test]
    fn non_macho_returns_empty() {
        let elf_magic = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(macho_stubs_map(&elf_magic).is_empty());
    }

    #[test]
    fn resolves_stubs_and_laptr_on_real_sample() {
        // Ground truth (from `llvm-otool -Iv`):
        //   __TEXT,__stubs (6-byte stubs starting at 0x100000618):
        //     0x618 _free, 0x61e _puts, 0x624 _printf, 0x62a _strlen, 0x630 _malloc
        //   __DATA,__la_symbol_ptr (8-byte pointers starting at 0x100003000):
        //     0x3000 _free, 0x3008 _puts, 0x3010 _printf, 0x3018 _strlen, 0x3020 _malloc
        let path = Path::new(
            "samples/binaries/platforms/darwin/amd64/export/native/multi_import-macho",
        );
        if !path.exists() {
            eprintln!("sample missing: {}", path.display());
            return; // sample-optional test
        }
        let data = std::fs::read(path).expect("read sample");
        let map = macho_stubs_map(&data);
        assert!(!map.is_empty(), "no entries produced for Mach-O sample");

        // Must contain all five imported symbols as stub entries.
        let names: std::collections::HashSet<&str> =
            map.iter().map(|(_, n)| n.as_str()).collect();
        for want in ["free@stub", "puts@stub", "printf@stub", "strlen@stub", "malloc@stub"] {
            assert!(names.contains(want), "missing {want} in {names:?}");
        }
        // And the lazy-pointer equivalents.
        for want in ["free@laptr", "puts@laptr", "printf@laptr", "strlen@laptr", "malloc@laptr"] {
            assert!(names.contains(want), "missing {want} in {names:?}");
        }

        // Verify known VAs from llvm-otool.
        let lookup: std::collections::HashMap<u64, String> = map.into_iter().collect();
        assert_eq!(lookup.get(&0x100000618).map(String::as_str), Some("free@stub"));
        assert_eq!(lookup.get(&0x10000061e).map(String::as_str), Some("puts@stub"));
        assert_eq!(lookup.get(&0x100000624).map(String::as_str), Some("printf@stub"));
        assert_eq!(lookup.get(&0x10000062a).map(String::as_str), Some("strlen@stub"));
        assert_eq!(lookup.get(&0x100000630).map(String::as_str), Some("malloc@stub"));

        assert_eq!(lookup.get(&0x100003000).map(String::as_str), Some("free@laptr"));
        assert_eq!(lookup.get(&0x100003020).map(String::as_str), Some("malloc@laptr"));
    }
}
