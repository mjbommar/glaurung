//! ELF GOT mapping helpers (generic ELF64/ELF32 best-effort).
//!
//! Builds a map from relocation offsets (GOT/GOT.PL T entries) to symbol names
//! by parsing `.dynsym`/`.dynstr` and `.rela.*`/`.rel.*` sections. This helps
//! resolve indirect calls or jumps through the GOT on ELF platforms.

use object::read::Object;
use object::{ObjectSection, ObjectSymbol, RelocationTarget};

/// Build a best-effort map of GOT entry addresses (r_offset) to symbol names.
/// Supports ELF64 RELA and ELF32 REL formats. Returns empty on failure.
pub fn elf_got_map(data: &[u8]) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = Vec::new();
    let Ok(obj) = crate::decompile::profile::parse_object(data) else {
        return out;
    };
    if obj.format() != object::BinaryFormat::Elf {
        return out;
    }

    // Collect dynsym index -> name map
    let mut dynsym_off: Option<usize> = None;
    let mut dynsym_size: Option<usize> = None;
    let mut dynstr_off: Option<usize> = None;
    let mut dynstr_size: Option<usize> = None;
    for sec in obj.sections() {
        if let Ok(name) = sec.name() {
            match name {
                ".dynsym" => {
                    if let Some((off, sz)) = sec.file_range() {
                        dynsym_off = Some(off as usize);
                        dynsym_size = Some(sz as usize);
                    }
                }
                ".dynstr" => {
                    if let Some((off, sz)) = sec.file_range() {
                        dynstr_off = Some(off as usize);
                        dynstr_size = Some(sz as usize);
                    }
                }
                _ => {}
            }
        }
    }
    let (Some(dso), Some(dss), Some(sto), Some(sts)) =
        (dynsym_off, dynsym_size, dynstr_off, dynstr_size)
    else {
        return out;
    };
    let dynsym = &data[dso..dso + dss.min(data.len() - dso)];
    let dynstr = &data[sto..sto + sts.min(data.len() - sto)];

    // Class and endianness from ELF header
    let class = data.get(4).copied().unwrap_or(2); // 1=ELF32, 2=ELF64
    let is_le = data.get(5).copied().unwrap_or(1) == 1;

    // Helper to name by dynsym index
    let entsize64 = 24usize; // Elf64_Sym
    let entsize32 = 16usize; // Elf32_Sym
    let name_for_index = |idx: u32| -> Option<String> {
        let (entsize, _need64) = if class == 2 {
            (entsize64, true)
        } else {
            (entsize32, false)
        };
        let count = dynsym.len() / entsize;
        let i = idx as usize;
        if i >= count {
            return None;
        }
        let base = i * entsize;
        let st_name = if is_le {
            u32::from_le_bytes(dynsym[base..base + 4].try_into().ok()?)
        } else {
            u32::from_be_bytes(dynsym[base..base + 4].try_into().ok()?)
        } as usize;
        if st_name >= dynstr.len() {
            return None;
        }
        let s = &dynstr[st_name..];
        let end = s.iter().position(|&b| b == 0).unwrap_or(0);
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&s[..end]).to_string())
    };

    // Parse relocation sections: .rela.plt, .rela.dyn, .rel.plt, .rel.dyn
    for sec in obj.sections() {
        let Ok(name) = sec.name() else {
            continue;
        };
        let lname = name.to_ascii_lowercase();
        if !lname.starts_with(".rel") {
            continue;
        }
        if let Some((off, sz)) = sec.file_range() {
            let start = off as usize;
            let end = start.saturating_add(sz as usize).min(data.len());
            let bytes = &data[start..end];
            if class == 2 {
                // RELA64: 3x u64 (r_offset, r_info, r_addend)
                if bytes.len() < 24 {
                    continue;
                }
                for chunk in bytes.chunks_exact(24) {
                    let r_offset = if is_le {
                        u64::from_le_bytes(chunk[0..8].try_into().unwrap())
                    } else {
                        u64::from_be_bytes(chunk[0..8].try_into().unwrap())
                    };
                    let r_info = if is_le {
                        u64::from_le_bytes(chunk[8..16].try_into().unwrap())
                    } else {
                        u64::from_be_bytes(chunk[8..16].try_into().unwrap())
                    };
                    let sym_idx = (r_info >> 32) as u32;
                    if let Some(name) = name_for_index(sym_idx) {
                        out.push((r_offset, name));
                    }
                }
            } else {
                // REL32: 2x u32 (r_offset, r_info)
                if bytes.len() < 8 {
                    continue;
                }
                for chunk in bytes.chunks_exact(8) {
                    let r_offset = if is_le {
                        u32::from_le_bytes(chunk[0..4].try_into().unwrap()) as u64
                    } else {
                        u32::from_be_bytes(chunk[0..4].try_into().unwrap()) as u64
                    };
                    let r_info = if is_le {
                        u32::from_le_bytes(chunk[4..8].try_into().unwrap())
                    } else {
                        u32::from_be_bytes(chunk[4..8].try_into().unwrap())
                    } as u64;
                    let sym_idx = (r_info >> 8) as u32;
                    if let Some(name) = name_for_index(sym_idx) {
                        out.push((r_offset, name));
                    }
                }
            }
        }
    }

    // Deduplicate by address
    out.sort_by_key(|(a, _)| *a);
    out.dedup_by_key(|(a, _)| *a);
    out
}

/// Map each GOT slot to the IN-IMAGE address the loader will store in it.
///
/// A GOT slot holding a pointer to a symbol this same object DEFINES has a
/// value that is fixed the moment the image is mapped: `R_*_GLOB_DAT` against a
/// defined symbol resolves to that symbol's `st_value`, and `R_*_RELATIVE`
/// resolves to its addend. Both are link-time facts, so the load through the
/// slot can be folded away.
///
/// This is what a `-fPIC` build does to every reference to a global that
/// interposition could rebind: `vis_public_bias` becomes
/// `mov 0x3fe8(%rip),%rax ; mov (%rax),%eax`. Without the fold, the renderer
/// sees a dereference of a `.got` address, and `.got` is deliberately excluded
/// from portable static storage (it is linkage, not a program object — see
/// [`crate::ir::static_storage`]), so the slot renders as a zero-filled
/// stand-in. The recompiled function then dereferences a null pointer, which is
/// how fixtures 157, 158 and 160 segfaulted rather than returning a value.
///
/// Deliberately EXCLUDED: slots whose symbol is undefined here (`st_value == 0`
/// with `SHN_UNDEF`) — those really are resolved by the dynamic linker at load
/// time from another object, and no value in this file predicts them. They keep
/// their existing treatment.
pub fn elf_got_target_map(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let Ok(obj) = crate::decompile::profile::parse_object(data) else {
        return out;
    };
    if obj.format() != object::BinaryFormat::Elf {
        return out;
    }

    for section in obj.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if !name.to_ascii_lowercase().starts_with(".rel") {
            continue;
        }
        for (offset, relocation) in section.relocations() {
            let target = match relocation.target() {
                RelocationTarget::Symbol(index) => {
                    let Ok(symbol) = obj.symbol_by_index(index) else {
                        continue;
                    };
                    // `is_definition` is what separates "this file owns the
                    // object" from "the dynamic linker will supply it".
                    if !symbol.is_definition() {
                        continue;
                    }
                    let address = symbol.address();
                    if address == 0 {
                        continue;
                    }
                    address.wrapping_add(relocation.addend() as u64)
                }
                // `R_*_RELATIVE`: no symbol, the addend IS the target, already
                // biased by the link-time load address.
                RelocationTarget::Absolute => {
                    let addend = relocation.addend();
                    if addend <= 0 {
                        continue;
                    }
                    addend as u64
                }
                _ => continue,
            };
            out.push((offset, target));
        }

        // `object::Section::relocations()` does not expose the dynamic
        // R_AARCH64_RELATIVE records in current linked ELFs. Parse that one
        // ABI-defined RELA shape from the section bytes so a file-only image
        // can recover pointers such as crt1's GOT-held `main` address. Keep the
        // architecture/type gate exact: other symbol-zero relocation kinds
        // (notably IRELATIVE) are executable resolvers, not stored addends.
        if obj.architecture() == object::Architecture::Aarch64
            && name.eq_ignore_ascii_case(".rela.dyn")
        {
            let Ok(bytes) = section.uncompressed_data() else {
                continue;
            };
            out.extend(aarch64_relative_relocations(&bytes, obj.is_little_endian()));
        }
        if obj.architecture() == object::Architecture::Arm && name.eq_ignore_ascii_case(".rel.dyn")
        {
            let Ok(bytes) = section.uncompressed_data() else {
                continue;
            };
            out.extend(arm_relative_relocations(
                &bytes,
                obj.is_little_endian(),
                |slot| {
                    let offset = crate::analysis::entry::va_to_file_offset(data, slot)?;
                    let raw: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
                    Some(if obj.is_little_endian() {
                        u32::from_le_bytes(raw) as u64
                    } else {
                        u32::from_be_bytes(raw) as u64
                    })
                },
            ));
        }
    }

    out.sort_by_key(|(slot, _)| *slot);
    out.dedup_by_key(|(slot, _)| *slot);
    out
}

fn arm_relative_relocations(
    bytes: &[u8],
    little_endian: bool,
    mut read_addend: impl FnMut(u64) -> Option<u64>,
) -> Vec<(u64, u64)> {
    const R_ARM_RELATIVE: u32 = 23;
    let read_u32 = |raw: &[u8]| {
        let array: [u8; 4] = raw.try_into().expect("exact ELF32 field width");
        if little_endian {
            u32::from_le_bytes(array)
        } else {
            u32::from_be_bytes(array)
        }
    };
    bytes
        .chunks_exact(8)
        .filter_map(|entry| {
            let offset = u64::from(read_u32(&entry[0..4]));
            let info = read_u32(&entry[4..8]);
            let symbol = info >> 8;
            let relocation_type = info & 0xff;
            if symbol != 0 || relocation_type != R_ARM_RELATIVE {
                return None;
            }
            let addend = read_addend(offset)?;
            (addend != 0).then_some((offset, addend))
        })
        .collect()
}

fn aarch64_relative_relocations(bytes: &[u8], little_endian: bool) -> Vec<(u64, u64)> {
    const R_AARCH64_RELATIVE: u32 = 1027;
    let read_u64 = |raw: &[u8]| {
        let array: [u8; 8] = raw.try_into().expect("exact ELF64 field width");
        if little_endian {
            u64::from_le_bytes(array)
        } else {
            u64::from_be_bytes(array)
        }
    };
    bytes
        .chunks_exact(24)
        .filter_map(|entry| {
            let offset = read_u64(&entry[0..8]);
            let info = read_u64(&entry[8..16]);
            let addend = read_u64(&entry[16..24]);
            let symbol = info >> 32;
            let relocation_type = info as u32;
            (symbol == 0 && relocation_type == R_AARCH64_RELATIVE && addend != 0)
                .then_some((offset, addend))
        })
        .collect()
}

#[cfg(test)]
mod relative_relocation_tests {
    use super::{aarch64_relative_relocations, arm_relative_relocations};

    #[test]
    fn aarch64_relative_rela_keeps_its_slot_and_addend() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1fff0_u64.to_le_bytes());
        bytes.extend_from_slice(&u64::from(1027_u32).to_le_bytes());
        bytes.extend_from_slice(&0x7a8_u64.to_le_bytes());

        assert_eq!(
            aarch64_relative_relocations(&bytes, true),
            vec![(0x1fff0, 0x7a8)]
        );
    }

    #[test]
    fn aarch64_irelative_is_not_mistaken_for_a_stored_pointer() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1fff0_u64.to_le_bytes());
        bytes.extend_from_slice(&u64::from(1032_u32).to_le_bytes());
        bytes.extend_from_slice(&0x7a8_u64.to_le_bytes());

        assert!(aarch64_relative_relocations(&bytes, true).is_empty());
    }

    #[test]
    fn arm_rel_reads_its_addend_from_the_relocated_slot() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1fff8_u32.to_le_bytes());
        bytes.extend_from_slice(&23_u32.to_le_bytes());

        assert_eq!(
            arm_relative_relocations(&bytes, true, |slot| { (slot == 0x1fff8).then_some(0x505) }),
            vec![(0x1fff8, 0x505)]
        );
    }
}
