//! PE IAT (Import Address Table) mapping helpers.
//!
//! Builds a conservative map from IAT entry VAs to imported function names.
//! This lets us resolve indirect calls like `call [rip+disp]` on Windows x64
//! and `call dword ptr [imm32]` on Windows x86 to symbol names.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy)]
struct CoffHeader {
    number_of_sections: u16,
    size_of_optional_header: u16,
}

#[derive(Debug, Clone, Copy)]
struct OptionalHeaderLocs {
    data_dir_offset: usize,
    num_data_dirs: u32,
    _is_pe32_plus: bool,
}

#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    rva: u32,
    _size: u32,
}

#[derive(Debug, Clone)]
struct SectionHdr {
    va: u32,
    raw_ptr: u32,
    raw_size: u32,
    virt_size: u32,
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rva_to_offset(rva: u32, secs: &[SectionHdr]) -> Option<usize> {
    for s in secs {
        let start = s.va;
        let size = s.virt_size.max(s.raw_size);
        if size == 0 {
            continue;
        }
        if rva >= start && rva < start.saturating_add(size) {
            let delta = rva - start;
            let off = s.raw_ptr.saturating_add(delta);
            return Some(off as usize);
        }
    }
    None
}

/// Build a best-effort map of IAT entry VAs to imported function names for PE files.
/// Returns empty when format is not PE or on parse failures.
pub fn pe_iat_map(data: &[u8]) -> Vec<(u64, String)> {
    // Minimal parse of PE headers for performance and resilience.
    let mut out: Vec<(u64, String)> = Vec::new();
    if data.len() < 0x40 {
        return out;
    }
    let e_lfanew = match read_u32_le(data, 0x3c) {
        Some(v) => v as usize,
        None => return out,
    };
    if e_lfanew + 4 + 20 > data.len() {
        return out;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return out;
    }

    // COFF header
    let coff_off = e_lfanew + 4;
    let number_of_sections = read_u16_le(data, coff_off + 2).unwrap_or(0);
    let size_of_optional_header = read_u16_le(data, coff_off + 16).unwrap_or(0);
    let coff = CoffHeader {
        number_of_sections,
        size_of_optional_header,
    };

    // Optional header
    let opt_off = coff_off + 20;
    if opt_off + (size_of_optional_header as usize) > data.len() {
        return out;
    }
    let magic = read_u16_le(data, opt_off).unwrap_or(0);
    let (is_pe32_plus, data_dir_offset) = if magic == 0x20B {
        (true, opt_off + 112)
    } else if magic == 0x10B {
        (false, opt_off + 96)
    } else {
        return out;
    };
    let num_dirs_off = if is_pe32_plus {
        opt_off + 108
    } else {
        opt_off + 92
    };
    let num_dirs = read_u32_le(data, num_dirs_off).unwrap_or(0); // NumberOfRvaAndSizes
    let opt = OptionalHeaderLocs {
        data_dir_offset,
        num_data_dirs: num_dirs,
        _is_pe32_plus: is_pe32_plus,
    };

    // ImageBase for RVA->VA conversion
    let image_base: u64 = if is_pe32_plus {
        let lo = read_u32_le(data, opt_off + 24).unwrap_or(0) as u64;
        let hi = read_u32_le(data, opt_off + 28).unwrap_or(0) as u64;
        (hi << 32) | lo
    } else {
        read_u32_le(data, opt_off + 28).unwrap_or(0) as u64
    };

    // Data directory helper
    let dd = |index: usize| -> Option<DataDirectory> {
        if index as u32 >= opt.num_data_dirs {
            return None;
        }
        let off = opt.data_dir_offset + index * 8;
        if off + 8 > data.len() {
            return None;
        }
        Some(DataDirectory {
            rva: read_u32_le(data, off)?,
            _size: read_u32_le(data, off + 4)?,
        })
    };
    let import_dd = dd(1).unwrap_or(DataDirectory { rva: 0, _size: 0 });
    let delay_dd = dd(13).unwrap_or(DataDirectory { rva: 0, _size: 0 });

    // Sections
    let mut sections: Vec<SectionHdr> = Vec::new();
    let sec_off = opt_off + (coff.size_of_optional_header as usize);
    let sec_table_size = (coff.number_of_sections as usize).saturating_mul(40);
    if sec_off + sec_table_size <= data.len() {
        let mut off = sec_off;
        for _ in 0..coff.number_of_sections {
            if off + 40 > data.len() {
                break;
            }
            let virt_size = read_u32_le(data, off + 8).unwrap_or(0);
            let va = read_u32_le(data, off + 12).unwrap_or(0);
            let raw_size = read_u32_le(data, off + 16).unwrap_or(0);
            let raw_ptr = read_u32_le(data, off + 20).unwrap_or(0);
            sections.push(SectionHdr {
                va,
                raw_ptr,
                raw_size,
                virt_size,
            });
            off += 40;
        }
    }

    // Helper to read C-string from an RVA
    let read_string_rva = |rva: u32, limit: usize| -> Option<String> {
        let off = rva_to_offset(rva, &sections)?;
        let mut end = off;
        let max = (off + limit).min(data.len());
        while end < max {
            if data[end] == 0 {
                break;
            }
            end += 1;
        }
        if end > off {
            if let Ok(s) = std::str::from_utf8(&data[off..end]) {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        None
    };

    // Iterate both normal and delay import descriptors
    for (ddesc, _is_delay) in [(import_dd, false), (delay_dd, true)] {
        if ddesc.rva == 0 {
            continue;
        }
        let Some(mut off) = rva_to_offset(ddesc.rva, &sections) else {
            continue;
        };
        // IMAGE_IMPORT_DESCRIPTORs (20 bytes)
        loop {
            if off + 20 > data.len() {
                break;
            }
            let original_first_thunk = read_u32_le(data, off).unwrap_or(0);
            let name_rva = read_u32_le(data, off + 12).unwrap_or(0);
            let first_thunk = read_u32_le(data, off + 16).unwrap_or(0);
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            // Resolve DLL name (optional; unused in mapping key but could be included)
            let _dll_name = read_string_rva(name_rva, 256).unwrap_or_default();

            // Iterate thunks; map IAT slot VA -> import name (if any)
            if first_thunk != 0 {
                if let Some(mut toff) = rva_to_offset(first_thunk, &sections) {
                    let entry_size = if is_pe32_plus { 8 } else { 4 };
                    let mut index = 0usize;
                    loop {
                        if toff + entry_size > data.len() {
                            break;
                        }
                        // Stop on terminator
                        let val = if is_pe32_plus {
                            let lo = read_u32_le(data, toff).unwrap_or(0) as u64;
                            let hi = read_u32_le(data, toff + 4).unwrap_or(0) as u64;
                            (hi << 32) | lo
                        } else {
                            read_u32_le(data, toff).unwrap_or(0) as u64
                        };
                        if val == 0 {
                            break;
                        }
                        // IAT slot VA
                        let slot_rva =
                            first_thunk.saturating_add((index as u32) * (entry_size as u32));
                        let slot_va = image_base.saturating_add(slot_rva as u64);

                        // Name via OriginalFirstThunk when present. Some PEs
                        // omit it and use FirstThunk as the on-disk import
                        // lookup table, so fall back to FirstThunk for names
                        // while still reporting FirstThunk as the IAT slot VA.
                        let name_thunk = if original_first_thunk != 0 {
                            original_first_thunk
                        } else {
                            first_thunk
                        };
                        let name_opt = if name_thunk != 0 {
                            if let Some(n_off) = rva_to_offset(name_thunk, &sections) {
                                // Read parallel entry at same index
                                let n_entry_off = n_off.saturating_add(index * entry_size);
                                if n_entry_off + entry_size <= data.len() {
                                    let nval = if is_pe32_plus {
                                        let lo = read_u32_le(data, n_entry_off).unwrap_or(0) as u64;
                                        let hi =
                                            read_u32_le(data, n_entry_off + 4).unwrap_or(0) as u64;
                                        (hi << 32) | lo
                                    } else {
                                        read_u32_le(data, n_entry_off).unwrap_or(0) as u64
                                    };
                                    let is_ordinal = if is_pe32_plus {
                                        (nval & (1u64 << 63)) != 0
                                    } else {
                                        (nval & (1u64 << 31)) != 0
                                    };
                                    if !is_ordinal {
                                        let hint_name_rva = (nval & 0xFFFF_FFFF) as u32;
                                        // Skip 2-byte hint then read name
                                        if let Some(hint_off) =
                                            rva_to_offset(hint_name_rva, &sections)
                                        {
                                            if hint_off + 2 <= data.len() {
                                                read_string_rva(
                                                    hint_name_rva.saturating_add(2),
                                                    256,
                                                )
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Some(name) = name_opt {
                            out.push((slot_va, name));
                        }
                        toff += entry_size;
                        index += 1;
                    }
                }
            }

            off += 20;
        }
    }

    out
}

/// Build a best-effort map of executable PE import thunks to imported names.
///
/// Some Windows binaries call a local thunk whose whole body is `jmp [IAT]`.
/// The normal IAT map names the slot, but a direct `call thunk_va` still renders
/// as a raw address unless the thunk entry VA is also known. This scanner only
/// aliases executable-section `jmp [mem]` patterns whose memory target exactly
/// matches a known IAT slot.
pub fn pe_import_thunk_map(data: &[u8]) -> Vec<(u64, String)> {
    let iat_names: BTreeMap<u64, String> = pe_iat_map(data).into_iter().collect();
    if iat_names.is_empty() {
        return Vec::new();
    }

    let Ok(parser) = crate::formats::pe::PeParser::new(data) else {
        return Vec::new();
    };

    let image_base = parser.image_base();
    let is_64bit = parser.is_64bit();
    let mut out: BTreeMap<u64, String> = BTreeMap::new();

    for section in parser.sections() {
        if !section.header.is_executable() {
            continue;
        }
        let raw_start = section.header.pointer_to_raw_data as usize;
        let raw_size = section.header.size_of_raw_data as usize;
        let Some(raw_end) = raw_start
            .checked_add(raw_size)
            .map(|end| end.min(data.len()))
        else {
            continue;
        };
        if raw_start >= raw_end || raw_start >= data.len() {
            continue;
        }

        let bytes = &data[raw_start..raw_end];
        let mut offset = 0usize;
        while offset < bytes.len() {
            let thunk_va = image_base
                .saturating_add(u64::from(section.header.virtual_address))
                .saturating_add(offset as u64);

            let matched = if is_64bit {
                match decode_x64_iat_jmp(bytes, offset, thunk_va) {
                    Some((target_va, size)) => {
                        if let Some(name) = iat_names.get(&target_va) {
                            out.insert(thunk_va, name.clone());
                        }
                        Some(size)
                    }
                    None => None,
                }
            } else {
                match decode_x86_iat_jmp(bytes, offset) {
                    Some((target_va, size)) => {
                        if let Some(name) = iat_names.get(&target_va) {
                            out.insert(thunk_va, name.clone());
                        }
                        Some(size)
                    }
                    None => None,
                }
            };

            offset += matched.unwrap_or(1);
        }
    }

    out.into_iter().collect()
}

fn decode_x64_iat_jmp(bytes: &[u8], offset: usize, thunk_va: u64) -> Option<(u64, usize)> {
    if offset + 7 <= bytes.len() && bytes[offset..].starts_with(&[0x48, 0xff, 0x25]) {
        let disp = read_i32_le(bytes, offset + 3)? as i64;
        let next_va = thunk_va.saturating_add(7);
        return Some((add_signed_u64(next_va, disp), 7));
    }
    if offset + 6 <= bytes.len() && bytes[offset..].starts_with(&[0xff, 0x25]) {
        let disp = read_i32_le(bytes, offset + 2)? as i64;
        let next_va = thunk_va.saturating_add(6);
        return Some((add_signed_u64(next_va, disp), 6));
    }
    None
}

fn decode_x86_iat_jmp(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset + 6 <= bytes.len() && bytes[offset..].starts_with(&[0xff, 0x25]) {
        let target = read_u32_le(bytes, offset + 2)? as u64;
        return Some((target, 6));
    }
    None
}

fn read_i32_le(data: &[u8], off: usize) -> Option<i32> {
    data.get(off..off + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn add_signed_u64(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub(delta.unsigned_abs())
    }
}

/// Find executable-section `call`/`jmp` sites that reference a PE import's IAT slot.
///
/// This is xrefs-to-an-imported-symbol for PE. Where [`pe_import_thunk_map`]
/// only aliases the `jmp [IAT]` thunk bodies, this returns EVERY
/// `call [rip+disp32]` (`FF /2`) and `jmp [rip+disp32]` (`FF /4`) instruction --
/// x64, with or without a `REX.W` (`0x48`) prefix -- whose memory operand
/// resolves to a known IAT slot, plus the x86 absolute (`FF 15`/`FF 25 imm32`)
/// forms. Each row is `(site_va, iat_slot_va, import_name)`.
///
/// Map the IAT name to its call sites, then attribute each site to its
/// containing function (e.g. via a PDB public-symbol map + a sorted-entry
/// bisect) to learn which functions call a given API -- without paying for full
/// CFG/decompile recovery. The IAT-target constraint keeps the linear byte scan
/// conservative: a stray `FF 15`/`FF 25` whose displacement lands exactly on an
/// IAT slot is vanishingly unlikely, so false positives are negligible in
/// practice. The scan does not attempt full instruction-boundary recovery, so a
/// caller wanting only true boundaries can cross-check `site_va` against a
/// disassembler.
pub fn pe_import_call_sites(data: &[u8]) -> Vec<(u64, u64, String)> {
    let iat_names: BTreeMap<u64, String> = pe_iat_map(data).into_iter().collect();
    if iat_names.is_empty() {
        return Vec::new();
    }

    let Ok(parser) = crate::formats::pe::PeParser::new(data) else {
        return Vec::new();
    };

    let image_base = parser.image_base();
    let is_64bit = parser.is_64bit();
    let mut out: Vec<(u64, u64, String)> = Vec::new();

    for section in parser.sections() {
        if !section.header.is_executable() {
            continue;
        }
        let raw_start = section.header.pointer_to_raw_data as usize;
        let raw_size = section.header.size_of_raw_data as usize;
        let Some(raw_end) = raw_start
            .checked_add(raw_size)
            .map(|end| end.min(data.len()))
        else {
            continue;
        };
        if raw_start >= raw_end || raw_start >= data.len() {
            continue;
        }

        let bytes = &data[raw_start..raw_end];
        let va_base = image_base.saturating_add(u64::from(section.header.virtual_address));
        let mut offset = 0usize;
        while offset < bytes.len() {
            let site_va = va_base.saturating_add(offset as u64);
            let decoded = if is_64bit {
                decode_x64_iat_mem_ref(bytes, offset, site_va)
            } else {
                decode_x86_iat_mem_ref(bytes, offset)
            };
            match decoded {
                Some((target_va, size)) => {
                    if let Some(name) = iat_names.get(&target_va) {
                        out.push((site_va, target_va, name.clone()));
                    }
                    offset += size.max(1);
                }
                None => offset += 1,
            }
        }
    }

    out
}

/// Decode an x64 `call`/`jmp` through a RIP-relative memory operand
/// (`FF /2` call m64, `FF /4` jmp m64), with or without a `REX.W` (`0x48`)
/// prefix. Returns `(rip_relative_target_va, instruction_size)`.
fn decode_x64_iat_mem_ref(bytes: &[u8], offset: usize, site_va: u64) -> Option<(u64, usize)> {
    // Optional REX.W prefix (0x48) ahead of the FF opcode.
    let (op_off, extra) = if bytes.get(offset) == Some(&0x48) {
        (offset + 1, 1usize)
    } else {
        (offset, 0usize)
    };
    if bytes.get(op_off) != Some(&0xff) {
        return None;
    }
    // ModRM: mod=00, reg=/2 (call) or /4 (jmp), rm=101 (RIP-relative) => 0x15 / 0x25.
    let modrm = *bytes.get(op_off + 1)?;
    if modrm != 0x15 && modrm != 0x25 {
        return None;
    }
    let disp = read_i32_le(bytes, op_off + 2)? as i64;
    let size = extra + 6; // [REX] + FF + ModRM + disp32
    let next_va = site_va.saturating_add(size as u64);
    Some((add_signed_u64(next_va, disp), size))
}

/// Decode an x86 `call`/`jmp` through an absolute memory operand
/// (`FF 15 imm32` / `FF 25 imm32`). Returns `(absolute_target_va, size)`.
fn decode_x86_iat_mem_ref(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    if bytes.get(offset) != Some(&0xff) {
        return None;
    }
    let modrm = *bytes.get(offset + 1)?;
    if modrm != 0x15 && modrm != 0x25 {
        return None;
    }
    let target = read_u32_le(bytes, offset + 2)? as u64;
    Some((target, 6))
}

#[cfg(test)]
mod import_call_site_tests {
    use super::{decode_x64_iat_mem_ref, decode_x86_iat_mem_ref};

    #[test]
    fn x64_call_mem_ref_rip_relative() {
        // FF 15 disp32; disp = 0x100 at site 0x1000 -> 0x1000 + 6 + 0x100.
        let bytes = [0xFF, 0x15, 0x00, 0x01, 0x00, 0x00];
        let (target, size) = decode_x64_iat_mem_ref(&bytes, 0, 0x1000).unwrap();
        assert_eq!(size, 6);
        assert_eq!(target, 0x1000 + 6 + 0x100);
    }

    #[test]
    fn x64_jmp_mem_ref_with_rex_w() {
        // 48 FF 25 disp32; disp = 0x10 at site 0x2000 -> 0x2000 + 7 + 0x10.
        let bytes = [0x48, 0xFF, 0x25, 0x10, 0x00, 0x00, 0x00];
        let (target, size) = decode_x64_iat_mem_ref(&bytes, 0, 0x2000).unwrap();
        assert_eq!(size, 7);
        assert_eq!(target, 0x2000 + 7 + 0x10);
    }

    #[test]
    fn x64_mem_ref_negative_disp() {
        let mut bytes = vec![0xFF, 0x15];
        bytes.extend_from_slice(&(-0x20i32).to_le_bytes());
        let (target, _) = decode_x64_iat_mem_ref(&bytes, 0, 0x3000).unwrap();
        assert_eq!(target, 0x3000 + 6 - 0x20);
    }

    #[test]
    fn x64_rejects_register_indirect_and_short() {
        // FF D0 = call rax (reg-direct), not a memory IAT ref.
        assert!(decode_x64_iat_mem_ref(&[0xFF, 0xD0, 0, 0, 0, 0], 0, 0).is_none());
        // Truncated displacement.
        assert!(decode_x64_iat_mem_ref(&[0xFF, 0x15, 0x00], 0, 0).is_none());
    }

    #[test]
    fn x86_absolute_mem_ref() {
        // FF 15 imm32 absolute = 0x00401000.
        let bytes = [0xFF, 0x15, 0x00, 0x10, 0x40, 0x00];
        let (target, size) = decode_x86_iat_mem_ref(&bytes, 0).unwrap();
        assert_eq!(size, 6);
        assert_eq!(target, 0x0040_1000);
    }
}
