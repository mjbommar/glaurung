//! PE IAT (Import Address Table) mapping helpers.
//!
//! Builds a conservative map from IAT entry VAs to imported function names.
//! This lets us resolve indirect calls like `call [rip+disp]` on Windows x64
//! and `call dword ptr [imm32]` on Windows x86 to symbol names.

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
    let num_dirs = read_u32_le(data, opt_off + 92).unwrap_or(0); // NumberOfRvaAndSizes
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

                        // Name via OriginalFirstThunk (by-name) or hint/name table
                        let name_opt = if original_first_thunk != 0 {
                            if let Some(n_off) = rva_to_offset(original_first_thunk, &sections) {
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
