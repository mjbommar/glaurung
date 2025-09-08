//! PE (Portable Executable) symbol extraction

use super::types::{BudgetCaps, SymbolSummary};
use crate::symbols::analysis::suspicious;

// Minimal PE header parsing for counts under strict bounds

#[derive(Debug, Clone, Copy)]
struct CoffHeader {
    number_of_sections: u16,
    size_of_optional_header: u16,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
}

#[derive(Debug, Clone, Copy)]
struct OptionalHeaderLocs {
    data_dir_offset: usize,
    num_data_dirs: u32,
}

#[derive(Debug, Clone, Copy)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

#[derive(Debug, Clone)]
struct SectionHdr {
    name: String,
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
        // Use max(VirtualSize, SizeOfRawData) as inclusive mapping window
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

/// Attempt to summarize PE imports/exports and flags from the header-limited buffer.
pub fn summarize_pe(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    // DOS header
    if data.len() < 0x40 {
        return SymbolSummary::default();
    }
    let e_lfanew = match read_u32_le(data, 0x3c) {
        Some(v) => v as usize,
        None => return SymbolSummary::default(),
    };
    if e_lfanew + 4 + 20 > data.len() {
        return SymbolSummary::default();
    }
    // Signature
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return SymbolSummary::default();
    }
    // COFF header
    let coff_off = e_lfanew + 4;
    let number_of_sections = read_u16_le(data, coff_off + 2).unwrap_or(0);
    let pointer_to_symbol_table = read_u32_le(data, coff_off + 8).unwrap_or(0);
    let number_of_symbols = read_u32_le(data, coff_off + 12).unwrap_or(0);
    let size_of_optional_header = read_u16_le(data, coff_off + 16).unwrap_or(0);
    let coff = CoffHeader {
        number_of_sections,
        size_of_optional_header,
        pointer_to_symbol_table,
        number_of_symbols,
    };
    // Optional header location
    let opt_off = coff_off + 20;
    if opt_off + (size_of_optional_header as usize) > data.len() {
        return SymbolSummary::default();
    }
    let magic = read_u16_le(data, opt_off).unwrap_or(0);
    let (is_pe32_plus, data_dir_offset) = if magic == 0x20B {
        // PE32+
        (true, opt_off + 112)
    } else if magic == 0x10B {
        // PE32
        (false, opt_off + 96)
    } else {
        return SymbolSummary::default();
    };
    let num_dirs = read_u32_le(data, opt_off + 92).unwrap_or(0); // NumberOfRvaAndSizes
    let opt = OptionalHeaderLocs {
        data_dir_offset,
        num_data_dirs: num_dirs,
    };

    // DLLCharacteristics flags for NX/ASLR/CFG
    let dll_char_off = if is_pe32_plus {
        opt_off + 0x5E // 94
    } else {
        opt_off + 0x46 // 70
    };
    let dll_chars = read_u16_le(data, dll_char_off).unwrap_or(0) as u32;
    let pe_aslr = (dll_chars & 0x0040) != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    let pe_nx = (dll_chars & 0x0100) != 0; // IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    let pe_cfg = (dll_chars & 0x4000) != 0; // IMAGE_DLLCHARACTERISTICS_GUARD_CF

    // Data directories of interest
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
            size: read_u32_le(data, off + 4)?,
        })
    };
    let export_dd = dd(0).unwrap_or(DataDirectory { rva: 0, size: 0 });
    let import_dd = dd(1).unwrap_or(DataDirectory { rva: 0, size: 0 });
    let base_reloc_dd = dd(5).unwrap_or(DataDirectory { rva: 0, size: 0 });
    let debug_dd = dd(6).unwrap_or(DataDirectory { rva: 0, size: 0 });
    let tls_dd = dd(9).unwrap_or(DataDirectory { rva: 0, size: 0 });
    let delay_dd = dd(13).unwrap_or(DataDirectory { rva: 0, size: 0 });

    // Section headers
    let mut sections: Vec<SectionHdr> = Vec::new();
    let sec_off = opt_off + (coff.size_of_optional_header as usize);
    let sec_table_size = (coff.number_of_sections as usize).saturating_mul(40);
    if sec_off + sec_table_size <= data.len() {
        let mut off = sec_off;
        for _ in 0..coff.number_of_sections {
            if off + 40 > data.len() {
                break;
            }
            // Fields at standard offsets
            // Name (8 bytes at +0)
            let name_bytes = &data[off..off + 8];
            let mut nend = 0usize;
            while nend < 8 && name_bytes[nend] != 0 {
                nend += 1;
            }
            let name = String::from_utf8_lossy(&name_bytes[..nend]).to_string();
            let virt_size = read_u32_le(data, off + 8).unwrap_or(0);
            let va = read_u32_le(data, off + 12).unwrap_or(0);
            let raw_size = read_u32_le(data, off + 16).unwrap_or(0);
            let raw_ptr = read_u32_le(data, off + 20).unwrap_or(0);
            sections.push(SectionHdr {
                name,
                va,
                raw_ptr,
                raw_size,
                virt_size,
            });
            off += 40;
        }
    }

    // Flags
    let stripped = coff.number_of_symbols == 0 || coff.pointer_to_symbol_table == 0;
    let debug_info_present = debug_dd.rva != 0 && rva_to_offset(debug_dd.rva, &sections).is_some();
    let tls_used = tls_dd.rva != 0 && rva_to_offset(tls_dd.rva, &sections).is_some();
    let relocations_present = base_reloc_dd.rva != 0 && base_reloc_dd.size != 0;

    // Entry section name if entry point falls within one
    let address_of_entry = read_u32_le(data, opt_off + 16).unwrap_or(0);
    let mut entry_section: Option<String> = None;
    if address_of_entry != 0 {
        for s in &sections {
            let size = s.virt_size.max(s.raw_size);
            if size == 0 {
                continue;
            }
            if address_of_entry >= s.va && address_of_entry < s.va.saturating_add(size) {
                entry_section = Some(s.name.clone());
                break;
            }
        }
    }

    // Counts
    let mut imports_count: u32 = 0;
    let mut import_names: Vec<String> = Vec::new();
    let mut libs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut exports_count: u32 = 0;
    let mut export_names: Vec<String> = Vec::new();
    let start = std::time::Instant::now();

    // Helper to check time budget
    let time_ok = |start: &std::time::Instant, caps: &BudgetCaps| {
        (start.elapsed().as_millis() as u64) <= caps.time_guard_ms
    };

    // Parse import descriptors (normal + delay)
    for (ddesc, _is_delay) in [(import_dd, false), (delay_dd, true)] {
        if ddesc.rva == 0 || !time_ok(&start, caps) {
            continue;
        }
        if let Some(mut off) = rva_to_offset(ddesc.rva, &sections) {
            // Iterate IMAGE_IMPORT_DESCRIPTORs (20 bytes) until zeroed
            let mut dlls_seen = 0u32;
            loop {
                if off + 20 > data.len() {
                    break;
                }
                let original_first_thunk = read_u32_le(data, off).unwrap_or(0);
                let name_rva = read_u32_le(data, off + 12).unwrap_or(0);
                let first_thunk = read_u32_le(data, off + 16).unwrap_or(0);
                // Zero descriptor terminates
                if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                    break;
                }

                // Resolve DLL name
                if let Some(name_off) = rva_to_offset(name_rva, &sections) {
                    // Read until NUL or cap
                    let mut end = name_off;
                    while end < data.len() && end - name_off < 256 {
                        if data[end] == 0 {
                            break;
                        }
                        end += 1;
                    }
                    if end <= data.len() {
                        if let Ok(s) = std::str::from_utf8(&data[name_off..end]) {
                            libs.insert(s.to_ascii_lowercase());
                        }
                    }
                }

                // Count thunks (imports)
                let thunk_rva = if original_first_thunk != 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };
                if thunk_rva != 0 {
                    if let Some(mut toff) = rva_to_offset(thunk_rva, &sections) {
                        let entry_size = if is_pe32_plus { 8 } else { 4 };
                        let mut local_count = 0u32;
                        loop {
                            if !time_ok(&start, caps) {
                                break;
                            }
                            if toff + entry_size > data.len() {
                                break;
                            }
                            let val = if is_pe32_plus {
                                let lo = read_u32_le(data, toff).unwrap_or(0);
                                let hi = read_u32_le(data, toff + 4).unwrap_or(0);
                                ((hi as u64) << 32) | (lo as u64)
                            } else {
                                read_u32_le(data, toff).unwrap_or(0) as u64
                            };
                            if val == 0 {
                                break;
                            }
                            local_count += 1;
                            // Try resolve by-name import name
                            let is_ordinal = if is_pe32_plus {
                                (val & (1u64 << 63)) != 0
                            } else {
                                (val & (1u64 << 31)) != 0
                            };
                            if !is_ordinal {
                                let rva = val as u32;
                                if let Some(n_off) = rva_to_offset(rva, &sections) {
                                    if n_off + 2 < data.len() {
                                        let mut p = n_off + 2; // skip Hint
                                        let max = (p + 256).min(data.len());
                                        while p < max && data[p] != 0 {
                                            p += 1;
                                        }
                                        if p <= data.len() {
                                            if let Ok(s) =
                                                std::str::from_utf8(&data[(n_off + 2)..p])
                                            {
                                                import_names.push(s.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                            imports_count = imports_count.saturating_add(1);
                            if imports_count >= caps.max_imports {
                                break;
                            }
                            toff += entry_size;
                        }
                        let _ = local_count; // no-op, informative
                    }
                }

                dlls_seen += 1;
                if dlls_seen >= caps.max_libs {
                    break;
                }
                off += 20;
                if imports_count >= caps.max_imports || !time_ok(&start, caps) {
                    break;
                }
            }
        }
    }

    // Parse export directory header to count exports
    if export_dd.rva != 0 {
        if let Some(off) = rva_to_offset(export_dd.rva, &sections) {
            if off + 40 <= data.len() {
                // IMAGE_EXPORT_DIRECTORY fields
                let number_of_functions = read_u32_le(data, off + 20).unwrap_or(0);
                let number_of_names = read_u32_le(data, off + 24).unwrap_or(0);
                exports_count = number_of_names
                    .max(number_of_functions)
                    .min(caps.max_exports);
                // AddressOfNames array at +36
                let addr_of_names_rva = read_u32_le(data, off + 36).unwrap_or(0);
                if addr_of_names_rva != 0 {
                    if let Some(names_off) = rva_to_offset(addr_of_names_rva, &sections) {
                        // Iterate up to caps.max_exports names
                        let max_names = (number_of_names as u32).min(caps.max_exports) as usize;
                        for i in 0..max_names {
                            let idx_off = names_off + i * 4;
                            if idx_off + 4 > data.len() {
                                break;
                            }
                            let name_rva = read_u32_le(data, idx_off).unwrap_or(0);
                            if name_rva == 0 {
                                continue;
                            }
                            if let Some(n_off) = rva_to_offset(name_rva, &sections) {
                                // Read NUL-terminated ASCII name
                                let mut end = n_off;
                                while end < data.len() && end - n_off < 256 {
                                    if data[end] == 0 {
                                        break;
                                    }
                                    end += 1;
                                }
                                if end <= data.len() {
                                    if let Ok(s) = std::str::from_utf8(&data[n_off..end]) {
                                        if !s.is_empty() {
                                            export_names.push(s.to_string());
                                            if export_names.len() as u32 >= caps.max_exports {
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let suspicious_list = if import_names.is_empty() {
        None
    } else {
        let v = suspicious::detect_suspicious_imports(&import_names, 64);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let demangled_import_names = {
        let mut v: Vec<String> = Vec::new();
        for s in &import_names {
            if let Some(r) = crate::demangle::demangle_one(s) {
                if r.demangled != *s {
                    v.push(r.demangled);
                }
            }
        }
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let demangled_export_names = {
        let mut v: Vec<String> = Vec::new();
        for s in &export_names {
            if let Some(r) = crate::demangle::demangle_one(s) {
                if r.demangled != *s {
                    v.push(r.demangled);
                }
            }
        }
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };

    // ImageBase for VA->RVA conversion
    let image_base: u64 = if is_pe32_plus {
        let lo = read_u32_le(data, opt_off + 24).unwrap_or(0) as u64;
        let hi = read_u32_le(data, opt_off + 28).unwrap_or(0) as u64;
        (hi << 32) | lo
    } else {
        read_u32_le(data, opt_off + 28).unwrap_or(0) as u64
    };

    SymbolSummary {
        imports_count,
        exports_count,
        libs_count: (libs.len() as u32).min(caps.max_libs),
        import_names: if import_names.is_empty() {
            None
        } else {
            Some(import_names)
        },
        export_names: if export_names.is_empty() {
            None
        } else {
            Some(export_names)
        },
        demangled_import_names,
        demangled_export_names,
        stripped,
        tls_used,
        tls_callback_count: {
            // Enumerate TLS callbacks count best-effort
            if let Some(tls_off) = if tls_dd.rva != 0 {
                rva_to_offset(tls_dd.rva, &sections)
            } else {
                None
            } {
                // AddressOfCallbacks: +0x14 (PE32) or +0x20 (PE32+)
                let cb_va_u64: u64 = if is_pe32_plus {
                    let lo = read_u32_le(data, tls_off + 0x20).unwrap_or(0) as u64;
                    let hi = read_u32_le(data, tls_off + 0x24).unwrap_or(0) as u64;
                    (hi << 32) | lo
                } else {
                    read_u32_le(data, tls_off + 0x14).unwrap_or(0) as u64
                };
                if cb_va_u64 != 0 {
                    let cb_rva_u64 = cb_va_u64.saturating_sub(image_base);
                    let cb_rva = (cb_rva_u64 & 0xFFFF_FFFF) as u32;
                    if let Some(mut cb_off) = rva_to_offset(cb_rva, &sections) {
                        let mut cnt: u32 = 0;
                        let step = if is_pe32_plus { 8 } else { 4 };
                        for _ in 0..1024u32 {
                            if cb_off + step > data.len() {
                                break;
                            }
                            let val = if is_pe32_plus {
                                let lo = read_u32_le(data, cb_off).unwrap_or(0);
                                let hi = read_u32_le(data, cb_off + 4).unwrap_or(0);
                                ((hi as u64) << 32) | (lo as u64)
                            } else {
                                read_u32_le(data, cb_off).unwrap_or(0) as u64
                            };
                            if val == 0 {
                                break;
                            }
                            cnt = cnt.saturating_add(1);
                            cb_off += step;
                        }
                        Some(cnt)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        },
        tls_callback_vas: {
            if let Some(tls_off) = if tls_dd.rva != 0 {
                rva_to_offset(tls_dd.rva, &sections)
            } else {
                None
            } {
                let cb_va_u64: u64 = if is_pe32_plus {
                    let lo = read_u32_le(data, tls_off + 0x20).unwrap_or(0) as u64;
                    let hi = read_u32_le(data, tls_off + 0x24).unwrap_or(0) as u64;
                    (hi << 32) | lo
                } else {
                    read_u32_le(data, tls_off + 0x14).unwrap_or(0) as u64
                };
                if cb_va_u64 != 0 {
                    let cb_rva_u64 = cb_va_u64.saturating_sub(image_base);
                    let cb_rva = (cb_rva_u64 & 0xFFFF_FFFF) as u32;
                    if let Some(mut cb_off) = rva_to_offset(cb_rva, &sections) {
                        let mut list: Vec<u64> = Vec::new();
                        let step = if is_pe32_plus { 8 } else { 4 };
                        for _ in 0..1024u32 {
                            if cb_off + step > data.len() {
                                break;
                            }
                            let val = if is_pe32_plus {
                                let lo = read_u32_le(data, cb_off).unwrap_or(0) as u64;
                                let hi = read_u32_le(data, cb_off + 4).unwrap_or(0) as u64;
                                (hi << 32) | lo
                            } else {
                                read_u32_le(data, cb_off).unwrap_or(0) as u64
                            };
                            if val == 0 {
                                break;
                            }
                            list.push(val);
                            cb_off += step;
                            if list.len() >= 1024 {
                                break;
                            }
                        }
                        if list.is_empty() {
                            None
                        } else {
                            Some(list)
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
        },
        debug_info_present,
        pdb_path: {
            // Best-effort CodeView RSDS scan for PDB path; prefer scanning debug directory if present
            // RSDS format: 'RSDS' (4) + GUID (16) + Age (4) + UTF-8 path (NUL-terminated)
            let mut found: Option<String> = None;
            // Try to locate the debug dir first
            let search_ranges: Vec<(usize, usize)> =
                if let Some(off) = rva_to_offset(debug_dd.rva, &sections) {
                    let sz = (debug_dd.size as usize).min(64 * 1024); // bound
                    let end = (off + sz).min(data.len());
                    vec![(off, end)]
                } else {
                    // Fallback: scan first 64 KiB
                    vec![(0usize, data.len().min(64 * 1024))]
                };
            for (start, end) in search_ranges {
                let hay = &data[start..end];
                if let Some(pos) = memchr::memmem::find(hay, b"RSDS") {
                    let base = start + pos;
                    let path_off = base.saturating_add(24);
                    if path_off < data.len() {
                        let mut p = path_off;
                        let max = (p + 512).min(data.len());
                        while p < max && data[p] != 0 {
                            p += 1;
                        }
                        if p > path_off {
                            if let Ok(s) = std::str::from_utf8(&data[path_off..p]) {
                                if !s.is_empty() {
                                    found = Some(s.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            found
        },
        suspicious_imports: suspicious_list,
        entry_section,
        nx: Some(pe_nx),
        aslr: Some(pe_aslr),
        relro: None,
        pie: None,
        cfg: Some(pe_cfg),
        relocations_present: Some(relocations_present),
        rpaths: None,
        runpaths: None,
    }
}
