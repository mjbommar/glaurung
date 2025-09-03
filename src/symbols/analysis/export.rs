//! Export analysis for PE: forwarded vs direct vs ordinal-only.

pub struct ExportCounts {
    pub direct: u32,
    pub forwarded: u32,
    pub ordinal_only: u32,
}

/// Analyze PE export table using a minimal, bounded parser.
pub fn analyze_pe_exports(data: &[u8]) -> Option<ExportCounts> {
    // Minimal header checks
    if data.len() < 0x40 {
        return None;
    }
    let read_u16 = |off: usize| -> Option<u16> {
        data.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let e_lfanew = read_u32(0x3c)? as usize;
    if e_lfanew + 4 + 20 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    let size_of_optional_header = read_u16(coff_off + 16)? as usize;
    let opt_off = coff_off + 20;
    if opt_off + size_of_optional_header > data.len() {
        return None;
    }
    let magic = read_u16(opt_off)?;
    let is_pe32_plus = magic == 0x20B;
    if !(is_pe32_plus || magic == 0x10B) {
        return None;
    }
    let data_dir_offset = if is_pe32_plus {
        opt_off + 112
    } else {
        opt_off + 96
    };
    let num_dirs = read_u32(opt_off + 92)? as usize;
    if num_dirs == 0 {
        return None;
    }
    let dd = |index: usize| -> Option<(u32, u32)> {
        if index >= num_dirs {
            return None;
        }
        let off = data_dir_offset + index * 8;
        if off + 8 > data.len() {
            return None;
        }
        Some((read_u32(off)?, read_u32(off + 4)?))
    };
    let (export_rva, export_size) = dd(0)?; // IMAGE_DIRECTORY_ENTRY_EXPORT
    if export_rva == 0 || export_size == 0 {
        return None;
    }

    // Section headers used for RVA->offset mapping
    let number_of_sections = read_u16(coff_off + 2)? as usize;
    let sec_off = opt_off + size_of_optional_header;
    let mut sections: Vec<(u32, u32, u32, u32)> = Vec::new(); // (va, raw_ptr, raw_size, virt_size)
    let mut off = sec_off;
    for _ in 0..number_of_sections {
        if off + 40 > data.len() {
            break;
        }
        let virt_size = read_u32(off + 8).unwrap_or(0);
        let va = read_u32(off + 12).unwrap_or(0);
        let raw_size = read_u32(off + 16).unwrap_or(0);
        let raw_ptr = read_u32(off + 20).unwrap_or(0);
        sections.push((va, raw_ptr, raw_size, virt_size));
        off += 40;
    }
    let rva_to_off = |rva: u32| -> Option<usize> {
        for (va, raw_ptr, raw_size, virt_size) in &sections {
            let size = std::cmp::max(*raw_size, *virt_size);
            if size == 0 {
                continue;
            }
            if rva >= *va && rva < va.saturating_add(size) {
                return Some(raw_ptr.saturating_add(rva - *va) as usize);
            }
        }
        None
    };
    let exp_off = rva_to_off(export_rva)?;
    if exp_off + 40 > data.len() {
        return None;
    }
    let addr_funcs_rva = read_u32(exp_off + 28).unwrap_or(0);
    let addr_names_rva = read_u32(exp_off + 32).unwrap_or(0);
    let addr_ordinals_rva = read_u32(exp_off + 36).unwrap_or(0);
    let number_of_funcs = read_u32(exp_off + 20).unwrap_or(0) as usize;
    let number_of_names = read_u32(exp_off + 24).unwrap_or(0) as usize;
    let _base = read_u32(exp_off + 16).unwrap_or(0);
    // Export directory bounds for forwarder detection
    let exp_dir_start = export_rva;
    let exp_dir_end = export_rva.saturating_add(export_size);
    let mut forwarded = 0u32;
    let mut direct = 0u32;
    let mut ordinal_only = 0u32;
    if addr_funcs_rva != 0 {
        let funcs_off = rva_to_off(addr_funcs_rva)?;
        for i in 0..number_of_funcs.min(4096) {
            let entry_off = funcs_off + i * 4;
            if entry_off + 4 > data.len() {
                break;
            }
            let rva = read_u32(entry_off).unwrap_or(0);
            if rva == 0 {
                continue;
            }
            if rva >= exp_dir_start && rva < exp_dir_end {
                forwarded += 1;
            } else {
                direct += 1;
            }
        }
    }
    // Ordinal-only exports = functions not in the AddressOfNames mapping
    if addr_names_rva != 0 && addr_ordinals_rva != 0 && number_of_funcs > 0 {
        let ords_off = rva_to_off(addr_ordinals_rva)?;
        let _names_off = rva_to_off(addr_names_rva)?;
        // Build set of named ordinals
        let mut named = std::collections::HashSet::new();
        for i in 0..number_of_names.min(4096) {
            let ord_index_off = ords_off + i * 2;
            if ord_index_off + 2 > data.len() {
                break;
            }
            let ord_index = data
                .get(ord_index_off..ord_index_off + 2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .unwrap_or(0) as usize;
            if ord_index < number_of_funcs {
                named.insert(ord_index);
            }
        }
        let named_count = named.len() as u32;
        if number_of_funcs as u32 >= named_count {
            ordinal_only = (number_of_funcs as u32).saturating_sub(named_count);
        }
    }
    Some(ExportCounts {
        direct,
        forwarded,
        ordinal_only,
    })
}
