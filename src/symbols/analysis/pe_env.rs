//! PE environment analysis: PDB CodeView path and TLS callbacks count.

use object::Object;

pub struct PeEnv {
    pub pdb_path: Option<String>,
    pub tls_callbacks: usize,
    pub entry_section: Option<String>,
    pub relocations_present: bool,
}

pub fn analyze_pe_env(data: &[u8]) -> Option<PeEnv> {
    // Parse using object for pdb info and imports; TLS via manual read.
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return None,
    };
    let pdb_path = match obj.pdb_info() {
        Ok(Some(cv)) => Some(String::from_utf8_lossy(cv.path()).to_string()),
        _ => None,
    };
    // Manual TLS callbacks parse
    // DOS header
    if data.len() < 0x40 {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present: false,
        });
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
    let e_lfanew = read_u32(0x3c)? as usize;
    if e_lfanew + 4 + 20 > data.len() {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present: false,
        });
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present: false,
        });
    }
    let coff_off = e_lfanew + 4;
    let number_of_sections = read_u16(coff_off + 2).unwrap_or(0) as usize;
    let size_of_optional_header = read_u16(coff_off + 16).unwrap_or(0) as usize;
    let opt_off = coff_off + 20;
    if opt_off + size_of_optional_header > data.len() {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present: false,
        });
    }
    let magic = read_u16(opt_off).unwrap_or(0);
    let is_pe32_plus = magic == 0x20B;
    if !(is_pe32_plus || magic == 0x10B) {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present: false,
        });
    }
    let data_dir_offset = if is_pe32_plus {
        opt_off + 112
    } else {
        opt_off + 96
    };
    // ImageBase for VA->RVA
    let image_base: u64 = if is_pe32_plus {
        read_u64(opt_off + 24).unwrap_or(0)
    } else {
        read_u32(opt_off + 28).unwrap_or(0) as u64
    };
    let num_dirs = read_u32(opt_off + 92).unwrap_or(0) as usize;
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
    // TLS directory index = 9
    let relocations_present = match dd(5) {
        Some((rva, sz)) => rva != 0 && sz != 0,
        None => false,
    };
    let (tls_rva, _tls_size) = match dd(9) {
        Some(x) => x,
        None => {
            return Some(PeEnv {
                pdb_path,
                tls_callbacks: 0,
                entry_section: None,
                relocations_present,
            })
        }
    };
    if tls_rva == 0 {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section: None,
            relocations_present,
        });
    }
    // Section headers for rva mapping
    let mut sections: Vec<(String, u32, u32, u32, u32)> = Vec::new(); // (name, va, raw_ptr, raw_size, virt_size)
    let sec_off = opt_off + size_of_optional_header;
    let mut off = sec_off;
    for _ in 0..number_of_sections {
        if off + 40 > data.len() {
            break;
        }
        let name_bytes = &data[off..off + 8];
        let mut end = 0;
        while end < 8 && name_bytes[end] != 0 {
            end += 1;
        }
        let name = String::from_utf8_lossy(&name_bytes[..end]).to_string();
        let virt_size = read_u32(off + 8).unwrap_or(0);
        let va = read_u32(off + 12).unwrap_or(0);
        let raw_size = read_u32(off + 16).unwrap_or(0);
        let raw_ptr = read_u32(off + 20).unwrap_or(0);
        sections.push((name, va, raw_ptr, raw_size, virt_size));
        off += 40;
    }
    let rva_to_off = |rva: u32| -> Option<usize> {
        for (_name, va, raw_ptr, raw_size, virt_size) in &sections {
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
    // Entry section mapping
    let addr_of_entry = read_u32(opt_off + 16).unwrap_or(0);
    let mut entry_section: Option<String> = None;
    for (name, va, _raw_ptr, raw_size, virt_size) in &sections {
        let size = std::cmp::max(*raw_size, *virt_size);
        if size == 0 {
            continue;
        }
        if addr_of_entry >= *va && addr_of_entry < va.saturating_add(size) {
            entry_section = Some(name.clone());
            break;
        }
    }
    let tls_off = match rva_to_off(tls_rva) {
        Some(x) => x,
        None => {
            return Some(PeEnv {
                pdb_path,
                tls_callbacks: 0,
                entry_section,
                relocations_present,
            })
        }
    };
    // TLS structure: AddressOfCallbacks at +0x14 (PE32) or +0x20 (PE32+)
    let callbacks_va = if is_pe32_plus {
        read_u64(tls_off + 0x20).unwrap_or(0)
    } else {
        read_u32(tls_off + 0x14).unwrap_or(0) as u64
    };
    let callbacks_rva = callbacks_va.saturating_sub(image_base) as u32;
    if callbacks_rva == 0 {
        return Some(PeEnv {
            pdb_path,
            tls_callbacks: 0,
            entry_section,
            relocations_present,
        });
    }
    let mut count = 0usize;
    if let Some(mut cb_off) = rva_to_off(callbacks_rva) {
        // Iterate pointer-sized entries until null; bounds to avoid long scans
        for _ in 0..1024usize {
            if is_pe32_plus {
                if cb_off + 8 > data.len() {
                    break;
                }
                let lo = read_u32(cb_off).unwrap_or(0);
                let hi = read_u32(cb_off + 4).unwrap_or(0);
                let val = ((hi as u64) << 32) | lo as u64;
                if val == 0 {
                    break;
                }
                count += 1;
                cb_off += 8;
            } else {
                if cb_off + 4 > data.len() {
                    break;
                }
                let val = read_u32(cb_off).unwrap_or(0);
                if val == 0 {
                    break;
                }
                count += 1;
                cb_off += 4;
            }
        }
    }
    Some(PeEnv {
        pdb_path,
        tls_callbacks: count,
        entry_section,
        relocations_present,
    })
}
