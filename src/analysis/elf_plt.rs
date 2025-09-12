//! ELF PLT mapping helpers (best-effort for x86_64).
//!
//! Provides a conservative mapper from PLT entry VAs to imported function names
//! by pairing `.rela.plt` entries with `.plt` stubs in order.

use object::read::Object;

/// Build a best-effort map of PLT entry addresses to imported function names.
/// Currently supports ELF x86_64 with `.plt` and `.rela.plt` sections.
pub fn elf_plt_map(data: &[u8]) -> Vec<(u64, String)> {
    let mut out: Vec<(u64, String)> = Vec::new();
    let Ok(obj) = object::read::File::parse(data) else {
        return out;
    };
    if obj.format() != object::BinaryFormat::Elf {
        return out;
    }

    // Locate canonical .plt section VA range (prefer exact ".plt")
    let mut plt_start: Option<u64> = None;
    let mut plt_size: Option<u64> = None;
    for sec in obj.sections() {
        if let Ok(name) = sec.name() {
            if name == ".plt" {
                let addr = sec.address();
                let size = sec.size();
                if size > 0 {
                    plt_start = Some(addr);
                    plt_size = Some(size);
                    break;
                }
            }
        }
    }
    let (Some(plt_start), Some(plt_size)) = (plt_start, plt_size) else {
        return out;
    };
    let plt_end = plt_start.saturating_add(plt_size);

    // Collect imported names using .rela.plt order by raw parsing (ELF64)
    use object::ObjectSection;
    let class = data.get(4).copied().unwrap_or(2); // 2=ELF64
    let is_le = data.get(5).copied().unwrap_or(1) == 1;
    let mut imported: Vec<String> = Vec::new();
    if class == 2 {
        // Build dynsym index -> name map
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
        if let (Some(dso), Some(dss), Some(sto), Some(sts)) =
            (dynsym_off, dynsym_size, dynstr_off, dynstr_size)
        {
            let dynsym = &data[dso..dso + dss.min(data.len() - dso)];
            let dynstr = &data[sto..sto + sts.min(data.len() - sto)];
            let entsize = 24usize; // Elf64_Sym
            let count = dynsym.len() / entsize;
            // Helper for name
            let name_for_index = |idx: u32| -> Option<String> {
                let i = idx as usize;
                if i >= count {
                    return None;
                }
                let base = i * entsize;
                let st_name = if is_le {
                    u32::from_le_bytes(dynsym[base..base + 4].try_into().unwrap())
                } else {
                    u32::from_be_bytes(dynsym[base..base + 4].try_into().unwrap())
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
            // Parse .rela.plt entries to collect names in PLT order
            for sec in obj.sections() {
                if let Ok(name) = sec.name() {
                    let lname = name.to_ascii_lowercase();
                    if lname == ".rela.plt" {
                        if let Some((off, sz)) = sec.file_range() {
                            let start = off as usize;
                            let end = start.saturating_add(sz as usize).min(data.len());
                            let bytes = &data[start..end];
                            if bytes.len() >= 24 {
                                for chunk in bytes.chunks_exact(24) {
                                    let r_info = if is_le {
                                        u64::from_le_bytes(chunk[8..16].try_into().unwrap())
                                    } else {
                                        u64::from_be_bytes(chunk[8..16].try_into().unwrap())
                                    };
                                    let sym_idx = (r_info >> 32) as u32;
                                    if let Some(s) = name_for_index(sym_idx) {
                                        imported.push(s);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // If relocation-based collection failed or not present, use fallbacks
    if imported.is_empty() {
        if let Ok(imps) = obj.imports() {
            for imp in imps {
                let name = String::from_utf8_lossy(imp.name()).to_string();
                if !name.is_empty() {
                    imported.push(name);
                }
            }
        }
    }
    if imported.is_empty() {
        use object::ObjectSymbol;
        for sym in obj.dynamic_symbols() {
            if sym.is_undefined() {
                if let Ok(name) = sym.name() {
                    let s = name.to_string();
                    // Filter common book-keeping non-call imports
                    let low = s.to_ascii_lowercase();
                    if s.is_empty() {
                        continue;
                    }
                    if low.starts_with("_itm_")
                        || low == "__gmon_start__"
                        || low == "__cxa_finalize"
                    {
                        continue;
                    }
                    imported.push(s);
                }
            }
        }
    }
    if imported.is_empty() {
        return out;
    }

    // Derive PLT entry size from section size and reloc count (reserved slot at index 0)
    let mut entry_size = 0x10u64; // default
    if !imported.is_empty() {
        let denom = (imported.len() as u64).saturating_add(1);
        if denom > 0 {
            let es = plt_size / denom;
            // Accept common PLT entry sizes across arches
            if matches!(es, 0x10 | 0x18 | 0x20 | 0x30 | 0x40) {
                entry_size = es;
            }
        }
    }
    let mut addr = plt_start.saturating_add(entry_size); // skip PLT0
    let slots = plt_size / entry_size;
    // First slot is reserved
    let usable = slots.saturating_sub(1);
    for (i, name) in imported.into_iter().enumerate() {
        if i as u64 >= usable {
            break;
        }
        if addr >= plt_end {
            break;
        }
        out.push((addr, format!("{}@plt", name)));
        addr = addr.saturating_add(entry_size);
    }
    out
}
