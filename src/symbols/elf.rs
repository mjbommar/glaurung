//! ELF (Executable and Linkable Format) symbol extraction

use super::types::{BudgetCaps, SymbolSummary};
use crate::symbols::analysis::suspicious;

fn read_u16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}
fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}
fn read_u64(data: &[u8], off: usize, le: bool) -> Option<u64> {
    let b = data.get(off..off + 8)?;
    Some(if le {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

#[derive(Clone, Copy)]
struct Shdr {
    name_off: u32,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
    sh_flags: u64,
}

pub fn summarize_elf(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    if data.len() < 0x40 {
        return SymbolSummary::default();
    }
    if &data[0..4] != b"\x7FELF" {
        return SymbolSummary::default();
    }
    let class = data[4]; // 1=32, 2=64
    let is_le = match data[5] {
        1 => true,
        2 => false,
        _ => true,
    };
    let e_type = read_u16(data, 16, is_le).unwrap_or(0);
    let e_phoff = if class == 2 {
        read_u64(data, 32, is_le).unwrap_or(0)
    } else {
        read_u32(data, 28, is_le).unwrap_or(0) as u64
    };
    let e_shoff = if class == 2 {
        read_u64(data, 40, is_le).unwrap_or(0)
    } else {
        read_u32(data, 32, is_le).unwrap_or(0) as u64
    };
    let e_phentsize = read_u16(data, 54, is_le).unwrap_or(0);
    let e_phnum = read_u16(data, 56, is_le).unwrap_or(0);
    let e_shentsize = read_u16(data, 58, is_le).unwrap_or(0);
    let e_shnum = read_u16(data, 60, is_le).unwrap_or(0);
    let e_shstrndx = read_u16(data, 62, is_le).unwrap_or(0);

    // Section headers
    let mut shdrs: Vec<Shdr> = Vec::new();
    let shoff = e_shoff as usize;
    let shentsize = e_shentsize as usize;
    if shentsize == 0 || shoff == 0 || e_shnum == 0 {
        return SymbolSummary::default();
    }
    if shoff + (shentsize * (e_shnum as usize)) > data.len() {
        return SymbolSummary::default();
    }
    for i in 0..(e_shnum as usize) {
        let off = shoff + i * shentsize;
        // Parse per class
        let (name_off, sh_type, sh_flags, sh_offset, sh_size, sh_link, sh_entsize) = if class == 2 {
            (
                read_u32(data, off, is_le).unwrap_or(0),
                read_u32(data, off + 4, is_le).unwrap_or(0),
                read_u64(data, off + 8, is_le).unwrap_or(0),
                read_u64(data, off + 24, is_le).unwrap_or(0),
                read_u64(data, off + 32, is_le).unwrap_or(0),
                read_u32(data, off + 40, is_le).unwrap_or(0),
                read_u64(data, off + 56, is_le).unwrap_or(0),
            )
        } else {
            (
                read_u32(data, off, is_le).unwrap_or(0),
                read_u32(data, off + 4, is_le).unwrap_or(0),
                read_u32(data, off + 8, is_le).unwrap_or(0) as u64,
                read_u32(data, off + 16, is_le).unwrap_or(0) as u64,
                read_u32(data, off + 20, is_le).unwrap_or(0) as u64,
                read_u32(data, off + 24, is_le).unwrap_or(0),
                read_u32(data, off + 36, is_le).unwrap_or(0) as u64,
            )
        };
        shdrs.push(Shdr {
            name_off,
            sh_type,
            sh_offset,
            sh_size,
            sh_link,
            sh_entsize,
            sh_flags,
        });
    }

    // Strings for section names
    let mut debug_info_present = false;
    let mut has_debuglink = false; // .gnu_debuglink indicates external debug file
    let mut has_build_id = false; // .note.gnu.build-id present
    if (e_shstrndx as usize) < shdrs.len() {
        let sh = shdrs[e_shstrndx as usize];
        let base = sh.sh_offset as usize;
        let end = base.saturating_add(sh.sh_size as usize).min(data.len());
        let shstr = if base < data.len() {
            &data[base..end]
        } else {
            &[]
        };
        for s in &shdrs {
            let name_off = s.name_off as usize;
            if name_off < shstr.len() {
                // read cstr
                let mut idx = name_off;
                while idx < shstr.len() && shstr[idx] != 0 {
                    idx += 1;
                }
                if idx <= shstr.len() {
                    if let Ok(n) = std::str::from_utf8(&shstr[name_off..idx]) {
                        if n.starts_with(".debug") {
                            debug_info_present = true;
                        }
                        if n == ".gnu_debuglink" {
                            has_debuglink = true;
                        }
                        if n == ".note.gnu.build-id" {
                            has_build_id = true;
                        }
                    }
                }
            }
        }
    }

    // TLS used if any section has SHF_TLS flag (0x400)
    let tls_used = shdrs.iter().any(|s| (s.sh_flags & 0x400) != 0);

    // Program headers: detect NX via PT_GNU_STACK (non-executable), and RELRO via PT_GNU_RELRO
    let mut nx: Option<bool> = None;
    let mut relro: Option<bool> = None;
    if e_phoff != 0 && e_phnum > 0 && e_phentsize > 0 {
        let phoff = e_phoff as usize;
        let phentsize = e_phentsize as usize;
        if phoff + phentsize.saturating_mul(e_phnum as usize) <= data.len() {
            for i in 0..(e_phnum as usize) {
                let off = phoff + i * phentsize;
                let p_type = read_u32(data, off, is_le).unwrap_or(0);
                // flags offset differs by class
                let p_flags = if class == 2 {
                    read_u32(data, off + 4, is_le).unwrap_or(0)
                } else {
                    read_u32(data, off + 24, is_le).unwrap_or(0)
                };
                // PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552
                if p_type == 0x6474_e551 {
                    // NX when PF_X (execute) is not set on GNU_STACK
                    let exec = (p_flags & 0x1) != 0; // PF_X
                    nx = Some(!exec);
                } else if p_type == 0x6474_e552 {
                    relro = Some(true);
                }
            }
            if relro.is_none() {
                relro = Some(false);
            }
        }
    }

    // Count symbols
    let mut dynsym_count: u32 = 0;
    let mut symtab_count: u32 = 0;
    for s in &shdrs {
        // SHT_DYNSYM = 11, SHT_SYMTAB = 2
        if (s.sh_type == 11 || s.sh_type == 2) && s.sh_entsize > 0 {
            let cnt = (s.sh_size / s.sh_entsize) as u32;
            if s.sh_type == 11 {
                dynsym_count = dynsym_count.saturating_add(cnt);
            }
            if s.sh_type == 2 {
                symtab_count = symtab_count.saturating_add(cnt);
            }
        }
    }
    // Stripped heuristic refinement:
    // - Not stripped if .symtab present or .debug* present
    // - Likely stripped if only .dynsym exists and .gnu_debuglink or build-id present
    // - Otherwise, treat no .symtab as stripped
    let has_symtab = symtab_count > 0;
    let has_dynsym = dynsym_count > 0;
    let stripped = decide_stripped(
        has_symtab,
        has_dynsym,
        debug_info_present,
        has_debuglink,
        has_build_id,
    );

    // DT_NEEDED from SHT_DYNAMIC
    let mut libs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let start = std::time::Instant::now();
    let time_ok = |start: &std::time::Instant, caps: &BudgetCaps| {
        (start.elapsed().as_millis() as u64) <= caps.time_guard_ms
    };
    let mut rpaths: Vec<String> = Vec::new();
    let mut runpaths: Vec<String> = Vec::new();
    for s in &shdrs {
        if s.sh_type != 6 {
            continue;
        } // SHT_DYNAMIC
        if s.sh_size == 0 || s.sh_entsize == 0 {
            continue;
        }
        // Find linked string table
        let strtab = match shdrs.get(s.sh_link as usize) {
            Some(x) => x,
            None => continue,
        };
        let dyn_base = s.sh_offset as usize;
        let dyn_end = dyn_base.saturating_add(s.sh_size as usize).min(data.len());
        let str_base = strtab.sh_offset as usize;
        let str_end = str_base
            .saturating_add(strtab.sh_size as usize)
            .min(data.len());
        if dyn_base >= data.len() || str_base >= data.len() {
            continue;
        }
        let entsize = if class == 2 { 16 } else { 8 };
        let mut off = dyn_base;
        while off + entsize <= dyn_end {
            if !time_ok(&start, caps) {
                break;
            }
            let d_tag = if class == 2 {
                read_u64(data, off, is_le).unwrap_or(0) as i64
            } else {
                read_u32(data, off, is_le).unwrap_or(0) as i32 as i64
            };
            let d_val = if class == 2 {
                read_u64(data, off + 8, is_le).unwrap_or(0)
            } else {
                read_u32(data, off + 4, is_le).unwrap_or(0) as u64
            };
            if d_tag == 0 {
                break;
            } // DT_NULL
            if d_tag == 1 {
                // DT_NEEDED
                let so = str_base.saturating_add(d_val as usize);
                if so < data.len() {
                    let max = str_end.min(data.len());
                    let mut idx = so;
                    while idx < max && idx - so < 512 {
                        if data[idx] == 0 {
                            break;
                        }
                        idx += 1;
                    }
                    if idx <= max {
                        if let Ok(s) = std::str::from_utf8(&data[so..idx]) {
                            libs.insert(s.to_string());
                            if libs.len() as u32 >= caps.max_libs {
                                break;
                            }
                        }
                    }
                }
            } else if d_tag == 15 || d_tag == 29 {
                // DT_RPATH (15) or DT_RUNPATH (29)
                let so = str_base.saturating_add(d_val as usize);
                if so < data.len() {
                    let max = str_end.min(data.len());
                    let mut idx = so;
                    while idx < max && idx - so < 1024 {
                        if data[idx] == 0 {
                            break;
                        }
                        idx += 1;
                    }
                    if idx <= max {
                        if let Ok(s) = std::str::from_utf8(&data[so..idx]) {
                            if d_tag == 15 {
                                rpaths.push(s.to_string());
                            } else {
                                runpaths.push(s.to_string());
                            }
                        }
                    }
                }
            }
            off += entsize;
        }
        if libs.len() as u32 >= caps.max_libs {
            break;
        }
    }

    // Attempt to collect undefined dynamic symbol names (imports) and defined (exports)
    let mut import_names: Vec<String> = Vec::new();
    let mut export_names: Vec<String> = Vec::new();
    for s in &shdrs {
        if s.sh_type != 11 {
            continue;
        } // SHT_DYNSYM
        if s.sh_size == 0 || s.sh_entsize == 0 {
            continue;
        }
        let strtab = match shdrs.get(s.sh_link as usize) {
            Some(x) => x,
            None => continue,
        };
        let sym_base = s.sh_offset as usize;
        let sym_end = sym_base.saturating_add(s.sh_size as usize).min(data.len());
        let str_base = strtab.sh_offset as usize;
        let str_end = str_base
            .saturating_add(strtab.sh_size as usize)
            .min(data.len());
        let esize = s.sh_entsize as usize;
        let mut off = sym_base;
        while off + esize <= sym_end {
            if !time_ok(&start, caps) {
                break;
            }
            let st_name = read_u32(data, off, is_le).unwrap_or(0) as usize;
            let is_undef = if class == 2 {
                let shndx = read_u16(data, off + 6, is_le).unwrap_or(0);
                shndx == 0
            } else {
                let shndx = read_u16(data, off + 14, is_le).unwrap_or(0);
                shndx == 0
            };
            if st_name != 0 {
                let so = str_base.saturating_add(st_name);
                if so < data.len() {
                    let max = str_end.min(data.len());
                    let mut i = so;
                    while i < max && i - so < 512 {
                        if data[i] == 0 {
                            break;
                        }
                        i += 1;
                    }
                    if i <= max {
                        if let Ok(sname) = std::str::from_utf8(&data[so..i]) {
                            if is_undef {
                                if (import_names.len() as u32) < caps.max_imports {
                                    import_names.push(sname.to_string());
                                }
                            } else if (export_names.len() as u32) < caps.max_exports {
                                export_names.push(sname.to_string());
                            }
                        }
                    }
                }
            }
            off += esize;
        }
        if import_names.len() as u32 >= caps.max_imports {
            break;
        }
    }

    let suspicious_list = if import_names.is_empty() {
        None
    } else {
        let v = suspicious::detect_suspicious_imports(&import_names, 128);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    // PIE: ET_DYN commonly indicates PIE for executables
    let pie = Some(e_type == 3);
    let aslr = pie; // Effective ASLR when PIE is enabled
                    // Demangle names when possible
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

    SymbolSummary {
        imports_count: (import_names.len() as u32).min(caps.max_imports),
        exports_count: (export_names.len() as u32).min(caps.max_exports),
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
        tls_callback_count: None,
        tls_callback_vas: None,
        debug_info_present,
        pdb_path: None,
        suspicious_imports: suspicious_list,
        entry_section: None,
        nx,
        aslr,
        relro,
        pie,
        cfg: None,
        relocations_present: None,
        rpaths: if rpaths.is_empty() {
            None
        } else {
            Some(rpaths)
        },
        runpaths: if runpaths.is_empty() {
            None
        } else {
            Some(runpaths)
        },
    }
}

/// Decide stripped status based on symbol/debug indicators.
fn decide_stripped(
    has_symtab: bool,
    has_dynsym: bool,
    debug_info_present: bool,
    has_debuglink: bool,
    has_build_id: bool,
) -> bool {
    if has_symtab {
        return false;
    }
    if debug_info_present {
        return false;
    }
    if has_dynsym && (has_debuglink || has_build_id) {
        return true;
    }
    if has_dynsym && !has_symtab {
        return true;
    }
    // Default conservative: treat as stripped when we lack clear evidence otherwise.
    true
}

#[cfg(test)]
mod tests {
    use super::decide_stripped;

    #[test]
    fn stripped_heuristic_with_symtab_is_false() {
        assert!(!decide_stripped(true, true, false, false, false));
        assert!(!decide_stripped(true, false, false, false, false));
    }

    #[test]
    fn debug_info_means_not_stripped() {
        assert!(!decide_stripped(false, true, true, false, false));
        assert!(!decide_stripped(false, false, true, false, false));
    }

    #[test]
    fn dynsym_only_with_debuglink_or_build_id_is_stripped() {
        assert!(decide_stripped(false, true, false, true, false));
        assert!(decide_stripped(false, true, false, false, true));
    }

    #[test]
    fn dynsym_only_without_symtab_is_stripped() {
        assert!(decide_stripped(false, true, false, false, false));
    }

    #[test]
    fn no_syms_defaults_to_stripped() {
        assert!(decide_stripped(false, false, false, false, false));
    }
}
