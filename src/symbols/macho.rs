//! Mach-O symbol extraction

use super::types::{BudgetCaps, SymbolSummary};
use crate::symbols::analysis::suspicious;

const MH_MAGIC: u32 = 0xfeedface;
const MH_CIGAM: u32 = 0xcefaedfe; // swapped
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM_64: u32 = 0xcffaedfe; // swapped
const FAT_MAGIC: u32 = 0xcafebabe; // big-endian
const FAT_CIGAM: u32 = 0xbebafeca; // little-endian
const FAT_MAGIC_64: u32 = 0xcafebabf; // big-endian 64
const FAT_CIGAM_64: u32 = 0xbfbafeca; // little-endian 64

fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn cmd_kind(cmd: u32) -> u32 {
    cmd & 0x7fff_ffff
}

pub fn summarize_macho(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    if data.len() < 32 {
        return SymbolSummary::default();
    }
    let magic_raw = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    // Detect FAT and bail (bounded header buffer not enough to parse inner slice safely)
    if matches!(
        magic_raw,
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
    ) {
        return SymbolSummary::default();
    }
    // Determine 32/64 and endianness
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (is_64, le) = match (magic_le, magic_raw) {
        (MH_MAGIC_64, _) => (true, true),
        (MH_MAGIC, _) => (false, true),
        (_, MH_CIGAM_64) => (true, false),
        (_, MH_CIGAM) => (false, false),
        _ => return SymbolSummary::default(),
    };

    // Mach-O header fields
    // 32-bit header: magic,u32 cputype,u32 cpusubtype,u32 filetype,u32 ncmds,u32 sizeofcmds,u32 flags
    // 64-bit adds reserved u32
    let ncmds = read_u32(data, 16, le).unwrap_or(0);
    let sizeofcmds = read_u32(data, 20, le).unwrap_or(0) as usize;
    let mut off: usize = if is_64 { 32 } else { 28 };
    let lc_end = off.saturating_add(sizeofcmds).min(data.len());

    let start = std::time::Instant::now();
    let time_ok = |start: &std::time::Instant, caps: &BudgetCaps| {
        (start.elapsed().as_millis() as u64) <= caps.time_guard_ms
    };

    let mut imports_count: u32 = 0;
    let mut exports_count: u32 = 0;
    let mut import_names: Vec<String> = Vec::new();
    let mut export_names: Vec<String> = Vec::new();
    let mut libs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stripped = false;
    let mut saw_symtab = false;
    // Track symtab and dysymtab for name extraction
    let mut symtab_symoff: u32 = 0;
    let mut symtab_nsyms: u32 = 0;
    let mut symtab_stroff: u32 = 0;
    let mut symtab_strsize: u32 = 0;
    let mut iextdefsym: u32 = 0;
    let mut nextdefsym: u32 = 0;
    let mut iundefsym: u32 = 0;
    let mut nundefsym: u32 = 0;

    for _i in 0..ncmds {
        if !time_ok(&start, caps) || off + 8 > lc_end {
            break;
        }
        let cmd = read_u32(data, off, le).unwrap_or(0);
        let cmdsize = read_u32(data, off + 4, le).unwrap_or(0) as usize;
        if cmdsize < 8 || off + cmdsize > lc_end {
            break;
        }
        match cmd_kind(cmd) {
            0x2 /* LC_SYMTAB */ => {
                // symoff at +8, nsyms at +12, stroff at +16, strsize at +20
                if off + 24 <= lc_end {
                    symtab_symoff = read_u32(data, off + 8, le).unwrap_or(0);
                    symtab_nsyms = read_u32(data, off + 12, le).unwrap_or(0);
                    symtab_stroff = read_u32(data, off + 16, le).unwrap_or(0);
                    symtab_strsize = read_u32(data, off + 20, le).unwrap_or(0);
                    saw_symtab = true;
                    stripped = symtab_nsyms == 0;
                }
            }
            0xb /* LC_DYSYMTAB */ => {
                // iextdefsym at +16, nextdefsym at +20, iundefsym at +24, nundefsym at +28
                if off + 32 <= lc_end {
                    iextdefsym = read_u32(data, off + 16, le).unwrap_or(0);
                    nextdefsym = read_u32(data, off + 20, le).unwrap_or(0);
                    iundefsym = read_u32(data, off + 24, le).unwrap_or(0);
                    nundefsym = read_u32(data, off + 28, le).unwrap_or(0);
                    exports_count = nextdefsym.min(caps.max_exports);
                    imports_count = nundefsym.min(caps.max_imports);
                }
            }
            0xc /* LC_LOAD_DYLIB */
            | 0x18 /* LC_LOAD_WEAK_DYLIB */
            | 0x1f /* LC_REEXPORT_DYLIB */
            | 0x23 /* LC_LOAD_UPWARD_DYLIB */ => {
                // name offset at +8 from start
                if off + 8 <= lc_end {
                    let name_off = read_u32(data, off + 8, le).unwrap_or(0) as usize;
                    let ns = off.saturating_add(name_off);
                    if ns < lc_end {
                        let end = (off + cmdsize).min(lc_end);
                        let mut i = ns;
                        while i < end && i - ns < 512 { if data[i] == 0 { break; } i += 1; }
                        if i <= end {
                            if let Ok(s) = std::str::from_utf8(&data[ns..i]) {
                                libs.insert(s.to_ascii_lowercase());
                            }
                        }
                    }
                }
                if libs.len() as u32 >= caps.max_libs { break; }
            }
            _ => {}
        }
        off += cmdsize;
        if !time_ok(&start, caps) {
            break;
        }
    }
    if !saw_symtab {
        stripped = true;
    }
    // Name extraction for imports/exports where possible
    if saw_symtab
        && symtab_nsyms > 0
        && (symtab_symoff as usize) < data.len()
        && (symtab_stroff as usize) < data.len()
    {
        let esize = if is_64 { 16 } else { 12 };
        let sym_base = symtab_symoff as usize;
        let sym_end = sym_base
            .saturating_add((symtab_nsyms as usize).saturating_mul(esize))
            .min(data.len());
        let str_base = symtab_stroff as usize;
        let str_end = str_base
            .saturating_add(symtab_strsize as usize)
            .min(data.len());
        // Helper to read name by index
        let read_name = |idx: u32| -> Option<String> {
            let i = idx as usize;
            let off = sym_base + i.saturating_mul(esize);
            if off + esize > sym_end {
                return None;
            }
            let n_strx = read_u32(data, off, le).unwrap_or(0) as usize;
            if n_strx == 0 {
                return None;
            }
            let so = str_base.saturating_add(n_strx);
            if so >= data.len() {
                return None;
            }
            let max = str_end.min(data.len());
            let mut j = so;
            while j < max && j - so < 512 {
                if data[j] == 0 {
                    break;
                }
                j += 1;
            }
            if j <= max {
                if let Ok(s) = std::str::from_utf8(&data[so..j]) {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
            None
        };
        // Imports: iundefsym .. iundefsym+nundefsym
        let import_max = std::cmp::min(nundefsym, caps.max_imports);
        for k in 0..import_max {
            if !time_ok(&start, caps) {
                break;
            }
            let idx = iundefsym.saturating_add(k);
            if let Some(name) = read_name(idx) {
                import_names.push(name);
            }
        }
        // Exports: iextdefsym .. iextdefsym+nextdefsym
        let export_max = std::cmp::min(nextdefsym, caps.max_exports);
        for k in 0..export_max {
            if !time_ok(&start, caps) {
                break;
            }
            let idx = iextdefsym.saturating_add(k);
            if let Some(name) = read_name(idx) {
                export_names.push(name);
            }
        }
    }
    // Suspicious imports (use collected import names if any)
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
        tls_used: false,
        tls_callback_count: None,
        tls_callback_vas: None,
        debug_info_present: false,
        suspicious_imports: suspicious_list,
        entry_section: None,
        nx: None,
        aslr: None,
        relro: None,
        pie: None,
        cfg: None,
        relocations_present: None,
        rpaths: None,
        runpaths: None,
    }
}
