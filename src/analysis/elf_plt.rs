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

    // Locate the stub sections. `.plt` is the classic lazy-binding table whose
    // first slot is reserved (PLT0). A binary built with CET/IBT — the default on
    // current distributions — ALSO has `.plt.sec`, and that is the table calls
    // actually target: `call 2250 <_ZNSaIcED2Ev@plt>` is a `.plt.sec` address.
    // Mapping only `.plt` left every intra-module call resolving to nothing and
    // rendering as an indirect jump through a magic constant.
    //
    // `.plt.sec` has NO reserved slot: entry i pairs with relocation i.
    let mut plt: Option<(u64, u64)> = None;
    let mut plt_sec: Option<(u64, u64)> = None;
    for sec in obj.sections() {
        if let Ok(name) = sec.name() {
            let (addr, size) = (sec.address(), sec.size());
            if size == 0 {
                continue;
            }
            match name {
                ".plt" => plt = plt.or(Some((addr, size))),
                ".plt.sec" => plt_sec = plt_sec.or(Some((addr, size))),
                _ => {}
            }
        }
    }
    if plt.is_none() && plt_sec.is_none() {
        return out;
    }

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

    // `reserved` slots precede the first real entry: one for `.plt`'s PLT0, none
    // for `.plt.sec`.
    let mut emit = |start: u64, size: u64, reserved: u64| {
        let entry_size = plt_entry_size(size, imported.len() as u64, reserved);
        let end = start.saturating_add(size);
        let mut addr = start.saturating_add(entry_size.saturating_mul(reserved));
        let usable = (size / entry_size).saturating_sub(reserved);
        for (i, name) in imported.iter().enumerate() {
            if i as u64 >= usable || addr >= end {
                break;
            }
            out.push((addr, format!("{}@plt", name)));
            addr = addr.saturating_add(entry_size);
        }
    };
    if let Some((start, size)) = plt {
        emit(start, size, 1);
    }
    if let Some((start, size)) = plt_sec {
        emit(start, size, 0);
    }
    out.sort_by_key(|(va, _)| *va);
    out.dedup_by_key(|(va, _)| *va);
    out
}

/// Stub size for a table of `size` bytes holding `count` entries after `reserved`
/// leading slots. Derived rather than assumed, then sanity-checked against the
/// sizes real linkers emit; anything else falls back to the x86-64 default.
fn plt_entry_size(size: u64, count: u64, reserved: u64) -> u64 {
    let denom = count.saturating_add(reserved);
    if denom > 0 {
        let es = size / denom;
        if matches!(es, 0x10 | 0x18 | 0x20 | 0x30 | 0x40) {
            return es;
        }
    }
    0x10
}

#[cfg(test)]
mod tests {
    use super::*;

    const CET_SAMPLE: &str = "samples/containers/hello-cpp-g++-O0";

    /// A binary built with CET/IBT (the default on current distros) has BOTH a
    /// `.plt` of lazy-binding stubs and a `.plt.sec` of the entries calls actually
    /// target. Mapping only `.plt` means every intra-module call resolves to
    /// nothing and renders as an indirect jump through a magic constant.
    #[test]
    fn plt_sec_entries_are_mapped_because_that_is_what_calls_target() {
        let Ok(data) = std::fs::read(CET_SAMPLE) else {
            panic!("missing sample {CET_SAMPLE}");
        };
        let map = elf_plt_map(&data);
        // `objdump -d` shows `call 2250 <_ZNSaIcED2Ev@plt>`: the first `.plt.sec`
        // entry, at the section start with NO reserved slot 0.
        let at_2250 = map.iter().find(|(va, _)| *va == 0x2250);
        assert!(
            at_2250.is_some(),
            "no name for the .plt.sec entry at 0x2250 that calls actually target; \
             mapped addresses were {:?}",
            map.iter().map(|(v, _)| format!("{v:#x}")).take(12).collect::<Vec<_>>()
        );
        assert_eq!(at_2250.unwrap().1, "_ZNSaIcED2Ev@plt");
    }

    /// The `.plt` entries stay mapped too — a binary without `.plt.sec` still
    /// calls them directly, and nothing should regress for those.
    #[test]
    fn plt_entries_remain_mapped() {
        let Ok(data) = std::fs::read(CET_SAMPLE) else {
            panic!("missing sample {CET_SAMPLE}");
        };
        let map = elf_plt_map(&data);
        assert!(
            map.iter().any(|(va, _)| (0x2020..0x2240).contains(va)),
            "expected .plt entries in 0x2020..0x2240 to still be mapped"
        );
    }

    /// Every mapped address must be distinct: `.plt` and `.plt.sec` describe the
    /// same imports at different addresses, and a duplicate key would let one
    /// silently shadow the other in the caller's map.
    #[test]
    fn mapped_addresses_are_unique() {
        let Ok(data) = std::fs::read(CET_SAMPLE) else {
            panic!("missing sample {CET_SAMPLE}");
        };
        let map = elf_plt_map(&data);
        let mut seen = std::collections::HashSet::new();
        for (va, name) in &map {
            assert!(seen.insert(*va), "duplicate PLT address {va:#x} ({name})");
        }
    }
}
