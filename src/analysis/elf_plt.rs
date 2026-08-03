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

    // Collect imported names in `.rel(a).plt` order by raw parsing.
    //
    // Both ELF classes are walked. Gating this on ELF64 left every 32-bit target
    // — ARM32 and i386, which use 8-byte `Elf32_Rel` in a section named
    // `.rel.plt` — falling through to the unordered `obj.imports()` fallback
    // below, which pairs stub `i` with whatever import happens to sit at index
    // `i` in the dynamic symbol table. That is not a missing name, it is a
    // CONFIDENTLY WRONG one: a call to `sum_arg6@plt` rendered as
    // `_ITM_deregisterTMCloneTable(...)`.
    use object::ObjectSection;
    let class = data.get(4).copied().unwrap_or(2); // 1=ELF32, 2=ELF64
    let is_le = data.get(5).copied().unwrap_or(1) == 1;
    let mut imported: Vec<String> = Vec::new();
    //: GOT slot address -> imported name, from the same relocations. ARM needs
    //: the slot, not the order — see `arm_plt_map`.
    let mut got_slots: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    {
        // `Elf32_Sym` is 16 bytes and `Elf64_Sym` 24; `st_name` is the leading
        // u32 in both.
        let sym_entsize = if class == 2 { 24usize } else { 16usize };
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
            let count = dynsym.len() / sym_entsize;
            // Helper for name
            let name_for_index = |idx: u32| -> Option<String> {
                let i = idx as usize;
                if i >= count {
                    return None;
                }
                let base = i * sym_entsize;
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
            // Parse .rel(a).plt entries to collect names in PLT order.
            for sec in obj.sections() {
                let Ok(name) = sec.name() else { continue };
                let lname = name.to_ascii_lowercase();
                let addend = match lname.as_str() {
                    ".rela.plt" => true,
                    ".rel.plt" => false,
                    _ => continue,
                };
                // Elf32_Rel 8, Elf32_Rela 12, Elf64_Rel 16, Elf64_Rela 24.
                let rel_entsize = match (class, addend) {
                    (2, true) => 24usize,
                    (2, false) => 16,
                    (_, true) => 12,
                    (_, false) => 8,
                };
                let Some((off, sz)) = sec.file_range() else {
                    continue;
                };
                let start = off as usize;
                let end = start.saturating_add(sz as usize).min(data.len());
                if start >= end {
                    continue;
                }
                for chunk in data[start..end].chunks_exact(rel_entsize) {
                    let r_offset = if class == 2 {
                        if is_le {
                            u64::from_le_bytes(chunk[0..8].try_into().unwrap())
                        } else {
                            u64::from_be_bytes(chunk[0..8].try_into().unwrap())
                        }
                    } else if is_le {
                        u64::from(u32::from_le_bytes(chunk[0..4].try_into().unwrap()))
                    } else {
                        u64::from(u32::from_be_bytes(chunk[0..4].try_into().unwrap()))
                    };
                    // `r_info` follows `r_offset`; the symbol index is its high
                    // 24 bits on ELF32 and its high 32 on ELF64.
                    let sym_idx = if class == 2 {
                        let r_info = if is_le {
                            u64::from_le_bytes(chunk[8..16].try_into().unwrap())
                        } else {
                            u64::from_be_bytes(chunk[8..16].try_into().unwrap())
                        };
                        (r_info >> 32) as u32
                    } else {
                        let r_info = if is_le {
                            u32::from_le_bytes(chunk[4..8].try_into().unwrap())
                        } else {
                            u32::from_be_bytes(chunk[4..8].try_into().unwrap())
                        };
                        r_info >> 8
                    };
                    if let Some(s) = name_for_index(sym_idx) {
                        got_slots.insert(r_offset, s.clone());
                        imported.push(s);
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

    // A header may precede the first real entry: `.plt` has one, `.plt.sec` has
    // none. Its size is *derived*, not assumed, because it is not one entry on
    // every architecture — x86-64's PLT0 is 16 bytes and AArch64's is 32, so
    // "skip one entry" silently shifted every AArch64 name onto its neighbour's
    // stub and labelled `fprintf` calls `__deregister_frame_info`.
    //
    // `size - count * entry_size` recovers the header directly from the table
    // the linker actually emitted. It is trusted only when it comes out as a
    // whole number of entries; otherwise fall back to the caller's assumption
    // rather than invent a layout.
    let arch = obj.architecture();
    // ARM32 stubs are decoded, never counted. See `arm_plt_map`.
    if arch == object::Architecture::Arm {
        let mut arm = arm_plt_map(data, &obj, &got_slots);
        if !arm.is_empty() {
            arm.sort_by_key(|(va, _)| *va);
            arm.dedup_by_key(|(va, _)| *va);
            return arm;
        }
    }
    let mut emit = |start: u64, size: u64, reserved: u64| {
        let count = imported.len() as u64;
        let (entry_size, header) = plt_geometry(arch, size, count, reserved);
        let end = start.saturating_add(size);
        let mut addr = start.saturating_add(header);
        let usable = (size / entry_size).saturating_sub(header / entry_size);
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

/// The ARM32 PLT, decoded stub by stub rather than counted.
///
/// Counting cannot work here. A `.plt` produced for mixed ARM/Thumb code
/// interleaves 12-byte ARM stubs with 4-byte Thumb-to-ARM veneers
/// (`bx pc; b .-4`), so the table is NOT a uniform array and any
/// "header + n * entry" arithmetic silently shifts part of the table onto its
/// neighbours' addresses. The checked-in `hello-armhf-gcc` has exactly this
/// shape — 20-byte header, five stubs, a veneer, then two more stubs — and a
/// uniform reading mislabels every entry before the veneer.
///
/// Each stub instead states its own answer. The BFD ARM stub is
///
/// ```text
///   add r12, pc,  #a      ; r12 = stub+8 + a
///   add r12, r12, #b
///   ldr pc, [r12, #c]!    ; the GOT slot for this import
/// ```
///
/// so `stub + 8 + a + b + c` is the relocation's `r_offset`, and the name comes
/// from the relocation rather than from a position. `a` and `b` are ARM modified
/// immediates and are expanded as such.
fn arm_plt_map(
    data: &[u8],
    obj: &object::read::File,
    got_slots: &std::collections::HashMap<u64, String>,
) -> Vec<(u64, String)> {
    use object::ObjectSection;
    /// ARM data-processing immediate: an 8-bit value rotated right by twice the
    /// 4-bit rotate field (ARM DDI 0406C A5.2.4).
    fn expand_imm12(imm12: u32) -> u64 {
        u64::from((imm12 & 0xff).rotate_right(2 * ((imm12 >> 8) & 0xf)))
    }
    /// The `bx pc; b .-4` Thumb-to-ARM veneer, as a little-endian word. It is
    /// what a Thumb caller branches to, so it must carry the name of the ARM
    /// stub that follows it — otherwise every Thumb tail call to an imported
    /// function renders as a bare `sub_<addr>` and fails to link.
    const THUMB_VENEER: u32 = 0xe7fd_4778;

    let mut out: Vec<(u64, String)> = Vec::new();
    let mut veneers: Vec<u64> = Vec::new();
    for section in obj.sections() {
        if !matches!(section.name(), Ok(".plt" | ".plt.sec" | ".iplt")) {
            continue;
        }
        let Some((file_start, file_size)) = section.file_range() else {
            continue;
        };
        let start = file_start as usize;
        let end = start.saturating_add(file_size as usize).min(data.len());
        let Some(bytes) = data.get(start..end) else {
            continue;
        };
        let base = section.address();
        let word = |offset: usize| -> Option<u32> {
            bytes
                .get(offset..offset + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        };
        let mut offset = 0usize;
        while offset + 4 <= bytes.len() {
            let va = base.saturating_add(offset as u64);
            let (Some(w0), Some(w1), Some(w2)) = (word(offset), word(offset + 4), word(offset + 8))
            else {
                if word(offset) == Some(THUMB_VENEER) {
                    veneers.push(va);
                }
                offset += 4;
                continue;
            };
            let is_stub = w0 & 0xffff_f000 == 0xe28f_c000   // add r12, pc,  #a
                && w1 & 0xffff_f000 == 0xe28c_c000          // add r12, r12, #b
                && w2 & 0xffff_f000 == 0xe5bc_f000; // ldr pc, [r12, #c]!
            if is_stub {
                let slot = va
                    .wrapping_add(8)
                    .wrapping_add(expand_imm12(w0 & 0xfff))
                    .wrapping_add(expand_imm12(w1 & 0xfff))
                    .wrapping_add(u64::from(w2 & 0xfff));
                if let Some(name) = got_slots.get(&slot) {
                    out.push((va, format!("{name}@plt")));
                }
                offset += 12;
                continue;
            }
            if w0 == THUMB_VENEER {
                veneers.push(va);
            }
            offset += 4;
        }
    }
    let named: std::collections::HashMap<u64, String> = out.iter().cloned().collect();
    for va in veneers {
        if let Some(name) = named.get(&va.saturating_add(4)) {
            out.push((va, name.clone()));
        }
    }
    out
}

/// `(entry_size, header_size)` for a `.plt`-like table of `size` bytes holding
/// `count` stubs after a reserved header.
///
/// A header may precede the first real entry: `.plt` has one, `.plt.sec` has
/// none. Its size is *derived*, not assumed, because "one entry" is wrong on
/// most architectures — x86-64's PLT0 is 16 bytes, AArch64's 32, and ARM32's 20
/// bytes in front of 12-byte stubs, a combination the earlier "header must be a
/// whole number of entries" rule could not express at all.
///
/// The stub size is taken from the architecture rather than divided out of the
/// table, because `size / (count + reserved)` is not invertible: an ARM32 table
/// of 4 stubs is 68 bytes, and 68 - 4*16 = 4 is a perfectly plausible-looking
/// header for a 16-byte stub. Each candidate is then CHECKED against the table
/// the linker actually emitted, and only a candidate that accounts for every
/// byte is used; otherwise the caller's `reserved` assumption stands.
fn plt_geometry(
    arch: object::Architecture,
    size: u64,
    count: u64,
    reserved: u64,
) -> (u64 /* entry */, u64 /* header */) {
    use object::Architecture as A;
    // In preference order. ARM32 is 12 bytes under BFD ld and 16 under lld, so
    // both are offered and the table's own size picks.
    let candidates: &[u64] = match arch {
        A::Arm => &[0xc, 0x10],
        A::Aarch64 => &[0x10],
        A::X86_64 | A::I386 => &[0x10],
        _ => &[0x10, 0xc, 0x20, 0x8],
    };
    for &entry in candidates {
        let Some(header) = size.checked_sub(count.saturating_mul(entry)) else {
            continue;
        };
        // A header is a whole number of words and never more than a couple of
        // stubs; anything else means this entry size does not describe the table.
        if header % 4 == 0 && header <= entry.saturating_mul(4) {
            return (entry, header);
        }
    }
    let entry = candidates[0];
    (entry, entry.saturating_mul(reserved))
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
            map.iter()
                .map(|(v, _)| format!("{v:#x}"))
                .take(12)
                .collect::<Vec<_>>()
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

    /// AArch64's PLT header is 32 bytes, not one entry.
    ///
    /// x86-64 reserves a single 16-byte PLT0 slot, so "skip one entry" happens
    /// to be right there. AArch64 reserves 32 bytes — two entries' worth — and
    /// skipping only one shifts every name by one slot, so each call site is
    /// labelled with its *neighbour's* import. That is worse than an unresolved
    /// call: a stripped AArch64 `getconf` rendered `fprintf(...)` as
    /// `__deregister_frame_info(...)` and `exit(...)` as `__libc_start_main(...)`,
    /// confidently and wrongly.
    ///
    /// Ground truth is objdump's own `<name@plt>` labels for this fixture.
    #[test]
    fn aarch64_plt_header_is_not_mistaken_for_an_entry() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/arm64/c2_demo-arm64-gcc");
        if !path.exists() {
            eprintln!("skipping AArch64 PLT test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let map: std::collections::HashMap<u64, String> = elf_plt_map(&data).into_iter().collect();

        for (va, want) in [
            (0x810u64, "__libc_start_main@plt"),
            (0x820, "__cxa_finalize@plt"),
            (0x830, "__snprintf_chk@plt"),
            (0x840, "__printf_chk@plt"),
            (0x850, "__stack_chk_fail@plt"),
        ] {
            assert_eq!(
                map.get(&va).map(String::as_str),
                Some(want),
                "PLT entry {va:#x} mislabelled; got {:?}",
                map.get(&va)
            );
        }
        // The 32-byte header holds no import and must not be labelled.
        assert!(
            !map.contains_key(&0x7f0) && !map.contains_key(&0x800),
            "PLT header slots were labelled as imports"
        );
    }

    /// ARM32 is ELF **32**-bit and uses `.rel.plt` (8-byte `Elf32_Rel`), not
    /// `.rela.plt` — and its PLT is a 20-byte header followed by 12-byte stubs.
    ///
    /// Both of those were unhandled: the relocation walk was gated on
    /// `class == 2`, so `imported` came from the unordered `obj.imports()`
    /// fallback, and `plt_entry_size` rejected 12 and fell back to 16. Every
    /// ARM32 PLT call was therefore labelled with an unrelated import — a call
    /// to `sum_arg6@plt` rendered as `_ITM_deregisterTMCloneTable(...)` — or not
    /// labelled at all, and the round-tripped C failed to link.
    ///
    /// Ground truth is objdump's own `<name@plt>` labels for this fixture.
    #[test]
    fn arm32_rel_plt_and_twelve_byte_stubs_are_mapped() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/c2_demo-armhf-gcc");
        if !path.exists() {
            eprintln!("skipping ARM32 PLT test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let map: std::collections::HashMap<u64, String> = elf_plt_map(&data).into_iter().collect();

        for (va, want) in [
            (0x4ecu64, "__libc_start_main@plt"),
            (0x4f8, "__cxa_finalize@plt"),
            (0x504, "__stack_chk_fail@plt"),
            (0x510, "puts@plt"),
            (0x51c, "__gmon_start__@plt"),
            (0x528, "__printf_chk@plt"),
            (0x534, "abort@plt"),
            (0x540, "__snprintf_chk@plt"),
        ] {
            assert_eq!(
                map.get(&va).map(String::as_str),
                Some(want),
                "ARM32 PLT entry {va:#x} mislabelled; got {:?}",
                map.get(&va)
            );
        }
        // The 20-byte header holds no import and must not be labelled.
        assert!(
            !map.contains_key(&0x4d8),
            "the ARM32 PLT header was labelled as an import"
        );
    }

    /// A `.plt` holding Thumb-to-ARM veneers is NOT a uniform array.
    ///
    /// `hello-armhf-gcc` interleaves a 4-byte `bx pc; b .-4` veneer between the
    /// fifth and sixth 12-byte stubs, so "header + n * entry" arithmetic puts
    /// every entry after the header 4 bytes late and labels each stub with its
    /// neighbour's import. Ground truth is objdump's own `<name@plt>` labels.
    #[test]
    fn arm32_thumb_veneers_do_not_shift_the_table() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc");
        if !path.exists() {
            eprintln!("skipping ARM32 veneer test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        let map: std::collections::HashMap<u64, String> = elf_plt_map(&data).into_iter().collect();

        for (va, want) in [
            (0x414u64, "__libc_start_main@plt"),
            (0x420, "__cxa_finalize@plt"),
            (0x42c, "puts@plt"),
            (0x438, "__gmon_start__@plt"),
            (0x444, "strlen@plt"),
            // The veneer at 0x450 is what a THUMB caller branches to, and it
            // reaches the stub at 0x454 — it carries that stub's name.
            (0x450, "__printf_chk@plt"),
            (0x454, "__printf_chk@plt"),
            (0x460, "abort@plt"),
        ] {
            assert_eq!(
                map.get(&va).map(String::as_str),
                Some(want),
                "PLT entry {va:#x} mislabelled; got {:?}",
                map.get(&va)
            );
        }
        assert!(
            !map.contains_key(&0x400) && !map.contains_key(&0x410),
            "the 20-byte PLT header was labelled as an import"
        );
    }

    /// Version-suffixed relocation symbols must be reported *unversioned*.
    ///
    /// `.rel.plt` names `__libc_start_main@GLIBC_2.34`; the ELF64 path already
    /// yields the bare name because `.dynstr` stores the version separately, and
    /// the 32-bit path must not start emitting `foo@GLIBC_2.4@plt` — the callee
    /// name is what the rebuilt C links against.
    #[test]
    fn arm32_plt_names_carry_no_version_suffix() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/c2_demo-armhf-gcc");
        if !path.exists() {
            eprintln!("skipping ARM32 PLT test: {} absent", path.display());
            return;
        }
        let data = std::fs::read(&path).expect("read fixture");
        for (va, name) in elf_plt_map(&data) {
            assert_eq!(
                name.matches('@').count(),
                1,
                "PLT name at {va:#x} carries a version suffix: {name}"
            );
        }
    }
}
