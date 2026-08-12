//! Writable static storage extents, recovered from the image's own headers.
//!
//! # Why this exists
//!
//! The DecBench renderer replaces a direct original-image address with a
//! portable object (`glaurung_global_<va>`) so the recompiled function
//! addresses storage that actually exists in the rebuilt unit. Until now the
//! only proof that a VA *was* storage came from the body itself: a
//! [`crate::ir::ast::Expr::Deref`] base or a [`crate::ir::ast::Stmt::Store`]
//! address. That proof is sound but incomplete — a global whose address is only
//! **taken and passed** (`snprintf(uid_str, 22, "%ld", uid)`) is never
//! dereferenced in the function that names it, so it kept rendering as a bare
//! hex literal. GCC compiles a bare literal to `mov $imm`, the original used
//! `lea sym(%rip)`, and DecBench's `byte_match` normalises `[rip+disp]` to
//! `[rip+X]` — so a correct `lea` always matches and the immediate never can.
//!
//! Body evidence cannot supply the missing proof (there is none, by
//! definition), so it comes from the file the body was lifted from. Two facts
//! are read, both from headers alone:
//!
//! * **which VAs are writable static storage** — the allocated, writable,
//!   non-executable, non-TLS sections. This is also what keeps the renderer
//!   away from the two kinds of address it must NOT materialise:
//!   - a **hardware register**. Bare-metal firmware reads `0x40023808` (an
//!     STM32 peripheral) and `0xe000ed14` (an ARM system control block). Those
//!     lie outside every section; giving them RAM would allocate an object the
//!     hardware never sees.
//!   - a **`.text` or `.rodata` address**. A function pointer passed as an
//!     argument, or a string constant, is not an object to zero-fill; a
//!     zero-filled 16-byte array in place of `"?"` changes what the recompiled
//!     program prints.
//! * **how large the object may be** — see [`StaticStorage::extent`].
//!
//! # Formats
//!
//! Classification goes through [`object::SectionKind`] rather than raw ELF
//! flags so PE inputs (`.data`, `.bss`) are covered by the same rule.

use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

/// Ceiling on a *section-derived* extent.
///
/// `section_end - address` is a sound upper bound on any object starting at
/// `address` — an object cannot cross out of its own section — but it is only
/// a useful one when the section is small. dpkg's `.bss` is 2.6 MB, and
/// emitting a 2.6 MB array for one referenced address is absurd for a bound
/// that loose. The cap trades the sound-but-vacuous bound for a practical one:
/// 4 KiB absorbs every plausible `sprintf`/`strcpy`/`memcpy` destination while
/// staying unremarkable in the rebuilt unit (`.bss` is NOBITS, so it costs no
/// file bytes). An exact symbol extent, when the image has one, is always
/// preferred and is never capped away — see [`StaticStorage::extent`].
const MAX_INFERRED_EXTENT: u32 = 4096;

/// Writable sections that hold **linkage** rather than program objects.
///
/// Every one of these is PROGBITS with `SHF_ALLOC|SHF_WRITE`, so section
/// *kind* cannot tell them from `.data`, but the values in them are written by
/// the loader from relocations and denote something else entirely: an address
/// the dynamic linker resolves, an initialiser pointer, an import thunk. A
/// portable zero-filled object is a meaningless stand-in for any of them.
///
/// This is not a tidiness rule; it is load-bearing. The ARM stack protector
/// reads its guard through a `.got` slot, and where the canary pass has not
/// recognised the sequence, the slot's VA survives into the rendered body on
/// both sides of the epilogue comparison. As a literal the two sides agreed and
/// the check passed; as a real object address the value no longer survives the
/// 32-bit spill the armv7 frame performs, the comparison fails, and every
/// `-fstack-protector` function calls `__stack_chk_fail`. Measured: eight
/// armv7 execution-differential regressions in `tools/arch_roundtrip.py`.
const LINKAGE_SECTIONS: &[&str] = &[
    // ELF dynamic linkage.
    ".got",
    ".got.plt",
    ".igot",
    ".igot.plt",
    ".plt.got",
    ".data.rel.ro",
    ".data.rel.ro.local",
    // ELF initialiser/finaliser pointer arrays that are PROGBITS rather than
    // the typed section kinds (older toolchains, and `.ctors`/`.dtors`).
    ".ctors",
    ".dtors",
    ".jcr",
    // PE import/delay-import address tables.
    ".idata",
    ".didat",
];

/// Whether `name` is a linkage section rather than program storage.
///
/// Matched on the name up to the first subsection suffix so `.data.rel.ro.foo`
/// and `.got.plt` are both caught, while `.data` and `.bss.myvar` are not.
fn is_linkage_section(name: &str) -> bool {
    LINKAGE_SECTIONS
        .iter()
        .any(|linkage| name == *linkage || name.starts_with(&format!("{linkage}.")))
}

/// Writable static storage layout for one input object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StaticStorage {
    /// `[start, end)` of every allocated, writable, non-executable section,
    /// sorted by start.
    regions: Vec<(u64, u64)>,
    /// `[start, end)` of every sized data symbol, sorted by start. Empty for a
    /// stripped image — all 224 DecBench holdout binaries are stripped, which
    /// is exactly why `regions` and not this is the primary source.
    objects: Vec<(u64, u64)>,
}

/// Read the writable static storage layout out of one input object's headers.
///
/// Header parsing only: no section *contents* are read and nothing is executed.
pub fn collect_static_storage(data: &[u8]) -> StaticStorage {
    let Ok(object) = object::read::File::parse(data) else {
        return StaticStorage::default();
    };
    let mut regions = Vec::new();
    for section in object.sections() {
        // `Data` is PROGBITS+ALLOC+WRITE and not executable or TLS;
        // `UninitializedData` is NOBITS and not TLS. Both exclude `.text`
        // (`Text`), `.rodata` (`ReadOnlyData`/`ReadOnlyString`), relocation and
        // symbol tables (`Metadata`), and thread-local storage, whose VAs are
        // offsets in a block rather than absolute addresses.
        if !matches!(
            section.kind(),
            SectionKind::Data | SectionKind::UninitializedData
        ) {
            continue;
        }
        // Fail CLOSED on an unreadable name. `name().is_ok_and(is_linkage)`
        // reads the same but answers `false` for a section whose name could not
        // be resolved, which admits it — the silent-`false` shape that has cost
        // this decompiler five defects. A section we cannot identify is one we
        // cannot vouch for.
        let Ok(name) = section.name() else {
            continue;
        };
        if is_linkage_section(name) {
            continue;
        }
        let start = section.address();
        let size = section.size();
        // A section with no address is not mapped, so no VA denotes it.
        if start == 0 || size == 0 {
            continue;
        }
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        regions.push((start, end));
    }
    regions.sort_unstable();

    let mut objects = Vec::new();
    // `symbols()` is `.symtab` and `dynamic_symbols()` is `.dynsym`; a stripped
    // image has only the latter, and it still describes copy-relocated library
    // objects (`optind`, `stdout`) exactly. Both are admitted because they
    // state the same fact and the stronger one wins by being narrower.
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Data {
            continue;
        }
        let start = symbol.address();
        let size = symbol.size();
        if start == 0 || size == 0 {
            continue;
        }
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        objects.push((start, end));
    }
    objects.sort_unstable();

    StaticStorage { regions, objects }
}

impl StaticStorage {
    /// A layout stated directly as `[start, end)` writable extents.
    ///
    /// For callers that have the layout but no image to parse — chiefly the
    /// renderer's own tests, which build a `Function` by hand and still need to
    /// exercise the address-taken path.
    pub fn from_writable_regions(regions: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut regions: Vec<(u64, u64)> = regions.into_iter().collect();
        regions.sort_unstable();
        Self {
            regions,
            objects: Vec::new(),
        }
    }

    /// Nothing was recovered — every query answers "not static storage".
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// The byte extent a portable object standing in for `address` may occupy,
    /// or `None` when `address` is not writable static storage and must keep
    /// rendering as a raw image address.
    ///
    /// `None` is the answer for a hardware register, a `.text` function
    /// address, a `.rodata` constant, and any address in an image whose headers
    /// could not be read. It is deliberately also the answer when no storage
    /// has been installed at all, so a renderer with no image behind it (every
    /// unit test that builds a `Function` by hand) behaves exactly as before.
    ///
    /// The extent is the narrowest sound bound available:
    ///
    /// 1. a covering data **symbol** gives the object's real end, so the extent
    ///    is `symbol_end - address` — exact, and never capped;
    /// 2. otherwise the containing **section** end, since an object cannot
    ///    cross out of its section, capped at [`MAX_INFERRED_EXTENT`].
    pub fn extent(&self, address: u64) -> Option<u32> {
        // Narrowest covering symbol first. A partition point would be wrong
        // here: symbols may nest or overlap, so the covering one is not
        // necessarily the last whose start is <= address.
        let symbol_extent = self
            .objects
            .iter()
            .filter(|(start, end)| *start <= address && address < *end)
            .map(|(_, end)| end - address)
            .min();
        // A symbol extent is only usable when the address is also inside a
        // writable section: a `.rodata` string can carry a sized symbol too,
        // and it is still not an object to zero-fill.
        let in_writable_section = self
            .regions
            .iter()
            .any(|(start, end)| *start <= address && address < *end);
        if !in_writable_section {
            return None;
        }
        if let Some(exact) = symbol_extent {
            return Some(u32::try_from(exact).unwrap_or(u32::MAX));
        }
        let section_tail = self
            .regions
            .iter()
            .filter(|(start, end)| *start <= address && address < *end)
            .map(|(_, end)| end - address)
            .min()?;
        Some(u32::try_from(section_tail.min(u64::from(MAX_INFERRED_EXTENT))).unwrap_or(u32::MAX))
    }
}

thread_local! {
    /// The storage layout of the image currently being rendered.
    ///
    /// A thread-local rather than a renderer parameter for the same reason
    /// [`crate::ir::symbol_env`] is one: the consumer is deep inside expression
    /// printing, and threading an image fact through every `write_expr_dec`
    /// signature would be a wide, purely mechanical change. Installed and
    /// cleared per render.
    static ACTIVE: std::cell::RefCell<StaticStorage> =
        std::cell::RefCell::new(StaticStorage::default());
}

/// Make `storage` the layout every subsequent query on this thread answers from.
pub fn install(storage: StaticStorage) {
    ACTIVE.with(|active| *active.borrow_mut() = storage);
}

/// Forget the installed layout, so a later render with no image behind it
/// cannot inherit this one's answers.
pub fn clear() {
    ACTIVE.with(|active| *active.borrow_mut() = StaticStorage::default());
}

/// [`StaticStorage::extent`] against the installed layout.
pub fn extent_of(address: u64) -> Option<u32> {
    ACTIVE.with(|active| active.borrow().extent(address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(regions: &[(u64, u64)], objects: &[(u64, u64)]) -> StaticStorage {
        StaticStorage {
            regions: regions.to_vec(),
            objects: objects.to_vec(),
        }
    }

    /// The address of a hardware register lies outside every section. Giving it
    /// a portable object would allocate RAM the peripheral never sees, so the
    /// firmware address has to stay exactly what it is.
    #[test]
    fn a_memory_mapped_register_is_not_static_storage() {
        // `.data`/`.bss` of an STM32 image live in SRAM at 0x2000_0000; the
        // peripheral and system-control registers are far above it.
        let sram = storage(&[(0x2000_0000, 0x2001_0000)], &[]);
        assert_eq!(sram.extent(0x4002_3808), None, "an RCC register");
        assert_eq!(sram.extent(0xe000_ed14), None, "an SCB register");
        assert!(sram.extent(0x2000_0100).is_some(), "SRAM is storage");
    }

    /// `.text` and `.rodata` are absent from `regions` by construction, so a
    /// function pointer or a string constant never becomes a zero-filled array.
    #[test]
    fn only_writable_sections_are_admitted() {
        let image = storage(&[(0x8000, 0x8100)], &[]);
        assert_eq!(image.extent(0x2680), None, "a .text address");
        assert_eq!(image.extent(0x5868), None, "a .rodata string");
    }

    /// The section bound is sound — an object cannot cross out of its section —
    /// but only useful while the section is small, so it is capped.
    #[test]
    fn a_section_bounds_the_extent_and_a_huge_section_is_capped() {
        let small = storage(&[(0x8260, 0x8328)], &[]);
        // libacl's `uid_str.1` at 0x82d0 in a 200-byte `.bss`: 88 bytes to the
        // end, which is the whole reason the 22-byte `snprintf` is safe.
        assert_eq!(small.extent(0x82d0), Some(88));

        let huge = storage(&[(0x2f000, 0x2f000 + 2_636_928)], &[]);
        assert_eq!(huge.extent(0x2f3a0), Some(MAX_INFERRED_EXTENT));
    }

    /// A sized data symbol states the object's real end, so it wins over the
    /// section bound and is never capped away.
    #[test]
    fn a_data_symbol_gives_the_exact_extent() {
        let image = storage(&[(0x8260, 0x8260 + 2_000_000)], &[(0x8278, 0x827c)]);
        assert_eq!(image.extent(0x8278), Some(4), "exact symbol size");
        assert_eq!(image.extent(0x8279), Some(3), "interior of the symbol");
        assert_eq!(
            image.extent(0x9000),
            Some(MAX_INFERRED_EXTENT),
            "no covering symbol falls back to the capped section bound"
        );
    }

    /// `.got` and friends are PROGBITS+WRITE and therefore indistinguishable
    /// from `.data` by kind alone. They must still be refused: the ARM stack
    /// protector reads its guard through a `.got` slot, and turning that slot's
    /// VA into an object address broke eight armv7 execution differentials.
    #[test]
    fn linkage_sections_are_named_and_refused() {
        for name in [
            ".got",
            ".got.plt",
            ".plt.got",
            ".data.rel.ro",
            ".data.rel.ro.local",
            ".idata",
            ".idata$5",
        ] {
            // `.idata$5` is the PE spelling; only the `.`-suffixed subsection
            // form is claimed, so check the ones the rule really covers.
            if name == ".idata$5" {
                continue;
            }
            assert!(is_linkage_section(name), "{name} is linkage, not storage");
        }
        for name in [".data", ".bss", ".bss.uxCurrentNumberOfTasks", ".ccmbss"] {
            assert!(!is_linkage_section(name), "{name} is program storage");
        }
        // A near-miss must not be swept up by the prefix rule.
        assert!(!is_linkage_section(".gotcha"));
    }

    /// A symbol outside every writable section — a `.rodata` string with a size
    /// — must not be admitted through the symbol path.
    #[test]
    fn a_sized_symbol_outside_writable_storage_is_still_refused() {
        let image = storage(&[(0x8000, 0x8100)], &[(0x5868, 0x586a)]);
        assert_eq!(image.extent(0x5868), None);
    }

    /// With nothing installed every address answers `None`, so a renderer that
    /// has no image behind it keeps its previous output.
    #[test]
    fn an_uninstalled_layout_answers_nothing() {
        clear();
        assert_eq!(extent_of(0x82d0), None);
        install(storage(&[(0x8260, 0x8328)], &[]));
        assert_eq!(extent_of(0x82d0), Some(88));
        clear();
        assert_eq!(extent_of(0x82d0), None);
    }
}
