//! Build signatures from the unlinked objects inside a `.a` archive.
//!
//! # Why the input has to be an archive
//!
//! A linked binary is the contaminated input. The linker has already resolved
//! every `call rel32` and every RIP-relative displacement to a value it chose
//! for that link, and it kept no record of which bytes those were. Harvesting a
//! prologue from a linked image therefore records the *layout*, not the
//! function, and the signature cannot match the same function in the next
//! build. That is the defect this module exists to fix: the shipped library
//! used to be thirty exact prologues taken from this repository's own linked
//! samples.
//!
//! An `ar` archive holds unlinked `.o` members, and a relocatable object
//! carries the relocation table that identifies which parts of the text the
//! linker may change. Usually that is exactly the relocated field. Relaxable
//! relocations are the important exception: their contract also permits the
//! linker to rewrite surrounding instruction bytes, which must be masked too.
//!
//! FLIRT, Ghidra FunctionID, SigKit and WARP's own `WARP\Process` all take the
//! same input class for the same reason.
//!
//! # What a relocation covers
//!
//! `object`'s `Relocation` gives an offset and a size in bits. The masked span
//! is normally `[offset, offset + size/8)`, clamped to the pattern. Known
//! linker-relaxable relocation kinds widen that span to cover the affected
//! opcode bytes as well. A relocation with a
//! reported size of zero -- some formats leave it implicit -- is widened to the
//! natural pointer width for the architecture rather than skipped, because a
//! relocation we mask too generously costs recall while one we miss costs
//! correctness.
//!
//! # How long a function is
//!
//! ELF answers this directly: `STT_FUNC` carries `st_size`. **COFF has no
//! symbol size at all**, and that single gap was the whole of the COFF
//! failure -- see [`coff`]. Extent is therefore derived when the format does
//! not state it: the next defined symbol address in the same section, or the
//! section end. That is what FLIRT's own `pcf` does, and it is why a MinGW
//! `.a` now yields signatures where it used to yield none.

mod coff;

use std::collections::{BTreeMap, BTreeSet};

use object::read::archive::ArchiveFile;
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget,
    SectionIndex, SectionKind, SymbolKind,
};

use super::{crc16, FlirtLibraryKey, FlirtReference, FlirtSignatureEntry};

/// Why signature extraction failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// The bytes are not an `ar` archive.
    NotAnArchive(String),
    /// A member could not be read or parsed as an object.
    BadMember { member: String, why: String },
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArchive(why) => write!(f, "not an ar archive: {why}"),
            Self::BadMember { member, why } => write!(f, "archive member {member}: {why}"),
        }
    }
}

impl std::error::Error for ArchiveError {}

/// One extracted signature plus the member it came from.
#[derive(Debug, Clone)]
pub struct ArchiveSignature {
    /// The signature as it will be written to the library file.
    pub entry: FlirtSignatureEntry,
    /// The archive member (`mathlib.o`) the function was defined in.
    pub member: String,
    /// Section-relative symbol address. Equal addresses in one member prove
    /// that differently named symbols are aliases, not coincidental byte
    /// matches between distinct functions.
    pub address: u64,
    /// How many pattern bytes the relocation table marked variant.
    pub masked_bytes: usize,
}

/// Extraction settings.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// Pattern length in bytes. The shipped library uses 32, as FLIRT does.
    pub pattern_len: usize,
    /// Cap on the CRC range, which FLIRT stores in a single byte.
    pub max_crc_len: usize,
    /// Skip functions shorter than this. FLIRT drops functions under four
    /// bytes with no references for the same reason: below some length there
    /// is nothing to be right about.
    pub min_function_len: u64,
    /// Skip signatures with fewer than this many *fixed* pattern bytes.
    ///
    /// A short function whose window is mostly relocated, or mostly past its
    /// own end, produces a pattern that compares almost nothing. FLIRT's rule
    /// is the same one stated about length; stating it about the surviving
    /// bytes is the version that actually bounds the false-positive rate,
    /// because the mask is what decides how much of the window is compared.
    ///
    /// **The default is 16, half the pattern, and it was measured rather than
    /// chosen.** At 8 the shipped library kept four signatures with 10 or 11
    /// fixed bytes and no CRC and no references -- `mathlib_version_major` is
    /// `endbr64; mov eax, 1; ret`, ten bytes -- and those four produced four
    /// false positives across the 2,801-function fixture corpus, naming
    /// `zext_u32_to_u64` and two C++ methods. A ten-byte function that returns
    /// a constant is not identifiable by its bytes at any pattern length; the
    /// only honest thing to do with it is decline. Raising the floor to 16
    /// drops exactly those four (nothing in this archive sits between 11 and
    /// 17 fixed bytes) and takes the false-positive count to zero.
    pub min_fixed_bytes: usize,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            pattern_len: 32,
            max_crc_len: 255,
            min_function_len: 8,
            min_fixed_bytes: 16,
        }
    }
}

/// The natural relocated-field width for an architecture, in bytes.
///
/// Used only when a relocation reports a size of zero.
fn default_reloc_width(arch: Architecture) -> u64 {
    match arch {
        Architecture::X86_64 | Architecture::Aarch64 | Architecture::Riscv64 => 8,
        _ => 4,
    }
}

/// Bytes an assembler emits to align the next function, never as content.
///
/// `0x90` is x86 `nop`, `0xcc` is `int3` (MSVC's filler), `0x00` is the
/// default fill everywhere else.
const ALIGNMENT_FILLER: [u8; 3] = [0x00, 0x90, 0xcc];

/// The first address after `address` that another symbol claims, or the
/// section end.
///
/// Strictly-greater is load-bearing. Aliases -- two names for one entry --
/// share an address, and a `>=` scan would give each of them an extent of
/// zero and drop the pair.
fn next_boundary(address: u64, boundaries: Option<&BTreeSet<u64>>, section_end: u64) -> u64 {
    boundaries
        .and_then(|b| b.range(address + 1..).next().copied())
        .unwrap_or(section_end)
        .min(section_end)
}

/// How far a symbol reaches when the format does not say.
///
/// The next distinct symbol address in the same section, or the section end,
/// **minus the alignment padding at the end of that span**. FLIRT's `pcf`
/// uses the same next-symbol rule for COFF, and it is the only rule
/// available: a COFF symbol record has no size field, and GCC writes the aux
/// function record's `TotalSize` as zero.
///
/// **Trimming the padding is what keeps the false-positive rate at zero, and
/// it was measured.** Without it, `libmingwex.a`'s `alarm` -- `xor eax,eax;
/// ret`, three bytes, alone in a 16-byte-aligned section -- signs as sixteen
/// *fixed* bytes, thirteen of which are `0x90`. It clears the
/// `min_fixed_bytes` floor on padding alone and then names every other
/// three-byte stub in the image: measured on a MinGW `hello.exe`, `alarm` was
/// applied to `_setargv` and `__tlregdtor`, and `libgcc.a`'s one-byte
/// `__clear_cache` to `__gcc_deregister_frame`. Padding is identical in every
/// object in the world, so counting it as pattern is counting the alignment
/// rule, not the function.
///
/// A byte covered by a relocation is never filler, whatever its value: an
/// unlinked `jmp rel32` tail call ends in four zero displacement bytes that
/// the linker is about to overwrite, and trimming those would shorten a real
/// function.
fn symbol_extent(
    address: u64,
    boundaries: Option<&BTreeSet<u64>>,
    section_end: u64,
    section: &object::Section<'_, '_>,
    spans: &[(u64, u64, u64, Option<String>)],
) -> u64 {
    let mut end = next_boundary(address, boundaries, section_end);
    while end > address {
        let byte = end - 1;
        if spans
            .iter()
            .any(|(offset, len, _, _)| byte >= *offset && byte < offset + len)
        {
            break;
        }
        match section.data_range(byte, 1) {
            Ok(Some([value])) if ALIGNMENT_FILLER.contains(value) => end = byte,
            _ => break,
        }
    }
    end.saturating_sub(address)
}

fn relocation_variant_span(
    arch: Architecture,
    offset: u64,
    len: u64,
    flags: RelocationFlags,
) -> (u64, u64) {
    // GNU ld may relax `mov disp32(%ebx),reg` carrying R_386_GOT32X into a
    // different opcode/modrm pair. Those two bytes precede the relocated
    // disp32 field, but are just as link-variant as the field itself.
    if arch == Architecture::I386
        && matches!(flags, RelocationFlags::Elf { r_type } if r_type == object::elf::R_386_GOT32X)
    {
        return (offset.saturating_sub(2), len.saturating_add(2));
    }
    (offset, len)
}

/// Extract masked signatures from every object member of an `ar` archive.
///
/// Deterministic: members are visited in archive order and symbols within a
/// member are visited sorted by `(address, name)`, so two runs over the same
/// bytes produce the same list in the same order.
pub fn signatures_from_archive(
    data: &[u8],
    options: &ArchiveOptions,
) -> Result<Vec<ArchiveSignature>, ArchiveError> {
    let archive =
        ArchiveFile::parse(data).map_err(|e| ArchiveError::NotAnArchive(e.to_string()))?;
    let mut out: Vec<ArchiveSignature> = Vec::new();
    for member in archive.members() {
        let member = member.map_err(|e| ArchiveError::BadMember {
            member: "<unreadable header>".to_string(),
            why: e.to_string(),
        })?;
        let name = String::from_utf8_lossy(member.name()).to_string();
        let Ok(member_data) = member.data(data) else {
            continue;
        };
        // Non-object members (`/`, `//`, the symbol index) are not errors.
        let Ok(obj) = object::File::parse(member_data) else {
            continue;
        };
        out.extend(signatures_from_object(&obj, &name, options));
    }
    Ok(out)
}

/// Extract masked signatures from one already-parsed relocatable object.
pub fn signatures_from_object(
    obj: &object::File<'_>,
    member: &str,
    options: &ArchiveOptions,
) -> Vec<ArchiveSignature> {
    let arch = obj.architecture();
    let format = obj.format();
    let width = default_reloc_width(arch);

    // Relocations per section, as `(offset, byte length)`, plus the symbol
    // name each one targets so the reference list can be built.
    let mut relocs: BTreeMap<usize, Vec<(u64, u64, u64, Option<String>)>> = BTreeMap::new();
    for section in obj.sections() {
        let mut spans: Vec<(u64, u64, u64, Option<String>)> = Vec::new();
        for (offset, reloc) in section.relocations() {
            let len = if reloc.size() == 0 {
                width
            } else {
                u64::from(reloc.size()) / 8
            };
            let target = match reloc.target() {
                RelocationTarget::Symbol(index) => obj
                    .symbol_by_index(index)
                    .ok()
                    // A COFF relocation against a constant pool targets the
                    // *section* symbol, so its name is `.rdata` -- a name
                    // every COFF object in the world contains, that no
                    // resolver over a linked image can ever confirm, and that
                    // a resolver reporting the real symbol there would
                    // actively contradict. Recording it would turn the
                    // second-level disambiguator into a source of false
                    // eliminations. (ELF section symbols are unnamed, so this
                    // filter is a no-op there.)
                    .filter(|s| s.kind() != SymbolKind::Section)
                    .and_then(|s| {
                        s.name()
                            .ok()
                            .map(|n| coff::undecorate(format, arch, n).into_owned())
                    })
                    .filter(|n| !n.is_empty()),
                _ => None,
            };
            let (variant_offset, variant_len) =
                relocation_variant_span(arch, offset, len.max(1), reloc.flags());
            spans.push((variant_offset, variant_len, offset, target));
        }
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        relocs.insert(section.index().0, spans);
    }

    // Every defined symbol address in a section bounds the symbol before it.
    // Collected for all symbols, not only functions, because a jump table or
    // a literal pool emitted into `.text` ends the function it follows just
    // as surely as the next function does.
    let mut boundaries: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
    for sym in obj.symbols() {
        if matches!(sym.kind(), SymbolKind::Section | SymbolKind::File) {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        boundaries
            .entry(index.0)
            .or_default()
            .insert(code_symbol_address(arch, sym.address()));
    }

    // Text symbols in code sections, sorted for determinism.
    let mut symbols: Vec<(u64, String, SectionIndex, u64)> = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        // A `DTYPE_FUNCTION` COFF symbol that does not live in a code section
        // is not a function we can pattern-match; neither is anything in
        // `.drectve`, `.debug*` or a COMDAT data section.
        if section.kind() != SectionKind::Text {
            continue;
        }
        // ELF encodes Thumb state in bit zero of STT_FUNC values. It is not a
        // byte offset: section data and relocations are addressed at the
        // underlying even location. Keeping the bit shifted every ARM FLIRT
        // pattern by one byte, so no linked Thumb function could ever match.
        let address = code_symbol_address(arch, sym.address());
        // COFF states no size. Derive one rather than dropping the symbol.
        let size = match sym.size() {
            0 => symbol_extent(
                address,
                boundaries.get(&index.0),
                section.address() + section.size(),
                &section,
                relocs.get(&index.0).map(Vec::as_slice).unwrap_or(&[]),
            ),
            n => n,
        };
        if size < options.min_function_len {
            continue;
        }
        symbols.push((
            address,
            coff::undecorate(format, arch, name).into_owned(),
            index,
            size,
        ));
    }
    symbols.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    let mut out = Vec::new();
    for (address, name, index, size) in symbols {
        let Ok(section) = obj.section_by_index(index) else {
            continue;
        };
        // Read as much of the window as the section actually holds. The last
        // function in a section is short of a full pattern -- `mathlib_init`
        // is 25 bytes at the end of `.text` -- and dropping it would silently
        // lose exactly the functions that sit at a section boundary. The
        // shortfall is zero-filled and masked below, so it carries no weight.
        let mut readable = 0u64;
        let mut pattern: Vec<u8> = Vec::new();
        for len in (1..=options.pattern_len as u64).rev() {
            if let Ok(Some(bytes)) = section.data_range(address, len) {
                readable = len;
                pattern = bytes.to_vec();
                break;
            }
        }
        if readable == 0 {
            continue;
        }
        pattern.resize(options.pattern_len, 0);
        let empty = Vec::new();
        let spans = relocs.get(&index.0).unwrap_or(&empty);

        // Mask: true where the byte survives the link unchanged.
        let mut fixed = vec![true; options.pattern_len];

        // Everything past the end of the function is variant, because it is
        // not the function: a short symbol's 32-byte window runs into
        // whatever the linker placed next, and that is a different neighbour
        // in every link. Leaving those bytes fixed is what made
        // `mathlib_init` and `mathlib_version_minor` -- 12 and 20 bytes long
        // -- match in neither of the two relink fixtures while every longer
        // function matched in both.
        let real = usize::try_from(size.min(readable)).unwrap_or(options.pattern_len);
        for f in fixed.iter_mut().skip(real) {
            *f = false;
        }

        for (offset, len, _, _) in spans {
            for byte in *offset..offset + len {
                if byte < address {
                    continue;
                }
                let rel = (byte - address) as usize;
                if rel < options.pattern_len {
                    fixed[rel] = false;
                }
            }
        }

        // CRC: the bytes after the pattern, up to the first variant byte, up
        // to the recorded function length, capped by the format's one byte.
        let crc_start = address + options.pattern_len as u64;
        let function_end = address + size;
        let mut crc_len = 0u64;
        let limit = function_end
            .saturating_sub(crc_start)
            .min(options.max_crc_len as u64);
        'crc: while crc_len < limit {
            let byte = crc_start + crc_len;
            for (offset, len, _, _) in spans {
                if byte >= *offset && byte < offset + len {
                    break 'crc;
                }
            }
            crc_len += 1;
        }
        let crc_bytes = section.data_range(crc_start, crc_len).ok().flatten();
        let (crc, crc_len) = match crc_bytes {
            Some(bytes) if !bytes.is_empty() => (Some(crc16(bytes)), bytes.len() as u16),
            _ => (None, 0),
        };

        // References: every relocation inside the function that names a symbol
        // other than the function itself, at its offset from the entry.
        let mut refs: Vec<FlirtReference> = Vec::new();
        for (_, _, reference_offset, target) in spans {
            if *reference_offset < address || *reference_offset >= function_end {
                continue;
            }
            let Some(target) = target else { continue };
            if target == &name {
                continue;
            }
            refs.push(FlirtReference {
                offset: (reference_offset - address) as u32,
                name: target.clone(),
            });
        }
        refs.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.name.cmp(&b.name)));
        refs.dedup();

        let masked_bytes = fixed.iter().filter(|f| !**f).count();
        if options.pattern_len - masked_bytes < options.min_fixed_bytes {
            continue;
        }
        out.push(ArchiveSignature {
            entry: FlirtSignatureEntry {
                name: name.clone(),
                prologue_hex: pattern.iter().map(|b| format!("{b:02x}")).collect(),
                source_binary: format!("{member}!{name}"),
                mask_hex: Some(
                    fixed
                        .iter()
                        .map(|f| if *f { "ff" } else { "00" })
                        .collect::<String>(),
                ),
                crc16: crc,
                crc_len,
                function_len: u32::try_from(size).ok(),
                refs,
            },
            member: member.to_string(),
            address,
            masked_bytes,
        });
    }
    out
}

fn code_symbol_address(arch: Architecture, address: u64) -> u64 {
    if arch == Architecture::Arm {
        address & !1
    } else {
        address
    }
}

/// The `arch` tag a library file should carry for this object.
pub fn arch_tag(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 => "x86_64",
        Architecture::I386 => "i386",
        Architecture::Aarch64 => "aarch64",
        Architecture::Arm => "armv7",
        Architecture::Riscv64 => "riscv64",
        Architecture::Riscv32 => "riscv32",
        _ => "unknown",
    }
}

/// A convenience wrapper that stamps a provenance key onto an extraction.
pub fn library_key(name: &str, version: &str, variant: &str, arch: &str) -> FlirtLibraryKey {
    FlirtLibraryKey {
        name: name.to_string(),
        version: version.to_string(),
        variant: variant.to_string(),
        arch: arch.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i386_got32x_masks_the_linker_relaxable_opcode_pair() {
        assert_eq!(
            relocation_variant_span(
                Architecture::I386,
                0x26,
                4,
                RelocationFlags::Elf {
                    r_type: object::elf::R_386_GOT32X,
                },
            ),
            (0x24, 6)
        );
    }
    use std::path::PathBuf;

    fn mathlib_archive() -> Option<Vec<u8>> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a");
        std::fs::read(path).ok()
    }

    /// The real archive in the tree yields signatures, and the relocation
    /// table actually marks bytes variant. A run that masked nothing would be
    /// indistinguishable from v1 and is the failure mode worth catching.
    #[test]
    fn the_shipped_archive_yields_masked_signatures() {
        let Some(data) = mathlib_archive() else {
            panic!(
                "samples/.../libmathlib.a is committed, not generated; its \
                 absence means the samples tree was pruned"
            );
        };
        let sigs = signatures_from_archive(&data, &ArchiveOptions::default())
            .expect("libmathlib.a must parse");
        assert!(
            sigs.len() >= 15,
            "expected ~20 sized mathlib_* functions, got {}",
            sigs.len()
        );
        let masked: usize = sigs.iter().filter(|s| s.masked_bytes > 0).count();
        assert!(
            masked > 0,
            "no signature had a relocation in its 32-byte window; either the \
             relocation reader is broken or this is not a relocatable object"
        );
        eprintln!(
            "libmathlib.a: {} signatures, {masked} with masked bytes in the \
             32-byte pattern",
            sigs.len()
        );
    }

    /// Extraction must be a pure function of the bytes.
    #[test]
    fn extraction_is_deterministic() {
        let Some(data) = mathlib_archive() else {
            return;
        };
        let a = signatures_from_archive(&data, &ArchiveOptions::default()).unwrap();
        let b = signatures_from_archive(&data, &ArchiveOptions::default()).unwrap();
        let names_a: Vec<&str> = a.iter().map(|s| s.entry.name.as_str()).collect();
        let names_b: Vec<&str> = b.iter().map(|s| s.entry.name.as_str()).collect();
        assert_eq!(names_a, names_b);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.entry.prologue_hex, y.entry.prologue_hex);
            assert_eq!(x.entry.mask_hex, y.entry.mask_hex);
            assert_eq!(x.entry.crc16, y.entry.crc16);
        }
    }

    /// Every emitted mask must be the same byte length as its pattern, or the
    /// loader drops the entry and the library silently shrinks.
    #[test]
    fn masks_are_the_same_length_as_patterns() {
        let Some(data) = mathlib_archive() else {
            return;
        };
        for s in signatures_from_archive(&data, &ArchiveOptions::default()).unwrap() {
            let mask = s
                .entry
                .mask_hex
                .as_ref()
                .expect("archive masks are always emitted");
            assert_eq!(
                mask.len(),
                s.entry.prologue_hex.len(),
                "{} has a mask of a different length to its pattern",
                s.entry.name
            );
        }
    }

    /// The CRC range must stop at the first variant byte; if it did not, the
    /// CRC would cover linker-chosen bytes and could never match.
    #[test]
    fn the_crc_range_never_covers_a_relocated_byte() {
        let Some(data) = mathlib_archive() else {
            return;
        };
        let sigs = signatures_from_archive(&data, &ArchiveOptions::default()).unwrap();
        let archive = ArchiveFile::parse(&*data).unwrap();
        for member in archive.members() {
            let member = member.unwrap();
            let obj = object::File::parse(member.data(&*data).unwrap()).unwrap();
            // Relocations are section-scoped: an offset in `.data`'s table
            // says nothing about an address in `.text`. Collecting them into
            // one flat list is how the first draft of this test reported a
            // `.rodata` relocation as covering `mathlib_add`.
            let mut spans: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
            for section in obj.sections() {
                let offsets: Vec<(u64, u64)> = section
                    .relocations()
                    .map(|(offset, reloc)| {
                        let len = if reloc.size() == 0 {
                            8
                        } else {
                            u64::from(reloc.size()) / 8
                        };
                        (offset, len.max(1))
                    })
                    .collect();
                spans.insert(section.index().0, offsets);
            }
            for sym in obj.symbols() {
                if sym.kind() != SymbolKind::Text || sym.size() < 8 {
                    continue;
                }
                let Ok(name) = sym.name() else { continue };
                let Some(sig) = sigs.iter().find(|s| s.entry.name == name) else {
                    continue;
                };
                let Some(index) = sym.section_index() else {
                    continue;
                };
                let empty = Vec::new();
                let spans = spans.get(&index.0).unwrap_or(&empty);
                let start = sym.address() + 32;
                for byte in start..start + u64::from(sig.entry.crc_len) {
                    for (offset, len) in spans {
                        assert!(
                            byte < *offset || byte >= offset + len,
                            "{name}'s CRC range covers relocated byte {byte:#x}"
                        );
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // COFF: MinGW-w64 `.a` and MSVC-layout `.lib`.
    //
    // Fixtures and their provenance: `tests/fixtures/flirt/coff/README.md`.
    // -----------------------------------------------------------------

    fn coff_fixture(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/flirt/coff")
            .join(name);
        std::fs::read(&path)
            .unwrap_or_else(|e| panic!("committed fixture {} must read: {e}", path.display()))
    }

    /// The diagnosis, asserted rather than described.
    ///
    /// Every function symbol in a real MinGW COFF member reports
    /// `size() == 0`, so the builder's original `sym.size() < min_function_len`
    /// guard rejected all of them and three MinGW archives returned nothing.
    /// If a future `object` release starts synthesising sizes this test goes
    /// red, which is the correct outcome: the derived-extent path would then
    /// be dead code that nothing exercises.
    #[test]
    fn every_coff_function_symbol_reports_no_size() {
        let data = coff_fixture("mingw_crt_subset.a");
        let archive = ArchiveFile::parse(&*data).expect("fixture must parse as an archive");
        let mut text_symbols = 0usize;
        for member in archive.members() {
            let member = member.expect("fixture members must read");
            let obj = object::File::parse(member.data(&*data).expect("member data"))
                .expect("every fixture member is a COFF object");
            assert_eq!(obj.format(), object::BinaryFormat::Coff);
            for sym in obj.symbols() {
                if sym.kind() != SymbolKind::Text || sym.section_index().is_none() {
                    continue;
                }
                text_symbols += 1;
                assert_eq!(
                    sym.size(),
                    0,
                    "{} reported a size; the derived-extent path is now unreachable \
                     for this input and the COFF tests below prove less than they say",
                    sym.name().unwrap_or("<unnamed>")
                );
            }
        }
        assert!(
            text_symbols >= 60,
            "only {text_symbols} COFF text symbols in the fixture; a vacuous pass"
        );
    }

    /// The bug this lane fixes: a MinGW archive yields signatures at all.
    #[test]
    fn a_mingw_coff_archive_yields_masked_signatures() {
        let data = coff_fixture("mingw_crt_subset.a");
        let sigs = signatures_from_archive(&data, &ArchiveOptions::default())
            .expect("mingw_crt_subset.a must parse");
        assert!(
            sigs.len() >= 50,
            "expected ~62 signatures from the MinGW CRT subset, got {}",
            sigs.len()
        );
        let masked = sigs.iter().filter(|s| s.masked_bytes > 0).count();
        assert!(
            masked >= 10,
            "only {masked} of {} signatures had a relocation in the 32-byte \
             window; COFF relocation widths are not reaching the mask",
            sigs.len()
        );
        let with_refs = sigs.iter().filter(|s| !s.entry.refs.is_empty()).count();
        assert!(
            with_refs >= 10,
            "only {with_refs} signatures recorded a referenced name"
        );
        // A COFF relocation against a constant pool targets the `.rdata`
        // *section definition* symbol. Recording that as a reference would
        // make the second-level disambiguator fire on a name no resolver can
        // confirm, and that every COFF object in the world contains.
        //
        // MinGW's `.refptr.<name>` COMDAT stubs are NOT that. They are ordinary
        // static symbols whose name happens to start with a dot, they identify
        // exactly one target, and they are kept.
        const SECTION_NAMES: [&str; 8] = [
            ".text", ".data", ".bss", ".rdata", ".xdata", ".pdata", ".tls", ".idata",
        ];
        for s in &sigs {
            for r in &s.entry.refs {
                assert!(
                    !SECTION_NAMES.contains(&r.name.as_str()),
                    "{} records the section name {} as a reference",
                    s.entry.name,
                    r.name
                );
            }
        }
        assert!(
            sigs.iter()
                .any(|s| s.entry.refs.iter().any(|r| r.name.starts_with(".refptr."))),
            "no `.refptr.` stub was recorded as a reference; the section-symbol \
             filter has swallowed MinGW's COMDAT indirection stubs too"
        );
        eprintln!(
            "mingw_crt_subset.a: {} signatures, {masked} masked, {with_refs} with refs",
            sigs.len()
        );
    }

    /// Alignment padding must not be signed as if it were the function.
    ///
    /// A COFF function's extent is derived, so without trimming it runs to the
    /// next symbol -- through however many `nop`s the assembler inserted. Those
    /// bytes are identical in every object ever compiled, so a three-byte stub
    /// would clear the `min_fixed_bytes` floor on padding alone and then name
    /// every other three-byte stub in the image. Measured before the trim was
    /// added: `alarm` named `_setargv` and `__tlregdtor` in a MinGW
    /// `hello.exe`, and `__clear_cache` named `__gcc_deregister_frame`.
    #[test]
    fn derived_extents_do_not_include_alignment_padding() {
        let data = coff_fixture("mingw_crt_subset.a");
        for s in signatures_from_archive(&data, &ArchiveOptions::default()).unwrap() {
            let len = s
                .entry
                .function_len
                .expect("COFF extents are always derived") as usize;
            let bytes = hex_bytes(&s.entry.prologue_hex);
            if len == 0 || len > bytes.len() {
                continue;
            }
            assert!(
                !ALIGNMENT_FILLER.contains(&bytes[len - 1]),
                "{} ends at offset {} on filler byte {:#04x}: its extent ran \
                 into the alignment padding",
                s.entry.name,
                len - 1,
                bytes[len - 1]
            );
        }
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// The MSVC archive layout is a header difference, not an object one.
    ///
    /// A `.lib` written by `llvm-lib` (and by MSVC's `lib.exe`) carries a
    /// *first* and a *second* linker member, both named `/`, then the `//`
    /// longnames member; a GNU `.a` has one `/` and one `//`. None of those is
    /// an object, and mistaking one for an object is the failure mode this
    /// test exists for. The three objects inside are the same three objects,
    /// so the signatures must be identical.
    #[test]
    fn the_msvc_lib_layout_reads_the_same_objects_as_a_gnu_archive() {
        let gnu = coff_fixture("mingw_crt_subset.a");
        let msvc = coff_fixture("mingw_crt_three.msvc.lib");
        assert_eq!(
            ArchiveFile::parse(&*msvc).expect("fixture parses").kind(),
            object::read::archive::ArchiveKind::Coff,
            "the fixture is supposed to be in the MSVC layout; if it is read as \
             a GNU archive this test proves nothing"
        );

        let options = ArchiveOptions::default();
        let from_gnu = signatures_from_archive(&gnu, &options).unwrap();
        let from_msvc = signatures_from_archive(&msvc, &options).unwrap();
        assert!(
            from_msvc.len() >= 5,
            "only {} signatures from the MSVC-layout fixture",
            from_msvc.len()
        );
        for m in &from_msvc {
            let peer = from_gnu
                .iter()
                .find(|g| g.entry.name == m.entry.name)
                .unwrap_or_else(|| panic!("{} is in the .lib but not in the .a", m.entry.name));
            assert_eq!(peer.entry.prologue_hex, m.entry.prologue_hex);
            assert_eq!(peer.entry.mask_hex, m.entry.mask_hex);
            assert_eq!(peer.entry.crc16, m.entry.crc16);
            assert_eq!(peer.entry.crc_len, m.entry.crc_len);
            assert_eq!(peer.entry.function_len, m.entry.function_len);
        }
        eprintln!(
            "MSVC layout: {} signatures, all identical to the GNU archive's",
            from_msvc.len()
        );
    }

    /// An import-only `.lib` is not an error, and is not signatures either.
    ///
    /// Every member of a Windows SDK import library is a short-import record
    /// (`IMPORT_OBJECT_HDR_SIG2`), which is not a COFF object and has no code
    /// in it. The builder must walk past all of them and return an empty list.
    #[test]
    fn an_import_only_library_yields_nothing_rather_than_failing() {
        let data = coff_fixture("import_only.msvc.lib");
        // Three `\0\0\xff\xff` short-import headers, one per export.
        assert_eq!(
            data.windows(4).filter(|w| w == b"\x00\x00\xff\xff").count(),
            3,
            "the fixture is supposed to hold three short-import members"
        );
        let sigs = signatures_from_archive(&data, &ArchiveOptions::default())
            .expect("an import library is still an archive");
        assert!(
            sigs.is_empty(),
            "an import library has no function bodies, but {} signatures came \
             out of one",
            sigs.len()
        );
    }

    /// Extraction from COFF is a pure function of the bytes, as it is for ELF.
    #[test]
    fn coff_extraction_is_deterministic() {
        let data = coff_fixture("mingw_crt_subset.a");
        let a = signatures_from_archive(&data, &ArchiveOptions::default()).unwrap();
        let b = signatures_from_archive(&data, &ArchiveOptions::default()).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.entry.name, y.entry.name);
            assert_eq!(x.entry.prologue_hex, y.entry.prologue_hex);
            assert_eq!(x.entry.mask_hex, y.entry.mask_hex);
            assert_eq!(x.entry.crc16, y.entry.crc16);
            assert_eq!(x.entry.function_len, y.entry.function_len);
        }
    }

    /// Masks stay the length of their patterns on COFF too.
    #[test]
    fn coff_masks_are_the_same_length_as_patterns() {
        let data = coff_fixture("mingw_crt_subset.a");
        for s in signatures_from_archive(&data, &ArchiveOptions::default()).unwrap() {
            let mask = s.entry.mask_hex.as_ref().expect("masks are always emitted");
            assert_eq!(mask.len(), s.entry.prologue_hex.len(), "{}", s.entry.name);
        }
    }

    #[test]
    fn an_extent_stops_at_the_next_symbol_not_at_an_alias() {
        let mut boundaries = BTreeSet::new();
        boundaries.insert(0x00);
        boundaries.insert(0x40);
        // Two names at 0x00 collapse to one entry, so the extent is still the
        // distance to 0x40 rather than zero.
        assert_eq!(next_boundary(0x00, Some(&boundaries), 0x80), 0x40);
        assert_eq!(next_boundary(0x40, Some(&boundaries), 0x80), 0x80);
        // A section end below the next recorded symbol wins.
        assert_eq!(next_boundary(0x00, Some(&boundaries), 0x20), 0x20);
        assert_eq!(next_boundary(0x00, None, 0x80), 0x80);
    }

    #[test]
    fn a_non_archive_is_reported_rather_than_ignored() {
        let err = signatures_from_archive(b"not an archive", &ArchiveOptions::default())
            .expect_err("plain bytes must not parse as an archive");
        assert!(matches!(err, ArchiveError::NotAnArchive(_)));
    }

    #[test]
    fn arch_tags_cover_the_targets_the_library_is_keyed_by() {
        assert_eq!(arch_tag(Architecture::X86_64), "x86_64");
        assert_eq!(arch_tag(Architecture::I386), "i386");
        assert_eq!(arch_tag(Architecture::Aarch64), "aarch64");
    }

    #[test]
    fn thumb_state_bit_is_not_used_as_a_section_byte_offset() {
        assert_eq!(code_symbol_address(Architecture::Arm, 0x101), 0x100);
        assert_eq!(code_symbol_address(Architecture::Aarch64, 0x101), 0x101);
    }
}
