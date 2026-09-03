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

use std::collections::BTreeMap;

use object::read::archive::ArchiveFile;
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget,
    SectionIndex, SymbolKind,
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
    let width = default_reloc_width(obj.architecture());

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
                    .and_then(|s| s.name().ok().map(|n| n.to_string()))
                    .filter(|n| !n.is_empty()),
                _ => None,
            };
            let (variant_offset, variant_len) =
                relocation_variant_span(obj.architecture(), offset, len.max(1), reloc.flags());
            spans.push((variant_offset, variant_len, offset, target));
        }
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        relocs.insert(section.index().0, spans);
    }

    // Sized text symbols, sorted for determinism.
    let mut symbols: Vec<(u64, String, SectionIndex, u64)> = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != SymbolKind::Text || sym.size() < options.min_function_len {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        // ELF encodes Thumb state in bit zero of STT_FUNC values. It is not a
        // byte offset: section data and relocations are addressed at the
        // underlying even location. Keeping the bit shifted every ARM FLIRT
        // pattern by one byte, so no linked Thumb function could ever match.
        let address = code_symbol_address(obj.architecture(), sym.address());
        symbols.push((address, name.to_string(), index, sym.size()));
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
