//! Where an ELF image's import stubs are.
//!
//! Two answers, because the usual one is not always available.
//!
//! [`elf_plt_stub_ranges`] reads the section table and asks for `.plt`,
//! `.plt.sec`, `.plt.got` and `.iplt` by name. That is exact when the table is
//! there and returns **nothing at all** when it is not — `sstrip` deletes the
//! section headers outright and UPX writes `e_shnum == 0`.
//!
//! Usually that degrades quietly: an unnamed stub instead of a named one. It
//! stopped being quiet when `super::extents` began trusting `.eh_frame`, because
//! the linker covers the entire `.plt` with a **single FDE**. A caller that
//! cannot see where the PLT is reads that FDE as one 128-byte function and
//! rejects every real stub inside it — five of them on the `sstrip` corpus lane,
//! against zero on `strip`, from one identical link.
//!
//! [`stub_ranges_including_unsectioned`] therefore unions the section answer with
//! [`crate::formats::elf::dynamic_segment::plt_stub_ranges`], which identifies a
//! stub by what it *does* rather than by where it lives.

use super::{BArch, ExecRegion};

/// The ELF PLT stub extents this walk may treat as tail-call targets.
///
/// A PLT entry is linker-generated import glue. No compiler places one inside a
/// function body, so an unconditional branch to one always leaves the function
/// for good. GCC lowers `return f(x);` for an imported `f` to exactly
/// `b.w f@plt`, while x86-64 may use a compact `.plt.got` stub for an
/// address-taken import. Neither target can be an intra-function block.
///
/// This is deliberately a section-membership proof rather than a byte-pattern
/// guess. The object architecture must also agree with the active decoder so a
/// mismatched caller cannot classify unrelated bytes as a tail target.
///
/// Resolved ONCE per discovery run. The membership question used to be answered
/// per branch instruction by reopening the object, so one whole-binary
/// discovery paid an object parse per discovered function and address-scoped
/// discovery paid one per call. The proof is unchanged; the section table now
/// comes from the session's image, or at worst from one parse on the byte-only
/// compatibility path.
pub(super) fn elf_plt_stub_ranges(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
) -> Vec<std::ops::Range<u64>> {
    use object::{Object, ObjectSection};
    if !matches!(
        arch,
        BArch::ARM | BArch::AArch64 | BArch::X86 | BArch::X86_64
    ) {
        return Vec::new();
    }
    if let Some(image) = image {
        // The image's architecture came from the same parse that produced its
        // section index, so an image whose architecture disagrees with the
        // active decoder is the mismatched-caller case the byte path rejects.
        if image.arch() != arch {
            return Vec::new();
        }
        return image.plt_stub_ranges().to_vec();
    }
    if !data.starts_with(b"\x7fELF") {
        return Vec::new();
    }
    let Ok(object) = crate::decompile::profile::parse_object(data) else {
        return Vec::new();
    };
    let architecture_matches = matches!(
        (arch, object.architecture()),
        (BArch::ARM, object::Architecture::Arm)
            | (BArch::AArch64, object::Architecture::Aarch64)
            | (BArch::X86, object::Architecture::I386)
            | (BArch::X86_64, object::Architecture::X86_64)
    );
    if !architecture_matches {
        return Vec::new();
    }
    object
        .sections()
        .filter(|section| {
            matches!(
                section.name(),
                Ok(".plt" | ".plt.sec" | ".plt.got" | ".iplt")
            ) && section.size() != 0
        })
        .filter_map(|section| {
            let address = section.address();
            address.checked_add(section.size()).map(|end| address..end)
        })
        .collect()
}

/// Every PLT stub range, from the section table **and** from the relocations.
///
/// The union rather than a fallback: where both apply they agree, and a caller
/// that guesses which one to trust would have to know in advance whether the
/// image had been stripped.
pub(super) fn stub_ranges_including_unsectioned(
    image: Option<&crate::program::image::ProgramImage>,
    data: &[u8],
    arch: BArch,
) -> Vec<std::ops::Range<u64>> {
    let mut ranges = elf_plt_stub_ranges(image, data, arch);
    ranges.extend(crate::formats::elf::dynamic_segment::plt_stub_ranges(data));
    ranges
}
