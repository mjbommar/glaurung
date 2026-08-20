//! Address-ranged byte spans of an image, whether or not it has section headers.
//!
//! Several scans need "the mapped bytes, and the address they are mapped at":
//! the read-only code-pointer sweep that finds vtables, the jump-table reader,
//! and anything else looking for a table by address. They all reach for
//! `obj.sections()`, which is the natural spelling and is wrong for a whole
//! class of real input.
//!
//! A section header table is metadata. No loader reads it — `execve` follows
//! the program headers — so it is routinely absent from exactly the binaries an
//! analyst most wants to look at. `sstrip` deletes it outright, and UPX and
//! most other packers emit `e_shnum == 0`. When it is gone, `obj.sections()`
//! yields nothing at all and every section-driven scan quietly returns an empty
//! result: not an error, not a diagnostic, just zero findings on a file that
//! runs perfectly well.
//!
//! Measured on a section-header-less build of our own corpus whose executable
//! bytes are byte-identical to the merely-stripped one (same sha256 over the
//! executable segment, the two files differing by exactly the 2,240 bytes of
//! section headers and `.shstrtab`): function discovery was **43 against 105**,
//! because the `vtable` (91), `jump_table` (20) and `trusted_eh_frame` (5)
//! seeds all collapsed to zero.
//!
//! The loadable segments describe the same bytes at the same addresses, so this
//! module hands back sections when they exist and segments when they do not.
//! It is deliberately not a general "sections or segments" merge: mixing the
//! two would double-count every byte on an ordinary image, and the fallback is
//! only correct *because* it is a fallback.

use object::{Object, ObjectSection, ObjectSegment};

/// One addressable run of image bytes.
#[derive(Debug, Clone, Copy)]
pub struct Span<'data> {
    /// Virtual address the first byte is mapped at.
    pub address: u64,
    /// The mapped bytes themselves.
    pub bytes: &'data [u8],
}

/// Every addressable span of an image.
///
/// Prefers the section header table, which is more precise: it distinguishes
/// `.rodata` from `.text` from `.data`, and it excludes the ELF and program
/// headers that a segment-derived span necessarily includes. Falls back to the
/// loadable segments only when there are no sections at all, which is the
/// section-header-less case this module exists for.
///
/// Callers that care about a span's *permissions* must not use this — it
/// deliberately reports position and bytes only, because that is all a
/// table reader needs and anything more would differ between the two sources.
pub fn addressable_spans<'data>(object: &object::File<'data>) -> Vec<Span<'data>> {
    let sections: Vec<Span<'data>> = object
        .sections()
        .filter_map(|section| {
            Some(Span {
                address: section.address(),
                bytes: section.data().ok()?,
            })
        })
        .collect();
    if !sections.is_empty() {
        return sections;
    }
    object
        .segments()
        .filter_map(|segment| {
            let bytes = segment.data().ok()?;
            (!bytes.is_empty()).then_some(Span {
                address: segment.address(),
                bytes,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary image must be read through its sections, unchanged.
    ///
    /// The fallback is only sound as a fallback: segments overlap the sections
    /// they contain, so taking both would present the same byte at the same
    /// address twice and let a table reader find one table in two places.
    #[test]
    fn an_image_with_sections_is_read_through_them_and_not_through_its_segments() {
        let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2";
        let Ok(data) = std::fs::read(path) else {
            eprintln!("sample missing; skipping");
            return;
        };
        let object = object::File::parse(&*data).expect("sample parses");
        let section_count = object.sections().count();
        assert!(
            section_count > 0,
            "this sample is supposed to have sections"
        );
        assert_eq!(
            addressable_spans(&object).len(),
            object.sections().filter(|s| s.data().is_ok()).count(),
            "a sectioned image must report exactly its readable sections"
        );
    }

    /// With no section header table, the mapped bytes are still reachable.
    ///
    /// Built here rather than committed: a section-header-less ELF is four
    /// bytes of edit away from an ordinary one (`e_shoff`, `e_shnum`,
    /// `e_shentsize`, `e_shstrndx`), and generating it keeps the test honest
    /// about what it is actually asserting.
    #[test]
    fn an_image_with_no_section_headers_falls_back_to_its_loadable_segments() {
        let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2";
        let Ok(mut data) = std::fs::read(path) else {
            eprintln!("sample missing; skipping");
            return;
        };
        assert_eq!(&data[..4], b"\x7fELF", "sample is ELF");
        assert_eq!(data[4], 2, "sample is ELF64");

        // ELF64: e_shoff at 0x28 (8 bytes), e_shentsize 0x3a, e_shnum 0x3c,
        // e_shstrndx 0x3e. Zeroing them is exactly what `sstrip` does.
        data[0x28..0x30].fill(0);
        data[0x3a..0x40].fill(0);

        let object = object::File::parse(&*data).expect("a section-less ELF still parses");
        assert_eq!(
            object.sections().count(),
            0,
            "the section header table is supposed to be gone"
        );
        let spans = addressable_spans(&object);
        assert!(
            !spans.is_empty(),
            "an image with no section headers still maps bytes, and every \
             table-reading scan needs to be able to see them"
        );
        assert!(
            spans.iter().any(|s| s.address != 0 && !s.bytes.is_empty()),
            "the fallback must report real mapped addresses, not empty spans"
        );
    }
}
