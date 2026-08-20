//! Locate the unwind tables through `PT_GNU_EH_FRAME` rather than `.eh_frame`.
//!
//! `.eh_frame` is the strongest function-boundary evidence a stripped ELF
//! carries: every FDE `initial_location` is a real function entry and every
//! `address_range` is that function's exact byte length. Discovery uses it as a
//! trusted seed for exactly that reason.
//!
//! It is reached today by section name, and that makes it metadata-dependent in
//! a way the unwinder itself is not. The section header table is not read by
//! any loader — `execve` follows the program headers — so it is routinely
//! absent from the binaries an analyst most wants to look at. `sstrip` deletes
//! it outright and most packers emit `e_shnum == 0`, and at that point
//! `section_by_name(".eh_frame")` returns `None` and the seeds vanish silently.
//!
//! Measured on a corpus built from our own fixtures, two files whose executable
//! bytes are byte-identical:
//!
//! ```text
//! strip    seeds_initial=120   trusted_eh_frame=5   (97 FDEs read)
//! sstrip   seeds_initial=99    trusted_eh_frame=0   (0 FDEs read)
//! ```
//!
//! `libgcc`'s unwinder has never had this problem. `_Unwind_Find_FDE` asks
//! `dl_iterate_phdr` for the `PT_GNU_EH_FRAME` segment, which *is* the
//! `.eh_frame_hdr` bytes, and follows its `eh_frame_ptr` field to `.eh_frame`.
//! This module does what the unwinder does: it hands back the `.eh_frame_hdr`
//! bytes and can resolve any mapped address to the bytes at it, leaving the
//! actual DWARF pointer decoding to the caller that already owns a `gimli`
//! parser.
//!
//! # Why it stops at the segment end
//!
//! [`ProgramHeaderView::mapped_from`] returns bytes only up to the end of the
//! *file* image of the one loadable segment containing the address. It does not
//! run on into the next segment even when they are adjacent in the file, and it
//! never reports bytes past `p_filesz` — a `.bss`-style tail is mapped but not
//! present, and reading the file bytes that happen to follow it would be
//! reading another segment's data under this one's address.

use super::headers::parse_header;
use super::segments::SegmentTable;
use super::types::{ElfClass, PT_GNU_EH_FRAME};

/// One run of image bytes and the address its first byte is mapped at.
#[derive(Debug, Clone, Copy)]
pub struct MappedSpan<'a> {
    /// Virtual address of `bytes[0]`.
    pub address: u64,
    /// The bytes present in the file for this run.
    pub bytes: &'a [u8],
}

/// An ELF image seen the way a loader sees it: program headers only.
///
/// Deliberately says nothing about sections. Its whole purpose is to be
/// correct on images that have none, and a caller that could consult the
/// section table should — it is more precise when it is there.
pub struct ProgramHeaderView<'a> {
    data: &'a [u8],
    segments: SegmentTable<'a>,
    is_little_endian: bool,
    address_size: u8,
}

impl<'a> ProgramHeaderView<'a> {
    /// Parse the ELF and program headers, or `None` if they do not parse.
    ///
    /// Returns `None` rather than an error for every malformed input. This is a
    /// fallback path: a caller that gets nothing back is exactly as well off as
    /// it was before this module existed, whereas a caller that gets a wrong
    /// answer is worse off.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let header = parse_header(data).ok()?;
        let segments = SegmentTable::parse(data, &header).ok()?;
        Some(Self {
            data,
            segments,
            is_little_endian: header.ident.data.is_little_endian(),
            // `parse_header` rejects any `e_ident[EI_CLASS]` that is neither
            // 32- nor 64-bit, so an unrecognised width never reaches here.
            address_size: match header.ident.class {
                ElfClass::Elf64 => 8,
                ElfClass::Elf32 => 4,
            },
        })
    }

    /// Whether the image is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Pointer width in bytes, as DWARF pointer decoding needs it.
    pub fn address_size(&self) -> u8 {
        self.address_size
    }

    /// The `.eh_frame_hdr` bytes, located through `PT_GNU_EH_FRAME`.
    ///
    /// The segment *is* the section: the linker emits `PT_GNU_EH_FRAME` with
    /// exactly `.eh_frame_hdr`'s address and size. `None` when the image has no
    /// such segment (hand-written assembly, `-fno-asynchronous-unwind-tables`,
    /// a packer that dropped it) or when the file is too short to hold the
    /// bytes the header claims — a truncated image must not be read past its
    /// end.
    pub fn eh_frame_hdr(&self) -> Option<MappedSpan<'a>> {
        let segment = self
            .segments
            .segments()
            .find(|segment| segment.header.p_type == PT_GNU_EH_FRAME)?;
        let start = usize::try_from(segment.header.p_offset).ok()?;
        let len = usize::try_from(segment.header.p_filesz).ok()?;
        if len == 0 {
            return None;
        }
        let end = start.checked_add(len)?;
        Some(MappedSpan {
            address: segment.header.p_vaddr,
            bytes: self.data.get(start..end)?,
        })
    }

    /// The mapped bytes starting at `address`, to the end of their segment.
    ///
    /// Bounded by `p_filesz`, not `p_memsz`: bytes past the file image are
    /// zero-filled at load time and are not in the file at all, so the file
    /// bytes at those offsets belong to whatever the linker laid down next.
    pub fn mapped_from(&self, address: u64) -> Option<MappedSpan<'a>> {
        let segment = self.segments.load_segments().find(|segment| {
            let start = segment.header.p_vaddr;
            let file_end = start.saturating_add(segment.header.p_filesz);
            (start..file_end).contains(&address)
        })?;
        let within = address - segment.header.p_vaddr;
        let start = usize::try_from(segment.header.p_offset.checked_add(within)?).ok()?;
        let len = usize::try_from(segment.header.p_filesz - within).ok()?;
        let end = start.checked_add(len)?;
        Some(MappedSpan {
            address,
            bytes: self.data.get(start..end)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The corpus this was measured on, if it has been built.
    fn corpus(variant: &str) -> Option<Vec<u8>> {
        let path = format!(
            "{}/tests/realistic_corpus/build/corpus.{variant}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(path).ok()
    }

    /// The same `.eh_frame_hdr` bytes with and without a section header table.
    ///
    /// `sstrip` removes only the section headers, so `PT_GNU_EH_FRAME` and
    /// everything it addresses are byte-identical between the two files. If
    /// these spans ever differ, the segment path is reading something other
    /// than what the section path names.
    #[test]
    fn the_same_eh_frame_hdr_is_found_with_and_without_section_headers() {
        let (Some(sectioned), Some(sectionless)) = (corpus("strip"), corpus("sstrip")) else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        let with = ProgramHeaderView::parse(&sectioned).expect("stripped corpus parses");
        let without = ProgramHeaderView::parse(&sectionless).expect("sstripped corpus parses");
        let with_hdr = with.eh_frame_hdr().expect("PT_GNU_EH_FRAME present");
        let without_hdr = without
            .eh_frame_hdr()
            .expect("PT_GNU_EH_FRAME survives sstrip");
        assert_eq!(with_hdr.address, without_hdr.address);
        assert_eq!(with_hdr.bytes, without_hdr.bytes);
        assert_eq!(
            with_hdr.bytes[0], 1,
            ".eh_frame_hdr version byte should be 1"
        );
    }

    /// A span must stop at its own segment, not run into the next one.
    #[test]
    fn mapped_bytes_stop_at_the_end_of_their_segment() {
        let Some(data) = corpus("sstrip") else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        let view = ProgramHeaderView::parse(&data).expect("corpus parses");
        let hdr = view.eh_frame_hdr().expect("PT_GNU_EH_FRAME present");
        let span = view
            .mapped_from(hdr.address)
            .expect(".eh_frame_hdr is inside a PT_LOAD segment");
        assert_eq!(span.address, hdr.address);
        assert!(
            span.bytes.len() >= hdr.bytes.len(),
            "the segment containing .eh_frame_hdr must contain all of it"
        );
        assert_eq!(
            &span.bytes[..hdr.bytes.len()],
            hdr.bytes,
            "the same address must yield the same bytes by either route"
        );
        // The read-only segment on this corpus is 0xdc0 bytes at 0x3000, and
        // .eh_frame_hdr sits at 0x3138 — so a span from there is strictly
        // shorter than the rest of the file.
        assert!(
            span.bytes.len() < data.len() - hdr.bytes.len(),
            "a span that reaches the end of the file is not segment-bounded"
        );
    }

    /// An address in no loadable segment resolves to nothing.
    #[test]
    fn an_unmapped_address_resolves_to_nothing() {
        let Some(data) = corpus("sstrip") else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        let view = ProgramHeaderView::parse(&data).expect("corpus parses");
        assert!(view.mapped_from(u64::MAX).is_none());
        assert!(view.mapped_from(0xdead_beef_0000).is_none());
    }

    /// A file cut off after `.eh_frame_hdr` still refuses the `.eh_frame` it names.
    ///
    /// The nastier truncation than "the header is gone": here the header is
    /// entirely present and parses, so nothing upstream notices, and only the
    /// `p_filesz` bound on the target segment stops the read. Asserted as a
    /// pair — the header readable, the target not — because if the header ever
    /// stopped being readable at this length the test would still pass while
    /// checking nothing.
    #[test]
    fn a_complete_header_pointing_past_the_end_of_the_file_resolves_to_nothing() {
        let Some(full) = corpus("sstrip") else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        // `.eh_frame_hdr` is 0x3138..0x344c and `.eh_frame` begins at 0x3450.
        let truncated = &full[..0x3460];
        let view = ProgramHeaderView::parse(truncated).expect("headers are intact");
        let hdr = view
            .eh_frame_hdr()
            .expect("the whole .eh_frame_hdr is still present at this length");
        assert_eq!(hdr.bytes.len(), 0x314);
        assert!(
            view.mapped_from(0x3450).is_none(),
            ".eh_frame's segment runs to 0x3dc0 and the file stops at 0x3460, \
             so there are no bytes here to hand back"
        );
    }

    /// Nonsense in, nothing out — never a panic and never a wrong answer.
    #[test]
    fn malformed_input_yields_nothing_rather_than_a_guess() {
        assert!(ProgramHeaderView::parse(&[]).is_none());
        assert!(ProgramHeaderView::parse(b"not an elf at all").is_none());
    }

    /// A truncated file must not report bytes it does not contain.
    ///
    /// The program headers still describe an `.eh_frame_hdr` at 0x3138 after
    /// the file has been cut short of it, and this is the check that turns that
    /// into `None` instead of into whatever is at that offset.
    #[test]
    fn a_truncated_image_reports_no_eh_frame_hdr() {
        let Some(full) = corpus("sstrip") else {
            eprintln!("corpus not built; run tools/realistic_corpus.py");
            return;
        };
        for keep in [0x1000usize, 0x3000, 0x3140] {
            let Some(view) = ProgramHeaderView::parse(&full[..keep]) else {
                continue;
            };
            assert!(
                view.eh_frame_hdr().is_none(),
                "truncated to {keep:#x} bytes and still reported .eh_frame_hdr"
            );
        }
    }
}
