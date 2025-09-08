//! BinaryView: deterministic view over a loaded image.
//!
//! Aggregates `core::binary::Binary` with sections/segments and basic
//! translation helpers between VA/RVA/FileOffset. This is intentionally
//! lightweight and does not perform any I/O itself.

use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;
use crate::core::binary::{Arch, Binary, Endianness, Format};
use crate::core::{Section, Segment};

/// Analysis-time container over the immutable Binary with layout data.
#[derive(Debug, Clone)]
pub struct BinaryView {
    /// Immutable descriptor of the program under analysis
    pub binary: Binary,
    /// Image base used for RVA <-> VA conversions when applicable
    pub image_base: Option<u64>,
    /// File sections (file/RVA view)
    pub sections: Vec<Section>,
    /// Memory segments (VA view)
    pub segments: Vec<Segment>,
    /// Optional overlay/trailer region (bytes beyond last mapped range)
    pub overlay: Option<AddressRange>,
}

impl BinaryView {
    /// Create a new BinaryView.
    pub fn new(
        binary: Binary,
        image_base: Option<u64>,
        sections: Vec<Section>,
        segments: Vec<Segment>,
        overlay: Option<AddressRange>,
    ) -> Self {
        Self {
            binary,
            image_base,
            sections,
            segments,
            overlay,
        }
    }

    /// Architecture of the underlying binary
    pub fn arch(&self) -> Arch {
        self.binary.arch
    }
    /// Endianness of the underlying binary
    pub fn endianness(&self) -> Endianness {
        self.binary.endianness
    }
    /// Executable format of the underlying binary
    pub fn format(&self) -> Format {
        self.binary.format
    }

    /// Convert a VA to a FileOffset using known segments.
    pub fn va_to_file_offset(&self, va: &Address) -> Option<Address> {
        if va.kind != AddressKind::VA {
            return None;
        }
        for seg in &self.segments {
            let start = seg.range.start.value;
            let size = seg.range.size;
            if va.value >= start && va.value < start.saturating_add(size) {
                let off_in_seg = va.value - start;
                let fo = seg.file_offset.value.saturating_add(off_in_seg);
                return Address::new(AddressKind::FileOffset, fo, va.bits, None, None).ok();
            }
        }
        None
    }

    /// Convert a FileOffset to VA using known segments.
    pub fn file_offset_to_va(&self, fo: &Address) -> Option<Address> {
        if fo.kind != AddressKind::FileOffset {
            return None;
        }
        for seg in &self.segments {
            let file_start = seg.file_offset.value;
            let size = seg.range.size;
            if fo.value >= file_start && fo.value < file_start.saturating_add(size) {
                let off_in_seg = fo.value - file_start;
                let va = seg.range.start.value.saturating_add(off_in_seg);
                return Address::new(AddressKind::VA, va, fo.bits, None, None).ok();
            }
        }
        None
    }

    /// Convert RVA to VA using image_base (if available).
    pub fn rva_to_va(&self, rva: &Address) -> Option<Address> {
        if rva.kind != AddressKind::RVA {
            return None;
        }
        let base = self.image_base?;
        Address::new(
            AddressKind::VA,
            base.saturating_add(rva.value),
            rva.bits,
            None,
            None,
        )
        .ok()
    }

    /// Convert VA to RVA using image_base (if available).
    pub fn va_to_rva(&self, va: &Address) -> Option<Address> {
        if va.kind != AddressKind::VA {
            return None;
        }
        let base = self.image_base?;
        if va.value < base {
            return None;
        }
        Address::new(AddressKind::RVA, va.value - base, va.bits, None, None).ok()
    }

    /// Provide a translator closure suitable for `SliceMemoryView`.
    pub fn translator(&self) -> impl Fn(&Address) -> Option<Address> + '_ {
        move |addr: &Address| match addr.kind {
            AddressKind::FileOffset => Some(addr.clone()),
            AddressKind::VA => self.va_to_file_offset(addr),
            AddressKind::RVA => self
                .rva_to_va(addr)
                .and_then(|va| self.va_to_file_offset(&va)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};
    use crate::core::address_range::AddressRange;
    use crate::core::section::{Section, SectionPerms};
    use crate::core::segment::{Perms, Segment};

    fn dummy_binary() -> Binary {
        Binary::new(
            "id".to_string(),
            "path".to_string(),
            Format::ELF,
            Arch::X86_64,
            64,
            Endianness::Little,
            vec![Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap()],
            0x2000,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn translate_va_fo_roundtrip() {
        // Segment: VA 0x400000..0x401000 mapped from FO 0x0000..0x1000
        let va_start = Address::new(AddressKind::VA, 0x400000, 64, None, None).unwrap();
        let seg_range = AddressRange::new(va_start.clone(), 0x1000, Some(0x1000)).unwrap();
        let fo_start = Address::new(AddressKind::FileOffset, 0x0, 64, None, None).unwrap();
        let seg = Segment::new(
            "text".to_string(),
            seg_range,
            Perms::new(true, false, true),
            fo_start,
            Some(".text".to_string()),
            Some(0x1000),
        )
        .unwrap();

        // Section (not used in translation here but part of view)
        let sec_range = AddressRange::new(
            Address::new(AddressKind::RVA, 0x0, 64, None, None).unwrap(),
            0x1000,
            Some(0x1000),
        )
        .unwrap();
        let section = Section::new(
            "text".to_string(),
            ".text".to_string(),
            sec_range,
            Address::new(AddressKind::FileOffset, 0x0, 64, None, None).unwrap(),
            Some(SectionPerms::new(true, false, true)),
            0,
            None,
        )
        .unwrap();

        let bv = BinaryView::new(
            dummy_binary(),
            Some(0x400000),
            vec![section],
            vec![seg],
            None,
        );

        let va = Address::new(AddressKind::VA, 0x400123, 64, None, None).unwrap();
        let fo = bv.va_to_file_offset(&va).unwrap();
        assert_eq!(fo.kind, AddressKind::FileOffset);
        assert_eq!(fo.value, 0x123);

        let back_va = bv.file_offset_to_va(&fo).unwrap();
        assert_eq!(back_va.kind, AddressKind::VA);
        assert_eq!(back_va.value, va.value);
    }

    #[test]
    fn rva_va_translation() {
        let bv = BinaryView::new(dummy_binary(), Some(0x400000), vec![], vec![], None);
        let rva = Address::new(AddressKind::RVA, 0x20, 64, None, None).unwrap();
        let va = bv.rva_to_va(&rva).unwrap();
        assert_eq!(va.value, 0x400020);
        let back_rva = bv.va_to_rva(&va).unwrap();
        assert_eq!(back_rva.value, 0x20);
    }
}
