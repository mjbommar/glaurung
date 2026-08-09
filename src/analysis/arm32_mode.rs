//! Per-function ARM32 instruction-set selection.
//!
//! ARM ELF files can interleave A32 and Thumb code in the same executable.
//! The ELF mapping symbols (`$a` and `$t`) are authoritative when present.
//! Stripped binaries commonly remove those symbols, so fall back to decoding
//! the first instruction in both modes and select the only viable mode. When
//! both modes happen to decode, retaining Thumb as the fallback preserves the
//! pipeline's historic Cortex-M/modern armhf default.

use crate::analysis::entry::va_to_code_file_offset;
use crate::core::address::{Address, AddressKind};
use crate::core::binary::Endianness;
use crate::core::disassembler::{Architecture, Disassembler};
use crate::disasm::registry;
use object::{Object, ObjectSection, ObjectSymbol};

/// ARM32 instruction encoding used by one discovered function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arm32Mode {
    A32,
    Thumb,
}

fn mapping_symbol_mode(data: &[u8], va: u64) -> Option<Arm32Mode> {
    let object = crate::decompile::profile::parse_object(data).ok()?;
    let target_section = object.sections().find(|section| {
        let start = section.address();
        va >= start && va < start.saturating_add(section.size())
    })?;
    let target_index = target_section.index();

    object
        .symbols()
        .filter(|symbol| symbol.section_index() == Some(target_index) && symbol.address() <= va)
        .filter_map(|symbol| {
            let name = symbol.name().ok()?;
            let mode = if name == "$a" || name.starts_with("$a.") {
                Some(Arm32Mode::A32)
            } else if name == "$t" || name.starts_with("$t.") {
                Some(Arm32Mode::Thumb)
            } else if name == "$d" || name.starts_with("$d.") {
                None
            } else {
                return None;
            };
            Some((symbol.address(), mode))
        })
        .max_by_key(|(address, _mode)| *address)
        .and_then(|(_address, mode)| mode)
}

fn first_instruction_decodes(data: &[u8], va: u64, end: Endianness, thumb: bool) -> bool {
    let Some(file_offset) = va_to_code_file_offset(data, va) else {
        return false;
    };
    let Some(bytes) = data.get(file_offset..) else {
        return false;
    };
    let Some(mut backend) = registry::for_arch(Architecture::ARM, end) else {
        return false;
    };
    if backend.set_thumb_mode(thumb).is_err() {
        return false;
    }
    let Ok(address) = Address::new(AddressKind::VA, va, 32, None, None) else {
        return false;
    };
    backend.disassemble_instruction(&address, bytes).is_ok()
}

/// Select the instruction encoding at an ARM32 function entry.
pub(crate) fn mode_at(data: &[u8], va: u64, end: Endianness) -> Arm32Mode {
    if va & 1 != 0 {
        return Arm32Mode::Thumb;
    }
    if let Some(mode) = mapping_symbol_mode(data, va) {
        return mode;
    }

    let a32 = first_instruction_decodes(data, va, end, false);
    let thumb = first_instruction_decodes(data, va, end, true);
    match (a32, thumb) {
        (true, false) => Arm32Mode::A32,
        (false, true) => Arm32Mode::Thumb,
        _ => Arm32Mode::Thumb,
    }
}

/// Normalise an externally supplied ARM32 function entry address.
///
/// The ARM ELF ABI (IHI 0044, 4.5.3) encodes "this symbol names Thumb code" in
/// bit 0 of the symbol's *value*, so a Thumb function at `0x37c` has
/// `st_value == 0x37d`. That is the address every consumer of `.symtab` sees,
/// including anything that resolves a static callee by name — and passing it
/// through unchanged starts the decode one byte into the first instruction,
/// which produces a body with no recovered parameters at all.
///
/// The clearing is applied only to ARM32 ELF images: on every other target bit 0
/// of a function address is a real address bit. [`mode_at`] already reads the
/// same bit as evidence of Thumb state, so the two agree by construction.
pub fn normalise_entry(data: &[u8], va: u64) -> u64 {
    if va & 1 == 0 {
        return va;
    }
    let is_arm32_elf = crate::decompile::profile::parse_object(data).is_ok_and(|object| {
        object.format() == object::BinaryFormat::Elf
            && object.architecture() == object::Architecture::Arm
    });
    if is_arm32_elf {
        va & !1
    } else {
        va
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Thumb function's `.symtab` value carries the Thumb bit; the entry
    /// address it denotes is one lower. `main` in the checked-in armhf sample is
    /// recorded at `0x46d` and begins at `0x46c`.
    #[test]
    fn a_thumb_symbol_value_normalises_to_its_real_entry() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc");
        let data = std::fs::read(path).expect("read checked-in armhf sample");
        assert_eq!(normalise_entry(&data, 0x46d), 0x46c);
        assert_eq!(normalise_entry(&data, 0x5c5), 0x5c4);
        // An A32 entry has no Thumb bit and is already exact.
        assert_eq!(normalise_entry(&data, 0x4c8), 0x4c8);
    }

    /// Bit 0 is only a mode marker on ARM32. On any other target it is an
    /// ordinary address bit and clearing it would silently move the request.
    #[test]
    fn a_non_arm_image_keeps_every_address_bit() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/arm64/c2_demo-arm64-gcc");
        let data = std::fs::read(path).expect("read checked-in arm64 sample");
        assert_eq!(normalise_entry(&data, 0x8d1), 0x8d1);
        assert_eq!(normalise_entry(&[], 0x1235), 0x1235);
    }

    #[test]
    fn real_mixed_armhf_elf_uses_mapping_symbols_per_function() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross/armhf/hello-armhf-gcc");
        let data = std::fs::read(path).expect("read checked-in mixed ARM32 sample");

        assert_eq!(mode_at(&data, 0x3f4, Endianness::Little), Arm32Mode::A32);
        assert_eq!(mode_at(&data, 0x46c, Endianness::Little), Arm32Mode::Thumb);
        assert_eq!(mode_at(&data, 0x4fc, Endianness::Little), Arm32Mode::A32);
    }
}
