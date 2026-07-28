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
    let object = object::read::File::parse(data).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
