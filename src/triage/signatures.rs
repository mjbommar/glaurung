//! Format signatures and magic numbers.
//!
//! Consolidates all format-specific signatures, magic numbers, and
//! architecture mappings used throughout the triage module.

use crate::core::binary::{Arch, Format};

/// Python bytecode magic numbers for different versions.
pub const PYTHON_MAGIC_NUMBERS: &[(u32, &str)] = &[
    (0x0A0D0D55, "Python 3.8"),
    (0x0A0D0D61, "Python 3.9"),
    (0x0A0D0D6F, "Python 3.10"),
    (0x0A0D0DA7, "Python 3.11"),
    (0x0A0D0DCB, "Python 3.12"),
    (0x0A0D0DF3, "Python 3.13"),
    (0x0D0D0A0D, "Python 3.7, 3.6"),
    (0x0D0D0A0C, "Python 3.5"),
    (0x0D0D0A0B, "Python 3.4 and older"),
];

/// Check if data contains Python bytecode magic number.
pub fn is_python_bytecode(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    for &(magic_num, version) in PYTHON_MAGIC_NUMBERS {
        if magic == magic_num {
            return Some(version);
        }
    }
    None
}

/// ELF machine types to architecture mapping.
pub fn elf_machine_to_arch(machine: u16) -> Arch {
    match machine {
        0x03 => Arch::X86,
        0x3E => Arch::X86_64,
        0x28 => Arch::ARM,
        0xB7 => Arch::AArch64,
        0x08 => Arch::MIPS,
        0xF3 => Arch::RISCV,
        0x14 => Arch::PPC,
        0x15 => Arch::PPC64,
        // Note: S390, SPARC not supported in core binary types
        _ => Arch::Unknown,
    }
}

/// PE machine types to architecture mapping.
pub fn pe_machine_to_arch(machine: u16) -> Arch {
    match machine {
        0x014C => Arch::X86,     // IMAGE_FILE_MACHINE_I386
        0x8664 => Arch::X86_64,  // IMAGE_FILE_MACHINE_AMD64
        0x01C0 => Arch::ARM,     // IMAGE_FILE_MACHINE_ARM
        0x01C4 => Arch::ARM,     // IMAGE_FILE_MACHINE_ARMNT
        0xAA64 => Arch::AArch64, // IMAGE_FILE_MACHINE_ARM64
        0x0166 => Arch::MIPS,    // IMAGE_FILE_MACHINE_MIPS16
        0x0266 => Arch::MIPS,    // IMAGE_FILE_MACHINE_MIPSFPU
        0x0366 => Arch::MIPS,    // IMAGE_FILE_MACHINE_MIPSFPU16
        _ => Arch::Unknown,
    }
}

/// Mach-O CPU types to architecture mapping.
pub fn macho_cpu_to_arch(cpu_type: u32) -> Arch {
    match cpu_type {
        7 => Arch::X86,              // CPU_TYPE_X86
        0x01000007 => Arch::X86_64,  // CPU_TYPE_X86_64
        12 => Arch::ARM,             // CPU_TYPE_ARM
        0x0100000C => Arch::AArch64, // CPU_TYPE_ARM64
        18 => Arch::PPC,             // CPU_TYPE_POWERPC
        0x01000012 => Arch::PPC64,   // CPU_TYPE_POWERPC64
        _ => Arch::Unknown,
    }
}

/// Common format conflicts for detection.
pub const FORMAT_CONFLICTS: &[(&str, &str)] = &[
    ("elf", "pe"),
    ("elf", "macho"),
    ("pe", "elf"),
    ("pe", "macho"),
    ("macho", "elf"),
    ("macho", "pe"),
    ("zip", "elf"),
    ("zip", "pe"),
    ("gzip", "elf"),
    ("tar", "elf"),
];

/// UPX packer signatures.
pub struct UPXSignatures {
    /// Main UPX signature pattern.
    pub main_signature: &'static [u8],
    /// Version patterns.
    pub version_patterns: Vec<(&'static [u8], &'static str)>,
}

impl Default for UPXSignatures {
    fn default() -> Self {
        Self {
            main_signature: b"UPX!",
            version_patterns: vec![
                (b"$Id: UPX 3.", "3.x"),
                (b"$Id: UPX 4.", "4.x"),
                (b"$Id: UPX 2.", "2.x"),
                (b"$Id: UPX 1.", "1.x"),
            ],
        }
    }
}

/// Common binary format magic numbers.
pub struct FormatMagic {
    pub elf: [u8; 4],
    pub pe_mz: [u8; 2],
    pub pe_signature: [u8; 4],
    pub macho_32: [u8; 4],
    pub macho_64: [u8; 4],
    pub macho_fat: [u8; 4],
    pub wasm: [u8; 4],
    pub zip: [u8; 4],
    pub gzip: [u8; 3],
    pub tar: Vec<Vec<u8>>,
    pub seven_zip: [u8; 6],
}

impl Default for FormatMagic {
    fn default() -> Self {
        Self {
            elf: [0x7F, b'E', b'L', b'F'],
            pe_mz: [b'M', b'Z'],
            pe_signature: [b'P', b'E', 0x00, 0x00],
            macho_32: [0xFE, 0xED, 0xFA, 0xCE],
            macho_64: [0xFE, 0xED, 0xFA, 0xCF],
            macho_fat: [0xCA, 0xFE, 0xBA, 0xBE],
            wasm: [0x00, b'a', b's', b'm'],
            zip: [b'P', b'K', 0x03, 0x04],
            gzip: [0x1F, 0x8B, 0x08],
            tar: vec![b"ustar".to_vec(), b"ustar ".to_vec(), b"ustar  ".to_vec()],
            seven_zip: [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C],
        }
    }
}

/// Quick format detection from magic bytes.
pub fn detect_format_from_magic(data: &[u8]) -> Option<Format> {
    let magic = FormatMagic::default();

    if data.len() >= 4 && data[0..4] == magic.elf {
        return Some(Format::ELF);
    }

    if data.len() >= 2 && data[0..2] == magic.pe_mz {
        return Some(Format::PE);
    }

    if data.len() >= 4 {
        let first_four = &data[0..4];
        if first_four == magic.macho_32
            || first_four == magic.macho_64
            || first_four == magic.macho_fat
        {
            return Some(Format::MachO);
        }
        if first_four == magic.wasm {
            return Some(Format::Wasm);
        }
    }

    if is_python_bytecode(data).is_some() {
        return Some(Format::PythonBytecode);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_bytecode_detection() {
        // Python 3.13 magic
        let data = &[0xF3, 0x0D, 0x0D, 0x0A];
        assert_eq!(is_python_bytecode(data), Some("Python 3.13"));

        // Python 3.11 magic
        let data = &[0xA7, 0x0D, 0x0D, 0x0A];
        assert_eq!(is_python_bytecode(data), Some("Python 3.11"));

        // Invalid magic
        let data = &[0x00, 0x00, 0x00, 0x00];
        assert_eq!(is_python_bytecode(data), None);
    }

    #[test]
    fn test_elf_machine_to_arch() {
        assert_eq!(elf_machine_to_arch(0x3E), Arch::X86_64);
        assert_eq!(elf_machine_to_arch(0x03), Arch::X86);
        assert_eq!(elf_machine_to_arch(0xB7), Arch::AArch64);
        assert_eq!(elf_machine_to_arch(0x9999), Arch::Unknown);
    }

    #[test]
    fn test_pe_machine_to_arch() {
        assert_eq!(pe_machine_to_arch(0x8664), Arch::X86_64);
        assert_eq!(pe_machine_to_arch(0x014C), Arch::X86);
        assert_eq!(pe_machine_to_arch(0xAA64), Arch::AArch64);
        assert_eq!(pe_machine_to_arch(0x9999), Arch::Unknown);
    }

    #[test]
    fn test_detect_format_from_magic() {
        // ELF magic
        let elf_data = &[0x7F, b'E', b'L', b'F'];
        assert_eq!(detect_format_from_magic(elf_data), Some(Format::ELF));

        // PE magic
        let pe_data = b"MZ";
        assert_eq!(detect_format_from_magic(pe_data), Some(Format::PE));

        // Python bytecode
        let pyc_data = &[0xF3, 0x0D, 0x0D, 0x0A];
        assert_eq!(
            detect_format_from_magic(pyc_data),
            Some(Format::PythonBytecode)
        );

        // Unknown
        let unknown_data = &[0x00, 0x00];
        assert_eq!(detect_format_from_magic(unknown_data), None);
    }
}
