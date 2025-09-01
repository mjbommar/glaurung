//! Header validation and minimal parsing.
//!
//! Fast magic checks and header validation for ELF, PE, Mach-O, Wasm
//! with precise error reporting.
use crate::core::binary::{Arch, Endianness, Format};
use crate::core::triage::{TriageError, TriageErrorKind, TriageVerdict};

pub struct HeaderResult {
    pub candidates: Vec<TriageVerdict>,
    pub errors: Vec<TriageError>,
}

pub fn validate(data: &[u8]) -> HeaderResult {
    let mut candidates = Vec::new();
    let mut errors = Vec::new();

    // ELF detailed checks
    if data.len() >= 4 && &data[..4] == b"\x7FELF" {
        if data.len() < 0x34 {
            errors.push(TriageError::new(
                TriageErrorKind::ShortRead,
                Some("ELF header too short".into()),
            ));
        }

        let class = data.get(4).copied().unwrap_or(1); // 1=32,2=64
        let bits = if class == 2 { 64 } else { 32 };
        let data_enc = data.get(5).copied().unwrap_or(1); // 1=little,2=big
        let end = if data_enc == 2 {
            Endianness::Big
        } else {
            Endianness::Little
        };

        // Basic structural sanity (e_ehsize/e_phentsize/e_shentsize)
        let mut confidence = 0.8f32;
        let (ehsize_off, phentsize_off, shentsize_off) = if bits == 64 {
            (0x34, 0x36, 0x3A)
        } else {
            (0x28, 0x2A, 0x2E)
        };
        if data.len() > shentsize_off + 1 {
            let read_u16 = |off: usize| -> u16 {
                if end == Endianness::Little {
                    u16::from_le_bytes([data[off], data[off + 1]])
                } else {
                    u16::from_be_bytes([data[off], data[off + 1]])
                }
            };
            let ehsize = read_u16(ehsize_off);
            let phentsize = read_u16(phentsize_off);
            let shentsize = read_u16(shentsize_off);
            let (exp_eh, exp_ph, exp_sh) = if bits == 64 {
                (64, 56, 64)
            } else {
                (52, 32, 40)
            };
            if ehsize as u32 != exp_eh || phentsize as u32 != exp_ph || shentsize as u32 != exp_sh {
                errors.push(TriageError::new(
                    TriageErrorKind::IncoherentFields,
                    Some("ELF header sizes unexpected".into()),
                ));
                confidence = 0.6;
            }
        }

        // Table bounds (program/section headers)
        let read_u16 = |off: usize| -> u16 {
            if end == Endianness::Little {
                u16::from_le_bytes([data[off], data[off + 1]])
            } else {
                u16::from_be_bytes([data[off], data[off + 1]])
            }
        };
        let (mut e_phoff, mut e_shoff, mut e_phnum, mut e_shnum) = (0u64, 0u64, 0u64, 0u64);
        if bits == 64 && data.len() >= 0x40 {
            let bph = [
                data[0x20], data[0x21], data[0x22], data[0x23], data[0x24], data[0x25], data[0x26],
                data[0x27],
            ];
            let bsh = [
                data[0x28], data[0x29], data[0x2A], data[0x2B], data[0x2C], data[0x2D], data[0x2E],
                data[0x2F],
            ];
            e_phoff = if end == Endianness::Little {
                u64::from_le_bytes(bph)
            } else {
                u64::from_be_bytes(bph)
            };
            e_shoff = if end == Endianness::Little {
                u64::from_le_bytes(bsh)
            } else {
                u64::from_be_bytes(bsh)
            };
            e_phnum = read_u16(0x38) as u64;
            e_shnum = read_u16(0x3C) as u64;
        } else if bits == 32 && data.len() >= 0x34 {
            let bph = [data[0x1C], data[0x1D], data[0x1E], data[0x1F]];
            let bsh = [data[0x20], data[0x21], data[0x22], data[0x23]];
            e_phoff = if end == Endianness::Little {
                u32::from_le_bytes(bph) as u64
            } else {
                u32::from_be_bytes(bph) as u64
            };
            e_shoff = if end == Endianness::Little {
                u32::from_le_bytes(bsh) as u64
            } else {
                u32::from_be_bytes(bsh) as u64
            };
            e_phnum = read_u16(0x2C) as u64;
            e_shnum = read_u16(0x30) as u64;
        }
        let phentsize = if bits == 64 { 56 } else { 32 } as u64;
        let shentsize = if bits == 64 { 64 } else { 40 } as u64;
        if e_phoff > 0 && e_phnum > 0 {
            let end_off = e_phoff.saturating_add(e_phnum.saturating_mul(phentsize));
            if end_off as usize > data.len() {
                errors.push(TriageError::new(
                    TriageErrorKind::Truncated,
                    Some("ELF program headers truncated".into()),
                ));
                confidence = confidence.min(0.6);
            }
        }
        if e_shoff > 0 && e_shnum > 0 {
            let end_off = e_shoff.saturating_add(e_shnum.saturating_mul(shentsize));
            if end_off as usize > data.len() {
                errors.push(TriageError::new(
                    TriageErrorKind::Truncated,
                    Some("ELF section headers truncated".into()),
                ));
                confidence = confidence.min(0.6);
            }
        }

        // Arch mapping from e_machine (best-effort)
        let em = if data.len() > 0x13 {
            if end == Endianness::Little {
                u16::from_le_bytes([data[0x12], data[0x13]])
            } else {
                u16::from_be_bytes([data[0x12], data[0x13]])
            }
        } else {
            0
        };
        let arch = match em {
            0x03 => Arch::X86,
            0x3E => Arch::X86_64,
            0x28 => Arch::ARM,
            0xB7 => Arch::AArch64,
            _ => {
                if bits == 64 {
                    Arch::X86_64
                } else {
                    Arch::X86
                }
            }
        };
        if let Ok(v) = TriageVerdict::try_new(Format::ELF, arch, bits, end, confidence, None) {
            candidates.push(v);
        }
    }

    // PE/COFF detailed checks
    if data.len() >= 0x40 && &data[..2] == b"MZ" {
        let e_lfanew =
            u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if e_lfanew + 0x18 >= data.len() {
            errors.push(TriageError::new(
                TriageErrorKind::Truncated,
                Some("PE header (e_lfanew) points beyond data".into()),
            ));
        } else if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            errors.push(TriageError::new(
                TriageErrorKind::BadMagic,
                Some("Missing PE\0\0 signature".into()),
            ));
        } else {
            // FileHeader
            let machine_off = e_lfanew + 4;
            let number_of_sections_off = e_lfanew + 6;
            let opt_magic_off = e_lfanew + 0x18; // OptionalHeader.Magic
            let machine = u16::from_le_bytes([data[machine_off], data[machine_off + 1]]);
            let num_sections = u16::from_le_bytes([
                data[number_of_sections_off],
                data[number_of_sections_off + 1],
            ]);
            let opt_magic = u16::from_le_bytes([data[opt_magic_off], data[opt_magic_off + 1]]);

            if num_sections == 0 || num_sections > 96 {
                errors.push(TriageError::new(
                    TriageErrorKind::IncoherentFields,
                    Some("Unreasonable NumberOfSections".into()),
                ));
            }

            let (bits, arch) = match (machine, opt_magic) {
                (0x8664, 0x20B) => (64, Arch::X86_64),  // AMD64 PE32+
                (0x14C, 0x10B) => (32, Arch::X86),      // I386 PE32
                (0xAA64, 0x20B) => (64, Arch::AArch64), // ARM64 PE32+
                (0x1C0, 0x10B) => (32, Arch::ARM),      // ARM PE32
                _ => (32, Arch::Unknown),
            };
            let mut conf = 0.7f32;
            if arch == Arch::Unknown {
                conf = 0.6;
                errors.push(TriageError::new(
                    TriageErrorKind::UnsupportedVariant,
                    Some(format!(
                        "PE Machine=0x{:x} OptionalMagic=0x{:x}",
                        machine, opt_magic
                    )),
                ));
            }
            // Optional header bounds and section table bounds
            let size_opt_off = e_lfanew + 4 + 16; // FileHeader.SizeOfOptionalHeader
            if size_opt_off + 2 <= data.len() {
                let size_opt =
                    u16::from_le_bytes([data[size_opt_off], data[size_opt_off + 1]]) as usize;
                let sec_table_off = e_lfanew + 4 + 20 + size_opt;
                let sec_table_size = (num_sections as usize).saturating_mul(40);
                if sec_table_off + sec_table_size > data.len() {
                    errors.push(TriageError::new(
                        TriageErrorKind::Truncated,
                        Some("PE section table truncated".into()),
                    ));
                    conf = conf.min(0.6);
                }
                // SizeOfOptionalHeader plausibility baseline
                let min_opt = if opt_magic == 0x20B { 0xF0 } else { 0xE0 };
                if size_opt < min_opt {
                    errors.push(TriageError::new(
                        TriageErrorKind::IncoherentFields,
                        Some("PE SizeOfOptionalHeader too small".into()),
                    ));
                    conf = conf.min(0.6);
                }
                // SizeOfHeaders at OptionalHeader + 0x3C
                let size_headers_off = (opt_magic_off).saturating_add(0x3C);
                if size_headers_off + 4 <= data.len() {
                    let so = u32::from_le_bytes([
                        data[size_headers_off],
                        data[size_headers_off + 1],
                        data[size_headers_off + 2],
                        data[size_headers_off + 3],
                    ]) as usize;
                    let min_headers = sec_table_off; // should cover all headers up to section table
                    if so < min_headers || so > data.len() {
                        errors.push(TriageError::new(
                            TriageErrorKind::IncoherentFields,
                            Some("PE SizeOfHeaders out of bounds".into()),
                        ));
                        conf = conf.min(0.6);
                    }
                }
            }
            if let Ok(v) =
                TriageVerdict::try_new(Format::PE, arch, bits, Endianness::Little, conf, None)
            {
                candidates.push(v);
            }
        }
    }

    // Mach-O (both endiannesses), not including FAT here
    if data.len() >= 4 {
        let m = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        // Big-endian view
        match m {
            0xFEEDFACE => {
                if let Ok(v) = TriageVerdict::try_new(
                    Format::MachO,
                    Arch::Unknown,
                    32,
                    Endianness::Big,
                    0.6,
                    None,
                ) {
                    candidates.push(v);
                }
            }
            0xFEEDFACF => {
                if let Ok(v) = TriageVerdict::try_new(
                    Format::MachO,
                    Arch::Unknown,
                    64,
                    Endianness::Big,
                    0.6,
                    None,
                ) {
                    candidates.push(v);
                }
            }
            0xCAFEBABE | 0xBEBAFECA => {
                // FAT binaries are a future enhancement; surface as Mach-O container later
            }
            _ => {
                // Little-endian view of magic
                let ml = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                match ml {
                    0xFEEDFACE => {
                        if let Ok(v) = TriageVerdict::try_new(
                            Format::MachO,
                            Arch::Unknown,
                            32,
                            Endianness::Little,
                            0.6,
                            None,
                        ) {
                            candidates.push(v);
                        }
                    }
                    0xFEEDFACF => {
                        if let Ok(v) = TriageVerdict::try_new(
                            Format::MachO,
                            Arch::Unknown,
                            64,
                            Endianness::Little,
                            0.6,
                            None,
                        ) {
                            candidates.push(v);
                        }
                    }
                    _ => {}
                }
            }
        }
        // WebAssembly 0x00 61 73 6D + version
        if data.len() >= 8 && data[..4] == [0x00, b'a', b's', b'm'] {
            let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            let mut conf = 0.6;
            if version >= 1 {
                conf = 0.75;
            }
            if let Ok(v) = TriageVerdict::try_new(
                Format::Wasm,
                Arch::Unknown,
                32,
                Endianness::Little,
                conf,
                None,
            ) {
                candidates.push(v);
            }
        }
    }

    // Python bytecode (.pyc) – many versions use 2-byte magic followed by CR/LF in bytes 2..4
    if data.len() >= 4 {
        let tail = (data[2], data[3]);
        if tail == (0x0D, 0x0A) || tail == (0x0D, 0x0D) {
            if let Ok(v) = TriageVerdict::try_new(
                Format::PythonBytecode,
                Arch::Unknown,
                32,
                Endianness::Little,
                0.8,
                None,
            ) {
                candidates.push(v);
            }
        }
    }

    // Python bytecode (.pyc) – validate header layout for 3.3+ and 3.7+ (PEP 552)
    // Layout (3.3..3.6): [magic(4)] [timestamp(4)] [source_size(4)]
    // Layout (3.7+ PEP 552): [magic(4)] [bitfield(4)] [hash(8)|timestamp(4)] [source_size(4)]
    if data.len() >= 4 {
        let magic_tail = (data[2], data[3]);
        if magic_tail == (0x0D, 0x0A) || magic_tail == (0x0D, 0x0D) {
            // Looks like CPython magic: accept as PythonBytecode and validate header sizing
            let mut confidence = 0.8f32;
            // Try PEP 552 first when large enough
            if data.len() >= 20 {
                let bit_field = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                let hash_based = (bit_field & 0x01) != 0;
                let required = if hash_based {
                    4 + 4 + 8 + 4
                } else {
                    4 + 4 + 4 + 4
                };
                if data.len() < required {
                    errors.push(TriageError::new(
                        TriageErrorKind::Truncated,
                        Some("PYC header indicates hash-based but data is too short".into()),
                    ));
                    confidence = 0.6;
                }
            } else if data.len() >= 12 {
                // 3.3..3.6 minimal header size
            } else {
                errors.push(TriageError::new(
                    TriageErrorKind::ShortRead,
                    Some("PYC header too short (< 12 bytes)".into()),
                ));
                confidence = 0.5;
            }

            if let Ok(v) = TriageVerdict::try_new(
                Format::PythonBytecode,
                Arch::Unknown,
                32,
                Endianness::Little,
                confidence,
                None,
            ) {
                candidates.push(v);
            }
        }
    }

    // No candidates on obvious garbage
    if candidates.is_empty() && !data.is_empty() {
        // Not an error; only record error on truncation
        if data.len() < 2 {
            errors.push(TriageError::new(
                TriageErrorKind::ShortRead,
                Some("Too short for header".into()),
            ));
        }
    }

    HeaderResult { candidates, errors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn elf_and_pyc_detection_on_real_samples() {
        // ELF
        let elf_path = "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release";
        if let Ok(d) = fs::read(elf_path) {
            let hr = validate(&d);
            assert!(hr.candidates.iter().any(|v| v.format == Format::ELF));
        }
        // Python bytecode (pyc)
        let pyc_path = "samples/binaries/platforms/linux/amd64/export/python/hello.pyc";
        if let Ok(d) = fs::read(pyc_path) {
            let hr = validate(&d);
            assert!(hr
                .candidates
                .iter()
                .any(|v| v.format == Format::PythonBytecode));
        }
    }
}
