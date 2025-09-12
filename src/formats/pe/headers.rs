//! PE header parsing

use crate::formats::pe::types::*;
use crate::formats::pe::utils::ReadExt;

/// Parse DOS header from data
pub fn parse_dos_header(data: &[u8]) -> Result<DosHeader> {
    if data.len() < 64 {
        return Err(PeError::TruncatedHeader {
            expected: 64,
            actual: data.len(),
        });
    }

    let e_magic = data.read_u16_le_at(0).unwrap();
    if e_magic != DOS_SIGNATURE {
        return Err(PeError::InvalidDosSignature);
    }

    Ok(DosHeader {
        e_magic,
        e_cblp: data.read_u16_le_at(2).unwrap(),
        e_cp: data.read_u16_le_at(4).unwrap(),
        e_crlc: data.read_u16_le_at(6).unwrap(),
        e_cparhdr: data.read_u16_le_at(8).unwrap(),
        e_minalloc: data.read_u16_le_at(10).unwrap(),
        e_maxalloc: data.read_u16_le_at(12).unwrap(),
        e_ss: data.read_u16_le_at(14).unwrap(),
        e_sp: data.read_u16_le_at(16).unwrap(),
        e_csum: data.read_u16_le_at(18).unwrap(),
        e_ip: data.read_u16_le_at(20).unwrap(),
        e_cs: data.read_u16_le_at(22).unwrap(),
        e_lfarlc: data.read_u16_le_at(24).unwrap(),
        e_ovno: data.read_u16_le_at(26).unwrap(),
        e_lfanew: data.read_u32_le_at(60).unwrap(),
    })
}

/// Parse COFF header from data at offset
pub fn parse_coff_header(data: &[u8], offset: usize) -> Result<CoffHeader> {
    if offset + 20 > data.len() {
        return Err(PeError::TruncatedHeader {
            expected: offset + 20,
            actual: data.len(),
        });
    }

    Ok(CoffHeader {
        machine: Machine::from(data.read_u16_le_at(offset).unwrap()),
        number_of_sections: data.read_u16_le_at(offset + 2).unwrap(),
        time_date_stamp: data.read_u32_le_at(offset + 4).unwrap(),
        pointer_to_symbol_table: data.read_u32_le_at(offset + 8).unwrap(),
        number_of_symbols: data.read_u32_le_at(offset + 12).unwrap(),
        size_of_optional_header: data.read_u16_le_at(offset + 16).unwrap(),
        characteristics: data.read_u16_le_at(offset + 18).unwrap(),
    })
}

/// Parse optional header from data at offset
pub fn parse_optional_header(data: &[u8], offset: usize, size: u16) -> Result<OptionalHeader> {
    if size < 2 {
        return Err(PeError::TruncatedHeader {
            expected: offset + 2,
            actual: data.len(),
        });
    }

    if offset + size as usize > data.len() {
        return Err(PeError::TruncatedHeader {
            expected: offset + size as usize,
            actual: data.len(),
        });
    }

    let magic = data.read_u16_le_at(offset).unwrap();

    match magic {
        PE32_MAGIC => parse_optional_header32(data, offset, size),
        PE32PLUS_MAGIC => parse_optional_header64(data, offset, size),
        _ => Err(PeError::InvalidMagic(magic)),
    }
}

fn parse_optional_header32(data: &[u8], offset: usize, size: u16) -> Result<OptionalHeader> {
    if size < 96 {
        return Err(PeError::TruncatedHeader {
            expected: offset + 96,
            actual: offset + size as usize,
        });
    }

    let common = OptionalHeaderCommon {
        magic: data.read_u16_le_at(offset).unwrap(),
        major_linker_version: data.read_u8_at(offset + 2).unwrap(),
        minor_linker_version: data.read_u8_at(offset + 3).unwrap(),
        size_of_code: data.read_u32_le_at(offset + 4).unwrap(),
        size_of_initialized_data: data.read_u32_le_at(offset + 8).unwrap(),
        size_of_uninitialized_data: data.read_u32_le_at(offset + 12).unwrap(),
        address_of_entry_point: data.read_u32_le_at(offset + 16).unwrap(),
        base_of_code: data.read_u32_le_at(offset + 20).unwrap(),
    };

    let header = OptionalHeader32 {
        common,
        base_of_data: data.read_u32_le_at(offset + 24).unwrap(),
        image_base: data.read_u32_le_at(offset + 28).unwrap(),
        section_alignment: data.read_u32_le_at(offset + 32).unwrap(),
        file_alignment: data.read_u32_le_at(offset + 36).unwrap(),
        major_operating_system_version: data.read_u16_le_at(offset + 40).unwrap(),
        minor_operating_system_version: data.read_u16_le_at(offset + 42).unwrap(),
        major_image_version: data.read_u16_le_at(offset + 44).unwrap(),
        minor_image_version: data.read_u16_le_at(offset + 46).unwrap(),
        major_subsystem_version: data.read_u16_le_at(offset + 48).unwrap(),
        minor_subsystem_version: data.read_u16_le_at(offset + 50).unwrap(),
        win32_version_value: data.read_u32_le_at(offset + 52).unwrap(),
        size_of_image: data.read_u32_le_at(offset + 56).unwrap(),
        size_of_headers: data.read_u32_le_at(offset + 60).unwrap(),
        checksum: data.read_u32_le_at(offset + 64).unwrap(),
        subsystem: Subsystem::from(data.read_u16_le_at(offset + 68).unwrap()),
        dll_characteristics: data.read_u16_le_at(offset + 70).unwrap(),
        size_of_stack_reserve: data.read_u32_le_at(offset + 72).unwrap(),
        size_of_stack_commit: data.read_u32_le_at(offset + 76).unwrap(),
        size_of_heap_reserve: data.read_u32_le_at(offset + 80).unwrap(),
        size_of_heap_commit: data.read_u32_le_at(offset + 84).unwrap(),
        loader_flags: data.read_u32_le_at(offset + 88).unwrap(),
        number_of_rva_and_sizes: data.read_u32_le_at(offset + 92).unwrap(),
    };

    Ok(OptionalHeader::Pe32(header))
}

fn parse_optional_header64(data: &[u8], offset: usize, size: u16) -> Result<OptionalHeader> {
    if size < 112 {
        return Err(PeError::TruncatedHeader {
            expected: offset + 112,
            actual: offset + size as usize,
        });
    }

    let common = OptionalHeaderCommon {
        magic: data.read_u16_le_at(offset).unwrap(),
        major_linker_version: data.read_u8_at(offset + 2).unwrap(),
        minor_linker_version: data.read_u8_at(offset + 3).unwrap(),
        size_of_code: data.read_u32_le_at(offset + 4).unwrap(),
        size_of_initialized_data: data.read_u32_le_at(offset + 8).unwrap(),
        size_of_uninitialized_data: data.read_u32_le_at(offset + 12).unwrap(),
        address_of_entry_point: data.read_u32_le_at(offset + 16).unwrap(),
        base_of_code: data.read_u32_le_at(offset + 20).unwrap(),
    };

    let header = OptionalHeader64 {
        common,
        image_base: data.read_u64_le_at(offset + 24).unwrap(),
        section_alignment: data.read_u32_le_at(offset + 32).unwrap(),
        file_alignment: data.read_u32_le_at(offset + 36).unwrap(),
        major_operating_system_version: data.read_u16_le_at(offset + 40).unwrap(),
        minor_operating_system_version: data.read_u16_le_at(offset + 42).unwrap(),
        major_image_version: data.read_u16_le_at(offset + 44).unwrap(),
        minor_image_version: data.read_u16_le_at(offset + 46).unwrap(),
        major_subsystem_version: data.read_u16_le_at(offset + 48).unwrap(),
        minor_subsystem_version: data.read_u16_le_at(offset + 50).unwrap(),
        win32_version_value: data.read_u32_le_at(offset + 52).unwrap(),
        size_of_image: data.read_u32_le_at(offset + 56).unwrap(),
        size_of_headers: data.read_u32_le_at(offset + 60).unwrap(),
        checksum: data.read_u32_le_at(offset + 64).unwrap(),
        subsystem: Subsystem::from(data.read_u16_le_at(offset + 68).unwrap()),
        dll_characteristics: data.read_u16_le_at(offset + 70).unwrap(),
        size_of_stack_reserve: data.read_u64_le_at(offset + 72).unwrap(),
        size_of_stack_commit: data.read_u64_le_at(offset + 80).unwrap(),
        size_of_heap_reserve: data.read_u64_le_at(offset + 88).unwrap(),
        size_of_heap_commit: data.read_u64_le_at(offset + 96).unwrap(),
        loader_flags: data.read_u32_le_at(offset + 104).unwrap(),
        number_of_rva_and_sizes: data.read_u32_le_at(offset + 108).unwrap(),
    };

    Ok(OptionalHeader::Pe32Plus(header))
}

/// Parse data directories from data at offset
pub fn parse_data_directories(
    data: &[u8],
    offset: usize,
    count: u32,
) -> Result<Vec<DataDirectory>> {
    let mut directories = Vec::new();
    let count = count.min(16); // Maximum 16 directories

    for i in 0..count {
        let dir_offset = offset + (i as usize * 8);
        if dir_offset + 8 > data.len() {
            break;
        }

        directories.push(DataDirectory {
            virtual_address: data.read_u32_le_at(dir_offset).unwrap(),
            size: data.read_u32_le_at(dir_offset + 4).unwrap(),
        });
    }

    // Pad with empty directories if needed
    while directories.len() < 16 {
        directories.push(DataDirectory::default());
    }

    Ok(directories)
}

/// Parse NT headers (PE signature + COFF + Optional)
pub fn parse_nt_headers(data: &[u8], offset: usize) -> Result<(NtHeaders, Vec<DataDirectory>)> {
    // Check PE signature
    if offset + 4 > data.len() {
        return Err(PeError::TruncatedHeader {
            expected: offset + 4,
            actual: data.len(),
        });
    }

    let signature = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];

    if signature != PE_SIGNATURE {
        return Err(PeError::InvalidPeSignature);
    }

    // Parse COFF header
    let coff_header = parse_coff_header(data, offset + 4)?;

    // Parse optional header
    let opt_offset = offset + 24; // 4 (signature) + 20 (COFF)
    let optional_header =
        parse_optional_header(data, opt_offset, coff_header.size_of_optional_header)?;

    // Parse data directories
    let dir_offset = opt_offset + coff_header.size_of_optional_header as usize
        - (optional_header.number_of_rva_and_sizes() * 8) as usize;
    let directories =
        parse_data_directories(data, dir_offset, optional_header.number_of_rva_and_sizes())?;

    let nt_headers = NtHeaders {
        signature,
        file_header: coff_header,
        optional_header,
    };

    Ok((nt_headers, directories))
}

/// Parse security features from DLL characteristics
pub fn parse_security_features(dll_characteristics: u16) -> SecurityFeatures {
    SecurityFeatures {
        high_entropy_va: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
        aslr_enabled: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
        force_integrity: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0,
        nx_compatible: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        dep_enabled: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
        isolation_aware: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) == 0,
        seh_enabled: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0,
        no_bind: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) != 0,
        appcontainer: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) != 0,
        wdm_driver: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) != 0,
        cfg_enabled: (dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
        terminal_server_aware: (dll_characteristics
            & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
            != 0,
        safe_seh: false, // Will be determined from load config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dos_header() {
        let mut data = vec![0u8; 64];
        // Set MZ signature
        data[0] = 0x4D;
        data[1] = 0x5A;
        // Set e_lfanew
        data[60] = 0x80;
        data[61] = 0x00;
        data[62] = 0x00;
        data[63] = 0x00;

        let header = parse_dos_header(&data).unwrap();
        assert_eq!(header.e_magic, DOS_SIGNATURE);
        assert_eq!(header.e_lfanew, 0x80);

        // Test invalid signature
        data[0] = 0xFF;
        assert!(matches!(
            parse_dos_header(&data),
            Err(PeError::InvalidDosSignature)
        ));

        // Test truncated
        let short_data = vec![0u8; 10];
        assert!(matches!(
            parse_dos_header(&short_data),
            Err(PeError::TruncatedHeader { .. })
        ));
    }

    #[test]
    fn test_parse_coff_header() {
        let mut data = vec![0u8; 100];
        let offset = 10;

        // Set machine type (x86)
        data[offset] = 0x4C;
        data[offset + 1] = 0x01;
        // Set number of sections
        data[offset + 2] = 0x05;
        data[offset + 3] = 0x00;
        // Set size of optional header
        data[offset + 16] = 0xE0;
        data[offset + 17] = 0x00;

        let header = parse_coff_header(&data, offset).unwrap();
        assert_eq!(header.machine, Machine::I386);
        assert_eq!(header.number_of_sections, 5);
        assert_eq!(header.size_of_optional_header, 0xE0);
    }

    #[test]
    fn test_parse_optional_header32() {
        let mut data = vec![0u8; 200];
        let offset = 0;

        // Set PE32 magic
        data[offset] = 0x0B;
        data[offset + 1] = 0x01;
        // Set entry point
        data[offset + 16] = 0x00;
        data[offset + 17] = 0x10;
        data[offset + 18] = 0x00;
        data[offset + 19] = 0x00;
        // Set image base
        data[offset + 28] = 0x00;
        data[offset + 29] = 0x00;
        data[offset + 30] = 0x40;
        data[offset + 31] = 0x00;
        // Set subsystem (Windows GUI)
        data[offset + 68] = 0x02;
        data[offset + 69] = 0x00;

        let header = parse_optional_header(&data, offset, 96).unwrap();
        match header {
            OptionalHeader::Pe32(h) => {
                assert_eq!(h.common.magic, PE32_MAGIC);
                assert_eq!(h.common.address_of_entry_point, 0x1000);
                assert_eq!(h.image_base, 0x400000);
                assert_eq!(h.subsystem, Subsystem::WindowsGui);
            }
            _ => panic!("Expected PE32 header"),
        }
    }

    #[test]
    fn test_parse_optional_header64() {
        let mut data = vec![0u8; 200];
        let offset = 0;

        // Set PE32+ magic
        data[offset] = 0x0B;
        data[offset + 1] = 0x02;
        // Set entry point
        data[offset + 16] = 0x00;
        data[offset + 17] = 0x20;
        data[offset + 18] = 0x00;
        data[offset + 19] = 0x00;
        // Set image base (64-bit) - 0x140000000
        data[offset + 24] = 0x00;
        data[offset + 25] = 0x00;
        data[offset + 26] = 0x00;
        data[offset + 27] = 0x40;
        data[offset + 28] = 0x01;
        data[offset + 29] = 0x00;
        data[offset + 30] = 0x00;
        data[offset + 31] = 0x00;

        let header = parse_optional_header(&data, offset, 112).unwrap();
        match header {
            OptionalHeader::Pe32Plus(h) => {
                assert_eq!(h.common.magic, PE32PLUS_MAGIC);
                assert_eq!(h.common.address_of_entry_point, 0x2000);
                assert_eq!(h.image_base, 0x140000000);
            }
            _ => panic!("Expected PE32+ header"),
        }
    }

    #[test]
    fn test_parse_security_features() {
        let features = parse_security_features(0);
        assert!(!features.aslr_enabled);
        assert!(!features.nx_compatible);
        assert!(features.seh_enabled);

        let features = parse_security_features(
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                | IMAGE_DLLCHARACTERISTICS_GUARD_CF,
        );
        assert!(features.aslr_enabled);
        assert!(features.nx_compatible);
        assert!(features.dep_enabled);
        assert!(features.cfg_enabled);
    }
}
