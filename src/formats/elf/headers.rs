//! ELF header parsing

use crate::formats::elf::types::*;
use crate::formats::elf::utils::EndianRead;

/// Parse ELF identification bytes
pub fn parse_ident(data: &[u8]) -> Result<ElfIdent> {
    if data.len() < 16 {
        return Err(ElfError::Truncated {
            offset: 0,
            needed: 16,
        });
    }

    // Check magic
    if &data[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    let class = ElfClass::from_u8(data[4])?;
    let data_encoding = ElfData::from_u8(data[5])?;
    let version = data[6];
    let osabi = data[7];
    let abiversion = data[8];

    Ok(ElfIdent {
        class,
        data: data_encoding,
        version,
        osabi,
        abiversion,
    })
}

/// Parse ELF header
pub fn parse_header(data: &[u8]) -> Result<ElfHeader> {
    let ident = parse_ident(data)?;

    let header_size = match ident.class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };

    if data.len() < header_size {
        return Err(ElfError::Truncated {
            offset: 0,
            needed: header_size,
        });
    }

    let endian = ident.data;

    let e_type = data.read_u16(16, endian)?;
    let e_machine = data.read_u16(18, endian)?;
    let e_version = data.read_u32(20, endian)?;

    let (
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = match ident.class {
        ElfClass::Elf32 => {
            let e_entry = data.read_u32(24, endian)? as u64;
            let e_phoff = data.read_u32(28, endian)? as u64;
            let e_shoff = data.read_u32(32, endian)? as u64;
            let e_flags = data.read_u32(36, endian)?;
            let e_ehsize = data.read_u16(40, endian)?;
            let e_phentsize = data.read_u16(42, endian)?;
            let e_phnum = data.read_u16(44, endian)?;
            let e_shentsize = data.read_u16(46, endian)?;
            let e_shnum = data.read_u16(48, endian)?;
            let e_shstrndx = data.read_u16(50, endian)?;
            (
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            )
        }
        ElfClass::Elf64 => {
            let e_entry = data.read_u64(24, endian)?;
            let e_phoff = data.read_u64(32, endian)?;
            let e_shoff = data.read_u64(40, endian)?;
            let e_flags = data.read_u32(48, endian)?;
            let e_ehsize = data.read_u16(52, endian)?;
            let e_phentsize = data.read_u16(54, endian)?;
            let e_phnum = data.read_u16(56, endian)?;
            let e_shentsize = data.read_u16(58, endian)?;
            let e_shnum = data.read_u16(60, endian)?;
            let e_shstrndx = data.read_u16(62, endian)?;
            (
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            )
        }
    };

    // Validate header
    let expected_ehsize = match ident.class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };
    if e_ehsize as usize != expected_ehsize {
        return Err(ElfError::MalformedHeader(format!(
            "Invalid e_ehsize: expected {}, got {}",
            expected_ehsize, e_ehsize
        )));
    }

    let expected_phentsize = match ident.class {
        ElfClass::Elf32 => 32,
        ElfClass::Elf64 => 56,
    };
    if e_phnum > 0 && e_phentsize as usize != expected_phentsize {
        return Err(ElfError::MalformedHeader(format!(
            "Invalid e_phentsize: expected {}, got {}",
            expected_phentsize, e_phentsize
        )));
    }

    let expected_shentsize = match ident.class {
        ElfClass::Elf32 => 40,
        ElfClass::Elf64 => 64,
    };
    if e_shnum > 0 && e_shentsize as usize != expected_shentsize {
        return Err(ElfError::MalformedHeader(format!(
            "Invalid e_shentsize: expected {}, got {}",
            expected_shentsize, e_shentsize
        )));
    }

    Ok(ElfHeader {
        ident,
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf32_header() -> Vec<u8> {
        let mut data = vec![0u8; 52];
        // ELF magic
        data[0..4].copy_from_slice(b"\x7fELF");
        // 32-bit, little endian, version 1
        data[4] = 1; // ELFCLASS32
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT

        // e_type = ET_EXEC (2)
        data[16] = 2;
        data[17] = 0;
        // e_machine = EM_386 (3)
        data[18] = 3;
        data[19] = 0;
        // e_version = 1
        data[20] = 1;
        // e_ehsize = 52
        data[40] = 52;
        data[41] = 0;
        // e_phentsize = 32
        data[42] = 32;
        data[43] = 0;
        // e_shentsize = 40
        data[46] = 40;
        data[47] = 0;

        data
    }

    fn minimal_elf64_header() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        // ELF magic
        data[0..4].copy_from_slice(b"\x7fELF");
        // 64-bit, little endian, version 1
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT

        // e_type = ET_DYN (3)
        data[16] = 3;
        data[17] = 0;
        // e_machine = EM_X86_64 (62)
        data[18] = 62;
        data[19] = 0;
        // e_version = 1
        data[20] = 1;
        // e_ehsize = 64
        data[52] = 64;
        data[53] = 0;
        // e_phentsize = 56
        data[54] = 56;
        data[55] = 0;
        // e_shentsize = 64
        data[58] = 64;
        data[59] = 0;

        data
    }

    #[test]
    fn test_parse_ident() {
        let data = minimal_elf32_header();
        let ident = parse_ident(&data).unwrap();
        assert_eq!(ident.class, ElfClass::Elf32);
        assert_eq!(ident.data, ElfData::Little);
        assert_eq!(ident.version, 1);
    }

    #[test]
    fn test_parse_elf32_header() {
        let data = minimal_elf32_header();
        let header = parse_header(&data).unwrap();
        assert_eq!(header.e_type, 2); // ET_EXEC
        assert_eq!(header.e_machine, 3); // EM_386
        assert_eq!(header.e_ehsize, 52);
        assert_eq!(header.e_phentsize, 32);
        assert_eq!(header.e_shentsize, 40);
    }

    #[test]
    fn test_parse_elf64_header() {
        let data = minimal_elf64_header();
        let header = parse_header(&data).unwrap();
        assert_eq!(header.e_type, 3); // ET_DYN
        assert_eq!(header.e_machine, 62); // EM_X86_64
        assert_eq!(header.e_ehsize, 64);
        assert_eq!(header.e_phentsize, 56);
        assert_eq!(header.e_shentsize, 64);
        assert!(header.is_pie());
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = minimal_elf32_header();
        data[0] = 0xFF; // Invalid magic
        assert!(matches!(parse_header(&data), Err(ElfError::InvalidMagic)));
    }

    #[test]
    fn test_truncated_header() {
        let data = vec![0x7f, b'E', b'L', b'F']; // Only magic
        assert!(matches!(
            parse_ident(&data),
            Err(ElfError::Truncated { .. })
        ));
    }
}
