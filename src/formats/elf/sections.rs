//! Section table management

use crate::formats::elf::types::*;
use crate::formats::elf::utils::{read_cstring, EndianRead};
use std::collections::HashMap;

/// Section table for efficient section lookup
pub struct SectionTable<'a> {
    headers: Vec<SectionHeader>,
    strings: &'a [u8],
    data: &'a [u8],
    by_name: HashMap<String, usize>,
    #[allow(dead_code)]
    class: ElfClass,
    #[allow(dead_code)]
    endian: ElfData,
}

impl<'a> SectionTable<'a> {
    /// Parse section table from ELF data
    pub fn parse(data: &'a [u8], header: &ElfHeader) -> Result<Self> {
        let sh_offset = header.e_shoff as usize;
        let sh_entsize = header.e_shentsize as usize;
        let sh_num = header.e_shnum as usize;

        if sh_num == 0 || sh_offset == 0 {
            // No sections
            return Ok(Self {
                headers: Vec::new(),
                strings: &[],
                data,
                by_name: HashMap::new(),
                class: header.ident.class,
                endian: header.ident.data,
            });
        }

        // Check bounds
        let total_size = sh_num * sh_entsize;
        if sh_offset + total_size > data.len() {
            return Err(ElfError::Truncated {
                offset: sh_offset,
                needed: total_size,
            });
        }

        // Parse section headers
        let mut headers = Vec::with_capacity(sh_num);
        for i in 0..sh_num {
            let offset = sh_offset + i * sh_entsize;
            let sh_header =
                parse_section_header(data, offset, header.ident.class, header.ident.data)?;
            headers.push(sh_header);
        }

        // Get string table for section names
        let shstrndx = header.e_shstrndx as usize;
        let strings = if shstrndx < headers.len() {
            let str_header = &headers[shstrndx];
            let str_offset = str_header.sh_offset as usize;
            let str_size = str_header.sh_size as usize;
            if str_offset + str_size <= data.len() {
                &data[str_offset..str_offset + str_size]
            } else {
                &[]
            }
        } else {
            &[]
        };

        // Build name index
        let mut by_name = HashMap::new();
        for (i, sh) in headers.iter().enumerate() {
            if let Ok(name) = read_cstring(strings, sh.sh_name as usize) {
                by_name.insert(name.to_string(), i);
            }
        }

        Ok(Self {
            headers,
            strings,
            data,
            by_name,
            class: header.ident.class,
            endian: header.ident.data,
        })
    }

    /// Get section by name
    pub fn by_name(&self, name: &str) -> Option<Section<'a>> {
        self.by_name.get(name).and_then(|&idx| self.by_index(idx))
    }

    /// Get section by index
    pub fn by_index(&self, index: usize) -> Option<Section<'a>> {
        self.headers.get(index).map(|header| {
            let name = read_cstring(self.strings, header.sh_name as usize).unwrap_or("");
            let offset = header.sh_offset as usize;
            let size = header.sh_size as usize;
            let data = if offset + size <= self.data.len() {
                &self.data[offset..offset + size]
            } else {
                &[]
            };
            Section {
                header: *header,
                name,
                data,
            }
        })
    }

    /// Find section containing virtual address
    pub fn by_addr(&self, addr: u64) -> Option<Section<'a>> {
        for (i, header) in self.headers.iter().enumerate() {
            if header.sh_addr <= addr && addr < header.sh_addr + header.sh_size {
                return self.by_index(i);
            }
        }
        None
    }

    /// Get all sections
    pub fn sections(&self) -> impl Iterator<Item = Section<'a>> + '_ {
        (0..self.headers.len()).filter_map(move |i| self.by_index(i))
    }

    /// Count sections
    pub fn count(&self) -> usize {
        self.headers.len()
    }

    /// Check if any section has debug info
    pub fn has_debug_info(&self) -> bool {
        self.by_name.keys().any(|name| name.starts_with(".debug"))
    }

    /// Get executable sections
    pub fn executable_sections(&self) -> Vec<Section<'a>> {
        self.sections().filter(|s| s.is_executable()).collect()
    }

    /// Get writable sections
    pub fn writable_sections(&self) -> Vec<Section<'a>> {
        self.sections().filter(|s| s.is_writable()).collect()
    }
}

/// Parse a single section header
fn parse_section_header(
    data: &[u8],
    offset: usize,
    class: ElfClass,
    endian: ElfData,
) -> Result<SectionHeader> {
    match class {
        ElfClass::Elf32 => {
            if offset + 40 > data.len() {
                return Err(ElfError::Truncated { offset, needed: 40 });
            }
            Ok(SectionHeader {
                sh_name: data.read_u32(offset, endian)?,
                sh_type: data.read_u32(offset + 4, endian)?,
                sh_flags: data.read_u32(offset + 8, endian)? as u64,
                sh_addr: data.read_u32(offset + 12, endian)? as u64,
                sh_offset: data.read_u32(offset + 16, endian)? as u64,
                sh_size: data.read_u32(offset + 20, endian)? as u64,
                sh_link: data.read_u32(offset + 24, endian)?,
                sh_info: data.read_u32(offset + 28, endian)?,
                sh_addralign: data.read_u32(offset + 32, endian)? as u64,
                sh_entsize: data.read_u32(offset + 36, endian)? as u64,
            })
        }
        ElfClass::Elf64 => {
            if offset + 64 > data.len() {
                return Err(ElfError::Truncated { offset, needed: 64 });
            }
            Ok(SectionHeader {
                sh_name: data.read_u32(offset, endian)?,
                sh_type: data.read_u32(offset + 4, endian)?,
                sh_flags: data.read_u64(offset + 8, endian)?,
                sh_addr: data.read_u64(offset + 16, endian)?,
                sh_offset: data.read_u64(offset + 24, endian)?,
                sh_size: data.read_u64(offset + 32, endian)?,
                sh_link: data.read_u32(offset + 40, endian)?,
                sh_info: data.read_u32(offset + 44, endian)?,
                sh_addralign: data.read_u64(offset + 48, endian)?,
                sh_entsize: data.read_u64(offset + 56, endian)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::elf::headers::parse_header;

    fn create_test_elf_with_sections() -> Vec<u8> {
        let mut data = vec![0u8; 1024];

        // ELF header
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // Little endian
        data[6] = 1; // Version

        // e_type = ET_EXEC
        data[16] = 2;
        // e_machine = EM_X86_64
        data[18] = 62;
        // e_version = 1
        data[20] = 1;

        // e_shoff = 0x100 (section headers at offset 256)
        data[40] = 0x00;
        data[41] = 0x01;

        // e_ehsize = 64
        data[52] = 64;
        // e_phentsize = 56
        data[54] = 56;
        // e_shentsize = 64
        data[58] = 64;
        // e_shnum = 3
        data[60] = 3;
        // e_shstrndx = 2 (string table is section 2)
        data[62] = 2;

        // Section 0: NULL section (offset 0x100)
        // All zeros

        // Section 1: .text (offset 0x140)
        let sect1_offset = 0x100 + 64;
        data[sect1_offset] = 1; // sh_name = 1 (offset in string table)
        data[sect1_offset + 4] = 1; // sh_type = SHT_PROGBITS
        data[sect1_offset + 8] = 6; // sh_flags = SHF_ALLOC | SHF_EXECINSTR
                                    // sh_addr = 0x1000
        data[sect1_offset + 16] = 0x00;
        data[sect1_offset + 17] = 0x10;
        // sh_offset = 0x200
        data[sect1_offset + 24] = 0x00;
        data[sect1_offset + 25] = 0x02;
        // sh_size = 0x10
        data[sect1_offset + 32] = 0x10;

        // Section 2: .shstrtab (offset 0x180)
        let sect2_offset = 0x100 + 128;
        data[sect2_offset] = 7; // sh_name = 7
        data[sect2_offset + 4] = 3; // sh_type = SHT_STRTAB
                                    // sh_offset = 0x300
        data[sect2_offset + 24] = 0x00;
        data[sect2_offset + 25] = 0x03;
        // sh_size = 0x20
        data[sect2_offset + 32] = 0x20;

        // String table at 0x300
        let strtab_offset = 0x300;
        data[strtab_offset] = 0; // Empty string at offset 0
        let text_bytes = b".text\0";
        data[strtab_offset + 1..strtab_offset + 1 + text_bytes.len()].copy_from_slice(text_bytes);
        let shstrtab_bytes = b".shstrtab\0";
        data[strtab_offset + 7..strtab_offset + 7 + shstrtab_bytes.len()]
            .copy_from_slice(shstrtab_bytes);

        data
    }

    #[test]
    fn test_parse_section_table() {
        let data = create_test_elf_with_sections();
        let header = parse_header(&data).unwrap();
        let sections = SectionTable::parse(&data, &header).unwrap();

        assert_eq!(sections.count(), 3);

        // Check .text section
        let text = sections.by_name(".text").unwrap();
        assert_eq!(text.header.sh_type, SHT_PROGBITS);
        assert!(text.is_executable());
        assert_eq!(text.addr(), 0x1000);

        // Check .shstrtab section
        let shstrtab = sections.by_name(".shstrtab").unwrap();
        assert_eq!(shstrtab.header.sh_type, SHT_STRTAB);
    }

    #[test]
    fn test_section_by_addr() {
        let data = create_test_elf_with_sections();
        let header = parse_header(&data).unwrap();
        let sections = SectionTable::parse(&data, &header).unwrap();

        // Address in .text section
        let section = sections.by_addr(0x1008).unwrap();
        assert_eq!(section.name(), ".text");
    }
}
