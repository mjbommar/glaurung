//! Dynamic section parsing

use crate::formats::elf::types::*;
use crate::formats::elf::utils::{read_cstring, EndianRead};
use std::collections::HashMap;

/// Dynamic section containing dynamic linking information
pub struct DynamicSection<'a> {
    entries: Vec<DynamicEntry>,
    strings: &'a [u8],
    #[allow(dead_code)]
    data: &'a [u8],
    by_tag: HashMap<i64, Vec<usize>>,
}

impl<'a> DynamicSection<'a> {
    /// Parse dynamic section from ELF data
    pub fn parse(
        data: &'a [u8],
        dynamic_section: &Section<'a>,
        strtab_section: Option<&Section<'a>>,
        class: ElfClass,
        endian: ElfData,
    ) -> Result<Self> {
        if dynamic_section.header.sh_type != SHT_DYNAMIC {
            return Err(ElfError::MalformedHeader(
                "Not a dynamic section".to_string(),
            ));
        }

        let entry_size = match class {
            ElfClass::Elf32 => 8,
            ElfClass::Elf64 => 16,
        };

        // Parse dynamic entries
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + entry_size <= dynamic_section.data.len() {
            let d_tag = match class {
                ElfClass::Elf32 => dynamic_section.data.read_i32(offset, endian)? as i64,
                ElfClass::Elf64 => dynamic_section.data.read_i64(offset, endian)?,
            };

            let d_val = match class {
                ElfClass::Elf32 => dynamic_section.data.read_u32(offset + 4, endian)? as u64,
                ElfClass::Elf64 => dynamic_section.data.read_u64(offset + 8, endian)?,
            };

            if d_tag == DT_NULL {
                break; // End of dynamic section
            }

            entries.push(DynamicEntry { d_tag, d_val });
            offset += entry_size;
        }

        // Build tag index
        let mut by_tag = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            by_tag.entry(entry.d_tag).or_insert_with(Vec::new).push(i);
        }

        // Get string table
        let strings = if let Some(strtab) = strtab_section {
            strtab.data
        } else {
            // Try to find string table from dynamic entries
            &[]
        };

        Ok(Self {
            entries,
            strings,
            data,
            by_tag,
        })
    }

    /// Get needed libraries (DT_NEEDED)
    pub fn needed_libraries(&self) -> Vec<&'a str> {
        self.entries
            .iter()
            .filter(|e| e.d_tag == DT_NEEDED)
            .filter_map(|e| read_cstring(self.strings, e.d_val as usize).ok())
            .collect()
    }

    /// Get RPATH
    pub fn rpath(&self) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_RPATH)
            .and_then(|e| read_cstring(self.strings, e.d_val as usize).ok())
    }

    /// Get RUNPATH
    pub fn runpath(&self) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_RUNPATH)
            .and_then(|e| read_cstring(self.strings, e.d_val as usize).ok())
    }

    /// Get SONAME
    pub fn soname(&self) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_SONAME)
            .and_then(|e| read_cstring(self.strings, e.d_val as usize).ok())
    }

    /// Get flags
    pub fn get_flags(&self) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_FLAGS)
            .map(|e| e.d_val)
    }

    /// Check if BIND_NOW is set
    pub fn is_bind_now(&self) -> bool {
        // Check DT_BIND_NOW tag
        if self.entries.iter().any(|e| e.d_tag == DT_BIND_NOW) {
            return true;
        }

        // Check DF_BIND_NOW flag
        if let Some(flags) = self.get_flags() {
            return (flags & DF_BIND_NOW) != 0;
        }

        false
    }

    /// Get INIT function address
    pub fn init_func(&self) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_INIT)
            .map(|e| e.d_val)
    }

    /// Get FINI function address
    pub fn fini_func(&self) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.d_tag == DT_FINI)
            .map(|e| e.d_val)
    }

    /// Get all entries
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    /// Get entries by tag
    pub fn entries_by_tag(&self, tag: i64) -> Vec<&DynamicEntry> {
        self.by_tag
            .get(&tag)
            .map(|indices| indices.iter().map(|&i| &self.entries[i]).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::elf::headers::parse_header;
    use crate::formats::elf::sections::SectionTable;

    fn create_test_elf_with_dynamic() -> Vec<u8> {
        let mut data = vec![0u8; 2048];

        // ELF header
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // Little endian
        data[6] = 1; // Version

        // e_type = ET_DYN
        data[16] = 3;
        // e_machine = EM_X86_64
        data[18] = 62;
        // e_version = 1
        data[20] = 1;

        // e_shoff = 0x100
        data[40] = 0x00;
        data[41] = 0x01;

        // e_ehsize = 64
        data[52] = 64;
        // e_shentsize = 64
        data[58] = 64;
        // e_shnum = 3
        data[60] = 3;
        // e_shstrndx = 2
        data[62] = 2;

        // Section headers start at 0x100

        // Section 1: .dynamic at 0x140
        let sect1_offset = 0x100 + 64;
        data[sect1_offset] = 1; // sh_name
        data[sect1_offset + 4] = SHT_DYNAMIC as u8;
        // sh_offset = 0x400
        data[sect1_offset + 24] = 0x00;
        data[sect1_offset + 25] = 0x04;
        // sh_size = 0x100
        data[sect1_offset + 32] = 0x00;
        data[sect1_offset + 33] = 0x01;
        // sh_link = 0 (would normally point to string table)
        // sh_entsize = 16
        data[sect1_offset + 56] = 16;

        // Section 2: .shstrtab at 0x180
        let sect2_offset = 0x100 + 128;
        data[sect2_offset] = 10; // sh_name
        data[sect2_offset + 4] = SHT_STRTAB as u8;
        // sh_offset = 0x300
        data[sect2_offset + 24] = 0x00;
        data[sect2_offset + 25] = 0x03;
        // sh_size = 0x40
        data[sect2_offset + 32] = 0x40;

        // String table at 0x300
        let strtab_offset = 0x300;
        data[strtab_offset] = 0;
        let dynamic_str = b".dynamic\0";
        data[strtab_offset + 1..strtab_offset + 1 + dynamic_str.len()].copy_from_slice(dynamic_str);
        let shstrtab_str = b".shstrtab\0";
        data[strtab_offset + 10..strtab_offset + 10 + shstrtab_str.len()]
            .copy_from_slice(shstrtab_str);

        // Dynamic section at 0x400
        let dyn_offset = 0x400;

        // DT_NEEDED = 1, value = 0 (offset in dynstr)
        data[dyn_offset] = 1; // DT_NEEDED
        data[dyn_offset + 8] = 0; // string offset

        // DT_SONAME = 14, value = 10
        data[dyn_offset + 16] = 14; // DT_SONAME
        data[dyn_offset + 24] = 10;

        // DT_RPATH = 15, value = 20
        data[dyn_offset + 32] = 15; // DT_RPATH
        data[dyn_offset + 40] = 20;

        // DT_NULL = 0 (terminator)
        // Already zeros

        // Dynamic string table at 0x500
        let dynstr_offset = 0x500;
        data[dynstr_offset] = 0;
        let libc_str = b"libc.so.6\0";
        data[dynstr_offset..dynstr_offset + libc_str.len()].copy_from_slice(libc_str);
        let libtest_str = b"libtest.so\0";
        data[dynstr_offset + 10..dynstr_offset + 10 + libtest_str.len()]
            .copy_from_slice(libtest_str);
        let rpath_str = b"/usr/lib\0";
        data[dynstr_offset + 20..dynstr_offset + 20 + rpath_str.len()].copy_from_slice(rpath_str);

        // Copy dynstr to the expected location (avoiding overlapping borrows)
        let temp: Vec<u8> = data[dynstr_offset..dynstr_offset + 0x40].to_vec();
        data[0x500..0x540].copy_from_slice(&temp);

        data
    }

    #[test]
    fn test_parse_dynamic_section() {
        let data = create_test_elf_with_dynamic();
        let header = parse_header(&data).unwrap();
        let sections = SectionTable::parse(&data, &header).unwrap();

        let dynamic_sect = sections.by_name(".dynamic").unwrap();

        // Create a fake string table section for testing
        let strtab_data = &data[0x500..0x540];
        let strtab_section = Section {
            header: SectionHeader {
                sh_name: 0,
                sh_type: SHT_STRTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0x500,
                sh_size: 0x40,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            },
            name: ".dynstr",
            data: strtab_data,
        };

        let dynamic = DynamicSection::parse(
            &data,
            &dynamic_sect,
            Some(&strtab_section),
            header.ident.class,
            header.ident.data,
        )
        .unwrap();

        // Check that we can find entries
        assert!(!dynamic.entries().is_empty());

        // Check for DT_NEEDED entries
        let needed = dynamic.needed_libraries();
        assert_eq!(needed.len(), 1);
        assert_eq!(needed[0], "libc.so.6");
    }
}
