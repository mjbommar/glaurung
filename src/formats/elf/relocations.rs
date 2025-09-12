//! Relocation processing

use crate::formats::elf::symbols::SymbolTable;
use crate::formats::elf::types::*;
use crate::formats::elf::utils::EndianRead;
use std::collections::HashMap;

/// Relocation table with GOT and PLT mappings
pub struct RelocationTable {
    relocations: Vec<Relocation>,
    got_map: HashMap<u64, String>,
    plt_map: HashMap<u64, String>,
    is_rela: bool,
}

impl RelocationTable {
    /// Parse relocations from section data
    pub fn parse(
        rel_data: &[u8],
        symbols: &SymbolTable,
        section_type: u32,
        class: ElfClass,
        endian: ElfData,
    ) -> Result<Self> {
        let is_rela = section_type == SHT_RELA;
        let entry_size = match (class, is_rela) {
            (ElfClass::Elf32, false) => 8,  // Elf32_Rel
            (ElfClass::Elf32, true) => 12,  // Elf32_Rela
            (ElfClass::Elf64, false) => 16, // Elf64_Rel
            (ElfClass::Elf64, true) => 24,  // Elf64_Rela
        };

        let mut relocations = Vec::new();
        let mut offset = 0;

        while offset + entry_size <= rel_data.len() {
            let reloc = parse_relocation(&rel_data[offset..], class, endian, is_rela)?;
            relocations.push(reloc);
            offset += entry_size;
        }

        let mut table = Self {
            relocations,
            got_map: HashMap::new(),
            plt_map: HashMap::new(),
            is_rela,
        };

        // Build GOT map
        table.build_got_map(symbols);

        Ok(table)
    }

    /// Build GOT map from relocations
    fn build_got_map(&mut self, symbols: &SymbolTable) {
        for reloc in &self.relocations {
            let sym_idx = reloc.symbol_index();
            if let Some(symbol) = symbols.by_index(sym_idx as usize) {
                if let Some(name) = symbols.symbol_name(symbol) {
                    self.got_map.insert(reloc.r_offset, name.to_string());
                }
            }
        }
    }

    /// Build PLT map from .rela.plt section
    pub fn build_plt_map(&mut self, plt_addr: u64, plt_entry_size: u64, symbols: &SymbolTable) {
        // Skip PLT[0] which is reserved
        let mut current_addr = plt_addr + plt_entry_size;

        for reloc in &self.relocations {
            let sym_idx = reloc.symbol_index();
            if let Some(symbol) = symbols.by_index(sym_idx as usize) {
                if let Some(name) = symbols.symbol_name(symbol) {
                    self.plt_map.insert(current_addr, name.to_string());
                    current_addr += plt_entry_size;
                }
            }
        }
    }

    /// Get GOT entries
    pub fn got_entries(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.got_map
            .iter()
            .map(|(&addr, name)| (addr, name.as_str()))
    }

    /// Get PLT entries
    pub fn plt_entries(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.plt_map
            .iter()
            .map(|(&addr, name)| (addr, name.as_str()))
    }

    /// Get relocation at address
    pub fn by_offset(&self, offset: u64) -> Option<&Relocation> {
        self.relocations.iter().find(|r| r.r_offset == offset)
    }

    /// Count relocations
    pub fn count(&self) -> usize {
        self.relocations.len()
    }

    /// Check if using RELA format
    pub fn is_rela(&self) -> bool {
        self.is_rela
    }
}

/// Parse a single relocation entry
fn parse_relocation(
    data: &[u8],
    class: ElfClass,
    endian: ElfData,
    is_rela: bool,
) -> Result<Relocation> {
    match class {
        ElfClass::Elf32 => {
            let r_offset = data.read_u32(0, endian)? as u64;
            let r_info = data.read_u32(4, endian)? as u64;
            let r_addend = if is_rela {
                data.read_i32(8, endian)? as i64
            } else {
                0
            };
            Ok(Relocation {
                r_offset,
                r_info,
                r_addend,
            })
        }
        ElfClass::Elf64 => {
            let r_offset = data.read_u64(0, endian)?;
            let r_info = data.read_u64(8, endian)?;
            let r_addend = if is_rela {
                data.read_i64(16, endian)?
            } else {
                0
            };
            Ok(Relocation {
                r_offset,
                r_info,
                r_addend,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::elf::symbols::SymbolTable;

    fn create_test_relocations() -> Vec<u8> {
        // Create RELA64 relocations
        let mut data = vec![0u8; 24 * 2]; // 2 relocations

        // Relocation 1: r_offset = 0x601000, r_info = (1 << 32) | 7, r_addend = 0
        data[0] = 0x00;
        data[1] = 0x10;
        data[2] = 0x60;
        // r_info: symbol index 1, type 7 (R_X86_64_JUMP_SLOT)
        data[12] = 1; // Symbol index in upper 32 bits

        // Relocation 2: r_offset = 0x601008, r_info = (2 << 32) | 7
        data[24] = 0x08;
        data[25] = 0x10;
        data[26] = 0x60;
        data[24 + 12] = 2;

        data
    }

    #[test]
    fn test_parse_relocations() {
        let rel_data = create_test_relocations();

        // Create a dummy symbol table
        let symtab_data = vec![0u8; 24 * 3]; // 3 symbols
        let strtab_data = b"\0printf\0main\0";
        let symbols =
            SymbolTable::parse(&symtab_data, strtab_data, ElfClass::Elf64, ElfData::Little)
                .unwrap();

        let relocations = RelocationTable::parse(
            &rel_data,
            &symbols,
            SHT_RELA,
            ElfClass::Elf64,
            ElfData::Little,
        )
        .unwrap();

        assert_eq!(relocations.count(), 2);
        assert!(relocations.is_rela());

        // Check first relocation
        let reloc1 = relocations.by_offset(0x601000).unwrap();
        assert_eq!(reloc1.symbol_index(), 1);
    }
}
