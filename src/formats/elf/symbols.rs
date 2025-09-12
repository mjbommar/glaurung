//! Symbol table parsing

use crate::formats::elf::types::*;
use crate::formats::elf::utils::{read_cstring, EndianRead};
use std::collections::{BTreeMap, HashMap};

/// Symbol table
pub struct SymbolTable<'a> {
    symbols: Vec<Symbol>,
    strings: &'a [u8],
    by_name: HashMap<String, usize>,
    by_addr: BTreeMap<u64, Vec<usize>>,
}

impl<'a> SymbolTable<'a> {
    /// Parse symbol table from section data
    pub fn parse(
        symbol_data: &[u8],
        string_data: &'a [u8],
        class: ElfClass,
        endian: ElfData,
    ) -> Result<Self> {
        let entry_size = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };

        let mut symbols = Vec::new();
        let mut by_name = HashMap::new();
        let mut by_addr = BTreeMap::new();

        let mut offset = 0;
        let mut index = 0;

        while offset + entry_size <= symbol_data.len() {
            let symbol = parse_symbol(&symbol_data[offset..], class, endian)?;

            // Build name index
            if symbol.st_name != 0 {
                if let Ok(name) = read_cstring(string_data, symbol.st_name as usize) {
                    by_name.insert(name.to_string(), index);
                }
            }

            // Build address index
            if symbol.st_value != 0 {
                by_addr
                    .entry(symbol.st_value)
                    .or_insert_with(Vec::new)
                    .push(index);
            }

            symbols.push(symbol);
            offset += entry_size;
            index += 1;
        }

        Ok(Self {
            symbols,
            strings: string_data,
            by_name,
            by_addr,
        })
    }

    /// Get symbol by index
    pub fn by_index(&self, index: usize) -> Option<&Symbol> {
        self.symbols.get(index)
    }

    /// Get symbol by name
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).and_then(|&idx| self.by_index(idx))
    }

    /// Get symbols at address
    pub fn by_addr(&self, addr: u64) -> Vec<&Symbol> {
        self.by_addr
            .get(&addr)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&idx| self.by_index(idx))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get symbol name
    pub fn symbol_name(&self, symbol: &Symbol) -> Option<&'a str> {
        if symbol.st_name == 0 {
            return None;
        }
        read_cstring(self.strings, symbol.st_name as usize).ok()
    }

    /// Get all imports (undefined symbols)
    pub fn imports(&self) -> Vec<SymbolInfo<'a>> {
        self.symbols
            .iter()
            .filter(|s| s.is_undefined() && s.st_name != 0)
            .map(|s| SymbolInfo {
                symbol: *s,
                name: self.symbol_name(s),
            })
            .collect()
    }

    /// Get all exports (defined global symbols)
    pub fn exports(&self) -> Vec<SymbolInfo<'a>> {
        self.symbols
            .iter()
            .filter(|s| !s.is_undefined() && s.is_global())
            .map(|s| SymbolInfo {
                symbol: *s,
                name: self.symbol_name(s),
            })
            .collect()
    }

    /// Get all function symbols
    pub fn functions(&self) -> Vec<SymbolInfo<'a>> {
        self.symbols
            .iter()
            .filter(|s| s.is_function())
            .map(|s| SymbolInfo {
                symbol: *s,
                name: self.symbol_name(s),
            })
            .collect()
    }

    /// Check if a symbol exists
    pub fn has_symbol(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Count total symbols
    pub fn count(&self) -> usize {
        self.symbols.len()
    }

    /// Count imports
    pub fn import_count(&self) -> usize {
        self.imports().len()
    }

    /// Count exports
    pub fn export_count(&self) -> usize {
        self.exports().len()
    }
}

/// Symbol information with name
pub struct SymbolInfo<'a> {
    pub symbol: Symbol, // Copy the symbol instead of reference
    pub name: Option<&'a str>,
}

impl<'a> SymbolInfo<'a> {
    pub fn name(&self) -> &'a str {
        self.name.unwrap_or("")
    }

    pub fn value(&self) -> u64 {
        self.symbol.st_value
    }

    pub fn size(&self) -> u64 {
        self.symbol.st_size
    }

    pub fn is_weak(&self) -> bool {
        self.symbol.is_weak()
    }

    pub fn is_function(&self) -> bool {
        self.symbol.is_function()
    }

    /// Try to demangle the symbol name
    pub fn demangled_name(&self) -> Option<String> {
        self.name.and_then(|n| {
            // Simple C++ demangling check
            if n.starts_with("_Z") {
                // Would use a proper demangler here
                Some(format!("<demangled: {}>", n))
            } else {
                None
            }
        })
    }
}

/// Parse a single symbol entry
fn parse_symbol(data: &[u8], class: ElfClass, endian: ElfData) -> Result<Symbol> {
    match class {
        ElfClass::Elf32 => {
            if data.len() < 16 {
                return Err(ElfError::Truncated {
                    offset: 0,
                    needed: 16,
                });
            }
            Ok(Symbol {
                st_name: data.read_u32(0, endian)?,
                st_value: data.read_u32(4, endian)? as u64,
                st_size: data.read_u32(8, endian)? as u64,
                st_info: data[12],
                st_other: data[13],
                st_shndx: data.read_u16(14, endian)?,
            })
        }
        ElfClass::Elf64 => {
            if data.len() < 24 {
                return Err(ElfError::Truncated {
                    offset: 0,
                    needed: 24,
                });
            }
            Ok(Symbol {
                st_name: data.read_u32(0, endian)?,
                st_info: data[4],
                st_other: data[5],
                st_shndx: data.read_u16(6, endian)?,
                st_value: data.read_u64(8, endian)?,
                st_size: data.read_u64(16, endian)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_symbol_table() -> (Vec<u8>, Vec<u8>) {
        // Create symbol table data (64-bit)
        let mut symtab = vec![0u8; 24 * 3]; // 3 symbols

        // Symbol 0: NULL symbol (all zeros)

        // Symbol 1: undefined symbol "printf"
        symtab[24] = 1; // st_name = 1
        symtab[24 + 4] = (STB_GLOBAL << 4) | STT_FUNC; // st_info
                                                       // st_shndx = SHN_UNDEF (0)

        // Symbol 2: defined symbol "main"
        symtab[48] = 8; // st_name = 8
        symtab[48 + 4] = (STB_GLOBAL << 4) | STT_FUNC; // st_info
        symtab[48 + 6] = 1; // st_shndx = 1 (defined)
                            // st_value = 0x1000
        symtab[48 + 8] = 0x00;
        symtab[48 + 9] = 0x10;
        // st_size = 0x50
        symtab[48 + 16] = 0x50;

        // Create string table
        let mut strtab = vec![0u8; 20];
        strtab[0] = 0; // Empty string
        let printf_bytes = b"printf\0";
        strtab[1..1 + printf_bytes.len()].copy_from_slice(printf_bytes);
        let main_bytes = b"main\0";
        strtab[8..8 + main_bytes.len()].copy_from_slice(main_bytes);

        (symtab, strtab)
    }

    #[test]
    fn test_parse_symbol_table() {
        let (symtab, strtab) = create_test_symbol_table();
        let table = SymbolTable::parse(&symtab, &strtab, ElfClass::Elf64, ElfData::Little).unwrap();

        assert_eq!(table.count(), 3);

        // Check imports
        let imports = table.imports();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].name(), "printf");

        // Check exports
        let exports = table.exports();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name(), "main");
        assert_eq!(exports[0].value(), 0x1000);

        // Check by name lookup
        assert!(table.has_symbol("printf"));
        assert!(table.has_symbol("main"));
        assert!(!table.has_symbol("foo"));

        // Check by address lookup
        let at_1000 = table.by_addr(0x1000);
        assert_eq!(at_1000.len(), 1);
    }
}
