//! ELF (Executable and Linkable Format) parser
//!
//! A zero-copy ELF parser with comprehensive format support.

pub mod dynamic;
pub mod headers;
pub mod notes;
pub mod relocations;
pub mod sections;
pub mod segments;
pub mod symbols;
pub mod types;
pub mod utils;

use dynamic::DynamicSection;
use headers::parse_header;
use notes::NoteSection;
use relocations::RelocationTable;
use sections::SectionTable;
use segments::SegmentTable;
use symbols::SymbolTable;
pub use types::*;

/// Main ELF parser
pub struct ElfParser<'data> {
    data: &'data [u8],
    header: ElfHeader,
}

impl<'data> ElfParser<'data> {
    /// Parse ELF from raw data
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let header = parse_header(data)?;

        Ok(Self { data, header })
    }

    /// Get ELF header
    pub fn header(&self) -> &ElfHeader {
        &self.header
    }

    /// Get raw data
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// Get sections
    pub fn sections(&self) -> Result<SectionTable<'data>> {
        SectionTable::parse(self.data, &self.header)
    }

    /// Get segments
    pub fn segments(&self) -> Result<SegmentTable<'data>> {
        SegmentTable::parse(self.data, &self.header)
    }

    /// Get symbol table
    pub fn symbols(&self) -> Result<Option<SymbolTable<'data>>> {
        self.parse_symbol_table(".symtab")
    }

    /// Get dynamic symbol table
    pub fn dynamic_symbols(&self) -> Result<Option<SymbolTable<'data>>> {
        self.parse_symbol_table(".dynsym")
    }

    /// Get dynamic section
    pub fn dynamic(&self) -> Result<Option<DynamicSection<'data>>> {
        self.parse_dynamic_section()
    }

    /// Get GOT relocations
    pub fn got_relocations(&self) -> Result<Option<RelocationTable>> {
        self.parse_relocations(".rela.dyn", false)
            .or_else(|_| self.parse_relocations(".rel.dyn", false))
    }

    /// Get PLT relocations
    pub fn plt_relocations(&self) -> Result<Option<RelocationTable>> {
        self.parse_relocations(".rela.plt", true)
            .or_else(|_| self.parse_relocations(".rel.plt", true))
    }

    /// Parse a symbol table by name
    fn parse_symbol_table(&self, name: &str) -> Result<Option<SymbolTable<'data>>> {
        let sections = self.sections()?;

        let symtab_section = match sections.by_name(name) {
            Some(s) => s,
            None => return Ok(None),
        };

        // Find associated string table
        let strtab_idx = symtab_section.header.sh_link as usize;
        let strtab_section = match sections.by_index(strtab_idx) {
            Some(s) => s,
            None => return Ok(None),
        };

        let table = SymbolTable::parse(
            symtab_section.data,
            strtab_section.data,
            self.header.ident.class,
            self.header.ident.data,
        )?;

        Ok(Some(table))
    }

    /// Parse dynamic section
    fn parse_dynamic_section(&self) -> Result<Option<DynamicSection<'data>>> {
        let sections = self.sections()?;

        let dynamic_section = match sections.by_name(".dynamic") {
            Some(s) => s,
            None => return Ok(None),
        };

        // Find dynamic string table
        let dynstr_section = sections.by_name(".dynstr");

        let dynamic = DynamicSection::parse(
            self.data,
            &dynamic_section,
            dynstr_section.as_ref(),
            self.header.ident.class,
            self.header.ident.data,
        )?;

        Ok(Some(dynamic))
    }

    /// Parse relocations from a section
    fn parse_relocations(&self, name: &str, is_plt: bool) -> Result<Option<RelocationTable>> {
        let sections = self.sections()?;

        let rel_section = match sections.by_name(name) {
            Some(s) => s,
            None => return Ok(None),
        };

        // Get dynamic symbols for relocation resolution
        let symbols = match self.dynamic_symbols()? {
            Some(s) => s,
            None => return Ok(None),
        };

        let mut table = RelocationTable::parse(
            rel_section.data,
            &symbols,
            rel_section.header.sh_type,
            self.header.ident.class,
            self.header.ident.data,
        )?;

        // Build PLT map if this is .rela.plt
        if is_plt {
            if let Some(plt_section) = sections.by_name(".plt") {
                let plt_addr = plt_section.header.sh_addr;
                let plt_size = plt_section.header.sh_size;
                let num_entries = table.count() as u64 + 1; // +1 for PLT[0]
                let entry_size = if num_entries > 0 {
                    plt_size / num_entries
                } else {
                    16
                };
                table.build_plt_map(plt_addr, entry_size, &symbols);
            }
        }

        Ok(Some(table))
    }

    /// Get security features
    pub fn security_features(&self) -> SecurityFeatures {
        let nx = self
            .segments()
            .ok()
            .map(|segs| segs.has_nx_stack())
            .unwrap_or(false);

        let pie = self.header.is_pie();

        let relro = self
            .segments()
            .ok()
            .map(|segs| {
                if !segs.has_relro() {
                    RelroLevel::None
                } else if self
                    .dynamic()
                    .ok()
                    .flatten()
                    .map(|d| d.is_bind_now())
                    .unwrap_or(false)
                {
                    RelroLevel::Full
                } else {
                    RelroLevel::Partial
                }
            })
            .unwrap_or(RelroLevel::None);

        let stack_canary = self.has_symbol("__stack_chk_fail");
        let fortify = self.has_symbol("__fortify_fail");
        let cfi = self.has_symbol("__cfi_check");
        let safestack = self.has_symbol("__safestack_init");
        let asan = self.has_symbol("__asan_init");

        SecurityFeatures {
            nx,
            pie,
            relro,
            stack_canary,
            fortify,
            cfi,
            safestack,
            asan,
        }
    }

    /// Check if a symbol exists
    fn has_symbol(&self, name: &str) -> bool {
        // Check dynamic symbols first (more common)
        if let Ok(Some(dynsym)) = self.dynamic_symbols() {
            if dynsym.has_symbol(name) {
                return true;
            }
        }

        // Check regular symbol table
        if let Ok(Some(symtab)) = self.symbols() {
            if symtab.has_symbol(name) {
                return true;
            }
        }

        false
    }

    /// Check if binary has debug info
    pub fn has_debug_info(&self) -> bool {
        self.sections().map(|s| s.has_debug_info()).unwrap_or(false)
    }

    /// Get entry point section
    pub fn entry_section(&self) -> Option<Section<'data>> {
        let entry = self.header.entry_point();
        if entry == 0 {
            return None;
        }

        self.sections().ok().and_then(|s| s.by_addr(entry))
    }

    /// Get interpreter path
    pub fn interpreter(&self) -> Option<&'data str> {
        self.segments().ok().and_then(|s| s.interpreter())
    }

    /// Check if binary has relocations
    pub fn has_relocations(&self) -> bool {
        self.sections()
            .ok()
            .map(|sections| {
                sections
                    .sections()
                    .any(|s| matches!(s.header.sh_type, SHT_REL | SHT_RELA))
            })
            .unwrap_or(false)
    }

    /// Get build ID from note sections
    pub fn build_id(&self) -> Option<Vec<u8>> {
        self.sections().ok().and_then(|sections| {
            sections
                .sections()
                .filter(|s| s.header.sh_type == SHT_NOTE)
                .find_map(|s| {
                    NoteSection::parse(s.data, self.header.ident.data)
                        .ok()
                        .and_then(|notes| notes.build_id().map(|b| b.to_vec()))
                })
        })
    }

    /// Validate ELF structure
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Check section headers
        if let Ok(sections) = self.sections() {
            if self.header.e_shstrndx as usize >= sections.count() {
                errors.push(format!(
                    "Invalid section string table index: {}",
                    self.header.e_shstrndx
                ));
            }
        }

        // Check program headers
        if let Ok(segments) = self.segments() {
            let load_segments: Vec<_> = segments.load_segments().collect();
            if load_segments.is_empty() && self.header.e_type == 2 {
                errors.push("Executable has no LOAD segments".to_string());
            }
        }

        // Check entry point for executables
        if self.header.e_type == 2 && self.header.e_entry == 0 {
            errors.push("Executable has null entry point".to_string());
        }

        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_elf() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        // ELF magic
        data[0..4].copy_from_slice(b"\x7fELF");
        // 64-bit, little endian, version 1
        data[4] = 2;
        data[5] = 1;
        data[6] = 1;

        // e_type = ET_DYN
        data[16] = 3;
        // e_machine = EM_X86_64
        data[18] = 62;
        // e_version = 1
        data[20] = 1;
        // e_ehsize = 64
        data[52] = 64;

        data
    }

    #[test]
    fn test_parse_minimal_elf() {
        let data = minimal_elf();
        let elf = ElfParser::parse(&data).unwrap();

        assert_eq!(elf.header().ident.class, ElfClass::Elf64);
        assert_eq!(elf.header().ident.data, ElfData::Little);
        assert_eq!(elf.header().machine(), ElfMachine::X86_64);
        assert!(elf.header().is_pie());
    }

    #[test]
    fn test_security_features() {
        let data = minimal_elf();
        let elf = ElfParser::parse(&data).unwrap();
        let security = elf.security_features();

        assert!(security.pie);
        assert_eq!(security.relro, RelroLevel::None);
        assert!(!security.stack_canary);
    }

    #[test]
    fn test_invalid_elf() {
        // Test with wrong magic but correct size
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(b"NOTF");
        let result = ElfParser::parse(&data);
        assert!(result.is_err());
        assert!(matches!(result, Err(ElfError::InvalidMagic)));

        // Test with too small data
        let data = b"short";
        let result = ElfParser::parse(data);
        assert!(result.is_err());
        assert!(matches!(result, Err(ElfError::Truncated { .. })));
    }
}
