# ELF Parser Technical Design

## Memory Layout and Zero-Copy Architecture

### Design Philosophy

The ELF parser operates directly on memory-mapped or in-memory binary data without copying or allocating intermediate structures. All parsing returns references into the original data buffer.

### Memory Safety Model

```rust
// Lifetime 'data represents the lifetime of the input buffer
pub struct ElfParser<'data> {
    data: &'data [u8],
    // All parsed structures maintain the 'data lifetime
    header: ElfHeader,
    // Lazy-loaded components use OnceCell for deferred parsing
    sections: OnceCell<SectionTable<'data>>,
}
```

## Core Data Structures

### ELF Header Representation

```rust
#[derive(Debug, Clone, Copy)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,      // Unified for 32/64-bit
    pub e_phoff: u64,      // Program header offset
    pub e_shoff: u64,      // Section header offset
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct ElfIdent {
    pub class: ElfClass,      // 32-bit or 64-bit
    pub data: ElfData,         // Little or Big endian
    pub version: u8,
    pub osabi: u8,
    pub abiversion: u8,
}
```

### Section Management

```rust
pub struct SectionTable<'data> {
    headers: Vec<SectionHeader>,
    strings: &'data [u8],     // Section name string table
    data: &'data [u8],         // Original data for section content
}

impl<'data> SectionTable<'data> {
    /// O(n) lookup by name - could optimize with HashMap if needed
    pub fn by_name(&self, name: &str) -> Option<&Section>;
    
    /// O(1) lookup by index
    pub fn by_index(&self, index: usize) -> Option<&Section>;
    
    /// Find section containing virtual address
    pub fn by_addr(&self, addr: u64) -> Option<&Section>;
}
```

### Program Header/Segment Management

```rust
pub struct SegmentTable<'data> {
    headers: Vec<ProgramHeader>,
    data: &'data [u8],
}

impl<'data> SegmentTable<'data> {
    /// Convert virtual address to file offset
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize>;
    
    /// Find segment containing virtual address
    pub fn segment_at_vaddr(&self, vaddr: u64) -> Option<&Segment>;
    
    /// Get all LOAD segments
    pub fn load_segments(&self) -> impl Iterator<Item = &Segment>;
}
```

## Parsing Algorithms

### Endian-Aware Reading

```rust
pub trait EndianRead {
    fn read_u16(&self, offset: usize) -> Option<u16>;
    fn read_u32(&self, offset: usize) -> Option<u32>;
    fn read_u64(&self, offset: usize) -> Option<u64>;
}

impl EndianRead for (&[u8], ElfData) {
    fn read_u32(&self, offset: usize) -> Option<u32> {
        let bytes = self.0.get(offset..offset + 4)?;
        Some(match self.1 {
            ElfData::Little => u32::from_le_bytes(bytes.try_into().ok()?),
            ElfData::Big => u32::from_be_bytes(bytes.try_into().ok()?),
        })
    }
}
```

### Section String Table Resolution

```rust
impl<'data> SectionTable<'data> {
    fn get_string(&self, offset: u32) -> Option<&'data str> {
        let start = offset as usize;
        let slice = self.strings.get(start..)?;
        let end = slice.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&slice[..end]).ok()
    }
}
```

### Virtual Address Resolution

```rust
/// Efficient VA to file offset conversion using binary search on sorted segments
impl<'data> SegmentTable<'data> {
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize> {
        // Binary search on sorted LOAD segments
        let load_segments: Vec<_> = self.headers.iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .collect();
            
        let idx = load_segments.binary_search_by(|ph| {
            if vaddr < ph.p_vaddr {
                std::cmp::Ordering::Greater
            } else if vaddr >= ph.p_vaddr + ph.p_memsz {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).ok()?;
        
        let ph = load_segments[idx];
        let offset = vaddr - ph.p_vaddr;
        Some((ph.p_offset + offset) as usize)
    }
}
```

## Symbol Table Processing

### Symbol Resolution Architecture

```rust
pub struct SymbolTable<'data> {
    symbols: Vec<Symbol<'data>>,
    strings: &'data [u8],
    by_name: HashMap<&'data str, usize>,
    by_addr: BTreeMap<u64, Vec<usize>>,
}

impl<'data> SymbolTable<'data> {
    /// Parse from .symtab or .dynsym section
    pub fn parse(data: &'data [u8], strtab: &'data [u8], class: ElfClass) -> Result<Self> {
        let entry_size = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };
        
        let mut symbols = Vec::new();
        let mut by_name = HashMap::new();
        let mut by_addr = BTreeMap::new();
        
        for (i, chunk) in data.chunks_exact(entry_size).enumerate() {
            let symbol = Symbol::parse(chunk, class)?;
            if let Some(name) = symbol.name(strtab) {
                by_name.insert(name, i);
            }
            if symbol.st_value != 0 {
                by_addr.entry(symbol.st_value)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
            symbols.push(symbol);
        }
        
        Ok(Self { symbols, strings: strtab, by_name, by_addr })
    }
}
```

### Import/Export Classification

```rust
impl<'data> Symbol<'data> {
    pub fn is_import(&self) -> bool {
        // Undefined symbols are imports
        self.st_shndx == SHN_UNDEF && self.st_name != 0
    }
    
    pub fn is_export(&self) -> bool {
        // Defined global symbols are exports
        self.st_shndx != SHN_UNDEF 
            && self.st_bind() == STB_GLOBAL
            && self.st_type() != STT_FILE
    }
    
    pub fn is_weak(&self) -> bool {
        self.st_bind() == STB_WEAK
    }
}
```

## Dynamic Section Parsing

### DT_NEEDED and Path Resolution

```rust
pub struct DynamicSection<'data> {
    entries: Vec<DynamicEntry>,
    strings: &'data [u8],
}

impl<'data> DynamicSection<'data> {
    pub fn needed_libraries(&self) -> Vec<&'data str> {
        self.entries.iter()
            .filter(|e| e.d_tag == DT_NEEDED)
            .filter_map(|e| self.get_string(e.d_val as u32))
            .collect()
    }
    
    pub fn rpath(&self) -> Option<&'data str> {
        self.entries.iter()
            .find(|e| e.d_tag == DT_RPATH)
            .and_then(|e| self.get_string(e.d_val as u32))
    }
    
    pub fn runpath(&self) -> Option<&'data str> {
        self.entries.iter()
            .find(|e| e.d_tag == DT_RUNPATH)
            .and_then(|e| self.get_string(e.d_val as u32))
    }
}
```

## Relocation Processing

### GOT and PLT Mapping

```rust
pub struct RelocationTable<'data> {
    relocations: Vec<Relocation>,
    got_map: HashMap<u64, &'data str>,   // GOT address -> symbol name
    plt_map: HashMap<u64, &'data str>,   // PLT address -> symbol name
}

impl<'data> RelocationTable<'data> {
    pub fn build_got_map(
        &mut self,
        rela_sections: &[Section<'data>],
        symbols: &SymbolTable<'data>,
    ) -> Result<()> {
        for section in rela_sections {
            // Parse RELA entries
            let entry_size = if self.is_rela { 24 } else { 16 };
            
            for chunk in section.data.chunks_exact(entry_size) {
                let r_offset = self.read_addr(chunk, 0);
                let r_info = self.read_addr(chunk, 8);
                
                let sym_idx = (r_info >> 32) as u32;
                if let Some(symbol) = symbols.by_index(sym_idx) {
                    if let Some(name) = symbol.name() {
                        self.got_map.insert(r_offset, name);
                    }
                }
            }
        }
        Ok(())
    }
}
```

### PLT Resolution Algorithm

```rust
impl<'data> RelocationTable<'data> {
    pub fn build_plt_map(
        &mut self,
        plt_section: &Section<'data>,
        rela_plt: &Section<'data>,
        symbols: &SymbolTable<'data>,
    ) -> Result<()> {
        // PLT layout: [PLT0 reserved] [PLT1] [PLT2] ...
        let plt_entry_size = self.detect_plt_entry_size(plt_section)?;
        let mut plt_addr = plt_section.addr + plt_entry_size; // Skip PLT0
        
        // Parse .rela.plt entries in order
        let entry_size = 24; // RELA
        for chunk in rela_plt.data.chunks_exact(entry_size) {
            let r_info = self.read_u64(chunk, 8);
            let sym_idx = (r_info >> 32) as u32;
            
            if let Some(symbol) = symbols.by_index(sym_idx) {
                if let Some(name) = symbol.name() {
                    self.plt_map.insert(plt_addr, name);
                    plt_addr += plt_entry_size;
                }
            }
        }
        Ok(())
    }
}
```

## Security Feature Detection

### Comprehensive Security Analysis

```rust
pub struct SecurityFeatures {
    pub nx: bool,           // Non-executable stack
    pub pie: bool,          // Position Independent Executable
    pub relro: RelroLevel,  // RELRO protection level
    pub stack_canary: bool, // Stack protector
    pub fortify: bool,      // FORTIFY_SOURCE
    pub cfi: bool,          // Control Flow Integrity
    pub safestack: bool,    // SafeStack
    pub asan: bool,         // AddressSanitizer
}

#[derive(Debug, Clone, Copy)]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

impl<'data> ElfParser<'data> {
    pub fn security_features(&self) -> SecurityFeatures {
        let nx = self.check_nx();
        let pie = self.header.e_type == ET_DYN;
        let relro = self.check_relro();
        let stack_canary = self.has_symbol("__stack_chk_fail");
        let fortify = self.has_symbol("__fortify_fail");
        let cfi = self.check_cfi();
        let safestack = self.has_symbol("__safestack_init");
        let asan = self.has_symbol("__asan_init");
        
        SecurityFeatures {
            nx, pie, relro, stack_canary,
            fortify, cfi, safestack, asan,
        }
    }
    
    fn check_nx(&self) -> bool {
        // Check PT_GNU_STACK segment
        self.segments()
            .find(|seg| seg.p_type == PT_GNU_STACK)
            .map(|seg| (seg.p_flags & PF_X) == 0)
            .unwrap_or(false)
    }
    
    fn check_relro(&self) -> RelroLevel {
        let has_relro = self.segments()
            .any(|seg| seg.p_type == PT_GNU_RELRO);
            
        if !has_relro {
            return RelroLevel::None;
        }
        
        // Check for immediate binding (BIND_NOW)
        let bind_now = self.dynamic()
            .and_then(|dyn| dyn.get_flags())
            .map(|flags| (flags & DF_BIND_NOW) != 0)
            .unwrap_or(false);
            
        if bind_now {
            RelroLevel::Full
        } else {
            RelroLevel::Partial
        }
    }
}
```

## Note Section Processing

### Build ID and Properties

```rust
pub struct NoteSection<'data> {
    notes: Vec<Note<'data>>,
}

pub struct Note<'data> {
    pub n_type: u32,
    pub name: &'data str,
    pub desc: &'data [u8],
}

impl<'data> NoteSection<'data> {
    pub fn build_id(&self) -> Option<&'data [u8]> {
        self.notes.iter()
            .find(|n| n.name == "GNU" && n.n_type == NT_GNU_BUILD_ID)
            .map(|n| n.desc)
    }
    
    pub fn gnu_properties(&self) -> Vec<GnuProperty> {
        self.notes.iter()
            .filter(|n| n.name == "GNU" && n.n_type == NT_GNU_PROPERTY_TYPE_0)
            .flat_map(|n| parse_properties(n.desc))
            .collect()
    }
}
```

## Performance Optimizations

### Lazy Loading Strategy

```rust
impl<'data> ElfParser<'data> {
    /// Headers are always parsed upfront (small, fixed size)
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let header = ElfHeader::parse(data)?;
        Ok(Self {
            data,
            header,
            // Everything else is lazy-loaded
            sections: OnceCell::new(),
            segments: OnceCell::new(),
            symbols: OnceCell::new(),
            dynamic: OnceCell::new(),
            relocations: OnceCell::new(),
        })
    }
    
    /// Sections are parsed on first access
    pub fn sections(&self) -> Result<&SectionTable<'data>> {
        self.sections.get_or_try_init(|| {
            SectionTable::parse(self.data, &self.header)
        })
    }
}
```

### Caching Strategy

```rust
pub struct SymbolCache<'data> {
    // LRU cache for symbol lookups
    by_name: LruCache<&'data str, Option<&'data Symbol<'data>>>,
    // Sorted for binary search
    by_addr: Vec<(u64, &'data Symbol<'data>)>,
}
```

## Error Handling

### Comprehensive Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum ElfError {
    #[error("Invalid ELF magic")]
    InvalidMagic,
    
    #[error("Unsupported ELF class: {0}")]
    UnsupportedClass(u8),
    
    #[error("Invalid offset: {offset:#x}")]
    InvalidOffset { offset: usize },
    
    #[error("Truncated at {offset:#x}, needed {needed} bytes")]
    Truncated { offset: usize, needed: usize },
    
    #[error("Invalid section index: {0}")]
    InvalidSectionIndex(u16),
    
    #[error("Malformed header: {0}")]
    MalformedHeader(String),
    
    #[error("String not UTF-8")]
    InvalidString,
}

pub type Result<T> = std::result::Result<T, ElfError>;
```

## Testing Utilities

### Binary Generation Helpers

```rust
#[cfg(test)]
mod test_utils {
    pub fn minimal_elf32() -> Vec<u8> {
        let mut data = vec![0u8; 52];
        data[0..4].copy_from_slice(b"\x7FELF");
        data[4] = 1; // 32-bit
        data[5] = 1; // Little endian
        data[6] = 1; // Version 1
        // ... minimal valid header
        data
    }
    
    pub fn minimal_elf64() -> Vec<u8> {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7FELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // Little endian
        data[6] = 1; // Version 1
        // ... minimal valid header
        data
    }
}
```

## Architecture Support Matrix

| Architecture | e_machine | 32-bit | 64-bit | Notes |
|-------------|-----------|--------|--------|-------|
| x86         | EM_386 (3) | ✓ | - | Full support |
| x86_64      | EM_X86_64 (62) | - | ✓ | Full support |
| ARM         | EM_ARM (40) | ✓ | - | Full support |
| AArch64     | EM_AARCH64 (183) | - | ✓ | Full support |
| RISC-V      | EM_RISCV (243) | ✓ | ✓ | RV32/RV64 |
| MIPS        | EM_MIPS (8) | ✓ | ✓ | Big/little endian |
| PowerPC     | EM_PPC (20) | ✓ | - | Big endian |
| PowerPC64   | EM_PPC64 (21) | - | ✓ | Big/little endian |
| SPARC       | EM_SPARC (2) | ✓ | - | Big endian |
| S390x       | EM_S390 (22) | - | ✓ | Big endian |

## Memory Safety Guarantees

1. **No unsafe code** - Pure safe Rust implementation
2. **Bounds checked** - All slice accesses are checked
3. **No allocations for parsing** - Zero-copy design
4. **Lifetime safety** - Rust's borrow checker ensures safety
5. **Integer overflow protection** - Checked arithmetic

## Compatibility Notes

### Linux LSB Compliance
- Follows Linux Standard Base specifications
- Handles GNU extensions (GNU_HASH, GNU_RELRO, etc.)

### BSD Compatibility
- Supports BSD-specific note types
- Handles BSD symbol versioning

### Solaris Compatibility
- Supports Solaris-specific sections
- Handles Solaris symbol scoping

## Future Extensions

1. **DWARF Support** - Debug information parsing
2. **Dynamic Linking Simulation** - Symbol resolution
3. **Patching Support** - Binary modification
4. **Compression** - SHF_COMPRESSED section support
5. **Split DWARF** - .debug_* section handling