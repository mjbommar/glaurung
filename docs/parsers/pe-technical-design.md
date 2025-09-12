# PE Parser Technical Design

## Memory Layout & Zero-Copy Design

### Core Principle: Borrow, Don't Copy

```rust
pub struct Pe<'data> {
    // Original data buffer - single source of truth
    data: &'data [u8],
    
    // Headers are parsed views into data
    dos_header: DosHeaderView,
    nt_headers: NtHeadersView,
    
    // Sections reference data ranges
    sections: Vec<SectionView>,
    
    // Lazy-loaded complex structures
    imports: OnceCell<ImportTable<'data>>,
    exports: OnceCell<ExportTable<'data>>,
}

// Views are just offset/size pairs
pub struct DosHeaderView {
    offset: usize,  // Always 0
    e_lfanew: u32,  // Cached for quick access
}

impl DosHeaderView {
    #[inline]
    pub fn magic(&self, data: &[u8]) -> [u8; 2] {
        [data[0], data[1]]
    }
    
    #[inline]
    pub fn e_lfanew(&self) -> u32 {
        self.e_lfanew
    }
}
```

### Reading Primitives

```rust
// utils.rs - Efficient primitive reading
pub trait ReadExt {
    fn read_u16_le_at(&self, offset: usize) -> Option<u16>;
    fn read_u32_le_at(&self, offset: usize) -> Option<u32>;
    fn read_u64_le_at(&self, offset: usize) -> Option<u64>;
    fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<&str>;
}

impl ReadExt for [u8] {
    #[inline(always)]
    fn read_u32_le_at(&self, offset: usize) -> Option<u32> {
        self.get(offset..offset + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    
    fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<&str> {
        let start = offset;
        let end = (offset + max_len).min(self.len());
        let slice = self.get(start..end)?;
        
        // Find null terminator
        let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..len]).ok()
    }
}
```

## RVA Resolution System

### Efficient Section Mapping

```rust
pub struct SectionTable {
    // Sorted by VA for binary search
    sections: Vec<SectionInfo>,
}

struct SectionInfo {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

impl SectionTable {
    /// Convert RVA to file offset - O(log n)
    #[inline]
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        // Binary search for containing section
        let idx = self.sections.binary_search_by(|s| {
            if rva < s.virtual_address {
                std::cmp::Ordering::Greater
            } else if rva >= s.virtual_address + s.virtual_size.max(s.raw_size) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }).ok()?;
        
        let section = &self.sections[idx];
        let offset = rva - section.virtual_address;
        Some((section.raw_offset + offset) as usize)
    }
    
    /// Batch RVA resolution for efficiency
    pub fn rva_to_offset_batch(&self, rvas: &[u32]) -> Vec<Option<usize>> {
        // Sort RVAs to improve cache locality
        let mut indexed_rvas: Vec<(usize, u32)> = 
            rvas.iter().enumerate().map(|(i, &r)| (i, r)).collect();
        indexed_rvas.sort_by_key(|&(_, rva)| rva);
        
        let mut results = vec![None; rvas.len()];
        let mut section_idx = 0;
        
        for (orig_idx, rva) in indexed_rvas {
            // Start search from last successful section
            while section_idx < self.sections.len() {
                let section = &self.sections[section_idx];
                if rva < section.virtual_address {
                    break;
                }
                if rva < section.virtual_address + section.virtual_size.max(section.raw_size) {
                    let offset = rva - section.virtual_address;
                    results[orig_idx] = Some((section.raw_offset + offset) as usize);
                    break;
                }
                section_idx += 1;
            }
        }
        
        results
    }
}
```

## Import/Export Optimization

### Import Table Parser

```rust
pub struct ImportTable<'data> {
    imports: Vec<ImportDescriptor<'data>>,
    // Cache for fast lookup
    by_name: HashMap<&'data str, Vec<ImportEntry<'data>>>,
    by_dll: HashMap<&'data str, Vec<ImportEntry<'data>>>,
}

pub struct ImportDescriptor<'data> {
    dll_name: &'data str,
    original_first_thunk: u32,
    first_thunk: u32,
    entries: Vec<ImportEntry<'data>>,
}

pub struct ImportEntry<'data> {
    name: Option<&'data str>,
    ordinal: Option<u16>,
    hint: Option<u16>,
    iat_va: u64,  // Virtual address in IAT
}

impl<'data> ImportTable<'data> {
    pub fn parse(data: &'data [u8], pe: &Pe<'data>) -> Result<Self> {
        let import_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)?;
        if import_dir.size == 0 {
            return Ok(Self::empty());
        }
        
        let mut imports = Vec::new();
        let mut offset = pe.rva_to_offset(import_dir.rva)?;
        
        // Parse import descriptors
        loop {
            // Check for terminator (all zeros)
            let desc_data = &data[offset..offset + 20];
            if desc_data.iter().all(|&b| b == 0) {
                break;
            }
            
            let original_first_thunk = data.read_u32_le_at(offset)?;
            let name_rva = data.read_u32_le_at(offset + 12)?;
            let first_thunk = data.read_u32_le_at(offset + 16)?;
            
            // Read DLL name
            let name_offset = pe.rva_to_offset(name_rva)?;
            let dll_name = data.read_cstring_at(name_offset, 256)?;
            
            // Parse thunks
            let entries = Self::parse_thunks(
                data, 
                pe, 
                original_first_thunk, 
                first_thunk
            )?;
            
            imports.push(ImportDescriptor {
                dll_name,
                original_first_thunk,
                first_thunk,
                entries,
            });
            
            offset += 20;
        }
        
        // Build lookup caches
        let mut by_name = HashMap::new();
        let mut by_dll = HashMap::new();
        
        for desc in &imports {
            by_dll.entry(desc.dll_name)
                .or_insert_with(Vec::new)
                .extend(desc.entries.iter().cloned());
            
            for entry in &desc.entries {
                if let Some(name) = entry.name {
                    by_name.entry(name)
                        .or_insert_with(Vec::new)
                        .push(entry.clone());
                }
            }
        }
        
        Ok(ImportTable { imports, by_name, by_dll })
    }
}
```

### Export Table Parser

```rust
pub struct ExportTable<'data> {
    name: Option<&'data str>,
    ordinal_base: u32,
    exports: Vec<ExportEntry<'data>>,
    // Fast lookup by name
    by_name: HashMap<&'data str, usize>,
    // Fast lookup by ordinal
    by_ordinal: HashMap<u32, usize>,
}

pub struct ExportEntry<'data> {
    name: Option<&'data str>,
    ordinal: u32,
    rva: u32,
    forwarder: Option<&'data str>,
}

impl<'data> ExportTable<'data> {
    pub fn parse(data: &'data [u8], pe: &Pe<'data>) -> Result<Self> {
        let export_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
        if export_dir.size == 0 {
            return Ok(Self::empty());
        }
        
        let dir_offset = pe.rva_to_offset(export_dir.rva)?;
        
        // Export directory fields
        let number_of_functions = data.read_u32_le_at(dir_offset + 20)?;
        let number_of_names = data.read_u32_le_at(dir_offset + 24)?;
        let ordinal_base = data.read_u32_le_at(dir_offset + 16)?;
        let address_table_rva = data.read_u32_le_at(dir_offset + 28)?;
        let name_table_rva = data.read_u32_le_at(dir_offset + 32)?;
        let ordinal_table_rva = data.read_u32_le_at(dir_offset + 36)?;
        
        // DLL name
        let name_rva = data.read_u32_le_at(dir_offset + 12)?;
        let name = if name_rva != 0 {
            let offset = pe.rva_to_offset(name_rva)?;
            Some(data.read_cstring_at(offset, 256)?)
        } else {
            None
        };
        
        // Parse address table
        let addr_offset = pe.rva_to_offset(address_table_rva)?;
        let mut addresses = Vec::with_capacity(number_of_functions as usize);
        for i in 0..number_of_functions {
            let rva = data.read_u32_le_at(addr_offset + i as usize * 4)?;
            addresses.push(rva);
        }
        
        // Parse name and ordinal tables
        let mut name_map = HashMap::new();
        if number_of_names > 0 {
            let name_offset = pe.rva_to_offset(name_table_rva)?;
            let ord_offset = pe.rva_to_offset(ordinal_table_rva)?;
            
            for i in 0..number_of_names as usize {
                let name_rva = data.read_u32_le_at(name_offset + i * 4)?;
                let ordinal = data.read_u16_le_at(ord_offset + i * 2)?;
                
                let name_off = pe.rva_to_offset(name_rva)?;
                let name = data.read_cstring_at(name_off, 512)?;
                
                name_map.insert(ordinal as usize, name);
            }
        }
        
        // Build export entries
        let mut exports = Vec::new();
        let mut by_name = HashMap::new();
        let mut by_ordinal = HashMap::new();
        
        for (i, &rva) in addresses.iter().enumerate() {
            if rva == 0 {
                continue; // Unused slot
            }
            
            let ordinal = ordinal_base + i as u32;
            let name = name_map.get(&i).copied();
            
            // Check if this is a forwarder
            let forwarder = if rva >= export_dir.rva 
                && rva < export_dir.rva + export_dir.size {
                // RVA points inside export directory = forwarder
                let offset = pe.rva_to_offset(rva)?;
                Some(data.read_cstring_at(offset, 256)?)
            } else {
                None
            };
            
            let entry_idx = exports.len();
            exports.push(ExportEntry {
                name,
                ordinal,
                rva,
                forwarder,
            });
            
            if let Some(n) = name {
                by_name.insert(n, entry_idx);
            }
            by_ordinal.insert(ordinal, entry_idx);
        }
        
        Ok(ExportTable {
            name,
            ordinal_base,
            exports,
            by_name,
            by_ordinal,
        })
    }
}
```

## Resource Directory Traversal

### Recursive Resource Parser

```rust
pub struct ResourceDirectory<'data> {
    root: ResourceNode<'data>,
}

pub enum ResourceNode<'data> {
    Directory {
        entries: Vec<ResourceEntry<'data>>,
    },
    Data {
        data: &'data [u8],
        code_page: u32,
    },
}

pub struct ResourceEntry<'data> {
    id: ResourceId<'data>,
    node: ResourceNode<'data>,
}

pub enum ResourceId<'data> {
    Name(&'data str),
    Id(u32),
}

impl<'data> ResourceDirectory<'data> {
    pub fn parse(data: &'data [u8], pe: &Pe<'data>) -> Result<Self> {
        let res_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if res_dir.size == 0 {
            return Ok(Self::empty());
        }
        
        let base_offset = pe.rva_to_offset(res_dir.rva)?;
        let mut parser = ResourceParser {
            data,
            base_offset,
            max_depth: 32,  // Prevent infinite recursion
        };
        
        let root = parser.parse_node(base_offset, 0)?;
        Ok(ResourceDirectory { root })
    }
    
    /// Find specific resource by type/name/language
    pub fn find_resource(
        &self,
        type_id: u32,
        name_id: u32,
        lang_id: u16,
    ) -> Option<&[u8]> {
        // Navigate three levels: Type -> Name -> Language
        self.root.find_entry(type_id)
            .and_then(|type_node| type_node.find_entry(name_id))
            .and_then(|name_node| name_node.find_entry(lang_id as u32))
            .and_then(|lang_node| lang_node.data())
    }
}

struct ResourceParser<'data> {
    data: &'data [u8],
    base_offset: usize,
    max_depth: usize,
}

impl<'data> ResourceParser<'data> {
    fn parse_node(&mut self, offset: usize, depth: usize) -> Result<ResourceNode<'data>> {
        if depth >= self.max_depth {
            return Err(PeError::ResourceDepthExceeded);
        }
        
        // Check if this is a directory or data
        let test = self.data.read_u32_le_at(offset)?;
        
        if test & 0x80000000 != 0 {
            // Directory node
            self.parse_directory(offset, depth)
        } else {
            // Data node
            self.parse_data(offset)
        }
    }
    
    fn parse_directory(&mut self, offset: usize, depth: usize) -> Result<ResourceNode<'data>> {
        let named_entries = self.data.read_u16_le_at(offset + 12)?;
        let id_entries = self.data.read_u16_le_at(offset + 14)?;
        let total_entries = (named_entries + id_entries) as usize;
        
        let mut entries = Vec::with_capacity(total_entries);
        let mut entry_offset = offset + 16;
        
        for i in 0..total_entries {
            let name_or_id = self.data.read_u32_le_at(entry_offset)?;
            let data_or_dir = self.data.read_u32_le_at(entry_offset + 4)?;
            
            let id = if name_or_id & 0x80000000 != 0 {
                // Named entry
                let name_offset = self.base_offset + (name_or_id & 0x7FFFFFFF) as usize;
                let len = self.data.read_u16_le_at(name_offset)? as usize;
                let name_data = &self.data[name_offset + 2..name_offset + 2 + len * 2];
                
                // Convert UTF-16LE to string
                let name = String::from_utf16_lossy(
                    name_data.chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                        .as_slice()
                );
                ResourceId::Name(name.leak())  // Need to handle lifetime properly
            } else {
                ResourceId::Id(name_or_id)
            };
            
            let node = if data_or_dir & 0x80000000 != 0 {
                // Subdirectory
                let sub_offset = self.base_offset + (data_or_dir & 0x7FFFFFFF) as usize;
                self.parse_node(sub_offset, depth + 1)?
            } else {
                // Data entry
                let data_offset = self.base_offset + data_or_dir as usize;
                self.parse_data(data_offset)?
            };
            
            entries.push(ResourceEntry { id, node });
            entry_offset += 8;
        }
        
        Ok(ResourceNode::Directory { entries })
    }
    
    fn parse_data(&mut self, offset: usize) -> Result<ResourceNode<'data>> {
        let data_rva = self.data.read_u32_le_at(offset)?;
        let size = self.data.read_u32_le_at(offset + 4)?;
        let code_page = self.data.read_u32_le_at(offset + 8)?;
        
        // Convert RVA to offset and get data slice
        // Note: Need PE context for RVA conversion
        let data_offset = self.base_offset; // Simplified
        let data = &self.data[data_offset..data_offset + size as usize];
        
        Ok(ResourceNode::Data { data, code_page })
    }
}
```

## Security Analysis

### Checksum Validation

```rust
impl Pe<'_> {
    pub fn validate_checksum(&self) -> bool {
        let stored = self.optional_header.checksum();
        if stored == 0 {
            return true; // No checksum to validate
        }
        
        let calculated = self.calculate_checksum();
        stored == calculated
    }
    
    fn calculate_checksum(&self) -> u32 {
        let mut sum = 0u64;
        let mut i = 0;
        
        // Sum all 16-bit words
        while i < self.data.len() {
            let word = if i + 1 < self.data.len() {
                u16::from_le_bytes([self.data[i], self.data[i + 1]]) as u64
            } else {
                self.data[i] as u64
            };
            
            // Skip the checksum field itself
            let checksum_offset = self.checksum_offset();
            if i != checksum_offset && i != checksum_offset + 1 {
                sum = sum.wrapping_add(word);
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            i += 2;
        }
        
        // Add file size
        sum = sum.wrapping_add(self.data.len() as u64);
        
        // Fold carries
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        sum as u32
    }
}
```

### Security Features Detection

```rust
pub struct SecurityFeatures {
    pub nx_compatible: bool,
    pub aslr_enabled: bool,
    pub dep_enabled: bool,
    pub cfg_enabled: bool,
    pub seh_enabled: bool,
    pub safe_seh: bool,
    pub authenticode_signed: bool,
    pub strong_name_signed: bool,
}

impl Pe<'_> {
    pub fn security_features(&self) -> SecurityFeatures {
        let dll_chars = self.optional_header.dll_characteristics();
        
        SecurityFeatures {
            nx_compatible: (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
            aslr_enabled: (dll_chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
            dep_enabled: (dll_chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0,
            cfg_enabled: (dll_chars & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0,
            seh_enabled: (dll_chars & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0,
            safe_seh: self.has_safe_seh(),
            authenticode_signed: self.has_authenticode(),
            strong_name_signed: self.has_strong_name(),
        }
    }
    
    fn has_safe_seh(&self) -> bool {
        // Check load config directory for SEH handler table
        if let Ok(load_config) = self.load_config() {
            load_config.se_handler_count > 0
        } else {
            false
        }
    }
}
```

## Performance Optimizations

### Lazy Loading Pattern

```rust
impl<'data> Pe<'data> {
    pub fn imports(&self) -> Result<&ImportTable<'data>> {
        self.imports.get_or_try_init(|| {
            ImportTable::parse(self.data, self)
        })
    }
    
    pub fn exports(&self) -> Result<&ExportTable<'data>> {
        self.exports.get_or_try_init(|| {
            ExportTable::parse(self.data, self)
        })
    }
    
    pub fn rich_header(&self) -> &Option<RichHeader> {
        self.rich_header.get_or_init(|| {
            RichHeader::parse(self.data)
        })
    }
}
```

### Budget-Aware Parsing

```rust
pub struct ParseBudget {
    pub max_time_ms: Option<u64>,
    pub max_imports: usize,
    pub max_exports: usize,
    pub max_resources: usize,
    pub max_resource_depth: usize,
    start_time: Instant,
}

impl ParseBudget {
    pub fn check_timeout(&self) -> Result<()> {
        if let Some(max_ms) = self.max_time_ms {
            if self.start_time.elapsed().as_millis() > max_ms as u128 {
                return Err(PeError::Timeout);
            }
        }
        Ok(())
    }
    
    pub fn check_import_limit(&self, count: usize) -> Result<()> {
        if count > self.max_imports {
            return Err(PeError::LimitExceeded("imports"));
        }
        Ok(())
    }
}
```

## Error Recovery

### Partial Results

```rust
pub struct ParseResult<T> {
    pub value: Option<T>,
    pub errors: Vec<PeError>,
}

impl<'data> Pe<'data> {
    pub fn parse_all(&self) -> ParseResults {
        let mut results = ParseResults::default();
        
        // Try each component independently
        match self.imports() {
            Ok(imports) => results.imports = Some(imports.clone()),
            Err(e) => results.errors.push(e),
        }
        
        match self.exports() {
            Ok(exports) => results.exports = Some(exports.clone()),
            Err(e) => results.errors.push(e),
        }
        
        // Continue with other components...
        
        results
    }
}
```

## Testing Infrastructure

### Fuzzing Support

```rust
#[cfg(fuzzing)]
pub fn fuzz_pe_parser(data: &[u8]) {
    // Don't panic on malformed input
    let _ = std::panic::catch_unwind(|| {
        if let Ok(pe) = Pe::parse(data) {
            // Exercise all parsing paths
            let _ = pe.imports();
            let _ = pe.exports();
            let _ = pe.resources();
            let _ = pe.certificates();
            let _ = pe.rich_header();
        }
    });
}
```

### Property-Based Testing

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn test_rva_offset_roundtrip(rva in 0u32..0x10000000) {
            let pe = create_test_pe();
            if let Some(offset) = pe.rva_to_offset(rva) {
                let rva2 = pe.offset_to_rva(offset);
                assert_eq!(Some(rva), rva2);
            }
        }
        
        #[test]
        fn test_section_bounds(offset in 0usize..1000000) {
            let pe = create_test_pe();
            if let Some(section) = pe.section_containing_offset(offset) {
                assert!(offset >= section.raw_offset as usize);
                assert!(offset < (section.raw_offset + section.raw_size) as usize);
            }
        }
    }
}
```

## Implementation Notes

### Endianness Handling
- PE is always little-endian
- No need for configurable endianness
- Can use `from_le_bytes` directly

### String Handling
- Most strings are ASCII (imports, exports)
- Resource strings are UTF-16LE
- Use `&str` references where possible
- Cache string conversions

### Memory Safety
- All offsets must be bounds-checked
- Use `get()` instead of indexing
- Return `Option` or `Result` for fallible operations
- No unsafe code in core parser

### Performance Tips
- Inline small functions (`#[inline]`)
- Use `OnceCell` for expensive computations
- Batch operations when possible
- Profile with real-world PEs

This technical design provides the foundation for implementing a high-performance, memory-efficient PE parser that can replace all existing implementations while adding new capabilities.