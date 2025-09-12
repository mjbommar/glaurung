# PE Parser Consolidation Plan

## Executive Summary

This document outlines the plan to consolidate all PE parsing functionality from multiple modules into a unified, self-contained PE parser implementation. We will eliminate dependencies on external crates like `object` and create a comprehensive, performance-optimized PE parsing library.

## Current State Analysis

### Existing PE Parsing Locations

1. **src/symbols/pe.rs** - Main PE symbol extraction (500+ lines)
   - Budget-aware parsing with time limits
   - Import/export extraction
   - TLS callback enumeration
   - PDB path extraction
   - Security flags detection

2. **src/analysis/pe_iat.rs** - IAT mapping (290 lines)
   - Duplicates much of PE header parsing
   - Focuses on import address table resolution

3. **src/symbols/analysis/pe_env.rs** - Environment analysis (240 lines)
   - Uses `object` crate for PDB info
   - Manual TLS callback parsing
   - Entry section identification

4. **src/symbols/analysis/imphash.rs** - Import hash (25 lines)
   - Relies entirely on `object` crate
   - Simple MD5 of imports

5. **src/triage/rich_header.rs** - Rich header parsing (440+ lines)
   - Self-contained implementation
   - XOR decryption
   - Compiler fingerprinting

6. **src/triage/headers.rs** - Header validation (200+ lines)
   - Basic PE validation
   - Architecture detection

7. **src/triage/parsers.rs** - Multi-parser validation
   - Uses `object`, `goblin`, `pelite`

### Key Issues to Address

1. **Code Duplication**: Multiple implementations of:
   - RVA to file offset conversion (3 implementations)
   - Section header parsing (4 implementations)
   - Data directory parsing (3 implementations)
   - String extraction from RVAs (3 implementations)

2. **External Dependencies**: Current reliance on:
   - `object` crate for imports/exports/PDB
   - Optional `goblin` and `pelite` for validation

3. **Inconsistent APIs**: Different modules use different:
   - Error handling strategies
   - Data structures for same concepts
   - Parsing approaches (streaming vs full buffer)

4. **Missing Features**: Not currently implemented:
   - Resource directory parsing
   - Certificate/Authenticode validation
   - .NET metadata parsing
   - Relocation processing
   - Debug directory parsing (beyond PDB path)

## Proposed Architecture

### Core Module Structure

```
src/formats/pe/
├── mod.rs                 # Public API and re-exports
├── types.rs               # Core PE data structures
├── headers.rs             # DOS/NT/Optional header parsing
├── sections.rs            # Section table management
├── directories/           # Data directory parsers
│   ├── mod.rs
│   ├── export.rs          # Export directory
│   ├── import.rs          # Import & delay import
│   ├── resource.rs        # Resource tree
│   ├── exceptions.rs      # Exception data (.pdata)
│   ├── security.rs        # Certificates/Authenticode
│   ├── relocations.rs     # Base relocations
│   ├── debug.rs           # Debug directory & PDB
│   ├── tls.rs             # TLS callbacks
│   ├── load_config.rs     # Load configuration
│   └── clr.rs             # .NET CLR header
├── rich_header.rs         # Rich header parsing
├── symbols.rs             # Symbol extraction & demangling
├── iat.rs                 # IAT/import resolution
├── analysis.rs            # Security analysis & heuristics
├── builder.rs             # PE construction (future)
└── utils.rs               # Common utilities

```

### Core Data Types

```rust
// types.rs
pub struct Pe<'data> {
    data: &'data [u8],
    dos_header: DosHeader,
    nt_headers: NtHeaders,
    sections: Vec<Section>,
    data_directories: DataDirectories,
    // Cached/lazy-loaded data
    imports: OnceCell<Vec<Import>>,
    exports: OnceCell<Vec<Export>>,
    resources: OnceCell<ResourceDirectory>,
    rich_header: OnceCell<Option<RichHeader>>,
}

pub struct NtHeaders {
    signature: [u8; 4],
    file_header: CoffHeader,
    optional_header: OptionalHeader,
}

pub enum OptionalHeader {
    Pe32(OptionalHeader32),
    Pe32Plus(OptionalHeader64),
}

pub struct DataDirectories {
    entries: [DataDirectory; 16],
}

pub struct Section {
    header: SectionHeader,
    data: Range<usize>,  // Offset range in file
}
```

### Unified Parser API

```rust
// mod.rs - Public API
pub struct PeParser<'data> {
    pe: Pe<'data>,
    options: ParseOptions,
}

impl<'data> PeParser<'data> {
    /// Create parser with default options
    pub fn new(data: &'data [u8]) -> Result<Self>;
    
    /// Create parser with custom options
    pub fn with_options(data: &'data [u8], options: ParseOptions) -> Result<Self>;
    
    /// Header access
    pub fn dos_header(&self) -> &DosHeader;
    pub fn nt_headers(&self) -> &NtHeaders;
    pub fn optional_header(&self) -> &OptionalHeader;
    pub fn is_64bit(&self) -> bool;
    pub fn machine(&self) -> Machine;
    pub fn entry_point(&self) -> u32;
    pub fn image_base(&self) -> u64;
    
    /// Section access
    pub fn sections(&self) -> &[Section];
    pub fn section_by_name(&self, name: &str) -> Option<&Section>;
    pub fn section_containing_rva(&self, rva: u32) -> Option<&Section>;
    
    /// Import/Export
    pub fn imports(&self) -> Result<&[Import]>;
    pub fn exports(&self) -> Result<&[Export]>;
    pub fn import_hash(&self) -> Result<String>;
    pub fn iat_map(&self) -> Result<BTreeMap<u64, String>>;
    
    /// Resources
    pub fn resources(&self) -> Result<&ResourceDirectory>;
    pub fn resource_by_id(&self, type_id: u32, name_id: u32) -> Result<Vec<u8>>;
    
    /// Security
    pub fn certificates(&self) -> Result<Vec<Certificate>>;
    pub fn authenticode_valid(&self) -> Result<bool>;
    pub fn security_features(&self) -> SecurityFeatures;
    
    /// Debug info
    pub fn debug_info(&self) -> Result<Vec<DebugEntry>>;
    pub fn pdb_path(&self) -> Result<Option<String>>;
    
    /// TLS
    pub fn tls_callbacks(&self) -> Result<Vec<u64>>;
    pub fn tls_data(&self) -> Result<Option<TlsDirectory>>;
    
    /// Rich header
    pub fn rich_header(&self) -> Result<Option<&RichHeader>>;
    
    /// .NET/CLR
    pub fn clr_header(&self) -> Result<Option<ClrHeader>>;
    pub fn is_dotnet(&self) -> bool;
    
    /// Analysis
    pub fn checksum_valid(&self) -> bool;
    pub fn is_signed(&self) -> bool;
    pub fn is_packed(&self) -> PackerDetection;
    pub fn anomalies(&self) -> Vec<PeAnomaly>;
    
    /// Utilities
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize>;
    pub fn offset_to_rva(&self, offset: usize) -> Option<u32>;
    pub fn read_string_at_rva(&self, rva: u32) -> Result<String>;
}

pub struct ParseOptions {
    pub parse_imports: bool,
    pub parse_exports: bool,
    pub parse_resources: bool,
    pub parse_certificates: bool,
    pub parse_debug_info: bool,
    pub parse_rich_header: bool,
    pub max_resource_depth: usize,
    pub timeout_ms: Option<u64>,
    pub validate_checksums: bool,
}
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

1. **Create new module structure**
   - Set up `src/formats/pe/` directory
   - Define core types in `types.rs`
   - Implement basic DOS/PE header parsing

2. **Port essential utilities**
   - Consolidate RVA/offset conversion
   - Unify string reading functions
   - Create section mapping utilities

3. **Implement header parsing**
   - DOS header with stub handling
   - NT headers (COFF + Optional)
   - Section table parsing

### Phase 2: Data Directory Parsers (Week 2)

1. **Import/Export directories**
   - Port from `src/symbols/pe.rs`
   - Add ordinal resolution
   - Implement forwarded exports

2. **Debug directory**
   - Port PDB path extraction
   - Add support for other debug types
   - Parse DWARF/STABS if present

3. **TLS directory**
   - Port callback enumeration
   - Add TLS data extraction
   - Support both PE32/PE32+

4. **Resource directory**
   - Implement tree traversal
   - Add resource extraction
   - Support string/version info

### Phase 3: Advanced Features (Week 3)

1. **Security features**
   - Certificate table parsing
   - Authenticode validation
   - Checksum verification

2. **Rich header**
   - Port from `src/triage/rich_header.rs`
   - Integrate with main parser

3. **Relocations**
   - Base relocation parsing
   - Support all relocation types

4. **.NET/CLR support**
   - CLR header parsing
   - Metadata stream identification
   - Basic .NET detection

### Phase 4: Analysis & Integration (Week 4)

1. **Security analysis**
   - Port security flag detection
   - Add packer detection
   - Implement anomaly detection

2. **Symbol management**
   - Unify import/export handling
   - Add comprehensive demangling
   - Create symbol cache

3. **Performance optimization**
   - Add lazy loading for expensive operations
   - Implement caching strategies
   - Add budget-aware parsing

4. **Testing & validation**
   - Port existing tests
   - Add fuzzing support
   - Validate against reference implementations

### Phase 5: Migration (Week 5)

1. **Update existing code**
   - Replace `src/symbols/pe.rs` usage
   - Replace `src/analysis/pe_iat.rs` usage
   - Update `src/symbols/analysis/pe_env.rs`
   - Update `src/symbols/analysis/imphash.rs`

2. **Remove external dependencies**
   - Remove `object` crate usage for PE
   - Remove optional `pelite` dependency
   - Update `Cargo.toml`

3. **Documentation**
   - Write comprehensive API docs
   - Create migration guide
   - Add usage examples

## Migration Strategy

### Step 1: Parallel Implementation
- Build new parser alongside existing code
- No breaking changes initially
- Test against same inputs

### Step 2: Feature Parity Testing
```rust
#[cfg(test)]
mod migration_tests {
    use super::*;
    
    #[test]
    fn test_import_extraction_parity() {
        let data = include_bytes!("test.exe");
        
        // Old implementation
        let old_result = old::summarize_pe(data, &caps);
        
        // New implementation
        let parser = PeParser::new(data).unwrap();
        let new_imports = parser.imports().unwrap();
        
        assert_eq!(old_result.imports_count, new_imports.len());
    }
}
```

### Step 3: Gradual Migration
1. Update low-risk modules first (imphash, rich_header)
2. Migrate analysis modules
3. Update core symbol extraction
4. Finally update triage pipeline

### Step 4: Cleanup
- Remove old implementations
- Remove unused dependencies
- Update documentation

## Performance Targets

### Benchmarks
- Parse minimal PE: < 100μs
- Parse typical PE (1MB): < 5ms
- Full import resolution: < 10ms
- Resource extraction: < 20ms

### Memory Usage
- Zero-copy where possible
- Lazy loading for expensive data
- Bounded resource traversal
- Configurable limits

## Error Handling

### Error Types
```rust
pub enum PeError {
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidMachine(u16),
    TruncatedHeader { expected: usize, actual: usize },
    InvalidRva { rva: u32 },
    InvalidOffset { offset: usize },
    MalformedImportTable,
    MalformedExportTable,
    ResourceDepthExceeded,
    Timeout,
    // ... comprehensive error types
}
```

### Recovery Strategy
- Continue parsing on non-critical errors
- Provide partial results when possible
- Clear error reporting with context
- Optional strict mode for validation

## Testing Strategy

### Unit Tests
- Each module independently tested
- Edge cases and malformed inputs
- Fuzzing with AFL/libfuzzer

### Integration Tests
- Real PE samples from various compilers
- Packed/obfuscated samples
- .NET assemblies
- Drivers and system files

### Comparison Tests
- Validate against `object` crate output
- Cross-check with `pelite` results
- Compare with IDA/Ghidra/radare2

## Success Criteria

1. **Functional**
   - All current PE parsing features preserved
   - No regression in analysis capabilities
   - New features (resources, certificates) working

2. **Performance**
   - 2x faster than current implementation
   - Memory usage reduced by 30%
   - Support for streaming/partial parsing

3. **Maintainability**
   - Single source of truth for PE parsing
   - Clear module boundaries
   - Comprehensive documentation

4. **Compatibility**
   - Drop-in replacement for existing code
   - Backward compatible API where possible
   - Clear migration path

## Risk Mitigation

### Technical Risks
- **Complexity**: PE format has many edge cases
  - Mitigation: Extensive testing, reference implementations
  
- **Performance**: May not meet targets initially
  - Mitigation: Profile-guided optimization, lazy loading
  
- **Compatibility**: Breaking changes for consumers
  - Mitigation: Compatibility layer, gradual migration

### Schedule Risks
- **Scope creep**: PE format is extensive
  - Mitigation: Phased implementation, MVP first
  
- **Testing burden**: Many edge cases to validate
  - Mitigation: Automated testing, fuzzing

## References

### Implementation References
- `/reference/object/src/read/pe/` - Object crate PE implementation
- `/reference/goblin/src/pe/` - Goblin PE parser
- `/reference/LIEF/include/LIEF/PE/` - LIEF PE structures

### Specifications
- Microsoft PE Format Documentation
- ECMA-335 (CLI/.NET)
- Undocumented PE features (Rich header, etc.)

## Appendix: Feature Comparison

| Feature | Current | Proposed | Priority |
|---------|---------|----------|----------|
| DOS header | ✓ | ✓ | High |
| NT headers | ✓ | ✓ | High |
| Section headers | ✓ | ✓ | High |
| Import table | ✓ | ✓ Enhanced | High |
| Export table | ✓ | ✓ Enhanced | High |
| IAT mapping | ✓ | ✓ Integrated | High |
| Resource directory | ✗ | ✓ | Medium |
| Certificates | ✗ | ✓ | Medium |
| Relocations | Partial | ✓ | Medium |
| Debug directory | Partial | ✓ | High |
| TLS | ✓ | ✓ Enhanced | High |
| Load config | ✗ | ✓ | Low |
| .NET/CLR | ✗ | ✓ | Medium |
| Rich header | ✓ | ✓ Integrated | High |
| Bound imports | ✗ | ✓ | Low |
| Delay imports | ✓ | ✓ Enhanced | High |
| Exception data | ✗ | ✓ | Medium |

## Timeline

- **Week 1**: Core infrastructure, basic parsing
- **Week 2**: Data directory parsers
- **Week 3**: Advanced features
- **Week 4**: Analysis & integration
- **Week 5**: Migration & cleanup
- **Week 6**: Documentation & testing
- **Week 7**: Performance optimization
- **Week 8**: Final validation & release

Total estimated time: 8 weeks for full implementation and migration.