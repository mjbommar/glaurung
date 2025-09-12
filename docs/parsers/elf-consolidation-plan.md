# ELF Parser Consolidation Plan

## Executive Summary

This document outlines the consolidation of all ELF (Executable and Linkable Format) parsing functionality scattered across the Glaurung codebase into a unified, self-contained ELF parser module at `src/formats/elf/`.

## Current State Analysis

### Existing Implementations

1. **src/symbols/elf.rs** (526 lines)
   - Core ELF symbol extraction
   - Security features detection
   - Dynamic library analysis
   - Import/export enumeration

2. **src/analysis/elf_got.rs** (152 lines)
   - GOT entry to symbol mapping
   - Relocation parsing

3. **src/analysis/elf_plt.rs** (192 lines)
   - PLT entry to function mapping
   - Import resolution

4. **src/triage/headers.rs** (partial)
   - Header validation
   - Architecture detection

5. **src/triage/parsers.rs** (partial)
   - Multi-parser validation
   - External library integration

6. **src/symbols/analysis/env.rs** (partial)
   - Environment information extraction

### Current Dependencies

- **object** crate - Primary parsing library
- **goblin** crate (optional) - Alternative parser
- External for all structural parsing

### Pain Points

1. **Scattered Implementation**: 6+ modules handle ELF parsing
2. **External Dependencies**: Relies heavily on object/goblin
3. **Redundant Parsing**: Multiple passes over same data
4. **Limited Architecture Support**: Focused on x86_64
5. **Incomplete Coverage**: Missing some ELF features
6. **Performance Issues**: Multiple allocations and copies

## Proposed Architecture

### Design Principles

1. **Zero-Copy Design**: Parse structures in-place from memory
2. **Lazy Loading**: Defer expensive operations until needed
3. **Unified API**: Single entry point for all ELF operations
4. **Multi-Architecture**: Support all major architectures
5. **Endian-Aware**: Handle both little and big endian
6. **Security-First**: Comprehensive security feature detection

### Module Structure

```
src/formats/elf/
├── mod.rs           # Main ElfParser API
├── types.rs         # Core structures and constants
├── headers.rs       # ELF header parsing
├── sections.rs      # Section header table management
├── segments.rs      # Program header table management
├── dynamic.rs       # Dynamic section parsing
├── symbols.rs       # Symbol table parsing
├── relocations.rs   # Relocation processing
├── notes.rs         # Note section parsing
└── utils.rs         # Utility functions
```

### Core Components

#### 1. ElfParser (mod.rs)
```rust
pub struct ElfParser<'data> {
    data: &'data [u8],
    header: ElfHeader,
    sections: OnceCell<SectionTable<'data>>,
    segments: OnceCell<SegmentTable<'data>>,
    symbols: OnceCell<SymbolTable<'data>>,
    dynamic: OnceCell<DynamicSection<'data>>,
    relocations: OnceCell<RelocationTable<'data>>,
}
```

#### 2. Type System (types.rs)
- ELF constants (ET_*, EM_*, SHT_*, PT_*, DT_*, etc.)
- Header structures (Elf32/64_Ehdr, Shdr, Phdr)
- Symbol structures (Elf32/64_Sym)
- Relocation structures (Elf32/64_Rel/Rela)
- Dynamic structures (Elf32/64_Dyn)

#### 3. Section Management (sections.rs)
- Efficient section lookup by name
- Section data access
- String table handling
- Special section detection

#### 4. Segment Management (segments.rs)
- Program header parsing
- Virtual address to file offset mapping
- Segment permission analysis
- LOAD segment enumeration

#### 5. Dynamic Section (dynamic.rs)
- DT_NEEDED library extraction
- RPATH/RUNPATH parsing
- Symbol versioning
- Dynamic symbol resolution

#### 6. Symbol Tables (symbols.rs)
- .symtab and .dynsym parsing
- Symbol lookup by name/address
- Import/export classification
- Symbol demangling

#### 7. Relocations (relocations.rs)
- REL and RELA parsing
- GOT/PLT mapping
- Relocation resolution
- Cross-references

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1-2)

1. **Create base module structure**
   - Set up directory hierarchy
   - Define core types and constants
   - Implement error handling

2. **Implement header parsing**
   - ELF identification
   - 32/64-bit detection
   - Endianness handling
   - Architecture mapping

3. **Implement section table**
   - Section header parsing
   - String table extraction
   - Section lookup utilities

### Phase 2: Data Structures (Week 3-4)

1. **Program header table**
   - Segment parsing
   - Virtual memory layout
   - Permission analysis

2. **Symbol tables**
   - Symbol parsing
   - String resolution
   - Import/export detection

3. **Dynamic section**
   - Dynamic entry parsing
   - Library dependencies
   - Path extraction

### Phase 3: Advanced Features (Week 5-6)

1. **Relocation processing**
   - REL/RELA parsing
   - GOT mapping
   - PLT resolution

2. **Security analysis**
   - NX bit detection
   - RELRO analysis
   - PIE/ASLR detection
   - Stack canary detection
   - FORTIFY_SOURCE indicators

3. **Note sections**
   - Build ID extraction
   - GNU properties
   - Version information

### Phase 4: Migration (Week 7-8)

1. **API compatibility layer**
   - Wrapper functions for existing code
   - Gradual migration helpers

2. **Update existing modules**
   - Replace object crate usage
   - Update import statements
   - Maintain backward compatibility

3. **Testing and validation**
   - Unit tests for each component
   - Integration tests
   - Performance benchmarks
   - Fuzzing

## Migration Strategy

### Step 1: Parallel Implementation
- Build new parser alongside existing code
- No breaking changes initially

### Step 2: Gradual Adoption
```rust
// Old code
let obj = object::read::File::parse(data)?;

// New code
let elf = ElfParser::parse(data)?;
```

### Step 3: Feature Parity
- Ensure all existing functionality is covered
- Add missing features identified during migration

### Step 4: Deprecation
- Mark old modules as deprecated
- Update documentation
- Provide migration guide

### Step 5: Removal
- Remove old implementations
- Remove external dependencies
- Clean up imports

## Performance Targets

### Parsing Speed
- < 1ms for typical ELF binaries (< 10MB)
- < 10ms for large binaries (< 100MB)
- Lazy loading for expensive operations

### Memory Usage
- Zero-copy parsing
- No unnecessary allocations
- Minimal memory overhead (< 1KB per parser)

### Accuracy
- 100% compatibility with ELF specification
- Support for all common extensions
- Graceful handling of malformed files

## Testing Strategy

### Unit Tests
- Each module fully tested
- Edge cases and error conditions
- Endianness variations
- 32/64-bit variations

### Integration Tests
- Real-world ELF binaries
- Various architectures (x86, ARM, RISC-V)
- Stripped vs unstripped
- Static vs dynamic

### Fuzz Testing
- AFL++ for coverage-guided fuzzing
- Property-based testing
- Malformed input handling

### Benchmarks
- Parsing performance
- Memory usage
- Comparison with object crate

## Security Considerations

### Input Validation
- Bounds checking on all reads
- Integer overflow protection
- Malformed header detection

### Resource Limits
- Maximum section/segment counts
- Maximum symbol table size
- Timeout on expensive operations

### Security Feature Detection
- Comprehensive security analysis
- Clear reporting of security features
- Detection of security anti-patterns

## Documentation Requirements

### API Documentation
- Comprehensive rustdoc comments
- Usage examples
- Common patterns

### Architecture Guide
- Design decisions
- Memory layout
- Performance characteristics

### Migration Guide
- Step-by-step migration
- Before/after examples
- Troubleshooting

## Success Metrics

1. **Code Consolidation**
   - Single module for all ELF parsing
   - Removal of external dependencies
   - 50% reduction in code duplication

2. **Performance**
   - 2x faster than object crate
   - 50% less memory usage
   - Sub-millisecond parsing for common cases

3. **Coverage**
   - All existing features maintained
   - Additional security features added
   - Support for more architectures

4. **Quality**
   - Zero panics on malformed input
   - 100% safe Rust (no unsafe blocks)
   - > 90% test coverage

## Timeline

- **Week 1-2**: Core infrastructure
- **Week 3-4**: Data structures
- **Week 5-6**: Advanced features
- **Week 7**: Migration and testing
- **Week 8**: Documentation and cleanup

## Risks and Mitigations

### Risk 1: Specification Complexity
- **Mitigation**: Reference existing implementations
- **Mitigation**: Extensive testing with real binaries

### Risk 2: Performance Regression
- **Mitigation**: Continuous benchmarking
- **Mitigation**: Profile-guided optimization

### Risk 3: Breaking Changes
- **Mitigation**: Compatibility layer
- **Mitigation**: Gradual migration path

## Conclusion

This consolidation will create a robust, performant, and self-contained ELF parser that eliminates external dependencies while providing superior functionality and performance. The modular design ensures maintainability and extensibility for future enhancements.