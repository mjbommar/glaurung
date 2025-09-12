# Mach-O Parser Consolidation Plan

## Executive Summary

This document outlines the plan to consolidate scattered Mach-O parsing functionality across the Glaurung codebase into a unified, comprehensive Mach-O parser module. The new parser will support Universal/Fat binaries, multi-architecture files, and modern security features while maintaining zero-copy design principles and lazy loading for performance.

## Current State Analysis

### Existing Implementations (7 locations)

1. **src/symbols/macho.rs** (87 lines)
   - Basic symbol extraction
   - Fat binary detection but no parsing
   - Limited load command parsing (LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB)
   - No section or segment parsing

2. **src/symbols/analysis/macho_env.rs** (87 lines)
   - Environment information extraction
   - RPATH parsing (LC_RPATH)
   - Code signature detection (LC_CODE_SIGNATURE)
   - Minimum OS version (LC_VERSION_MIN_*)
   - Duplicates header parsing logic

3. **src/triage/signatures.rs**
   - CPU type to architecture mapping
   - Magic number definitions
   - Duplicated constants

4. **src/core/binary.rs**
   - References to Mach-O format enum
   - No actual parsing

5. **src/triage/format_detection.rs**
   - Magic number detection only
   - No structural validation

6. **src/symbols/analysis/env.rs**
   - Calls into macho_env module
   - Format routing logic

7. **src/triage/signing.rs**
   - References LC_CODE_SIGNATURE
   - No actual parsing

### Problems with Current Approach

- **Fragmentation**: Mach-O parsing spread across 7+ files
- **Duplication**: Header parsing logic duplicated 3 times
- **Incomplete**: No segment/section parsing, no Fat binary support
- **Inconsistent**: Different error handling approaches
- **Limited**: Missing modern features (dyld cache, chained fixups, PAC)
- **Performance**: Multiple passes over the same data
- **No Architecture Support**: Cannot handle Universal binaries

## Proposed Architecture

### Module Structure

```
src/formats/macho/
├── mod.rs              // Main API and MachOParser
├── types.rs            // Core types and constants
├── headers.rs          // Header parsing (Fat, Mach32, Mach64)
├── segments.rs         // Segment and section parsing
├── load_commands.rs    // Load command parsing
├── symbols.rs          // Symbol table parsing
├── dyld.rs            // Dynamic linking information
├── codesign.rs        // Code signature parsing
├── fat.rs             // Universal/Fat binary support
└── utils.rs           // Endian utilities and helpers
```

### Core Design Principles

1. **Zero-Copy Parsing**: Parse structures in-place without allocation
2. **Lazy Loading**: Use OnceCell for expensive operations
3. **Multi-Architecture**: Full support for Universal/Fat binaries
4. **Endian-Aware**: Handle both big and little endian
5. **Security-First**: Comprehensive security feature detection
6. **Budget-Aware**: Timeout support for large binaries
7. **Validation**: Strict bounds checking and validation

## Implementation Timeline

### Week 1-2: Core Types and Headers
- [ ] Create types.rs with all Mach-O constants
- [ ] Implement CPU type/subtype enums
- [ ] Define load command types
- [ ] Create header structures (Fat, Mach32, Mach64)
- [ ] Implement endian-aware primitive reading

### Week 3-4: Fat Binary Support
- [ ] Parse Fat headers (32 and 64-bit)
- [ ] Enumerate architectures in Universal binaries
- [ ] Extract individual architecture slices
- [ ] Validate alignment and offsets
- [ ] Handle nested Fat binaries

### Week 5-6: Load Commands and Segments
- [ ] Parse all load command types
- [ ] Implement segment parsing (__TEXT, __DATA, __LINKEDIT)
- [ ] Parse sections within segments
- [ ] Build section index and lookup tables
- [ ] RVA to file offset conversion

### Week 7-8: Symbol Tables
- [ ] Parse LC_SYMTAB command
- [ ] Extract symbol entries
- [ ] Parse string tables
- [ ] Implement symbol lookup by name/address
- [ ] Support for N_STAB debugging symbols

### Week 9-10: Dynamic Linking
- [ ] Parse LC_LOAD_DYLIB commands
- [ ] Extract dependent libraries
- [ ] Parse LC_RPATH for runtime paths
- [ ] Handle LC_DYLD_INFO for modern binaries
- [ ] Parse chained fixups (iOS 15+)

### Week 11-12: Security Features
- [ ] Parse LC_CODE_SIGNATURE
- [ ] Detect PIE (MH_PIE flag)
- [ ] Detect stack canaries
- [ ] Parse LC_ENCRYPTION_INFO
- [ ] Detect hardened runtime flags
- [ ] Parse entitlements

### Week 13-14: Testing and Migration
- [ ] Comprehensive unit tests
- [ ] Fuzz testing with malformed binaries
- [ ] Migrate existing code to new parser
- [ ] Performance benchmarks
- [ ] Documentation

## Key Features to Implement

### 1. Universal/Fat Binary Support
```rust
pub struct FatParser<'a> {
    data: &'a [u8],
    header: FatHeader,
    architectures: Vec<FatArch>,
}

impl FatParser {
    pub fn architectures(&self) -> Vec<Architecture>;
    pub fn slice_for_arch(&self, arch: Architecture) -> Option<&[u8]>;
    pub fn best_arch_for_host(&self) -> Option<Architecture>;
}
```

### 2. Load Command Parsing
```rust
pub enum LoadCommand {
    Segment(SegmentCommand),
    DyLib(DyLibCommand),
    SymTab(SymTabCommand),
    DyldInfo(DyldInfoCommand),
    CodeSignature(CodeSignatureCommand),
    // ... 40+ more command types
}
```

### 3. Security Feature Detection
```rust
pub struct SecurityFeatures {
    pub pie: bool,                    // Position Independent Executable
    pub nx_heap: bool,                // Non-executable heap
    pub nx_stack: bool,               // Non-executable stack
    pub restricted: bool,             // SIP/hardened runtime
    pub library_validation: bool,     // Dylib validation
    pub code_signature: bool,         // Has LC_CODE_SIGNATURE
    pub encrypted: bool,              // Has LC_ENCRYPTION_INFO
    pub fortify: bool,                // _chk functions
    pub stack_canary: bool,           // __stack_chk_guard
    pub arc: bool,                    // Automatic Reference Counting
    pub pac: bool,                    // Pointer Authentication
}
```

### 4. Dyld Cache Support
```rust
pub struct DyldCacheParser<'a> {
    data: &'a [u8],
    header: DyldCacheHeader,
    images: Vec<DyldCacheImageInfo>,
}

impl DyldCacheParser {
    pub fn extract_image(&self, path: &str) -> Option<&[u8]>;
    pub fn slide_info(&self) -> Option<SlideInfo>;
}
```

### 5. Symbol Resolution
```rust
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    strings: StringTable,
    by_name: HashMap<String, usize>,
    by_address: BTreeMap<u64, Vec<usize>>,
}

impl SymbolTable {
    pub fn resolve_address(&self, addr: u64) -> Option<&Symbol>;
    pub fn find_symbol(&self, name: &str) -> Option<&Symbol>;
    pub fn exports(&self) -> Vec<&Symbol>;
    pub fn imports(&self) -> Vec<&Symbol>;
}
```

## Migration Strategy

### Phase 1: Create New Parser
1. Implement core Mach-O parser in src/formats/macho/
2. Ensure feature parity with existing code
3. Add comprehensive tests

### Phase 2: Update Dependencies
```rust
// Before (multiple locations):
use crate::symbols::macho::summarize_macho;
use crate::symbols::analysis::macho_env;

// After (single import):
use crate::formats::macho::MachOParser;
```

### Phase 3: Remove Old Code
1. Update all call sites to use new parser
2. Remove old implementations:
   - src/symbols/macho.rs
   - src/symbols/analysis/macho_env.rs
3. Update tests

## Testing Requirements

### Unit Tests
- Parse minimal Mach-O files
- Parse Fat binaries with multiple architectures
- Handle malformed headers gracefully
- Validate all load command types
- Test endianness handling

### Integration Tests
- Parse real macOS binaries (/bin/ls, /usr/bin/swift)
- Parse iOS binaries from dyld_shared_cache
- Parse kernel extensions (.kext)
- Parse dynamic libraries (.dylib)
- Parse bundles and frameworks

### Fuzz Testing
- Random data shouldn't cause panics
- Truncated files handled gracefully
- Invalid offsets detected
- Circular references prevented

## Performance Targets

- Parse /bin/ls (100KB) in < 1ms
- Parse Xcode (5GB Fat binary) headers in < 10ms
- Extract slice from Fat binary in O(1)
- Symbol lookup in O(log n)
- Zero allocations for basic parsing

## Security Considerations

1. **Input Validation**: Strict bounds checking on all offsets
2. **Integer Overflow**: Check size calculations
3. **Circular References**: Detect and prevent infinite loops
4. **Memory Safety**: Use safe Rust patterns, no unsafe except for performance-critical paths
5. **Timeout Support**: Budget-aware parsing for untrusted input

## Documentation Requirements

1. **API Documentation**: Comprehensive rustdoc for all public APIs
2. **Format Guide**: Document Mach-O format with diagrams
3. **Migration Guide**: Step-by-step migration from old code
4. **Examples**: Parse common binary types
5. **Security Guide**: Best practices for parsing untrusted input

## Success Criteria

- [ ] All existing functionality preserved
- [ ] Support for Universal/Fat binaries
- [ ] Comprehensive security feature detection
- [ ] Zero-copy design with lazy loading
- [ ] < 5ms parse time for typical binaries
- [ ] 100% safe Rust (minimal unsafe)
- [ ] Comprehensive test coverage (>90%)
- [ ] No external dependencies

## References

- [Apple Mach-O Reference](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CodeFootprint/Articles/MachOOverview.html)
- [mach-o/loader.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html)
- [Understanding Mach-O Format](https://lowlevelbits.org/parsing-mach-o-files/)
- [object crate](https://github.com/gimli-rs/object) - Reference implementation