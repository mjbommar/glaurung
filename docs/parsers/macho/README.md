# Mach-O Parser Documentation

## Overview

Mach-O (Mach Object) is the native executable format for Apple platforms including macOS, iOS, iPadOS, watchOS, and tvOS. GLAURUNG's Mach-O parser handles executables, dynamic libraries (dylibs), bundles, kernel extensions (kexts), and universal binaries (fat archives).

## Format Specifications

### Primary References
- **Apple Headers**: `/reference/specifications/macho/loader.h`
- **Fat/Universal Binary**: `/reference/specifications/macho/fat.h`
- **Dynamic Linker**: `/reference/specifications/macho/dyld.h`
- **Symbol Tables**: `/reference/specifications/macho/nlist.h`
- **Relocations**: `/reference/specifications/macho/reloc.h`

### Implementation References
- **Go Standard Library**: `/reference/specifications/macho/golang_macho.go`
- **LLVM LIEF**: `/reference/LIEF/include/LIEF/MachO/`
- **Apple Open Source**: dyld and cctools repositories

## Mach-O Structure

```
┌─────────────────┐
│   Mach Header   │  Magic, CPU type, file type, load commands
├─────────────────┤
│  Load Commands  │  Segments, dylib refs, symbol tables, etc.
├─────────────────┤
│    Segments     │  __TEXT, __DATA, __LINKEDIT, etc.
├─────────────────┤
│    Sections     │  __text, __data, __bss, __const, etc.
├─────────────────┤
│   Symbol Table  │  nlist entries
├─────────────────┤
│  String Table   │  Symbol names
└─────────────────┘
```

## Universal Binary Structure

```
┌─────────────────┐
│   Fat Header    │  Magic (0xCAFEBABE or 0xCAFEBABF)
├─────────────────┤
│   Fat Archs     │  CPU type, offset, size for each slice
├─────────────────┤
│  Architecture 1 │  Complete Mach-O for arch 1
├─────────────────┤
│  Architecture 2 │  Complete Mach-O for arch 2
├─────────────────┤
│       ...       │  Additional architectures
└─────────────────┘
```

## Parser Implementation

### Phase 1: Format Detection
- [ ] Fat binary detection (0xCAFEBABE, 0xCAFEBABF)
- [ ] Mach-O magic validation (0xFEEDFACE, 0xFEEDFACF, etc.)
- [ ] Architecture extraction (x86_64, arm64, arm64e)
- [ ] File type identification (executable, dylib, bundle)

### Phase 2: Header Parsing
- [ ] CPU type and subtype
- [ ] File type and flags
- [ ] Number of load commands
- [ ] Size of load commands

### Phase 3: Load Commands
- [ ] LC_SEGMENT/LC_SEGMENT_64
- [ ] LC_SYMTAB (symbol table)
- [ ] LC_DYLD_INFO (dynamic linking info)
- [ ] LC_LOAD_DYLIB (shared library dependencies)
- [ ] LC_ID_DYLIB (library identification)
- [ ] LC_MAIN (entry point)
- [ ] LC_CODE_SIGNATURE
- [ ] LC_ENCRYPTION_INFO
- [ ] LC_UUID
- [ ] LC_VERSION_MIN_*
- [ ] LC_BUILD_VERSION
- [ ] LC_RPATH
- [ ] LC_FUNCTION_STARTS
- [ ] LC_DATA_IN_CODE

### Phase 4: Segments and Sections
- [ ] Segment enumeration
- [ ] Section parsing within segments
- [ ] Virtual memory layout
- [ ] File offset mapping
- [ ] Protection flags

### Phase 5: Symbol Resolution
- [ ] Symbol table parsing
- [ ] String table indexing
- [ ] Local vs external symbols
- [ ] Undefined symbols
- [ ] Symbol name demangling

### Phase 6: Code Signing
- [ ] Code signature validation
- [ ] Certificate extraction
- [ ] Entitlements parsing
- [ ] Team ID verification
- [ ] Notarization check

## Data Model

```rust
pub struct MachOFile {
    pub header: MachHeader,
    pub load_commands: Vec<LoadCommand>,
    pub segments: Vec<Segment>,
    pub symbols: Vec<Symbol>,
    pub dylibs: Vec<Dylib>,
    pub code_signature: Option<CodeSignature>,
    pub uuid: Option<[u8; 16]>,
}

pub struct MachHeader {
    pub magic: u32,
    pub cpu_type: CpuType,
    pub cpu_subtype: CpuSubtype,
    pub file_type: FileType,
    pub flags: u32,
}

pub struct Segment {
    pub name: String,           // __TEXT, __DATA, etc.
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub max_prot: u32,
    pub init_prot: u32,
    pub sections: Vec<Section>,
}

pub struct UniversalBinary {
    pub architectures: Vec<FatArch>,
    pub slices: HashMap<CpuType, MachOFile>,
}
```

## Apple-Specific Features

### CPU Types
- x86_64 (Intel 64-bit)
- arm64 (Apple Silicon)
- arm64e (with pointer authentication)
- i386 (Intel 32-bit, legacy)
- armv7/armv7s (32-bit ARM, legacy iOS)

### File Types
- MH_EXECUTE (executable)
- MH_DYLIB (dynamic library)
- MH_BUNDLE (loadable bundle)
- MH_OBJECT (object file)
- MH_DYLINKER (dynamic linker)
- MH_KEXT_BUNDLE (kernel extension)
- MH_DSYM (debug symbols)

### Special Segments
- `__TEXT`: Executable code and read-only data
- `__DATA`: Initialized writable data
- `__DATA_CONST`: Read-only data after dyld processing
- `__LINKEDIT`: Dynamic linker info
- `__PAGEZERO`: Unmapped space (security)

## Security Considerations

### Runtime Protections
- ASLR (PIE - Position Independent Executable)
- Stack canaries
- Restrict segment
- Hardened runtime
- Library validation

### Code Signing
- Embedded signatures
- Detached signatures
- Designated requirements
- Entitlements

### Common Attack Vectors
- Dylib hijacking
- Code injection
- Entitlement escalation
- Signature stripping

## Testing Coverage

### Test Samples
- Minimal Mach-O: `/reference/specifications/samples/minimal_macho`
- Universal binaries: Multiple architectures
- Signed applications: With various entitlements
- Framework bundles: Complex dependencies
- Kernel extensions: Special load commands

### Validation Tests
- [ ] Header parsing correctness
- [ ] Load command enumeration
- [ ] Symbol resolution
- [ ] Code signature validation
- [ ] Universal binary slicing

## Platform Variations

### macOS
- Full feature set
- Notarization requirements
- Hardened runtime
- System extensions

### iOS/iPadOS
- Mandatory code signing
- Fairplay encryption
- App thinning
- Bitcode sections

### watchOS/tvOS
- Reduced architectures
- Platform-specific load commands
- Size optimizations

## Objective-C/Swift Support

### Objective-C Runtime
- [ ] __objc_* sections
- [ ] Class and category parsing
- [ ] Method lists
- [ ] Protocol definitions
- [ ] Property lists

### Swift Runtime
- [ ] __swift* sections
- [ ] Type metadata
- [ ] Protocol conformances
- [ ] Reflection data

## Performance Optimizations

### Lazy Loading
- Parse load commands on demand
- Defer section data reading
- Cache symbol lookups

### Memory Efficiency
- Map files instead of loading
- Share string tables
- Compress symbol data

## Error Handling

### Parse Errors
```rust
pub enum MachOParseError {
    InvalidMagic(u32),
    UnsupportedCpuType(i32),
    InvalidLoadCommand { cmd: u32, offset: u64 },
    MalformedSegment { name: String },
    InvalidCodeSignature,
    // ...
}
```

### Recovery Strategies
- Skip unknown load commands
- Continue on signature failures
- Handle encrypted sections
- Report architecture mismatches

## Integration Points

### With Triage Pipeline
- Format detection via magic numbers
- Architecture identification
- Binary type classification

### With Disassembler
- Text segment location
- Entry point determination
- Function starts data

### With Symbol Resolver
- Symbol table extraction
- Dynamic symbol resolution
- Swift/ObjC metadata

## Reverse Engineering Challenges

### Obfuscation Techniques
- [ ] String encryption
- [ ] Symbol stripping
- [ ] Control flow flattening
- [ ] Anti-debugging checks

### Analysis Helpers
- Objective-C class reconstruction
- Swift type demangling
- Import reconstruction
- Cross-reference generation

## Future Enhancements

- [ ] Full Objective-C runtime parsing
- [ ] Swift metadata extraction
- [ ] Bitcode disassembly
- [ ] XNU kernel binary support
- [ ] Dynamic cache parsing
- [ ] ChainedFixups support
- [ ] Rosetta 2 translation hints

## References

- [Apple's Mach-O Documentation](https://developer.apple.com/documentation/)
- [Darwin XNU Source](https://github.com/apple-oss-distributions/xnu)
- [dyld Source Code](https://github.com/apple-oss-distributions/dyld)
- [LLVM Mach-O Support](https://llvm.org/docs/)