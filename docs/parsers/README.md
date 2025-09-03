# GLAURUNG Binary Parser Documentation

This directory contains comprehensive documentation for GLAURUNG's binary format parsers. Each parser is designed to safely and efficiently extract structured information from binary files while maintaining security and resource bounds.

## Parser Categories

### Core Executable Formats (Priority 1)
- **[ELF](./elf/)** - Executable and Linkable Format (Linux/Unix)
- **[PE-COFF](./pe-coff/)** - Portable Executable / Common Object File Format (Windows)
- **[Mach-O](./macho/)** - Mach Object format (macOS/iOS)

### Bytecode & Virtual Machine Formats (Priority 2)
- **[Python](./python/)** - Python bytecode (.pyc, .pyo) files
- **[Java/JVM](./java/)** - Java class files and JAR archives
- **[.NET/CLR](./dotnet/)** - .NET assemblies and CLI metadata
- **[Android](./android/)** - DEX bytecode and APK packages
- **[WebAssembly](./wasm/)** - WebAssembly binary format

### Container & Archive Formats (Priority 3)
- **[Archive](./archive/)** - ZIP, TAR, AR, and other archive formats
- **[Compression](./compression/)** - GZIP, DEFLATE, XZ, Zstandard, and other compression formats

### Dynamic & Shared Libraries (Priority 4)
- **Shared Objects** - .so (ELF), .dll (PE), .dylib (Mach-O)
- **Static Libraries** - .a (AR format), .lib (COFF)

### Specialized Formats (Priority 5)
- **[Firmware](./firmware/)** - UEFI, Android boot images, embedded formats
- **[Debug Info](./debug-info/)** - DWARF, PDB, and other debug information formats
- **Kernel Modules** - .ko (Linux), .sys (Windows), .kext (macOS)

### Language-Specific Bytecode (Future)
- **Lua** - .luac compiled Lua bytecode
- **Ruby** - .rbc Rubinius bytecode
- **Erlang/Elixir** - .beam BEAM bytecode
- **Go** - Embedded metadata in Go binaries
- **Rust** - Embedded metadata in Rust binaries

## Parser Design Principles

### 1. Safety First
- **Bounded reads**: Never read beyond file boundaries
- **Resource limits**: Memory and CPU usage constraints
- **Timeout protection**: Prevent infinite loops in malformed files
- **Error recovery**: Graceful handling of corrupt data

### 2. Progressive Parsing
- **Lazy evaluation**: Parse only what's needed
- **Incremental analysis**: Build understanding progressively
- **Early termination**: Stop on critical errors

### 3. Format Validation
- **Magic number verification**: Check file signatures
- **Structure validation**: Verify internal consistency
- **Cross-reference checking**: Validate pointers and offsets

### 4. Rich Error Reporting
- **Detailed error context**: Offset, expected vs actual values
- **Recovery suggestions**: How to handle partial data
- **Validation warnings**: Non-critical issues

## Common Parser Components

### Header Parsing
Every parser implements header validation:
```rust
pub trait HeaderParser {
    fn parse_header(&self, data: &[u8]) -> Result<Header, ParseError>;
    fn validate_magic(&self, data: &[u8]) -> bool;
    fn get_endianness(&self) -> Endianness;
}
```

### Section/Segment Enumeration
Structured traversal of file regions:
```rust
pub trait SectionParser {
    fn enumerate_sections(&self) -> Vec<Section>;
    fn parse_section(&self, index: usize) -> Result<SectionData, ParseError>;
}
```

### Symbol Resolution
Extract and resolve symbolic information:
```rust
pub trait SymbolParser {
    fn parse_symbols(&self) -> Vec<Symbol>;
    fn resolve_symbol(&self, name: &str) -> Option<Symbol>;
}
```

## Parser Implementation Status

### Native Executables
| Format | Triage | Basic Parse | Full Parse | Symbols | Relocations | Resources |
|--------|--------|-------------|------------|---------|-------------|-----------|
| ELF    | ✅     | ✅         | ⏳         | ⏳      | ⏳          | N/A       |
| PE     | ✅     | ✅         | ⏳         | ⏳      | ⏳          | ⏳        |
| Mach-O | ✅     | ✅         | ⏳         | ⏳      | ⏳          | N/A       |

### Bytecode Formats
| Format  | Triage | Header | Disassembly | Decompile | Obfuscation | Metadata |
|---------|--------|--------|-------------|-----------|-------------|----------|
| Python  | ✅     | ⏳     | ⏳         | ⏳        | ⏳          | ⏳       |
| Java    | ✅     | ⏳     | ⏳         | ⏳        | ⏳          | ⏳       |
| .NET    | ✅     | ⏳     | ⏳         | ⏳        | ⏳          | ⏳       |
| Android | ⏳     | ⏳     | ⏳         | ⏳        | ⏳          | ⏳       |
| WASM    | ✅     | ⏳     | ⏳         | ⏳        | N/A         | ⏳       |

### Archive Formats
| Format | Detection | List | Extract | Nested | Compression | Encryption |
|--------|-----------|------|---------|--------|-------------|------------|
| ZIP    | ✅       | ⏳   | ⏳      | ⏳     | ⏳          | ⏳        |
| TAR    | ✅       | ⏳   | ⏳      | ⏳     | ⏳          | N/A       |
| AR     | ✅       | ⏳   | ⏳      | N/A    | N/A         | N/A       |

Legend: ✅ Complete | 🚧 In Progress | ⏳ Planned | N/A Not Applicable

## Reference Specifications

All parsers are implemented according to official specifications located in:
- `/reference/specifications/` - Format specifications and headers
- `/reference/LIEF/` - Reference parser implementation
- `/reference/goblin/` - Rust binary parsing examples

## Testing Strategy

### Unit Tests
- Header parsing edge cases
- Malformed file handling
- Resource limit enforcement

### Integration Tests
- Real-world binary samples
- Cross-validation with reference parsers
- Format compliance verification

### Fuzz Testing
- Coverage-guided fuzzing with cargo-fuzz
- Format-aware mutation strategies
- Crash reproduction and minimization

## Contributing

When adding or modifying parsers:

1. **Document the format**: Link to specifications
2. **Define the data model**: Use Rust type system
3. **Implement safety checks**: Bounds, timeouts, validation
4. **Add comprehensive tests**: Unit, integration, fuzz
5. **Update status matrix**: Track implementation progress

## See Also

- [Triage Pipeline](../triage/) - How files are identified and routed to parsers
- [Data Model](../data-model/) - Core types and structures
- [Error Handling](../../src/error.rs) - Error types and recovery strategies
