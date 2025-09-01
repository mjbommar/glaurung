# ELF Parser Documentation

## Overview

The Executable and Linkable Format (ELF) is the standard binary format for Unix and Unix-like systems including Linux, BSD, Solaris, and others. GLAURUNG's ELF parser provides comprehensive support for analyzing ELF binaries including executables, shared libraries, object files, and core dumps.

## Format Specifications

### Primary References
- **System V ABI**: `/reference/specifications/elf/ELF_Format.pdf`
- **Generic ABI**: `/reference/specifications/elf/gabi41.pdf`
- **Linux Extensions**: `/reference/specifications/elf/linux_elf.h`
- **DWARF Debug Format**: `/reference/specifications/elf/DWARF5.pdf`

### Implementation References
- **GNU Binutils**: `/reference/specifications/elf/binutils_elf_common.h`
- **LLVM**: `/reference/LIEF/include/LIEF/ELF/`
- **Go Standard Library**: `/reference/specifications/elf/golang_elf.go`

## ELF Structure

```
┌─────────────────┐
│   ELF Header    │  e_ident[16], e_type, e_machine, e_version...
├─────────────────┤
│ Program Headers │  p_type, p_offset, p_vaddr, p_paddr...
├─────────────────┤
│    Sections     │  .text, .data, .bss, .rodata...
├─────────────────┤
│ Section Headers │  sh_name, sh_type, sh_flags, sh_addr...
└─────────────────┘
```

## Parser Implementation

### Phase 1: Header Validation
- [ ] Magic number verification (0x7F 'E' 'L' 'F')
- [ ] Class detection (32-bit vs 64-bit)
- [ ] Endianness detection
- [ ] ABI version checking
- [ ] Machine architecture identification

### Phase 2: Program Headers
- [ ] Segment enumeration (LOAD, DYNAMIC, INTERP, NOTE)
- [ ] Memory layout calculation
- [ ] Entry point resolution
- [ ] Interpreter path extraction

### Phase 3: Section Headers
- [ ] Section table parsing
- [ ] String table resolution
- [ ] Section type identification
- [ ] Section flags interpretation

### Phase 4: Dynamic Linking
- [ ] Dynamic section parsing
- [ ] Shared library dependencies
- [ ] Symbol versioning
- [ ] Relocation entries

### Phase 5: Symbol Tables
- [ ] Symbol table parsing (.symtab, .dynsym)
- [ ] Symbol binding and visibility
- [ ] Name demangling
- [ ] PLT/GOT resolution

### Phase 6: Advanced Features
- [ ] Debug information (DWARF)
- [ ] Note sections
- [ ] TLS (Thread Local Storage)
- [ ] GNU extensions

## Data Model

```rust
pub struct ElfFile {
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub symbols: Vec<Symbol>,
    pub dynamic: Option<DynamicSection>,
    pub interpreter: Option<String>,
}

pub struct ElfHeader {
    pub class: ElfClass,           // 32-bit or 64-bit
    pub endianness: Endianness,    // Little or Big
    pub os_abi: OsAbi,            // System V, Linux, FreeBSD...
    pub machine: Machine,          // x86, x86_64, ARM, RISC-V...
    pub entry_point: Address,
}
```

## Security Considerations

### Common Attack Vectors
- **Malformed headers**: Validate all offsets and sizes
- **Overlapping segments**: Check for memory conflicts
- **Symbol table corruption**: Bounds check all string references
- **Integer overflows**: Use checked arithmetic

### Defensive Parsing
- Validate section/segment offsets before access
- Enforce maximum string lengths
- Limit symbol table sizes
- Timeout on complex relocations

## Testing Coverage

### Test Samples
- Minimal valid ELF: `/reference/specifications/samples/minimal_elf.bin`
- Standard executables: Various architectures and configurations
- Shared libraries: Position-independent code
- Core dumps: Process memory snapshots
- Malformed samples: Fuzzer-generated edge cases

### Validation Tests
- [ ] Header parsing correctness
- [ ] Section enumeration completeness
- [ ] Symbol resolution accuracy
- [ ] Dynamic linking information
- [ ] Resource limit enforcement

## Platform-Specific Extensions

### Linux
- GNU hash tables
- Build ID notes
- Stack executable flags
- RELRO (Relocation Read-Only)

### Android
- Android-specific relocations
- Packed relocations (RELR)
- Mini debug info

### BSD Variants
- BSD-specific note types
- Branded ELF executables

## Performance Optimizations

### Lazy Parsing
- Parse headers on demand
- Cache frequently accessed sections
- Defer symbol resolution

### Memory Efficiency
- Stream large sections
- Use memory-mapped I/O when possible
- Release unused data progressively

## Error Handling

### Parse Errors
```rust
pub enum ElfParseError {
    InvalidMagic,
    UnsupportedClass(u8),
    InvalidEndianness,
    CorruptHeader { offset: u64, reason: String },
    SectionOutOfBounds { index: usize, max: usize },
    // ...
}
```

### Recovery Strategies
- Continue parsing on non-critical errors
- Provide partial results when possible
- Report all issues with context

## Integration Points

### With Triage Pipeline
- Format detection via magic numbers
- Architecture and bit-width extraction
- Initial verdict generation

### With Disassembler
- Code section identification
- Entry point determination
- Function boundary hints

### With Symbol Resolver
- Symbol table extraction
- Name demangling
- Cross-reference generation

## Future Enhancements

- [ ] Full DWARF debug info parsing
- [ ] CFI (Call Frame Information) support
- [ ] Exception handling data
- [ ] Kernel module support
- [ ] Compressed section support
- [ ] Multi-architecture fat binaries

## References

- [System V ABI Documentation](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Linux ELF Extensions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h)
- [DWARF Debugging Standard](https://dwarfstd.org/)
- [GNU Binutils BFD](https://sourceware.org/binutils/docs/bfd/)