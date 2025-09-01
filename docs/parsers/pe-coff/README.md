# PE-COFF Parser Documentation

## Overview

The Portable Executable (PE) format, based on the Common Object File Format (COFF), is the standard executable format for Windows operating systems. GLAURUNG's PE-COFF parser handles executables (.exe), dynamic libraries (.dll), drivers (.sys), and .NET assemblies.

## Format Specifications

### Primary References
- **Microsoft PE Format**: `/reference/specifications/pe-coff/PE_Format_Microsoft.md`
- **Windows Headers**: `/reference/specifications/pe-coff/winnt.h`
- **ECMA-335 CLI**: `/reference/specifications/pe-coff/ECMA-335_CLI.pdf`
- **.NET Extensions**: `/reference/specifications/pe-coff/dotnet_PE_COFF.md`

### Implementation References
- **Wine Project**: `/reference/specifications/pe-coff/winnt.h`
- **ReactOS**: `/reference/specifications/pe-coff/reactos_winnt.h`
- **MinGW-w64**: `/reference/specifications/pe-coff/mingw_winnt.h`
- **LLVM LIEF**: `/reference/LIEF/include/LIEF/PE/`

## PE Structure

```
┌─────────────────┐
│   DOS Header    │  MZ signature, DOS stub
├─────────────────┤
│   PE Signature  │  "PE\0\0"
├─────────────────┤
│   COFF Header   │  Machine, sections, timestamp
├─────────────────┤
│ Optional Header │  Magic, entry point, image base
├─────────────────┤
│  Data Directory │  Export, import, resources, etc.
├─────────────────┤
│ Section Headers │  .text, .data, .rsrc, .reloc
├─────────────────┤
│  Section Data   │  Actual code and data
└─────────────────┘
```

## Parser Implementation

### Phase 1: DOS Header
- [ ] MZ signature verification (0x5A4D)
- [ ] DOS stub parsing
- [ ] PE header offset extraction
- [ ] DOS compatibility check

### Phase 2: PE Headers
- [ ] PE signature validation ("PE\0\0")
- [ ] COFF header parsing
- [ ] Machine type identification
- [ ] Timestamp extraction
- [ ] Characteristics flags

### Phase 3: Optional Header
- [ ] Magic number (PE32 vs PE32+)
- [ ] Entry point resolution
- [ ] Image base and alignment
- [ ] Subsystem detection
- [ ] DLL characteristics

### Phase 4: Data Directories
- [ ] Export directory parsing
- [ ] Import directory parsing
- [ ] Resource directory traversal
- [ ] Exception directory (.pdata)
- [ ] Certificate table
- [ ] Base relocation table
- [ ] Debug directory
- [ ] TLS directory
- [ ] Load config directory
- [ ] Bound import
- [ ] IAT (Import Address Table)
- [ ] Delay import
- [ ] CLR header (.NET)

### Phase 5: Sections
- [ ] Section enumeration
- [ ] Virtual address mapping
- [ ] Raw data extraction
- [ ] Section characteristics
- [ ] Entropy calculation

### Phase 6: Advanced Features
- [ ] Rich header parsing
- [ ] Authenticode signatures
- [ ] Manifest resources
- [ ] Version information
- [ ] .NET metadata

## Data Model

```rust
pub struct PeFile {
    pub dos_header: DosHeader,
    pub nt_headers: NtHeaders,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub resources: Option<ResourceDirectory>,
    pub certificates: Vec<Certificate>,
    pub debug_info: Vec<DebugEntry>,
}

pub struct NtHeaders {
    pub signature: u32,
    pub file_header: CoffHeader,
    pub optional_header: OptionalHeader,
}

pub struct OptionalHeader {
    pub magic: PeMagic,              // PE32 or PE32+
    pub entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub subsystem: Subsystem,
    pub dll_characteristics: u16,
    pub data_directories: [DataDirectory; 16],
}
```

## Security Considerations

### Common Attack Vectors
- **Malformed headers**: Buffer overflow attempts
- **Section manipulation**: Overlapping or invalid sections
- **Import table hijacking**: DLL injection techniques
- **Resource bombs**: Recursive or oversized resources
- **Certificate spoofing**: Invalid Authenticode signatures

### Defensive Parsing
- Validate all RVA (Relative Virtual Address) conversions
- Check section boundaries before access
- Limit resource directory depth
- Verify import/export ordinals
- Validate certificate chains

### Packer Detection
- UPX signatures
- ASPack patterns
- Themida/VMProtect indicators
- Custom packer heuristics

## Testing Coverage

### Test Samples
- Minimal PE: `/reference/specifications/samples/minimal_pe.exe`
- Standard executables: 32-bit and 64-bit
- DLL files: With exports and forwarding
- Drivers: Kernel-mode binaries
- .NET assemblies: Managed code
- Packed samples: Various packers

### Validation Tests
- [ ] Header parsing correctness
- [ ] Import/export resolution
- [ ] Resource extraction
- [ ] Certificate validation
- [ ] .NET metadata parsing

## Windows-Specific Features

### Subsystems
- Console applications
- Windows GUI applications
- Native system processes
- EFI applications
- Windows CE
- POSIX

### DLL Characteristics
- ASLR (Address Space Layout Randomization)
- DEP (Data Execution Prevention)
- SEH (Structured Exception Handling)
- CFG (Control Flow Guard)
- High entropy VA

## .NET/CLR Extensions

### CLR Header
- Metadata location
- Entry point token
- Strong name signature
- Resources

### Metadata Streams
- #~ (Tables)
- #Strings
- #US (User Strings)
- #GUID
- #Blob

## Performance Optimizations

### Selective Parsing
- Parse only requested directories
- Lazy resource enumeration
- On-demand import resolution

### Caching Strategies
- RVA to file offset mapping
- String table caching
- Symbol lookup tables

## Error Handling

### Parse Errors
```rust
pub enum PeParseError {
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidMachine(u16),
    SectionOutOfBounds { rva: u32, size: u32 },
    InvalidDataDirectory { index: usize },
    MalformedImportTable,
    // ...
}
```

### Recovery Strategies
- Skip corrupted imports
- Ignore invalid resources
- Continue on certificate errors
- Provide partial parsing results

## Integration Points

### With Triage Pipeline
- Format detection via MZ/PE signatures
- Architecture determination
- Subsystem identification

### With Disassembler
- Code section identification
- Entry point location
- Import thunk resolution

### With Symbol Resolver
- Export table parsing
- Debug symbol extraction
- PDB reference

## Anti-Analysis Techniques

### Common Obfuscations
- [ ] Entry point obfuscation
- [ ] Import table hiding
- [ ] Section name randomization
- [ ] Timestamp manipulation
- [ ] Resource encryption

### Detection Methods
- Entropy analysis
- Known packer signatures
- Anomaly detection
- Behavioral heuristics

## Future Enhancements

- [ ] Full PDB parsing support
- [ ] Advanced packer unpacking
- [ ] .NET decompilation hints
- [ ] Driver-specific analysis
- [ ] Windows 11 features
- [ ] ARM64 PE support

## References

- [Microsoft PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ECMA-335 Common Language Infrastructure](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
- [Undocumented PE Features](http://www.ntcore.com/files/richsign.htm)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/)