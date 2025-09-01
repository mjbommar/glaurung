# .NET CLR Parser Documentation

## Overview

.NET assemblies are PE files with embedded Common Language Runtime (CLR) metadata and Intermediate Language (IL) code. GLAURUNG's .NET parser handles managed assemblies (.exe, .dll), providing deep analysis of .NET applications including C#, VB.NET, F#, and other CLR languages.

## Format Specifications

### Primary References
- **ECMA-335 CLI**: `/reference/specifications/pe-coff/ECMA-335_CLI.pdf`
- **.NET PE Extensions**: `/reference/specifications/pe-coff/dotnet_PE_COFF.md`
- **CoreCLR Headers**: `/reference/specifications/pe-coff/dotnet_corinfo.h`
- **CLR Headers**: `/reference/specifications/dotnet/dotnet_cor.h`

## .NET Assembly Structure

```
┌─────────────────┐
│   PE Headers    │  Standard PE/COFF structure
├─────────────────┤
│  CLR Header     │  Runtime version, metadata location
├─────────────────┤
│    Metadata     │  Type system and member definitions
├─────────────────┤
│  Metadata       │  #~, #Strings, #US, #GUID, #Blob
│    Streams      │
├─────────────────┤
│   IL Code       │  Method bodies in MSIL
├─────────────────┤
│   Resources    │  Embedded resources
├─────────────────┤
│  Strong Name    │  Digital signature (optional)
└─────────────────┘
```

## Metadata Structure

```
┌─────────────────┐
│ Metadata Header │  Signature, version, stream count
├─────────────────┤
│   #~ Stream     │  Metadata tables (compressed)
├─────────────────┤
│ #Strings Stream │  String heap
├─────────────────┤
│   #US Stream    │  User string heap
├─────────────────┤
│  #GUID Stream   │  GUID heap
├─────────────────┤
│  #Blob Stream   │  Binary data heap
└─────────────────┘
```

## Parser Implementation

### Phase 1: PE Structure
- [ ] Standard PE validation
- [ ] CLR header location
- [ ] Runtime version detection
- [ ] Entry point resolution

### Phase 2: Metadata Parsing
- [ ] Stream enumeration
- [ ] Table schema detection
- [ ] String heap indexing
- [ ] GUID resolution

### Phase 3: Type System
- [ ] Module definition
- [ ] Type definitions and references
- [ ] Method signatures
- [ ] Field layouts
- [ ] Generic parameters

### Phase 4: IL Code Analysis
- [ ] Method body parsing
- [ ] Instruction decoding
- [ ] Exception handlers
- [ ] Local variable signatures

### Phase 5: Advanced Features
- [ ] Custom attributes
- [ ] Resource extraction
- [ ] Strong name validation
- [ ] Assembly references
- [ ] P/Invoke declarations

## Data Model

```rust
pub struct DotNetAssembly {
    pub pe_file: PeFile,
    pub clr_header: ClrHeader,
    pub metadata: Metadata,
    pub types: Vec<TypeDef>,
    pub methods: Vec<MethodDef>,
    pub assembly_refs: Vec<AssemblyRef>,
    pub resources: Vec<Resource>,
}

pub struct Metadata {
    pub version: String,
    pub tables: MetadataTables,
    pub strings: StringHeap,
    pub user_strings: UserStringHeap,
    pub guids: Vec<Guid>,
    pub blobs: BlobHeap,
}

pub struct TypeDef {
    pub namespace: String,
    pub name: String,
    pub base_type: Option<TypeRef>,
    pub fields: Vec<FieldDef>,
    pub methods: Vec<MethodDef>,
    pub properties: Vec<PropertyDef>,
    pub events: Vec<EventDef>,
}
```

## Metadata Tables

Key tables in the #~ stream:
- Module (0x00)
- TypeRef (0x01)
- TypeDef (0x02)
- Field (0x04)
- MethodDef (0x06)
- Param (0x08)
- MemberRef (0x0A)
- CustomAttribute (0x0C)
- Assembly (0x20)
- AssemblyRef (0x23)

## IL Instruction Categories

### Stack Manipulation
- ldloc, stloc (locals)
- ldarg, starg (arguments)
- dup, pop

### Control Flow
- br, beq, bne (branches)
- call, callvirt (method calls)
- ret, throw

### Object Model
- newobj (construction)
- ldfld, stfld (fields)
- castclass, isinst

## Security Considerations

### Code Access Security
- Permission demands
- Security transparency
- Strong name bypass
- Assembly loading

### Obfuscation
- Name mangling
- Control flow obfuscation
- String encryption
- Resource packing

## .NET Framework Versions

| Version | CLR Version | Release Year |
|---------|-------------|--------------|
| .NET 8  | 8.0         | 2023         |
| .NET 7  | 7.0         | 2022         |
| .NET 6  | 6.0         | 2021 (LTS)   |
| .NET 5  | 5.0         | 2020         |
| .NET Core 3.1 | 3.1   | 2019 (LTS)   |
| .NET Framework 4.8 | 4.0 | 2019    |

## Testing Coverage

### Test Samples
- Console applications: Various .NET versions
- Class libraries: With dependencies
- WPF/WinForms: GUI applications
- ASP.NET: Web applications
- Obfuscated: ConfuserEx, Dotfuscator

## Platform Support

### .NET Targets
- .NET (Core) 5+
- .NET Framework
- .NET Standard
- Mono
- Unity IL2CPP

### Special Formats
- Single-file executables
- ReadyToRun (R2R) images
- Native AOT compilation
- Mixed-mode assemblies

## Future Enhancements

- [ ] Full IL disassembly
- [ ] Type relationship graphs
- [ ] Async/await pattern detection
- [ ] LINQ expression trees
- [ ] Dynamic method analysis
- [ ] Roslyn metadata support
- [ ] Source link integration

## References

- [ECMA-335 Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
- [.NET Runtime Documentation](https://github.com/dotnet/runtime/tree/main/docs)
- [dnSpy Decompiler](https://github.com/dnSpy/dnSpy)
- [ILSpy Decompiler](https://github.com/icsharpcode/ILSpy)