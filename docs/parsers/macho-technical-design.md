# Mach-O Technical Design Document

## Format Overview

Mach-O (Mach Object) is the native executable format for macOS, iOS, and other Apple platforms. It supports multiple architectures in a single file (Universal/Fat binaries) and provides rich metadata for dynamic linking, code signing, and runtime security.

## File Structure

```
┌─────────────────────────────────────┐
│         Fat Header (optional)        │ ← Universal binary wrapper
├─────────────────────────────────────┤
│         Fat Arch Entry 1             │ ← Points to x86_64 slice
├─────────────────────────────────────┤
│         Fat Arch Entry 2             │ ← Points to ARM64 slice  
├─────────────────────────────────────┤
│         ... Padding ...              │
├─────────────────────────────────────┤
│    Mach-O Slice 1 (x86_64)          │
│    ┌───────────────────────┐        │
│    │     Mach Header       │        │ ← Magic, CPU type, load commands count
│    ├───────────────────────┤        │
│    │    Load Commands      │        │ ← Segment definitions, libraries, etc.
│    ├───────────────────────┤        │
│    │    Segment: __TEXT    │        │ ← Executable code
│    │    ├─ __text          │        │
│    │    ├─ __stubs         │        │
│    │    └─ __cstring       │        │
│    ├───────────────────────┤        │
│    │    Segment: __DATA    │        │ ← Writable data
│    │    ├─ __data          │        │
│    │    ├─ __bss           │        │
│    │    └─ __common        │        │
│    ├───────────────────────┤        │
│    │  Segment: __LINKEDIT  │        │ ← Symbol tables, code signature
│    └───────────────────────┘        │
├─────────────────────────────────────┤
│    Mach-O Slice 2 (ARM64)           │
│    ┌───────────────────────┐        │
│    │     Mach Header       │        │
│    │         ...           │        │
│    └───────────────────────┘        │
└─────────────────────────────────────┘
```

## Core Data Structures

### 1. Fat/Universal Binary Header

```rust
/// Fat binary header (big-endian)
pub struct FatHeader {
    pub magic: u32,      // 0xcafebabe or 0xcafebabf (64-bit)
    pub nfat_arch: u32,  // Number of architectures
}

/// Fat architecture entry
pub struct FatArch {
    pub cputype: i32,    // CPU type (e.g., x86_64, arm64)
    pub cpusubtype: i32, // CPU subtype
    pub offset: u64,     // File offset to this architecture
    pub size: u64,       // Size of this architecture
    pub align: u32,      // Alignment as power of 2
}
```

### 2. Mach-O Header

```rust
/// 64-bit Mach-O header
pub struct MachHeader64 {
    pub magic: u32,       // 0xfeedfacf (64-bit) or 0xfeedface (32-bit)
    pub cputype: i32,     // CPU type
    pub cpusubtype: i32,  // CPU subtype  
    pub filetype: u32,    // Type of file (executable, dylib, etc.)
    pub ncmds: u32,       // Number of load commands
    pub sizeofcmds: u32,  // Size of all load commands
    pub flags: u32,       // Flags (PIE, dyldlink, etc.)
    pub reserved: u32,    // 64-bit only
}
```

### 3. Load Commands

```rust
/// Load command header
pub struct LoadCommand {
    pub cmd: u32,     // Type of load command
    pub cmdsize: u32, // Size including this header
}

/// Common load command types
pub enum LoadCommandType {
    // Segments
    Segment64 = 0x19,        // LC_SEGMENT_64
    
    // Dynamic linking
    DyldInfo = 0x22,         // LC_DYLD_INFO
    LoadDylib = 0x0c,        // LC_LOAD_DYLIB
    LoadWeakDylib = 0x18,    // LC_LOAD_WEAK_DYLIB
    ReexportDylib = 0x1f,    // LC_REEXPORT_DYLIB
    
    // Symbol tables
    SymTab = 0x02,           // LC_SYMTAB
    DySymTab = 0x0b,         // LC_DYSYMTAB
    
    // Code signing
    CodeSignature = 0x1d,    // LC_CODE_SIGNATURE
    
    // Entry point
    Main = 0x28,             // LC_MAIN
    UnixThread = 0x05,       // LC_UNIXTHREAD (legacy)
    
    // Paths
    RPath = 0x1c,            // LC_RPATH
    
    // Encryption
    EncryptionInfo64 = 0x2c, // LC_ENCRYPTION_INFO_64
}
```

### 4. Segments and Sections

```rust
/// Segment command
pub struct SegmentCommand64 {
    pub cmd: u32,         // LC_SEGMENT_64
    pub cmdsize: u32,     // Size of this command
    pub segname: [u8; 16], // Segment name (e.g., "__TEXT")
    pub vmaddr: u64,      // Virtual memory address
    pub vmsize: u64,      // Virtual memory size
    pub fileoff: u64,     // File offset
    pub filesize: u64,    // File size
    pub maxprot: i32,     // Maximum protection
    pub initprot: i32,    // Initial protection
    pub nsects: u32,      // Number of sections
    pub flags: u32,       // Segment flags
}

/// Section within a segment
pub struct Section64 {
    pub sectname: [u8; 16], // Section name (e.g., "__text")
    pub segname: [u8; 16],  // Segment name
    pub addr: u64,          // Virtual address
    pub size: u64,          // Size in bytes
    pub offset: u32,        // File offset
    pub align: u32,         // Alignment (power of 2)
    pub reloff: u32,        // Relocation entries offset
    pub nreloc: u32,        // Number of relocations
    pub flags: u32,         // Section type and attributes
    pub reserved1: u32,     // Reserved
    pub reserved2: u32,     // Reserved
    pub reserved3: u32,     // 64-bit only
}
```

## Security Features Detection

### 1. Position Independent Executable (PIE)

```rust
// Check MH_PIE flag in header
const MH_PIE: u32 = 0x200000;
let is_pie = (header.flags & MH_PIE) != 0;
```

### 2. Stack Protection

```rust
// Look for __stack_chk_guard and __stack_chk_fail symbols
let has_stack_canary = symbols.iter()
    .any(|s| s.name == "__stack_chk_guard" || s.name == "__stack_chk_fail");
```

### 3. Hardened Runtime

```rust
// Check code signature flags
const CS_RUNTIME: u32 = 0x10000;
const CS_RESTRICT: u32 = 0x0800;
const CS_LIBRARY_VALIDATION: u32 = 0x2000;

let is_hardened = codesign_flags & CS_RUNTIME != 0;
```

### 4. FORTIFY_SOURCE

```rust
// Check for _chk function variants
let fortified_functions = ["__strcpy_chk", "__strcat_chk", "__sprintf_chk"];
let has_fortify = symbols.iter()
    .any(|s| fortified_functions.contains(&s.name.as_str()));
```

### 5. Automatic Reference Counting (ARC)

```rust
// Check for objc_retain/objc_release symbols
let has_arc = symbols.contains("_objc_retain") && 
               symbols.contains("_objc_release");
```

### 6. Pointer Authentication (PAC)

```rust
// Check CPU subtype for PAC support
const CPU_SUBTYPE_ARM64E: u32 = 0x80000002;
let has_pac = header.cpusubtype == CPU_SUBTYPE_ARM64E;
```

## Dynamic Linking Information

### 1. Dependent Libraries

```rust
pub struct DylibCommand {
    pub name: String,           // Library path
    pub timestamp: u32,         // Build timestamp
    pub current_version: u32,   // Current version
    pub compatibility_version: u32, // Minimum compatible version
}
```

### 2. Runtime Paths (RPATH)

```rust
// Parse LC_RPATH commands for dynamic library search paths
pub fn parse_rpaths(load_commands: &[LoadCommand]) -> Vec<String> {
    load_commands.iter()
        .filter_map(|cmd| match cmd {
            LoadCommand::RPath(path) => Some(path.clone()),
            _ => None
        })
        .collect()
}
```

### 3. Two-Level Namespace

```rust
// Symbol includes library ordinal for two-level namespace
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub library_ordinal: u8, // Which dylib this symbol comes from
}
```

## Chained Fixups (iOS 15+)

Modern format for rebase and bind information:

```rust
pub struct DyldChainedFixups {
    pub starts_in_image: u32,    // Offset to chain starts
    pub starts_in_segment: Vec<ChainStart>,
    pub imports: Vec<ChainedImport>,
}

pub struct ChainedImport {
    pub lib_ordinal: u8,
    pub weak_import: bool,
    pub name_offset: u32,
}
```

## Code Signing

### 1. Code Directory

```rust
pub struct CodeDirectory {
    pub version: u32,           // Format version
    pub flags: u32,             // Option flags
    pub hash_offset: u32,       // Offset to hash array
    pub ident_offset: u32,      // Offset to identifier string
    pub n_special_slots: u32,   // Number of special hash slots
    pub n_code_slots: u32,      // Number of code hash slots
    pub code_limit: u32,        // Size of signed code
    pub hash_size: u8,          // Size of each hash
    pub hash_type: u8,          // Hash algorithm (SHA1, SHA256)
    pub page_size: u8,          // log2(page size)
}
```

### 2. Entitlements

```rust
pub struct Entitlements {
    pub allow_jit: bool,
    pub allow_unsigned_executable_memory: bool,
    pub allow_dyld_environment_variables: bool,
    pub disable_library_validation: bool,
    pub app_sandbox: bool,
    pub hardened_runtime: bool,
}
```

## Parsing Algorithm

```rust
pub struct MachOParser<'a> {
    data: &'a [u8],
    header: OnceCell<MachHeader64>,
    load_commands: OnceCell<Vec<LoadCommand>>,
    segments: OnceCell<Vec<Segment>>,
    symbols: OnceCell<SymbolTable>,
}

impl<'a> MachOParser<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        // 1. Check for Fat binary
        let slice = if is_fat_binary(data) {
            extract_best_slice(data)?
        } else {
            data
        };
        
        // 2. Parse Mach header
        let header = parse_header(slice)?;
        
        // 3. Validate architecture
        validate_architecture(&header)?;
        
        // 4. Return lazy parser
        Ok(Self {
            data: slice,
            header: OnceCell::new(),
            load_commands: OnceCell::new(),
            segments: OnceCell::new(),
            symbols: OnceCell::new(),
        })
    }
    
    pub fn load_commands(&self) -> Result<&[LoadCommand]> {
        self.load_commands.get_or_try_init(|| {
            parse_load_commands(self.data, &self.header)
        })
    }
}
```

## Endianness Handling

```rust
pub trait EndianRead {
    fn read_u32(&self, offset: usize, big_endian: bool) -> Result<u32>;
    fn read_u64(&self, offset: usize, big_endian: bool) -> Result<u64>;
}

impl EndianRead for [u8] {
    fn read_u32(&self, offset: usize, big_endian: bool) -> Result<u32> {
        let bytes = self.get(offset..offset + 4)
            .ok_or(Error::InvalidOffset)?;
        Ok(if big_endian {
            u32::from_be_bytes(bytes.try_into().unwrap())
        } else {
            u32::from_le_bytes(bytes.try_into().unwrap())
        })
    }
}
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum MachOError {
    #[error("Invalid magic number: {0:#x}")]
    InvalidMagic(u32),
    
    #[error("Unsupported architecture: {cpu_type}")]
    UnsupportedArch { cpu_type: i32 },
    
    #[error("Invalid offset: {offset:#x} exceeds file size {size}")]
    InvalidOffset { offset: usize, size: usize },
    
    #[error("Malformed load command at offset {0:#x}")]
    MalformedLoadCommand(usize),
    
    #[error("No suitable architecture found in fat binary")]
    NoSuitableArch,
    
    #[error("Truncated file: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
}
```

## Performance Optimizations

### 1. Zero-Copy String Extraction

```rust
pub fn get_cstring(data: &[u8], offset: usize) -> Result<&str> {
    let start = offset;
    let mut end = offset;
    
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    
    std::str::from_utf8(&data[start..end])
        .map_err(|_| Error::InvalidString)
}
```

### 2. Lazy Symbol Table Building

```rust
impl SymbolTable {
    pub fn parse_lazy(data: &[u8], symtab: &SymTabCommand) -> Self {
        Self {
            data,
            symtab: *symtab,
            by_name: OnceCell::new(),
            by_address: OnceCell::new(),
        }
    }
    
    fn build_indices(&self) {
        self.by_name.get_or_init(|| {
            // Build hash map on first name lookup
            build_name_index(self.data, &self.symtab)
        });
    }
}
```

### 3. Memory-Mapped File Support

```rust
pub fn parse_mmap(path: &Path) -> Result<MachOParser> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    MachOParser::parse(&mmap)
}
```

## Architecture Support Matrix

| Architecture | CPU Type | CPU Subtype | Supported |
|--------------|----------|-------------|-----------|
| x86          | 0x07     | ALL         | ✅        |
| x86_64       | 0x01000007 | ALL       | ✅        |
| x86_64h      | 0x01000007 | 0x08      | ✅        |
| ARM          | 0x0C     | V7, V7S     | ✅        |
| ARM64        | 0x0100000C | ALL       | ✅        |
| ARM64E       | 0x0100000C | 0x02      | ✅        |
| ARM64_32     | 0x0200000C | V8       | ✅        |
| PowerPC      | 0x12     | ALL         | ⚠️         |
| PowerPC64    | 0x01000012 | ALL       | ⚠️         |

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_minimal_macho() {
        let data = create_minimal_macho();
        let parser = MachOParser::parse(&data).unwrap();
        assert_eq!(parser.header().magic, MH_MAGIC_64);
    }
    
    #[test]
    fn test_parse_fat_binary() {
        let data = create_fat_binary();
        let parser = MachOParser::parse(&data).unwrap();
        assert_eq!(parser.architectures().len(), 2);
    }
    
    #[test]
    fn test_invalid_magic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = MachOParser::parse(&data);
        assert!(matches!(result, Err(MachOError::InvalidMagic(_))));
    }
}
```

### Integration Tests

```rust
#[test]
fn test_parse_system_binary() {
    let data = std::fs::read("/bin/ls").unwrap();
    let parser = MachOParser::parse(&data).unwrap();
    
    // Verify expected segments
    let segments = parser.segments().unwrap();
    assert!(segments.iter().any(|s| s.name == "__TEXT"));
    assert!(segments.iter().any(|s| s.name == "__DATA"));
    assert!(segments.iter().any(|s| s.name == "__LINKEDIT"));
    
    // Verify security features
    let security = parser.security_features().unwrap();
    assert!(security.pie);
    assert!(security.stack_canary);
}
```

## References

- [Apple's Mach-O Programming Topics](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html)
- [mach-o/loader.h Source](https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html)
- [iOS Security Guide](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)
- [The Mach-O Executable Format](https://blog.timac.org/2016/1124-analysis-of-the-ios-10-kernelcache/)
- [dyld Source Code](https://opensource.apple.com/source/dyld/)