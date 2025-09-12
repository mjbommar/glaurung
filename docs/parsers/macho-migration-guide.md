# Mach-O Parser Migration Guide

This guide provides step-by-step instructions for migrating from the scattered Mach-O parsing implementations to the new unified parser in `src/formats/macho/`.

## Migration Overview

### Old Structure (7 modules)
```
src/
├── symbols/
│   ├── macho.rs              # Basic symbol extraction
│   └── analysis/
│       └── macho_env.rs      # Environment analysis
├── triage/
│   ├── signatures.rs         # CPU type mappings
│   ├── format_detection.rs   # Magic detection
│   └── signing.rs            # Code signature refs
├── core/
│   └── binary.rs             # Format enum
└── analysis/
    └── env.rs                # Format routing
```

### New Structure (1 unified module)
```
src/formats/macho/
├── mod.rs              # Main MachOParser API
├── types.rs            # All constants and types
├── headers.rs          # Header parsing
├── segments.rs         # Segment/section parsing
├── load_commands.rs    # Load command parsing
├── symbols.rs          # Symbol table parsing
├── dyld.rs            # Dynamic linking info
├── codesign.rs        # Code signature parsing
├── fat.rs             # Universal binary support
└── utils.rs           # Utilities
```

## Module-by-Module Migration

### 1. Symbol Extraction (`src/symbols/macho.rs`)

#### Before
```rust
use crate::symbols::macho::summarize_macho;

pub fn analyze_binary(data: &[u8]) -> SymbolSummary {
    let caps = BudgetCaps::default();
    summarize_macho(data, &caps)
}
```

#### After
```rust
use crate::formats::macho::MachOParser;

pub fn analyze_binary(data: &[u8]) -> Result<SymbolSummary> {
    let parser = MachOParser::parse(data)?;
    
    // Get symbol table
    let symbols = parser.symbol_table()?;
    
    Ok(SymbolSummary {
        total: symbols.count() as u64,
        imports: symbols.imports().len() as u64,
        exports: symbols.exports().len() as u64,
        suspicious: symbols.suspicious_symbols().len() as u64,
        metadata: parser.metadata()?,
    })
}
```

### 2. Environment Analysis (`src/symbols/analysis/macho_env.rs`)

#### Before
```rust
use crate::symbols::analysis::macho_env::analyze_macho_env;

pub fn get_env_info(data: &[u8]) -> Option<MachoEnv> {
    analyze_macho_env(data)
}
```

#### After
```rust
use crate::formats::macho::MachOParser;

pub fn get_env_info(data: &[u8]) -> Result<BinaryEnv> {
    let parser = MachOParser::parse(data)?;
    
    // Get dynamic linking info
    let dyld = parser.dynamic_info()?;
    
    Ok(BinaryEnv {
        rpaths: dyld.rpaths(),
        needed_libs: dyld.needed_libraries(),
        minos: dyld.minimum_os_version(),
        code_signature: parser.has_code_signature(),
        entitlements: parser.entitlements()?,
    })
}
```

### 3. Format Detection (`src/triage/format_detection.rs`)

#### Before
```rust
fn detect_format(data: &[u8]) -> Option<Format> {
    if data.len() < 4 {
        return None;
    }
    
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xfeedface | 0xfeedfacf => Some(Format::MachO),
        0xcafebabe | 0xcafebabf => Some(Format::MachO), // Fat
        _ => None
    }
}
```

#### After
```rust
use crate::formats::macho::MachOParser;

fn detect_format(data: &[u8]) -> Option<Format> {
    // Quick magic check
    if MachOParser::is_macho(data) {
        return Some(Format::MachO);
    }
    
    // Or for detailed validation
    match MachOParser::parse(data) {
        Ok(parser) => {
            let file_type = parser.file_type();
            Some(Format::MachO { 
                subtype: file_type,
                arch: parser.architecture() 
            })
        }
        Err(_) => None
    }
}
```

### 4. CPU Type Mapping (`src/triage/signatures.rs`)

#### Before
```rust
pub fn macho_cpu_to_arch(cpu_type: u32) -> Arch {
    match cpu_type {
        7 => Arch::X86,
        0x01000007 => Arch::X86_64,
        12 => Arch::ARM,
        0x0100000C => Arch::AArch64,
        _ => Arch::Unknown,
    }
}
```

#### After
```rust
use crate::formats::macho::types::{CpuType, Architecture};

// Now handled internally by the parser
let parser = MachOParser::parse(data)?;
let arch = parser.architecture(); // Returns proper Architecture enum
```

### 5. Security Feature Detection

#### Before (scattered across multiple files)
```rust
// In macho_env.rs
let code_signature = load_commands.iter()
    .any(|cmd| cmd.cmd == 0x1d /* LC_CODE_SIGNATURE */);

// In symbols/macho.rs
let pie = (header.flags & 0x200000) != 0;

// Missing: stack canary, fortify, PAC detection
```

#### After (unified)
```rust
use crate::formats::macho::MachOParser;

let parser = MachOParser::parse(data)?;
let security = parser.security_features()?;

// All security features in one place
println!("PIE: {}", security.pie);
println!("Stack Canary: {}", security.stack_canary);
println!("FORTIFY: {}", security.fortify);
println!("Code Signature: {}", security.code_signature);
println!("Hardened Runtime: {}", security.hardened_runtime);
println!("Library Validation: {}", security.library_validation);
println!("PAC: {}", security.pac);
```

### 6. Fat/Universal Binary Support

#### Before
```rust
// In symbols/macho.rs
pub fn summarize_macho(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    // Detect FAT and bail
    if matches!(magic_raw, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64) {
        return SymbolSummary::default(); // No support!
    }
    // ...
}
```

#### After
```rust
use crate::formats::macho::{MachOParser, FatParser};

// Automatic handling of Fat binaries
let parser = MachOParser::parse(data)?;

// Or explicit Fat binary parsing
if FatParser::is_fat(data) {
    let fat = FatParser::parse(data)?;
    
    // List all architectures
    for arch in fat.architectures() {
        println!("Found architecture: {:?}", arch);
    }
    
    // Extract specific architecture
    let arm64_data = fat.slice_for_arch(Architecture::Arm64)?;
    let arm64_parser = MachOParser::parse(arm64_data)?;
    
    // Or get best architecture for current host
    let best_slice = fat.best_arch_for_host()?;
    let parser = MachOParser::parse(best_slice)?;
}
```

### 7. Load Command Parsing

#### Before
```rust
// Manual parsing with magic numbers
let mut off = header_size;
for _ in 0..ncmds {
    let cmd = read_u32(data, off, le)?;
    let cmdsize = read_u32(data, off + 4, le)?;
    
    match cmd {
        0x2 => { /* LC_SYMTAB */ }
        0xc => { /* LC_LOAD_DYLIB */ }
        0x1c => { /* LC_RPATH */ }
        _ => { /* skip */ }
    }
    off += cmdsize;
}
```

#### After
```rust
use crate::formats::macho::{MachOParser, LoadCommand};

let parser = MachOParser::parse(data)?;

// Type-safe load command iteration
for cmd in parser.load_commands()? {
    match cmd {
        LoadCommand::SymTab(symtab) => {
            println!("Symbol table at offset {:#x}", symtab.symoff);
        }
        LoadCommand::LoadDylib(dylib) => {
            println!("Depends on: {}", dylib.name);
        }
        LoadCommand::RPath(rpath) => {
            println!("Runtime path: {}", rpath.path);
        }
        LoadCommand::CodeSignature(cs) => {
            println!("Code signature at offset {:#x}", cs.dataoff);
        }
        _ => {}
    }
}
```

## Common Migration Patterns

### Pattern 1: Error Handling

#### Before
```rust
pub fn parse_something(data: &[u8]) -> Option<Info> {
    if data.len() < 32 {
        return None;
    }
    // Silent failures
    Some(info)
}
```

#### After
```rust
pub fn parse_something(data: &[u8]) -> Result<Info, MachOError> {
    let parser = MachOParser::parse(data)?;
    // Explicit error types
    parser.get_info()
        .map_err(|e| MachOError::ParseError(e))
}
```

### Pattern 2: Budget/Timeout Support

#### Before
```rust
pub fn summarize_macho(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    let start = Instant::now();
    // Manual timeout checking throughout
    if !time_ok(&start, caps) {
        return summary;
    }
}
```

#### After
```rust
use crate::formats::macho::{MachOParser, ParseOptions};

let options = ParseOptions {
    timeout: Some(Duration::from_millis(100)),
    max_symbols: Some(10000),
    parse_imports: true,
    parse_exports: true,
};

let parser = MachOParser::parse_with_options(data, options)?;
// Automatic timeout enforcement
```

### Pattern 3: Lazy Loading

#### Before
```rust
// Always parse everything upfront
let symbols = parse_all_symbols(data);
let strings = parse_all_strings(data);
let imports = extract_imports(&symbols, &strings);
```

#### After
```rust
let parser = MachOParser::parse(data)?;

// Only parse what's needed, when needed
if need_symbols {
    let symbols = parser.symbol_table()?; // Parsed on first access
}

if need_imports {
    let imports = parser.imports()?; // Cached after first parse
}
```

## Testing Your Migration

### 1. Unit Test Updates

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::macho::MachOParser;
    
    #[test]
    fn test_symbol_extraction() {
        let data = include_bytes!("testdata/hello_world");
        
        // Old way
        let old_summary = summarize_macho(data, &BudgetCaps::default());
        
        // New way
        let parser = MachOParser::parse(data).unwrap();
        let symbols = parser.symbol_table().unwrap();
        
        // Verify same results
        assert_eq!(old_summary.total, symbols.count() as u64);
        assert_eq!(old_summary.imports, symbols.imports().len() as u64);
    }
}
```

### 2. Integration Test Template

```rust
#[test]
fn test_real_binary_parsing() {
    let test_files = [
        "/bin/ls",
        "/usr/bin/swift",
        "/System/Library/Frameworks/Foundation.framework/Foundation",
    ];
    
    for path in &test_files {
        if let Ok(data) = std::fs::read(path) {
            // Should parse without panic
            let parser = MachOParser::parse(&data).unwrap();
            
            // Should have expected segments
            let segments = parser.segments().unwrap();
            assert!(segments.iter().any(|s| s.name() == "__TEXT"));
            
            // Should detect security features
            let security = parser.security_features().unwrap();
            assert!(security.pie); // Modern binaries have PIE
        }
    }
}
```

## Performance Comparison

### Benchmark Template

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_parsing(c: &mut Criterion) {
    let data = std::fs::read("/bin/ls").unwrap();
    
    c.bench_function("old_parser", |b| {
        b.iter(|| {
            summarize_macho(black_box(&data), &BudgetCaps::default())
        });
    });
    
    c.bench_function("new_parser", |b| {
        b.iter(|| {
            MachOParser::parse(black_box(&data)).unwrap()
        });
    });
    
    c.bench_function("new_parser_with_symbols", |b| {
        b.iter(|| {
            let parser = MachOParser::parse(black_box(&data)).unwrap();
            parser.symbol_table().unwrap();
        });
    });
}
```

Expected improvements:
- **Header parsing**: 10x faster (single pass vs multiple)
- **Symbol extraction**: 2x faster (zero-copy strings)
- **Fat binary support**: New capability (was unsupported)
- **Memory usage**: 50% reduction (lazy loading)

## Deprecation Timeline

### Phase 1: Parallel Implementation (Weeks 1-2)
- New parser implemented alongside old code
- Old code marked with deprecation warnings
- Both implementations tested in parallel

### Phase 2: Migration (Weeks 3-4)
```rust
#[deprecated(since = "0.2.0", note = "Use formats::macho::MachOParser instead")]
pub fn summarize_macho(data: &[u8], caps: &BudgetCaps) -> SymbolSummary {
    // Temporary wrapper during migration
    MachOParser::parse(data)
        .and_then(|p| p.symbol_summary())
        .unwrap_or_default()
}
```

### Phase 3: Cleanup (Week 5)
- Remove deprecated functions
- Delete old implementation files
- Update all documentation

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Missing Fat Binary Support
```rust
// Old code assumed single architecture
let summary = summarize_macho(data, &caps);

// New code needs architecture selection
let parser = if FatParser::is_fat(data) {
    let fat = FatParser::parse(data)?;
    MachOParser::parse(fat.best_arch_for_host()?)?
} else {
    MachOParser::parse(data)?
};
```

#### Issue 2: Different Error Types
```rust
// Old: Option-based
match analyze_macho_env(data) {
    Some(env) => { /* use env */ }
    None => { /* handle error */ }
}

// New: Result-based with specific errors
match MachOParser::parse(data) {
    Ok(parser) => { /* use parser */ }
    Err(MachOError::InvalidMagic(m)) => { /* not a Mach-O */ }
    Err(MachOError::Truncated { .. }) => { /* incomplete file */ }
    Err(e) => { /* other error */ }
}
```

#### Issue 3: Performance Regression
If you see performance regression:
1. Ensure you're using release builds
2. Check that lazy loading is working (don't parse everything upfront)
3. Use `parse_with_options()` to limit parsing scope
4. Profile with `cargo flamegraph` to identify bottlenecks

## Support and Resources

- **Documentation**: See `docs/parsers/macho-technical-design.md`
- **Examples**: Check `examples/macho_parser.rs`
- **Tests**: Review `src/formats/macho/tests/`
- **Benchmarks**: Run `cargo bench --bench macho`

## Checklist

Before removing old code, ensure:

- [ ] All call sites updated to use new parser
- [ ] All tests passing with new implementation
- [ ] Performance benchmarks show improvement or parity
- [ ] Documentation updated
- [ ] Fat binary support tested
- [ ] Security feature detection validated
- [ ] Error handling properly migrated
- [ ] Lazy loading working correctly
- [ ] No memory leaks or excessive allocations
- [ ] Code review completed