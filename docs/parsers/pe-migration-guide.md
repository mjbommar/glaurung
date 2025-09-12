# PE Parser Migration Guide

## Overview

This guide helps migrate from the current scattered PE parsing implementations to the new unified PE parser.

## Quick Start

### Before (Multiple Implementations)

```rust
// Old: Using symbols/pe.rs
use crate::symbols::pe::summarize_pe;
use crate::symbols::types::BudgetCaps;

let caps = BudgetCaps::default();
let summary = summarize_pe(data, &caps);
println!("Imports: {}", summary.imports_count);

// Old: Using analysis/pe_iat.rs
use crate::analysis::pe_iat::pe_iat_map;
let iat_map = pe_iat_map(data);

// Old: Using symbols/analysis/pe_env.rs
use crate::symbols::analysis::pe_env::analyze_pe_env;
let env = analyze_pe_env(data);

// Old: Using object crate
use object::read::pe::PeFile;
let pe = PeFile::parse(data)?;
let imports = pe.imports()?;
```

### After (Unified Parser)

```rust
// New: Single unified parser
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;

// All functionality in one place
let imports = parser.imports()?;
let iat_map = parser.iat_map()?;
let pdb_path = parser.pdb_path()?;
let tls_callbacks = parser.tls_callbacks()?;

println!("Imports: {}", imports.len());
```

## Module-by-Module Migration

### 1. Migrating from `src/symbols/pe.rs`

#### Symbol Summary

**Old:**
```rust
use crate::symbols::pe::summarize_pe;
use crate::symbols::types::{BudgetCaps, SymbolSummary};

let caps = BudgetCaps {
    max_imports: 1000,
    max_exports: 1000,
    time_guard_ms: 100,
    ..Default::default()
};

let summary = summarize_pe(data, &caps);

// Access fields
let import_count = summary.imports_count;
let export_count = summary.exports_count;
let import_names = summary.import_names;
let is_stripped = summary.stripped;
let has_nx = summary.nx.unwrap_or(false);
```

**New:**
```rust
use crate::formats::pe::{PeParser, ParseOptions};

let options = ParseOptions {
    parse_imports: true,
    parse_exports: true,
    timeout_ms: Some(100),
    ..Default::default()
};

let parser = PeParser::with_options(data, options)?;

// Direct access to parsed data
let imports = parser.imports()?;
let exports = parser.exports()?;

// Equivalent fields
let import_count = imports.len();
let export_count = exports.len();
let import_names: Vec<String> = imports.iter()
    .filter_map(|i| i.name.map(|s| s.to_string()))
    .collect();

// Security features
let security = parser.security_features();
let has_nx = security.nx_compatible;
let is_stripped = parser.debug_info()?.is_empty();
```

#### TLS Callbacks

**Old:**
```rust
let summary = summarize_pe(data, &caps);
let tls_count = summary.tls_callback_count;
let tls_vas = summary.tls_callback_vas;
```

**New:**
```rust
let parser = PeParser::new(data)?;
let tls_callbacks = parser.tls_callbacks()?;
let tls_count = tls_callbacks.len();
let tls_vas = tls_callbacks; // Already a Vec<u64>
```

#### PDB Path

**Old:**
```rust
let summary = summarize_pe(data, &caps);
let pdb_path = summary.pdb_path;
```

**New:**
```rust
let parser = PeParser::new(data)?;
let pdb_path = parser.pdb_path()?;
```

### 2. Migrating from `src/analysis/pe_iat.rs`

#### IAT Mapping

**Old:**
```rust
use crate::analysis::pe_iat::pe_iat_map;

let iat_entries = pe_iat_map(data);
for (va, name) in iat_entries {
    println!("0x{:x} -> {}", va, name);
}
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;
let iat_map = parser.iat_map()?;

for (va, name) in iat_map {
    println!("0x{:x} -> {}", va, name);
}

// Additional: Can also access imports directly
let imports = parser.imports()?;
for import in imports {
    if let Some(iat_va) = import.iat_va {
        println!("0x{:x} -> {:?}", iat_va, import.name);
    }
}
```

### 3. Migrating from `src/symbols/analysis/pe_env.rs`

#### PE Environment Analysis

**Old:**
```rust
use crate::symbols::analysis::pe_env::{analyze_pe_env, PeEnv};

let env = analyze_pe_env(data).unwrap();
let pdb_path = env.pdb_path;
let tls_callbacks = env.tls_callbacks;
let entry_section = env.entry_section;
let has_relocs = env.relocations_present;
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;

let pdb_path = parser.pdb_path()?;
let tls_callbacks = parser.tls_callbacks()?.len();
let entry_section = parser.entry_section()?;
let has_relocs = parser.has_relocations();

// More detailed info available
let relocs = parser.relocations()?;
let debug_entries = parser.debug_info()?;
```

### 4. Migrating from `src/symbols/analysis/imphash.rs`

#### Import Hash

**Old:**
```rust
use crate::symbols::analysis::imphash::pe_imphash;

let imphash = pe_imphash(data);
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;
let imphash = parser.import_hash()?;

// Additional: Can customize hash algorithm
let sha256_hash = parser.import_hash_sha256()?;
```

### 5. Migrating from `src/triage/rich_header.rs`

#### Rich Header

**Old:**
```rust
use crate::triage::rich_header::{parse_rich_header, RichHeader};

let rich = parse_rich_header(data);
if let Some(header) = rich {
    println!("XOR key: 0x{:x}", header.xor_key);
    for entry in header.entries {
        println!("{:?}", entry);
    }
}
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;
let rich = parser.rich_header()?;

if let Some(header) = rich {
    println!("XOR key: 0x{:x}", header.xor_key);
    for entry in &header.entries {
        println!("{:?}", entry);
    }
}
```

### 6. Migrating from `object` Crate Usage

#### Basic Parsing

**Old:**
```rust
use object::read::pe::{PeFile32, PeFile64};
use object::Object;

// Try both architectures
let pe = if let Ok(pe) = PeFile64::parse(data) {
    pe
} else {
    PeFile32::parse(data)?
};

let entry = pe.entry();
let is_64 = pe.is_64();
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;

let entry = parser.entry_point();
let is_64 = parser.is_64bit();

// Architecture detection is automatic
let machine = parser.machine();
```

#### Imports

**Old:**
```rust
use object::read::pe::PeFile;
use object::Object;

let pe = PeFile::parse(data)?;
let imports = pe.imports()?;

for import in imports {
    let lib = std::str::from_utf8(import.library())?;
    let name = std::str::from_utf8(import.name())?;
    println!("{}:{}", lib, name);
}
```

**New:**
```rust
use crate::formats::pe::PeParser;

let parser = PeParser::new(data)?;
let imports = parser.imports()?;

for import in imports {
    println!("{}:{}", import.dll_name, import.name.unwrap_or("<ordinal>"));
}

// More detailed import info available
for descriptor in parser.import_descriptors()? {
    println!("DLL: {}", descriptor.dll_name);
    for entry in &descriptor.entries {
        match (entry.name, entry.ordinal) {
            (Some(name), _) => println!("  Name: {}", name),
            (None, Some(ord)) => println!("  Ordinal: {}", ord),
            _ => {}
        }
    }
}
```

#### Exports

**Old:**
```rust
let pe = PeFile::parse(data)?;
let exports = pe.exports()?;

for export in exports {
    let name = std::str::from_utf8(export.name())?;
    let address = export.address();
    println!("{}: 0x{:x}", name, address);
}
```

**New:**
```rust
let parser = PeParser::new(data)?;
let exports = parser.exports()?;

for export in exports {
    let name = export.name.unwrap_or("<unnamed>");
    println!("{}: 0x{:x}", name, export.rva);
    
    // Additional: Check for forwarders
    if let Some(forwarder) = export.forwarder {
        println!("  -> Forwarded to: {}", forwarder);
    }
}
```

#### Sections

**Old:**
```rust
let pe = PeFile::parse(data)?;
for section in pe.sections() {
    let name = std::str::from_utf8(section.name())?;
    let size = section.size();
    println!("{}: {} bytes", name, size);
}
```

**New:**
```rust
let parser = PeParser::new(data)?;
for section in parser.sections() {
    println!("{}: {} bytes", section.name(), section.size());
    
    // Additional info available
    println!("  Virtual: 0x{:x}", section.virtual_address());
    println!("  Characteristics: 0x{:x}", section.characteristics());
    println!("  Entropy: {:.2}", section.entropy());
}
```

## Common Patterns

### Error Handling

**Old:** Mixed error types across modules
```rust
// Different error types
let summary = summarize_pe(data, &caps); // Returns SymbolSummary (no error)
let iat = pe_iat_map(data); // Returns Vec (no error)
let env = analyze_pe_env(data); // Returns Option<PeEnv>
let pe = PeFile::parse(data)?; // Returns object::Error
```

**New:** Unified error handling
```rust
use crate::formats::pe::{PeParser, PeError};

match PeParser::new(data) {
    Ok(parser) => {
        // All methods return Result<T, PeError>
        let imports = parser.imports()?;
        let exports = parser.exports()?;
    }
    Err(PeError::InvalidDosSignature) => {
        println!("Not a PE file");
    }
    Err(PeError::Truncated { expected, actual }) => {
        println!("File truncated: expected {} bytes, got {}", expected, actual);
    }
    Err(e) => {
        println!("Parse error: {}", e);
    }
}
```

### Performance Optimization

**Old:** Everything parsed upfront
```rust
let summary = summarize_pe(data, &caps); // Parses everything
```

**New:** Lazy loading
```rust
let parser = PeParser::new(data)?; // Only parses headers

// These are parsed on-demand and cached
let imports = parser.imports()?; // Parsed once, cached
let imports2 = parser.imports()?; // Returns cached value

// Control what gets parsed
let options = ParseOptions {
    parse_imports: true,
    parse_exports: false, // Skip exports
    parse_resources: false, // Skip resources
    ..Default::default()
};
let parser = PeParser::with_options(data, options)?;
```

### Batch Operations

**Old:** Multiple passes over the file
```rust
let summary = summarize_pe(data, &caps);
let iat = pe_iat_map(data);
let env = analyze_pe_env(data);
// Each function re-parses the PE headers
```

**New:** Single parse, multiple queries
```rust
let parser = PeParser::new(data)?;

// All operations on same parsed structure
let analysis = PeAnalysis {
    imports: parser.imports()?.len(),
    exports: parser.exports()?.len(),
    iat_entries: parser.iat_map()?.len(),
    has_tls: !parser.tls_callbacks()?.is_empty(),
    has_resources: parser.has_resources(),
    security: parser.security_features(),
};
```

## Testing Your Migration

### Comparison Testing

```rust
#[cfg(test)]
mod migration_tests {
    use super::*;
    
    #[test]
    fn test_import_count_matches() {
        let data = include_bytes!("test.exe");
        
        // Old way
        let old_summary = summarize_pe(data, &BudgetCaps::default());
        
        // New way
        let parser = PeParser::new(data).unwrap();
        let new_imports = parser.imports().unwrap();
        
        assert_eq!(
            old_summary.imports_count as usize,
            new_imports.len(),
            "Import counts should match"
        );
    }
    
    #[test]
    fn test_iat_map_matches() {
        let data = include_bytes!("test.exe");
        
        // Old way
        let old_iat = pe_iat_map(data);
        
        // New way
        let parser = PeParser::new(data).unwrap();
        let new_iat = parser.iat_map().unwrap();
        
        // Compare entries
        for (va, name) in &old_iat {
            assert_eq!(
                new_iat.get(va),
                Some(name),
                "IAT entry at 0x{:x} should match",
                va
            );
        }
    }
}
```

### Performance Comparison

```rust
use criterion::{black_box, criterion_group, Criterion};

fn benchmark_parsers(c: &mut Criterion) {
    let data = include_bytes!("large.exe");
    
    c.bench_function("old_parser", |b| {
        b.iter(|| {
            let summary = summarize_pe(black_box(data), &BudgetCaps::default());
            let _ = pe_iat_map(black_box(data));
            let _ = analyze_pe_env(black_box(data));
        });
    });
    
    c.bench_function("new_parser", |b| {
        b.iter(|| {
            let parser = PeParser::new(black_box(data)).unwrap();
            let _ = parser.imports();
            let _ = parser.iat_map();
            let _ = parser.pdb_path();
        });
    });
}
```

## Deprecation Timeline

### Phase 1 (Weeks 1-2)
- New parser available in `src/formats/pe/`
- Old modules still functional
- Add deprecation warnings

### Phase 2 (Weeks 3-4)
- Update all internal usage
- Document migration in CHANGELOG
- Update examples and tests

### Phase 3 (Weeks 5-6)
- Mark old modules as deprecated
- Add compatibility shims if needed

### Phase 4 (Week 8)
- Remove old implementations
- Clean up dependencies
- Final documentation update

## Getting Help

### Documentation
- API docs: `cargo doc --open`
- Examples: `examples/pe_parser.rs`
- Tests: `tests/pe_migration.rs`

### Common Issues

**Issue:** Import counts don't match
- **Cause:** New parser deduplicates imports
- **Solution:** Use `import_descriptors()` for raw data

**Issue:** Missing `object` trait methods
- **Cause:** Different API design
- **Solution:** See trait mapping table below

**Issue:** Performance regression
- **Cause:** Not using lazy loading
- **Solution:** Use `ParseOptions` to skip unused data

## Trait Mapping

| object::Object Trait | New PeParser Method |
|---------------------|-------------------|
| `entry()` | `entry_point()` |
| `is_64()` | `is_64bit()` |
| `endianness()` | N/A (always LE) |
| `sections()` | `sections()` |
| `section_by_name()` | `section_by_name()` |
| `symbol_table()` | `symbols()` |
| `imports()` | `imports()` |
| `exports()` | `exports()` |
| `pdb_info()` | `pdb_path()` |
| `has_debug_symbols()` | `has_debug_info()` |

## Conclusion

The new unified PE parser provides:
- Single API for all PE operations
- Better performance through lazy loading
- Comprehensive error handling
- More features (resources, certificates, etc.)
- Cleaner codebase without external dependencies

Migration is straightforward with mostly 1:1 API mappings. The main changes are:
1. Single parser object instead of multiple functions
2. Unified error type
3. Lazy loading for performance
4. More detailed information available

For any issues during migration, refer to the examples and tests, or file an issue in the repository.